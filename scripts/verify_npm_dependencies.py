#!/usr/bin/env python3
"""Install eligible npm fixtures with scripts disabled and verify registry signatures."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def allowed_url(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in allowed_hosts


def preflight(project: Path, policy: dict[str, Any]) -> dict[str, Any]:
    manifest_path = project / "package.json"
    lock_path = project / "package-lock.json"
    if not manifest_path.is_file() or not lock_path.is_file():
        return {"eligible": False, "reasons": ["Falta package.json o package-lock.json."], "mismatches": {}, "unapprovedSources": []}

    manifest = read_json(manifest_path)
    lock = read_json(lock_path)
    declared: dict[str, str] = {}
    locked: dict[str, str] = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        declared.update(manifest.get(field, {}))
        locked.update(lock.get("packages", {}).get("", {}).get(field, {}))
    mismatches = {
        name: {"manifest": declared.get(name), "lock": locked.get(name)}
        for name in sorted(set(declared) | set(locked))
        if declared.get(name) != locked.get(name)
    }

    allowed_hosts = set(policy["registries"]["allowedHosts"])
    unapproved_sources: list[dict[str, str]] = []
    local_dependencies: list[dict[str, str]] = []
    registry_dependencies: list[dict[str, str]] = []
    for package_path, item in lock.get("packages", {}).items():
        resolved = item.get("resolved")
        if resolved and urlparse(resolved).scheme:
            if not allowed_url(resolved, allowed_hosts):
                unapproved_sources.append({"packagePath": package_path, "url": resolved})
            elif package_path.startswith("node_modules/"):
                registry_dependencies.append({"packagePath": package_path, "url": resolved})
        elif package_path.startswith("node_modules/") and (item.get("link") or resolved):
            local_dependencies.append({"packagePath": package_path, "resolved": str(resolved or "")})

    npmrc_path = project / ".npmrc"
    if npmrc_path.is_file():
        for line_number, raw_line in enumerate(npmrc_path.read_text(encoding="utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if (key == "registry" or key.endswith(":registry")) and not allowed_url(value, allowed_hosts):
                unapproved_sources.append({"packagePath": f".npmrc:{line_number}", "url": value})

    reasons: list[str] = []
    if mismatches:
        reasons.append("El manifiesto y el lockfile no concuerdan.")
    if unapproved_sources:
        reasons.append("El escenario contiene un registro o una URL de resolución no autorizados.")
    return {
        "eligible": not reasons,
        "reasons": reasons,
        "mismatches": mismatches,
        "unapprovedSources": unapproved_sources,
        "localDependencies": local_dependencies,
        "registryDependencies": registry_dependencies,
    }


def run(command: list[str], cwd: Path, env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def append_finding(
    findings: list[dict[str, Any]],
    control: str,
    decision: str,
    message: str,
    evidence: dict[str, Any],
) -> None:
    findings.append({"control": control, "decision": decision, "message": message, "evidence": evidence})


def evaluate(project: Path, policy: dict[str, Any]) -> dict[str, Any]:
    observed_at = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "project": str(project),
        "ecosystem": "npm",
        "observedAt": observed_at,
        "status": "not_applicable",
        "findings": [],
    }
    manifest_path = project / "package.json"
    lock_path = project / "package-lock.json"
    if not manifest_path.is_file() or not lock_path.is_file():
        report["reason"] = "El escenario no es un proyecto npm con lockfile."
        return report

    gate = preflight(project, policy)
    report["preflight"] = gate
    if not gate["eligible"]:
        report["status"] = "skipped"
        report["reason"] = "Se omitió la instalación para no descargar desde fuentes no autorizadas ni resolver un lockfile inconsistente."
        return report

    npm_version = subprocess.run(["npm", "--version"], text=True, capture_output=True, check=False)
    node_version = subprocess.run(["node", "--version"], text=True, capture_output=True, check=False)
    report["npmVersion"] = npm_version.stdout.strip() if npm_version.returncode == 0 else None
    report["nodeVersion"] = node_version.stdout.strip() if node_version.returncode == 0 else None
    report["findings"] = findings = []
    integrity_policy = policy["dependencyIntegrity"]

    if npm_version.returncode != 0 or node_version.returncode != 0:
        report["status"] = "manual_review"
        append_finding(
            findings,
            "npm_signature_verification",
            integrity_policy["verificationFailureDecision"],
            "No se pudo obtener la versión de Node.js/npm para verificar las dependencias.",
            {"npmExitCode": npm_version.returncode, "nodeExitCode": node_version.returncode},
        )
        return report

    version_match = re.match(r"^(\d+)\.(\d+)\.(\d+)", report["npmVersion"] or "")
    if not version_match or tuple(map(int, version_match.groups())) < (9, 5, 0):
        report["status"] = "manual_review"
        append_finding(
            findings,
            "npm_registry_signature",
            integrity_policy["verificationFailureDecision"],
            "La versión de npm es anterior a 9.5.0 o no se pudo interpretar; no se garantiza npm audit signatures.",
            {"npmVersion": report["npmVersion"], "minimumVersion": "9.5.0"},
        )
        return report

    with tempfile.TemporaryDirectory(prefix="dependency-integrity-") as temp_name:
        temp_root = Path(temp_name)
        workspace = temp_root / "project"
        shutil.copytree(
            project,
            workspace,
            ignore=shutil.ignore_patterns("node_modules", ".git", ".npm"),
        )
        user_config = temp_root / "npmrc"
        user_config.write_text(
            "registry=https://registry.npmjs.org/\nignore-scripts=true\naudit=false\nfund=false\n",
            encoding="utf-8",
        )
        cache = temp_root / "npm-cache"
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith("NPM_CONFIG_")}
        env.update(
            {
                "CI": "true",
                "npm_config_cache": str(cache),
                "npm_config_userconfig": str(user_config),
                "npm_config_registry": "https://registry.npmjs.org/",
                "npm_config_ignore_scripts": "true",
                "npm_config_audit": "false",
                "npm_config_fund": "false",
            }
        )
        marker_fixture_present = (workspace / "fixtures/lab-postinstall-fixture/package.json").is_file()
        marker_before = {
            str(path.relative_to(workspace)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in workspace.rglob("postinstall-marker.txt")
        }
        install_command = [
            "npm",
            "ci",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--registry=https://registry.npmjs.org/",
            f"--userconfig={user_config}",
        ]
        try:
            install = run(install_command, workspace, env, timeout=300)
        except (OSError, subprocess.TimeoutExpired) as error:
            report["status"] = "manual_review"
            append_finding(
                findings,
                "npm_install_verification",
                integrity_policy["verificationFailureDecision"],
                "No se pudo completar npm ci --ignore-scripts en el directorio temporal.",
                {"error": str(error), "scriptsIgnored": True},
            )
            return report

        report["install"] = {
            "command": [
                "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
                "--registry=https://registry.npmjs.org/", "--userconfig=<configuración temporal>",
            ],
            "exitCode": install.returncode,
            "scriptsIgnored": True,
            "stdout": install.stdout[-8000:],
            "stderr": install.stderr[-8000:],
        }
        if install.returncode != 0:
            report["status"] = "manual_review"
            append_finding(
                findings,
                "npm_install_verification",
                integrity_policy["verificationFailureDecision"],
                "npm ci --ignore-scripts no pudo reproducir el árbol fijado en el lockfile.",
                {"exitCode": install.returncode, "stderr": install.stderr[-4000:]},
            )
            return report

        marker_after = {
            str(path.relative_to(workspace)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in workspace.rglob("postinstall-marker.txt")
        }
        changed_markers = sorted(
            path for path, digest in marker_after.items()
            if marker_before.get(path) != digest
        )
        report["lifecycleMarkerCheck"] = {
            "checked": marker_fixture_present,
            "marker": "postinstall-marker.txt",
            "createdOrChangedDuringInstall": changed_markers,
            "scriptsIgnored": True,
        }
        if marker_fixture_present and changed_markers:
            append_finding(
                findings,
                "lifecycle_scripts_ignored",
                "bloquear",
                "Se creó o modificó el marcador del fixture durante npm ci --ignore-scripts.",
                {"changedMarkers": changed_markers},
            )

        signature_command = ["npm", "audit", "signatures", "--json", "--include-attestations"]
        try:
            signature_result = run(signature_command, workspace, env, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as error:
            report["status"] = "manual_review"
            append_finding(
                findings,
                "npm_registry_signature",
                integrity_policy["verificationFailureDecision"],
                "No se pudo completar npm audit signatures.",
                {"error": str(error)},
            )
            return report

        summary_command = ["npm", "audit", "signatures"]
        try:
            summary_result = run(summary_command, workspace, env, timeout=180)
        except (OSError, subprocess.TimeoutExpired) as error:
            summary_result = None
            summary_error = str(error)
        else:
            summary_error = None

        try:
            signature_data = json.loads(signature_result.stdout)
            if not isinstance(signature_data, dict):
                raise ValueError("La respuesta JSON no es un objeto.")
            if not all(isinstance(signature_data.get(key), list) for key in ("invalid", "missing", "verified")):
                raise ValueError("La respuesta JSON no contiene las listas invalid, missing y verified esperadas.")
        except (json.JSONDecodeError, ValueError) as error:
            signature_data = None
            parse_error = str(error)
        else:
            parse_error = None

        invalid = signature_data.get("invalid", []) if signature_data else []
        missing = signature_data.get("missing", []) if signature_data else []
        attestations = signature_data.get("verified", []) if signature_data else []
        human_summary = summary_result.stdout if summary_result else ""
        verified_count_match = re.search(
            r"(\d+)\s+packages?\s+(?:have|has)\s+(?:a\s+)?verified registry signatures?",
            human_summary,
            re.IGNORECASE,
        )
        verified_count = int(verified_count_match.group(1)) if verified_count_match else None
        signature_count_is_plausible = verified_count is not None and (
            verified_count > 0 or not gate.get("registryDependencies")
        )
        report["signatureVerification"] = {
            "command": signature_command,
            "summaryCommand": summary_command,
            "exitCode": signature_result.returncode,
            "summaryExitCode": summary_result.returncode if summary_result else None,
            "registrySignatures": "verified" if signature_data is not None and signature_result.returncode == 0 and not invalid and not missing and summary_result and summary_result.returncode == 0 and signature_count_is_plausible else "not_verified",
            "verifiedRegistrySignatureCount": verified_count,
            "registryDependenciesExpected": len(gate.get("registryDependencies", [])),
            "humanSummary": human_summary[-4000:],
            "invalid": invalid,
            "missing": missing,
            "provenance": "verified" if attestations else "no_attestation_reported",
            "verifiedAttestations": attestations,
            "localDependenciesNotRegistrySigned": gate.get("localDependencies", []),
            "summaryError": summary_error,
            "stderr": signature_result.stderr[-8000:],
        }

        if invalid:
            append_finding(
                findings,
                "npm_registry_signature",
                integrity_policy["invalidSignatureDecision"],
                "npm informó firmas de registro inválidas para dependencias descargadas.",
                {"invalid": invalid, "exitCode": signature_result.returncode},
            )
        if missing:
            append_finding(
                findings,
                "npm_registry_signature",
                integrity_policy["missingSignatureDecision"],
                "Una o más dependencias no tienen una firma de registro verificable.",
                {"missing": missing, "exitCode": signature_result.returncode},
            )
        if parse_error or (
            signature_result.returncode != 0 and not invalid and not missing
        ) or (summary_result is None or summary_result.returncode != 0) or not signature_count_is_plausible:
            append_finding(
                findings,
                "npm_registry_signature",
                integrity_policy["verificationFailureDecision"],
                "npm no pudo verificar las firmas del registro.",
                {
                    "exitCode": signature_result.returncode,
                    "summaryExitCode": summary_result.returncode if summary_result else None,
                    "verifiedRegistrySignatureCount": verified_count,
                    "registryDependenciesExpected": len(gate.get("registryDependencies", [])),
                    "error": parse_error,
                    "stdout": signature_result.stdout[-4000:],
                    "stderr": signature_result.stderr[-4000:],
                },
            )

    decisions = {finding["decision"] for finding in findings}
    report["status"] = "failed" if "bloquear" in decisions else "manual_review" if decisions else "passed"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    report = evaluate(args.project, read_json(args.policy))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{args.project}: npm integrity {report['status']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"Error de verificación npm: {error}", file=sys.stderr)
        raise SystemExit(2)
