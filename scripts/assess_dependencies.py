#!/usr/bin/env python3
"""Inspect committed dependency metadata and consolidate findings without installing packages."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DECISION_RANK = {"permitir": 0, "revision_manual": 1, "bloquear": 2}
USER_AGENT = "dependency-security-assessment/1.0"


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def request_registry_metadata(package: str, version: str | None = None) -> dict[str, Any]:
    encoded_package = urllib.parse.quote(package, safe="")
    suffix = f"/{urllib.parse.quote(version, safe='')}" if version else ""
    url = f"https://registry.npmjs.org/{encoded_package}{suffix}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def add_finding(
    findings: list[dict[str, Any]],
    control: str,
    decision: str,
    message: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    finding: dict[str, Any] = {
        "control": control,
        "decision": decision,
        "message": message,
    }
    if evidence is not None:
        finding["evidence"] = evidence
    findings.append(finding)


def allowed_host(url: str, hosts: set[str]) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in hosts


def inspect_npm_project(
    project: Path,
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> None:
    manifests = sorted(
        path
        for path in project.rglob("package.json")
        if "node_modules" not in path.parts
    )
    lock_path = project / "package-lock.json"
    root_manifest_path = project / "package.json"
    hosts = set(policy["registries"]["allowedHosts"])

    if root_manifest_path.is_file() and lock_path.is_file():
        manifest = read_json(root_manifest_path)
        lock = read_json(lock_path)
        manifest_dependencies: dict[str, str] = {}
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            manifest_dependencies.update(manifest.get(field, {}))
        locked_root = lock.get("packages", {}).get("", {})
        locked_dependencies: dict[str, str] = {}
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            locked_dependencies.update(locked_root.get(field, {}))
        mismatches = {
            name: {"manifest": manifest_dependencies.get(name), "lock": locked_dependencies.get(name)}
            for name in sorted(set(manifest_dependencies) | set(locked_dependencies))
            if manifest_dependencies.get(name) != locked_dependencies.get(name)
        }
        evidence["lockfile"] = {
            "manifest": str(root_manifest_path),
            "lock": str(lock_path),
            "mismatches": mismatches,
        }
        if mismatches:
            add_finding(
                findings,
                "lockfile_consistency",
                "bloquear",
                "Las dependencias declaradas en el manifiesto no coinciden con el lockfile.",
                {"mismatches": mismatches},
            )

        resolved_urls: list[dict[str, str]] = []
        for package_path, item in lock.get("packages", {}).items():
            resolved = item.get("resolved")
            if not resolved or not urllib.parse.urlparse(resolved).scheme:
                continue
            parsed = urllib.parse.urlparse(resolved)
            record = {"packagePath": package_path, "url": resolved, "host": parsed.hostname or ""}
            resolved_urls.append(record)
            if not allowed_host(resolved, hosts):
                add_finding(
                    findings,
                    "approved_registry",
                    "bloquear",
                    "El lockfile resuelve una dependencia desde un host no autorizado.",
                    record,
                )
        evidence["resolvedUrls"] = resolved_urls

        license_records: list[dict[str, Any]] = []
        allowed_licenses = set(policy["licenses"]["allowed"])
        for package_path, item in lock.get("packages", {}).items():
            license_name = item.get("license")
            if not license_name or package_path == "":
                continue
            record = {
                "packagePath": package_path,
                "version": item.get("version"),
                "license": license_name,
                "source": str(lock_path),
            }
            license_records.append(record)
            if license_name not in allowed_licenses:
                add_finding(
                    findings,
                    "license",
                    "bloquear",
                    "La licencia declarada en el lockfile no está en la lista permitida.",
                    record,
                )
        evidence["lockfileLicenses"] = license_records

    npmrc_path = project / ".npmrc"
    if npmrc_path.is_file():
        npmrc_values: list[str] = []
        for raw_line in npmrc_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith(("#", ";")) or "=" not in line:
                continue
            key, value = (part.strip() for part in line.split("=", 1))
            if key == "registry" or key.endswith(":registry"):
                npmrc_values.append(value)
                if not allowed_host(value, hosts):
                    add_finding(
                        findings,
                        "approved_registry",
                        "bloquear",
                        "La configuración npm apunta a un registro no autorizado.",
                        {"file": str(npmrc_path), "key": key, "registry": value},
                    )
        evidence["npmrc"] = {"file": str(npmrc_path), "registries": npmrc_values}

    lifecycle_events = set(policy["lifecycleEvents"])
    inspected_scripts: list[dict[str, Any]] = []
    for manifest_path in manifests:
        scripts = read_json(manifest_path).get("scripts", {})
        for event in sorted(lifecycle_events.intersection(scripts)):
            script = {"file": str(manifest_path), "event": event, "command": scripts[event]}
            inspected_scripts.append(script)
            add_finding(
                findings,
                "lifecycle_script",
                "bloquear",
                f"Se encontró el evento de ciclo de vida {event}; el comando no se ejecutó.",
                script,
            )
    evidence["lifecycleScripts"] = inspected_scripts

    inspect_local_archives(project, lock_path, policy, findings, evidence)
    inspect_maintenance(
        manifest=read_json(root_manifest_path) if root_manifest_path.is_file() else {},
        policy=policy,
        findings=findings,
        evidence=evidence,
    )


def inspect_local_archives(
    project: Path,
    lock_path: Path,
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> None:
    archives = sorted((project / "artifacts").glob("*.tgz")) if (project / "artifacts").is_dir() else []
    if not archives:
        return

    lock = read_json(lock_path) if lock_path.is_file() else {}
    lock_packages = lock.get("packages", {})
    integrity_records: list[dict[str, Any]] = []
    cache: dict[tuple[str, str], str | None] = {}

    for archive in archives:
        candidates = [
            (package_path.removeprefix("node_modules/"), item)
            for package_path, item in lock_packages.items()
            if package_path.startswith("node_modules/")
        ]
        matched: tuple[str, dict[str, Any]] | None = None
        for name, item in candidates:
            resolved = item.get("resolved", "")
            published_filename = Path(urllib.parse.urlparse(resolved).path).name
            if not published_filename:
                continue
            altered_filename_prefix = published_filename.removesuffix(".tgz") + "-"
            if archive.name == published_filename or (
                archive.name.startswith(altered_filename_prefix) and archive.name.endswith(".tgz")
            ):
                matched = (name, item)
                break

        if matched is None:
            add_finding(
                findings,
                "artifact_integrity",
                policy["externalSourceFailureDecision"],
                "No se encontró una entrada del lockfile que corresponda al artefacto.",
                {"artifact": str(archive)},
            )
            continue
        package_name, package_entry = matched
        version = package_entry.get("version")

        cache_key = (package_name, version)
        try:
            if cache_key not in cache:
                metadata = request_registry_metadata(package_name, version)
                cache[cache_key] = metadata.get("dist", {}).get("integrity")
            published_integrity = cache[cache_key]
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            add_finding(
                findings,
                "artifact_integrity",
                policy["externalSourceFailureDecision"],
                "No se pudo consultar la integridad publicada del artefacto.",
                {"artifact": str(archive), "package": package_name, "error": str(error)},
            )
            continue

        if not published_integrity or not published_integrity.startswith("sha512-"):
            add_finding(
                findings,
                "artifact_integrity",
                policy["externalSourceFailureDecision"],
                "El registro no proporcionó una referencia SHA-512 utilizable.",
                {"artifact": str(archive), "package": package_name},
            )
            continue

        digest = hashlib.sha512(archive.read_bytes()).digest()
        actual_integrity = "sha512-" + base64.b64encode(digest).decode("ascii")
        record = {
            "artifact": str(archive),
            "package": package_name,
            "version": version,
            "publishedIntegrity": published_integrity,
            "actualIntegrity": actual_integrity,
            "matches": actual_integrity == published_integrity,
            "referenceSource": f"https://registry.npmjs.org/{urllib.parse.quote(package_name, safe='')}/{version}",
        }
        integrity_records.append(record)
        if not record["matches"]:
            add_finding(
                findings,
                "artifact_integrity",
                "bloquear",
                "Los bytes del artefacto no coinciden con la integridad publicada por el registro.",
                record,
            )

    evidence["artifactIntegrity"] = integrity_records


def inspect_maintenance(
    manifest: dict[str, Any],
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> None:
    settings = policy["maintenance"]
    dependencies: dict[str, str] = {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        dependencies.update(manifest.get(field, {}))
    if not dependencies:
        return

    observed_at = datetime.now(timezone.utc)
    records: list[dict[str, Any]] = []
    threshold = settings["maxReleaseAgeDays"]
    for name, declared_version in sorted(dependencies.items()):
        try:
            metadata = request_registry_metadata(name)
            release_dates = [
                datetime.fromisoformat(value.replace("Z", "+00:00"))
                for key, value in metadata.get("time", {}).items()
                if key not in {"created", "modified"}
            ]
            latest_release = max(release_dates) if release_dates else None
            if latest_release is None:
                raise ValueError("El registro no publicó fechas de versiones")
            age_days = max(0, (observed_at - latest_release).days)
            record = {
                "package": name,
                "declaredVersion": declared_version,
                "latestReleaseAt": latest_release.isoformat(),
                "ageDays": age_days,
                "observedAt": observed_at.isoformat(),
                "source": f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='')}",
            }
            records.append(record)
            if age_days > threshold:
                add_finding(
                    findings,
                    "maintenance_age",
                    "revision_manual",
                    "La fecha del último release supera el umbral de mantenimiento de la política.",
                    {**record, "thresholdDays": threshold},
                )
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as error:
            add_finding(
                findings,
                "maintenance_age",
                policy["externalSourceFailureDecision"],
                "No se pudo obtener una señal verificable de antigüedad del release.",
                {"package": name, "declaredVersion": declared_version, "error": str(error)},
            )
    evidence["maintenance"] = {
        "thresholdDays": threshold,
        "observedAt": observed_at.isoformat(),
        "packages": records,
    }


def trivy_cvss(vulnerability: dict[str, Any]) -> float:
    scores: list[float] = []
    for source in vulnerability.get("CVSS", {}).values():
        if isinstance(source, dict) and isinstance(source.get("V3Score"), (int, float)):
            scores.append(float(source["V3Score"]))
        if isinstance(source, dict) and isinstance(source.get("V4Score"), (int, float)):
            scores.append(float(source["V4Score"]))
    return max(scores, default=0.0)


def inspect_trivy(
    report_path: Path,
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> None:
    report = read_json(report_path)
    vuln_policy = policy["vulnerabilities"]
    allowed_licenses = set(policy["licenses"]["allowed"])
    vulnerability_records: list[dict[str, Any]] = []
    license_records: list[dict[str, Any]] = []

    for result in report.get("Results", []):
        for vulnerability in result.get("Vulnerabilities", []) or []:
            severity = str(vulnerability.get("Severity", "UNKNOWN")).upper()
            cvss = trivy_cvss(vulnerability)
            record = {
                "target": result.get("Target"),
                "package": vulnerability.get("PkgName"),
                "installedVersion": vulnerability.get("InstalledVersion"),
                "vulnerabilityId": vulnerability.get("VulnerabilityID"),
                "severity": severity,
                "cvss": cvss,
            }
            vulnerability_records.append(record)
            if severity in vuln_policy["blockSeverity"] or cvss >= vuln_policy["blockCvssAtOrAbove"]:
                add_finding(findings, "vulnerability", "bloquear", "Vulnerabilidad sobre el umbral de bloqueo.", record)
            elif severity in vuln_policy["reviewSeverity"] or cvss >= vuln_policy["reviewCvssAtOrAbove"]:
                add_finding(findings, "vulnerability", "revision_manual", "Vulnerabilidad sobre el umbral de revisión.", record)

        for license_item in result.get("Licenses", []) or []:
            name = license_item.get("Name")
            record = {
                "target": result.get("Target"),
                "package": license_item.get("PkgName"),
                "license": name,
            }
            license_records.append(record)
            if name and name not in allowed_licenses:
                add_finding(findings, "license", "bloquear", "Licencia fuera de la lista permitida.", record)

    evidence["trivy"] = {
        "report": str(report_path),
        "schemaVersion": report.get("SchemaVersion"),
        "vulnerabilities": vulnerability_records,
        "licenses": license_records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--trivy-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    policy = read_json(args.policy)
    findings: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {"project": str(args.project), "policyVersion": policy["policyVersion"]}

    if (args.project / "package.json").is_file():
        inspect_npm_project(args.project, policy, findings, evidence)
    inspect_trivy(args.trivy_report, policy, findings, evidence)

    decision = max(
        (finding["decision"] for finding in findings),
        key=lambda item: DECISION_RANK[item],
        default="permitir",
    )
    result = {
        "project": str(args.project),
        "policyVersion": policy["policyVersion"],
        "policySha256": hashlib.sha256(args.policy.read_bytes()).hexdigest(),
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "findings": findings,
        "evidence": evidence,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{args.project}: {decision} ({len(findings)} hallazgos)")
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as summary:
            if args.project.name == "s0":
                summary.write("## Resultado de evaluación por escenario\n\n| Escenario | Decisión | Hallazgos |\n|---|---:|---:|\n")
            summary.write(
                f"| {args.project} | **{decision.replace('_', ' ')}** | {len(findings)} |\n"
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"Error de evaluación: {error}", file=sys.stderr)
        raise SystemExit(2)
