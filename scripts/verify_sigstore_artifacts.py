#!/usr/bin/env python3
"""Verify Sigstore bundles accompanying non-npm artifacts in a scenario."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def finding(decision: str, message: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "control": "sigstore_artifact_signature",
        "decision": decision,
        "message": message,
        "evidence": evidence,
    }


def evaluate(project: Path, policy: dict[str, Any], cosign: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "project": str(project),
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "status": "not_applicable",
        "artifacts": [],
        "findings": [],
    }
    if (project / "package.json").is_file():
        report["reason"] = "Los paquetes npm se verifican con npm audit signatures."
        return report

    artifact_root = project / "artifacts"
    if not artifact_root.is_dir():
        report["reason"] = "El escenario no versiona artefactos binarios para verificar con Cosign."
        return report

    artifacts = sorted(
        path for path in artifact_root.rglob("*")
        if path.is_file() and not path.name.endswith(".sigstore.json")
    )
    if not artifacts:
        report["reason"] = "No hay artefactos binarios bajo artifacts/."
        return report

    settings = policy["sigstore"]
    issuer = settings["certificateOidcIssuer"]
    identities = settings["trustedIdentityRegexes"]
    require_bundle = settings["requireBundleForArtifacts"]
    records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for artifact in artifacts:
        bundle = Path(f"{artifact}.sigstore.json")
        record: dict[str, Any] = {
            "artifact": str(artifact),
            "bundle": str(bundle),
            "status": "no_bundle",
        }
        if not bundle.is_file():
            if require_bundle:
                findings.append(finding(
                    policy["dependencyIntegrity"]["verificationFailureDecision"],
                    "No se encontró el bundle Sigstore requerido junto al artefacto.",
                    {"artifact": str(artifact), "expectedBundle": str(bundle)},
                ))
            records.append(record)
            continue

        if not identities:
            record["status"] = "unverified_identity_policy_missing"
            findings.append(finding(
                policy["dependencyIntegrity"]["verificationFailureDecision"],
                "Hay un bundle Sigstore, pero la política no define identidades de publicador confiables.",
                {"artifact": str(artifact), "bundle": str(bundle), "issuer": issuer},
            ))
            records.append(record)
            continue

        attempts: list[dict[str, Any]] = []
        verifier_unavailable = False
        for identity in identities:
            command = [
                cosign,
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-oidc-issuer",
                issuer,
                "--certificate-identity-regexp",
                identity,
                str(artifact),
            ]
            try:
                result = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
                attempts.append({
                    "identityRegex": identity,
                    "exitCode": result.returncode,
                    "stdout": result.stdout[-4000:],
                    "stderr": result.stderr[-4000:],
                })
                if result.returncode == 0:
                    record["status"] = "verified"
                    record["trustedIdentityRegex"] = identity
                    break
            except (OSError, subprocess.TimeoutExpired) as error:
                attempts.append({"identityRegex": identity, "error": str(error)})
                verifier_unavailable = True
        record["attempts"] = attempts
        if record["status"] != "verified":
            record["status"] = "verification_unavailable" if verifier_unavailable else "verification_failed"
            findings.append(finding(
                policy["dependencyIntegrity"]["verificationFailureDecision"] if verifier_unavailable else policy["dependencyIntegrity"]["invalidSignatureDecision"],
                "Cosign no pudo ejecutarse o completar la verificación." if verifier_unavailable else "Cosign no pudo validar la firma del artefacto con las identidades permitidas.",
                {"artifact": str(artifact), "bundle": str(bundle), "attempts": attempts},
            ))
        records.append(record)

    report["artifacts"] = records
    report["findings"] = findings
    report["status"] = "failed" if any(item["decision"] == "bloquear" for item in findings) else "manual_review" if findings else (
        "verified" if all(record["status"] == "verified" for record in records) else "not_verified"
    )
    report["trustPolicy"] = {
        "certificateOidcIssuer": issuer,
        "trustedIdentityRegexes": identities,
        "requireBundleForArtifacts": require_bundle,
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cosign", default="cosign")
    args = parser.parse_args()

    report = evaluate(args.project, read_json(args.policy), args.cosign)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{args.project}: Sigstore {report['status']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"Error de verificación Sigstore: {error}", file=sys.stderr)
        raise SystemExit(2)
