#!/usr/bin/env python3
"""Render consolidated scenario assessments as a GitHub Actions Markdown summary."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


EVIDENCE_KEYS = (
    "package",
    "packagePath",
    "installedVersion",
    "declaredVersion",
    "vulnerabilityId",
    "severity",
    "cvss",
    "host",
    "url",
    "registry",
    "event",
    "artifact",
    "ageDays",
    "thresholdDays",
    "license",
    "matches",
    "mismatches",
    "error",
    "file",
    "command",
    "npmVersion",
    "nodeVersion",
    "registrySignatures",
    "provenance",
    "invalid",
    "missing",
    "exitCode",
    "summaryExitCode",
    "verifiedRegistrySignatureCount",
    "localDependenciesNotRegistrySigned",
    "createdMarkers",
    "expectedBundle",
    "trustedIdentityRegex",
    "groupId",
    "artifactId",
    "version",
    "digestAlgorithm",
    "publishedDigest",
    "actualDigest",
    "source",
    "platform",
    "lockRequirement",
    "satisfiesLockRequirement",
    "bundleUrl",
    "image",
    "type",
    "packageType",
    "packageClass",
    "fixedVersion",
)


def markdown_cell(value: Any) -> str:
    text = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")
    return text.replace("`", "&#96;")


def evidence_summary(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    selected = {key: evidence[key] for key in EVIDENCE_KEYS if key in evidence}
    return json.dumps(selected, ensure_ascii=False, sort_keys=True) if selected else "—"


def verification_rows(evidence: dict[str, Any]) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    npm = evidence.get("npmIntegrity")
    if isinstance(npm, dict):
        install = npm.get("install", {})
        if install:
            install_status = "completada" if install.get("exitCode") == 0 else "fallida"
        else:
            install_status = npm.get("status", "sin ejecutar")
        rows.append(("npm ci --ignore-scripts", str(install_status), str(npm.get("reason", "copia temporal"))))

        signatures = npm.get("signatureVerification", {})
        if signatures:
            rows.append((
                "Firmas del registro npm",
                str(signatures.get("registrySignatures", "sin verificar")),
                f"npm {npm.get('npmVersion', 'desconocido')}; verificadas={signatures.get('verifiedRegistrySignatureCount', 'n/d')}; inválidas={len(signatures.get('invalid', []))}; ausentes={len(signatures.get('missing', []))}",
            ))
            local_packages = signatures.get("localDependenciesNotRegistrySigned", [])
            if local_packages:
                rows.append((
                    "Dependencias locales fuera de firmas npm",
                    "no aplicable",
                    ", ".join(item.get("packagePath", "") for item in local_packages),
                ))
            rows.append((
                "Provenance npm",
                str(signatures.get("provenance", "no reportada")),
                f"atestaciones verificadas={len(signatures.get('verifiedAttestations', []))}",
            ))
        marker = npm.get("lifecycleMarkerCheck", {})
        if marker.get("checked"):
            changed = marker.get("createdOrChangedDuringInstall", [])
            rows.append(("Marcador postinstall S4", "creado/modificado" if changed else "no creado", json.dumps(changed, ensure_ascii=False)))

    non_npm = evidence.get("nonNpmIntegrity")
    if isinstance(non_npm, dict):
        records = non_npm.get("directDependencies", [])
        details = non_npm.get("reason", "")
        if records:
            details = "; ".join(
                f"{item.get('package', item.get('artifactId', 'paquete'))}@{item.get('version', '?')} "
                f"{item.get('digestAlgorithm', 'hash')}={'coincide' if item.get('matches') else 'sin coincidencia/no verificado'} "
                f"Sigstore={item.get('sigstore', {}).get('status', 'sin bundle') if isinstance(item.get('sigstore'), dict) else 'sin bundle'}"
                for item in records
            )
        rows.append((f"Integridad directa {non_npm.get('ecosystem', 'no-npm')}", str(non_npm.get("status", "sin ejecutar")), str(details)))

    sigstore = evidence.get("sigstore")
    if isinstance(sigstore, dict):
        artifact_records = sigstore.get("artifacts", [])
        details = sigstore.get("reason", "")
        if artifact_records:
            details = "; ".join(f"{Path(item['artifact']).name}: {item['status']}" for item in artifact_records)
        rows.append(("Cosign / Sigstore", str(sigstore.get("status", "sin ejecutar")), str(details)))

    compose = evidence.get("compose")
    if isinstance(compose, dict) and compose.get("composeFile"):
        test = compose.get("test", {})
        rows.append((
            "Pruebas Docker Compose",
            str(test.get("status", "sin ejecutar")),
            f"servicio={test.get('service', 'test')}; exit={test.get('exitCode', 'n/d')}",
        ))
        scans = compose.get("imageScanReports", [])
        if scans:
            details = "; ".join(f"{item.get('image')}: {item.get('status')}" for item in scans)
            status = "analizada" if all(item.get("status") == "scanned" for item in scans) else "incompleta"
            rows.append(("Trivy imagen (paquetes OS)", status, details))
    return rows


def scenario_sort_key(assessment: dict[str, Any]) -> tuple[int, int | str, str]:
    scenario = Path(assessment["project"]).name
    match = re.fullmatch(r"s(\d+)", scenario, flags=re.IGNORECASE)
    if match:
        return (0, int(match.group(1)), scenario.casefold())
    return (1, scenario.casefold(), scenario)


def main() -> int:
    reports = [Path(name) for name in sys.argv[1:]]
    if not reports:
        print("No assessment reports were provided.", file=sys.stderr)
        return 2

    assessments = [json.loads(path.read_text(encoding="utf-8")) for path in reports]
    assessments.sort(key=scenario_sort_key)

    print("## Resumen de decisiones\n")
    print("| Escenario | Decisión | Hallazgos |")
    print("|---|---:|---:|")
    for assessment in assessments:
        scenario = Path(assessment["project"]).name
        decision = assessment["decision"].replace("_", " ")
        print(f"| {markdown_cell(scenario)} | **{markdown_cell(decision)}** | {len(assessment['findings'])} |")

    for assessment in assessments:
        scenario = Path(assessment["project"]).name
        print(f"\n### Detalle de {markdown_cell(scenario)}\n")
        controls = verification_rows(assessment.get("evidence", {}))
        if controls:
            print("| Control de integridad/procedencia | Estado | Detalle |")
            print("|---|---|---|")
            for control, status, detail in controls:
                print("| " + " | ".join(markdown_cell(value) for value in (control, status, detail or "—")) + " |")
            print()
        print("| Control | Qué ocurrió | Evidencia relevante | Decisión |")
        print("|---|---|---|---:|")
        findings = assessment["findings"]
        if not findings:
            print("| — | Sin hallazgos en los controles ejecutados | — | permitir |")
            continue
        for finding in findings:
            values = (
                finding["control"],
                finding["message"],
                evidence_summary(finding),
                finding["decision"].replace("_", " "),
            )
            print("| " + " | ".join(markdown_cell(value) for value in values) + " |")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
