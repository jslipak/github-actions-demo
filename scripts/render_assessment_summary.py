#!/usr/bin/env python3
"""Render consolidated scenario assessments as a GitHub Actions Markdown summary."""

from __future__ import annotations

import json
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
)


def markdown_cell(value: Any) -> str:
    text = str(value).replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")
    return text.replace("`", "&#96;")


def evidence_summary(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    selected = {key: evidence[key] for key in EVIDENCE_KEYS if key in evidence}
    return json.dumps(selected, ensure_ascii=False, sort_keys=True) if selected else "—"


def main() -> int:
    reports = [Path(name) for name in sys.argv[1:]]
    if not reports:
        print("No assessment reports were provided.", file=sys.stderr)
        return 2

    assessments = [json.loads(path.read_text(encoding="utf-8")) for path in sorted(reports)]

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
