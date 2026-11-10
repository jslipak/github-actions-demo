#!/usr/bin/env python3
"""Scan Compose images with Trivy and run a scenario's test service."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


def execute(command: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def append_finding(
    report: dict[str, Any],
    decision: str,
    message: str,
    evidence: dict[str, Any],
    control: str = "docker_compose_execution",
) -> None:
    report["findings"].append({
        "control": control,
        "decision": decision,
        "message": message,
        "evidence": evidence,
    })


def evaluate(
    project: Path,
    workspace: Path,
    reports_dir: Path,
    trivy_cache: Path,
    trivy_image: str,
    docker_socket: Path,
    test_timeout: int,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "project": str(project),
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "status": "not_applicable",
        "composeFile": None,
        "images": [],
        "imageScanReports": [],
        "test": {"status": "not_applicable", "service": "test"},
        "findings": [],
    }
    compose_file = next((project / name for name in COMPOSE_FILES if (project / name).is_file()), None)
    if compose_file is None:
        report["reason"] = "El escenario no contiene un archivo Docker Compose."
        return report

    report["composeFile"] = str(compose_file.relative_to(workspace))
    project_name = f"dependency-assessment-{project.name}"
    compose_command = [
        "docker",
        "compose",
        "--project-name",
        project_name,
        "-f",
        str(compose_file),
    ]
    try:
        services_result = execute(compose_command + ["config", "--services"], project, timeout=60)
        images_result = execute(compose_command + ["config", "--images"], project, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as error:
        report["status"] = "manual_review"
        report["test"] = {"status": "not_run", "service": "test", "error": str(error)}
        append_finding(report, "revision_manual", "No se pudo evaluar la configuración de Docker Compose.", {"error": str(error)})
        return report

    if services_result.returncode != 0 or images_result.returncode != 0:
        error_evidence = {
            "servicesExitCode": services_result.returncode,
            "servicesStderr": services_result.stderr[-6000:],
            "imagesExitCode": images_result.returncode,
            "imagesStderr": images_result.stderr[-6000:],
        }
        report["status"] = "manual_review"
        report["test"] = {"status": "not_run", "service": "test"}
        append_finding(report, "revision_manual", "Docker Compose no pudo resolver los servicios o imágenes.", error_evidence)
        return report

    services = [line.strip() for line in services_result.stdout.splitlines() if line.strip()]
    images = sorted(set(line.strip() for line in images_result.stdout.splitlines() if line.strip()))
    report["services"] = services
    report["images"] = images

    build_result: subprocess.CompletedProcess[str] | None = None
    try:
        build_result = execute(compose_command + ["build", "--pull"], project, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        report["status"] = "manual_review"
        report["imagePreparation"] = {"error": str(error)}
        append_finding(report, "revision_manual", "No se pudieron preparar las imágenes de Compose.", {"error": str(error)})

    if build_result is not None and build_result.returncode != 0:
        report["imagePreparation"] = {
            "buildExitCode": build_result.returncode,
            "buildStderr": build_result.stderr[-8000:],
        }
        append_finding(
            report,
            "revision_manual",
            "Falló la construcción de una imagen definida por Docker Compose.",
            report["imagePreparation"],
        )
    if not any(finding["control"] == "docker_compose_execution" and finding["decision"] == "revision_manual" for finding in report["findings"]):
        for index, image in enumerate(images, start=1):
            try:
                inspect_result = execute(["docker", "image", "inspect", image], project, timeout=30)
                if inspect_result.returncode != 0:
                    pull_result = execute(["docker", "pull", image], project, timeout=600)
                    if pull_result.returncode != 0:
                        prep_record = {
                            "image": image,
                            "pullExitCode": pull_result.returncode,
                            "pullStderr": pull_result.stderr[-8000:],
                        }
                        report.setdefault("imagePreparation", {"images": []})["images"].append(prep_record)
                        append_finding(
                            report,
                            "revision_manual",
                            "No se pudo preparar una imagen de Docker Compose.",
                            prep_record,
                            control="container_image_scan",
                        )
                        report["imageScanReports"].append({"image": image, "status": "failed", "error": "No se pudo descargar la imagen."})
                        continue
            except (OSError, subprocess.TimeoutExpired) as error:
                prep_record = {"image": image, "error": str(error)}
                report.setdefault("imagePreparation", {"images": []})["images"].append(prep_record)
                append_finding(
                    report,
                    "revision_manual",
                    "No se pudo comprobar o descargar una imagen de Docker Compose.",
                    prep_record,
                    control="container_image_scan",
                )
                report["imageScanReports"].append({"image": image, "status": "failed", "error": str(error)})
                continue

            scan_path = reports_dir / f"trivy-image-{project.name}-{index}.json"
            scan_relative_path = scan_path.relative_to(workspace).as_posix()
            command = [
                "docker",
                "run",
                "--rm",
                "--volume",
                f"{docker_socket}:/var/run/docker.sock",
                "--volume",
                f"{workspace}:/workspace",
                "--volume",
                f"{trivy_cache}:/root/.cache/trivy",
                "--env",
                "DOCKER_HOST=unix:///var/run/docker.sock",
                trivy_image,
                "image",
                "--docker-host",
                "unix:///var/run/docker.sock",
                "--scanners",
                "vuln",
                "--pkg-types",
                "os",
                "--format",
                "json",
                "--output",
                f"/workspace/{scan_relative_path}",
                "--exit-code",
                "0",
                image,
            ]
            try:
                scan_result = execute(command, workspace, timeout=360)
                scan_record = {
                    "image": image,
                    "report": scan_relative_path,
                    "exitCode": scan_result.returncode,
                    "status": "scanned" if scan_result.returncode == 0 and scan_path.is_file() else "failed",
                    "stderr": scan_result.stderr[-8000:],
                }
                if scan_record["status"] != "scanned":
                    append_finding(
                        report,
                        "revision_manual",
                        "Trivy no pudo completar el análisis de una imagen de Compose.",
                        scan_record.copy(),
                        control="container_image_scan",
                    )
            except (OSError, subprocess.TimeoutExpired) as error:
                scan_record = {"image": image, "report": scan_relative_path, "status": "failed", "error": str(error)}
                append_finding(
                    report,
                    "revision_manual",
                    "Trivy no pudo ejecutarse o completar el análisis de una imagen de Compose.",
                    scan_record.copy(),
                    control="container_image_scan",
                )
            report["imageScanReports"].append(scan_record)

    if "test" not in services:
        report["test"] = {"status": "not_configured", "service": "test"}
        append_finding(
            report,
            "revision_manual",
            "El Compose no define el servicio convencional `test`; no se ejecutó una prueba dentro del contenedor.",
            {"services": services, "expectedService": "test"},
            control="docker_compose_test",
        )
    elif report.get("imagePreparation", {}).get("images"):
        report["test"] = {"status": "not_run", "service": "test", "reason": "No se pudieron descargar todas las imágenes."}
    elif any(finding["control"] == "docker_compose_execution" and finding["decision"] == "revision_manual" for finding in report["findings"]):
        report["test"] = {"status": "not_run", "service": "test", "reason": "No se pudieron preparar o analizar las imágenes."}
    else:
        try:
            test_result = execute(
                compose_command + ["run", "--rm", "--no-TTY", "test"],
                project,
                timeout=test_timeout,
            )
            report["test"] = {
                "status": "passed" if test_result.returncode == 0 else "failed",
                "service": "test",
                "exitCode": test_result.returncode,
                "stdout": test_result.stdout[-20000:],
                "stderr": test_result.stderr[-20000:],
            }
            if test_result.returncode != 0:
                append_finding(
                    report,
                    "revision_manual",
                    "Las pruebas ejecutadas en el servicio Compose `test` fallaron.",
                    {key: value for key, value in report["test"].items() if key != "status"},
                    control="docker_compose_test",
                )
        except (OSError, subprocess.TimeoutExpired) as error:
            report["test"] = {"status": "failed", "service": "test", "error": str(error)}
            append_finding(
                report,
                "revision_manual",
                "No se pudieron completar las pruebas del servicio Compose `test`.",
                {"error": str(error)},
                control="docker_compose_test",
            )

    try:
        cleanup = execute(compose_command + ["down", "--volumes", "--remove-orphans", "--timeout", "5"], project, timeout=60)
        report["cleanup"] = {"exitCode": cleanup.returncode, "stderr": cleanup.stderr[-4000:]}
    except (OSError, subprocess.TimeoutExpired) as error:
        report["cleanup"] = {"error": str(error)}

    report["status"] = "manual_review" if report["findings"] else "completed"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--reports-dir", required=True, type=Path)
    parser.add_argument("--trivy-cache", required=True, type=Path)
    parser.add_argument("--trivy-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--docker-socket", type=Path, default=Path("/var/run/docker.sock"))
    parser.add_argument("--test-timeout", type=int, default=900)
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    project = args.project.resolve()
    reports_dir = args.reports_dir.resolve()
    reports_dir.mkdir(parents=True, exist_ok=True)
    args.trivy_cache.mkdir(parents=True, exist_ok=True)
    report = evaluate(
        project=project,
        workspace=workspace,
        reports_dir=reports_dir,
        trivy_cache=args.trivy_cache.resolve(),
        trivy_image=args.trivy_image,
        docker_socket=args.docker_socket.resolve(),
        test_timeout=args.test_timeout,
    )
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{project.name}: Compose {report['status']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
        print(f"Compose scenario runner error: {error}", file=sys.stderr)
        raise SystemExit(2)
