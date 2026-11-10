#!/usr/bin/env python3
"""Check direct RubyGems/Maven dependency bytes without installing or executing them."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


USER_AGENT = "dependency-security-assessment/1.0"
MAX_RESPONSE_BYTES = 100 * 1024 * 1024
GEMFILE_DIRECT = re.compile(r"^\s*gem\s+(['\"])(?P<name>[^'\"]+)\1(?:\s*,\s*(['\"])(?P<version>[^'\"]+)\3)?")
GEM_SPEC = re.compile(r"^ {4}(?P<name>[A-Za-z0-9_.-]+) \((?P<version>[^)]+)\)$")
GEM_DEPENDENCY = re.compile(r"^ {2}(?P<name>[A-Za-z0-9_.-]+)(?: \((?P<requirement>[^)]+)\))?$")
SHA_HEX_LENGTHS = {"sha512": 128, "sha256": 64, "sha1": 40}


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def request_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        chunks: list[bytes] = []
        total = 0
        while chunk := response.read(64 * 1024):
            total += len(chunk)
            if total > MAX_RESPONSE_BYTES:
                raise ValueError(f"La respuesta excede el límite de {MAX_RESPONSE_BYTES} bytes.")
            chunks.append(chunk)
        return b"".join(chunks)


def request_json(url: str) -> Any:
    return json.loads(request_bytes(url).decode("utf-8"))


def add_finding(
    findings: list[dict[str, Any]],
    control: str,
    decision: str,
    message: str,
    evidence: dict[str, Any],
) -> None:
    findings.append({"control": control, "decision": decision, "message": message, "evidence": evidence})


def version_tuple(value: str) -> tuple[int, ...] | None:
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        return None
    return tuple(int(part) for part in value.split("."))


def compare_versions(left: str, right: str) -> int | None:
    left_parts = version_tuple(left)
    right_parts = version_tuple(right)
    if left_parts is None or right_parts is None:
        return None
    width = max(len(left_parts), len(right_parts))
    left_parts += (0,) * (width - len(left_parts))
    right_parts += (0,) * (width - len(right_parts))
    return (left_parts > right_parts) - (left_parts < right_parts)


def ruby_requirement_satisfied(requirement: str, version: str) -> bool | None:
    if not requirement:
        return True
    for condition in (part.strip() for part in requirement.split(",")):
        match = re.fullmatch(r"(=|!=|>=|<=|>|<|~>)\s*(\d+(?:\.\d+)*)", condition)
        if not match:
            return None
        operator, expected = match.groups()
        comparison = compare_versions(version, expected)
        if comparison is None:
            return None
        if operator == "=" and comparison != 0:
            return False
        if operator == "!=" and comparison == 0:
            return False
        if operator == ">" and comparison <= 0:
            return False
        if operator == ">=" and comparison < 0:
            return False
        if operator == "<" and comparison >= 0:
            return False
        if operator == "<=" and comparison > 0:
            return False
        if operator == "~>":
            expected_parts = list(int(part) for part in expected.split("."))
            upper_index = 0 if len(expected_parts) <= 2 else len(expected_parts) - 2
            expected_parts[upper_index] += 1
            for index in range(upper_index + 1, len(expected_parts)):
                expected_parts[index] = 0
            upper_comparison = compare_versions(version, ".".join(map(str, expected_parts)))
            if upper_comparison is None or comparison < 0 or upper_comparison >= 0:
                return False
    return True


def normalize_gem_requirement(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip()
    if re.match(r"^(=|!=|>|<|>=|<=|~>)\s*", value):
        return value
    return f"= {value}"


def parse_ruby_lock(path: Path) -> dict[str, Any]:
    section = ""
    specs: dict[str, list[str]] = {}
    dependencies: dict[str, str] = {}
    platforms: list[str] = []
    remotes: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "  specs:":
            section = "specs"
            continue
        if line == "DEPENDENCIES":
            section = "dependencies"
            continue
        if line == "PLATFORMS":
            section = "platforms"
            continue
        if line in {"GEM", "GIT", "PATH", "BUNDLED WITH"}:
            section = "source" if line in {"GEM", "GIT", "PATH"} else "other"
            continue
        if section == "source" and line.startswith("  remote: "):
            remotes.append(line.removeprefix("  remote: ").strip())
        elif section == "specs":
            match = GEM_SPEC.match(line)
            if match:
                specs.setdefault(match.group("name"), []).append(match.group("version"))
        elif section == "dependencies":
            match = GEM_DEPENDENCY.match(line)
            if match:
                dependencies[match.group("name")] = match.group("requirement") or ""
        elif section == "platforms" and line.startswith("  "):
            platforms.append(line.strip())
    return {"specs": specs, "dependencies": dependencies, "platforms": platforms, "remotes": remotes}


def parse_gemfile(path: Path) -> dict[str, str]:
    dependencies: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = GEMFILE_DIRECT.match(line)
        if match:
            dependencies[match.group("name")] = normalize_gem_requirement(match.group("version"))
    return dependencies


def host_is_allowed(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in allowed_hosts


def runner_ruby_platform(platforms: list[str]) -> str | None:
    machine = platform.machine().lower()
    aliases = {"amd64": "x86_64", "arm64": "aarch64"}
    machine = aliases.get(machine, machine)
    candidates = [f"{machine}-linux-gnu", f"{machine}-linux-musl"]
    return next((item for item in candidates if item in platforms), None)


def split_gem_platform(version: str, platforms: list[str]) -> tuple[str, str]:
    for platform_name in sorted(platforms, key=len, reverse=True):
        suffix = f"-{platform_name}"
        if version.endswith(suffix):
            return version[: -len(suffix)], platform_name
    return version, "ruby"


def choose_gem_version(versions: list[str], platforms: list[str]) -> tuple[str, str] | None:
    current_platform = runner_ruby_platform(platforms)
    candidates = [split_gem_platform(version, platforms) for version in versions]
    if current_platform:
        match = next((item for item in candidates if item[1] == current_platform), None)
        if match:
            return match
    generic = next((item for item in candidates if item[1] == "ruby"), None)
    if generic:
        return generic
    return candidates[0] if len(candidates) == 1 else None


def ruby_registry_artifact(
    package: str,
    version: str,
    package_platform: str,
    registry_host: str,
) -> tuple[str, bytes, str]:
    metadata_url = f"https://{registry_host}/api/v1/versions/{urllib.parse.quote(package, safe='')}.json"
    records = request_json(metadata_url)
    entry = next(
        (
            item for item in records
            if item.get("number") == version and item.get("platform", "ruby") == package_platform
        ),
        None,
    )
    if entry is None:
        raise ValueError(f"No se encontró {package} {version} ({package_platform}) en los metadatos de RubyGems.")
    expected_sha256 = str(entry.get("sha", "")).lower()
    if len(expected_sha256) != SHA_HEX_LENGTHS["sha256"] or not re.fullmatch(r"[0-9a-f]+", expected_sha256):
        raise ValueError("RubyGems no publicó un SHA-256 utilizable para esta versión.")
    suffix = "" if package_platform == "ruby" else f"-{package_platform}"
    artifact_url = f"https://{registry_host}/downloads/{urllib.parse.quote(package, safe='')}-{version}{suffix}.gem"
    return artifact_url, request_bytes(artifact_url), expected_sha256


def verify_sigstore_sidecar(
    artifact: Path,
    artifact_url: str,
    policy: dict[str, Any],
    findings: list[dict[str, Any]],
    evidence: dict[str, Any],
    temp_dir: Path,
    cosign: str,
) -> None:
    settings = policy["sigstore"]
    bundle_url = f"{artifact_url}.sigstore.json"
    try:
        bundle_bytes = request_bytes(bundle_url)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            evidence["sigstore"] = {"status": "no_bundle_published", "bundleUrl": bundle_url}
            if settings["requireBundleForPublishedDependencies"]:
                add_finding(
                    findings,
                    "sigstore_artifact_signature",
                    policy["dependencyIntegrity"]["verificationFailureDecision"],
                    "El registro no publicó el bundle Sigstore requerido para el artefacto.",
                    {"artifact": str(artifact), "bundleUrl": bundle_url},
                )
            return
        evidence["sigstore"] = {"status": "bundle_lookup_failed", "bundleUrl": bundle_url, "error": str(error)}
        add_finding(
            findings,
            "sigstore_artifact_signature",
            policy["dependencyIntegrity"]["verificationFailureDecision"],
            "No se pudo consultar si el registro publica un bundle Sigstore para el artefacto.",
            {"artifact": str(artifact), "bundleUrl": bundle_url, "error": str(error)},
        )
        return
    except (urllib.error.URLError, TimeoutError) as error:
        evidence["sigstore"] = {"status": "bundle_lookup_failed", "bundleUrl": bundle_url, "error": str(error)}
        add_finding(
            findings,
            "sigstore_artifact_signature",
            policy["dependencyIntegrity"]["verificationFailureDecision"],
            "No se pudo consultar si el registro publica un bundle Sigstore para el artefacto.",
            {"artifact": str(artifact), "bundleUrl": bundle_url, "error": str(error)},
        )
        return
    bundle_path = temp_dir / f"{artifact.name}.sigstore.json"
    bundle_path.write_bytes(bundle_bytes)
    identities = settings["trustedIdentityRegexes"]
    if not identities:
        evidence["sigstore"] = {"status": "identity_policy_missing", "bundleUrl": bundle_url}
        add_finding(
            findings,
            "sigstore_artifact_signature",
            policy["dependencyIntegrity"]["verificationFailureDecision"],
            "Hay un bundle Sigstore, pero no se configuraron identidades de publicador confiables.",
            {"artifact": str(artifact), "bundleUrl": bundle_url},
        )
        return

    attempts: list[dict[str, Any]] = []
    verifier_unavailable = False
    for identity in identities:
        command = [
            cosign,
            "verify-blob",
            "--bundle",
            str(bundle_path),
            "--certificate-oidc-issuer",
            settings["certificateOidcIssuer"],
            "--certificate-identity-regexp",
            identity,
            str(artifact),
        ]
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=120, check=False)
            attempts.append({"identityRegex": identity, "exitCode": result.returncode, "stdout": result.stdout[-2000:], "stderr": result.stderr[-2000:]})
            if result.returncode == 0:
                evidence["sigstore"] = {"status": "verified", "bundleUrl": bundle_url, "identityRegex": identity}
                return
        except (OSError, subprocess.TimeoutExpired) as error:
            attempts.append({"identityRegex": identity, "error": str(error)})
            verifier_unavailable = True
    decision = policy["dependencyIntegrity"]["verificationFailureDecision"] if verifier_unavailable else policy["dependencyIntegrity"]["invalidSignatureDecision"]
    status = "verification_unavailable" if verifier_unavailable else "verification_failed"
    evidence["sigstore"] = {"status": status, "bundleUrl": bundle_url, "attempts": attempts}
    add_finding(
        findings,
        "sigstore_artifact_signature",
        decision,
        "Cosign no pudo completar o validar la firma del artefacto con las identidades permitidas.",
        {"artifact": str(artifact), "bundleUrl": bundle_url, "attempts": attempts},
    )


def check_ruby_project(project: Path, policy: dict[str, Any], temp_dir: Path, cosign: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    lock_path = project / "Gemfile.lock"
    gemfile_path = project / "Gemfile"
    settings = policy["nonNpmIntegrity"]
    lock = parse_ruby_lock(lock_path)
    gemfile_dependencies = parse_gemfile(gemfile_path)
    lock_dependencies = {name: normalize_gem_requirement(value) for name, value in lock["dependencies"].items()}
    mismatches = {
        name: {"Gemfile": gemfile_dependencies.get(name), "Gemfile.lock": lock_dependencies.get(name)}
        for name in sorted(set(gemfile_dependencies) | set(lock_dependencies))
        if gemfile_dependencies.get(name) != lock_dependencies.get(name)
    }
    if mismatches:
        add_finding(
            findings,
            "ruby_lockfile_consistency",
            "bloquear",
            "Las dependencias directas de Gemfile no coinciden con Gemfile.lock.",
            {"mismatches": mismatches},
        )
    if not gemfile_dependencies:
        add_finding(
            findings,
            "ruby_artifact_integrity",
            policy["dependencyIntegrity"]["verificationFailureDecision"],
            "No se pudieron identificar dependencias directas en Gemfile para verificar.",
            {"file": str(gemfile_path)},
        )
    allowed_hosts = set(settings["rubyGemsAllowedHosts"])
    invalid_remotes = [remote for remote in lock["remotes"] if not host_is_allowed(remote, allowed_hosts)]
    if invalid_remotes:
        add_finding(
            findings,
            "ruby_registry_origin",
            "bloquear",
            "Gemfile.lock contiene un origen RubyGems no autorizado.",
            {"remotes": invalid_remotes},
        )
        return {"ecosystem": "rubygems", "status": "blocked_by_preflight", "directDependencies": [], "findings": findings}

    for name in sorted(gemfile_dependencies):
        versions = lock["specs"].get(name, [])
        selected = choose_gem_version(versions, lock["platforms"])
        if not selected:
            add_finding(
                findings,
                "ruby_artifact_integrity",
                policy["dependencyIntegrity"]["verificationFailureDecision"],
                "No se pudo seleccionar una versión de la dependencia Ruby fijada para la plataforma del runner.",
                {"package": name, "lockedVersions": versions, "runnerPlatform": platform.machine()},
            )
            continue
        version, package_platform = selected
        record: dict[str, Any] = {"package": name, "version": version, "platform": package_platform}
        requirement = lock_dependencies.get(name, "")
        satisfies_requirement = ruby_requirement_satisfied(requirement, version)
        record["lockRequirement"] = requirement
        record["satisfiesLockRequirement"] = satisfies_requirement
        if satisfies_requirement is False:
            add_finding(
                findings,
                "ruby_version_pin",
                "bloquear",
                "La versión Ruby resuelta no satisface el requisito de Gemfile.lock.",
                {"package": name, "version": version, "requirement": requirement},
            )
            records.append(record)
            continue
        if satisfies_requirement is None:
            add_finding(
                findings,
                "ruby_version_pin",
                policy["dependencyIntegrity"]["verificationFailureDecision"],
                "No se pudo evaluar el requisito de versión Ruby de forma estática.",
                {"package": name, "version": version, "requirement": requirement},
            )
            records.append(record)
            continue
        try:
            artifact_url, artifact_bytes, expected = ruby_registry_artifact(
                name, version, package_platform, next(iter(allowed_hosts))
            )
            artifact_path = temp_dir / f"{name}-{version}-{package_platform}.gem"
            artifact_path.write_bytes(artifact_bytes)
            actual = hashlib.sha256(artifact_bytes).hexdigest()
            record.update({
                "source": artifact_url,
                "digestAlgorithm": "sha256",
                "publishedDigest": expected,
                "actualDigest": actual,
                "matches": actual == expected,
            })
            if actual != expected:
                add_finding(
                    findings,
                    "ruby_artifact_integrity",
                    policy["dependencyIntegrity"]["artifactMismatchDecision"],
                    "Los bytes del artefacto Ruby no coinciden con el SHA-256 publicado por RubyGems.",
                    record.copy(),
                )
            verify_sigstore_sidecar(artifact_path, artifact_url, policy, findings, record, temp_dir, cosign)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as error:
            record["status"] = "unverified"
            record["error"] = str(error)
            add_finding(
                findings,
                "ruby_artifact_integrity",
                policy["dependencyIntegrity"]["verificationFailureDecision"],
                "No se pudo obtener o verificar el artefacto Ruby desde RubyGems.",
                {"package": name, "version": version, "error": str(error)},
            )
        records.append(record)
    return {"ecosystem": "rubygems", "status": "review" if findings else "verified", "directDependencies": records, "findings": findings}


def xml_child(parent: ET.Element, name: str, namespace: str) -> ET.Element | None:
    return parent.find(f"{{{namespace}}}{name}")


def resolve_maven_property(value: str, properties: dict[str, str]) -> str:
    for _ in range(8):
        matches = list(re.finditer(r"\$\{([^}]+)\}", value))
        if not matches:
            return value
        for match in reversed(matches):
            replacement = properties.get(match.group(1))
            if replacement is None:
                return value
            value = value[: match.start()] + replacement + value[match.end() :]
    return value


def fetch_maven_checksum(artifact_url: str, artifact_bytes: bytes) -> tuple[str, str, str]:
    for algorithm in ("sha512", "sha256", "sha1"):
        try:
            checksum_text = request_bytes(f"{artifact_url}.{algorithm}").decode("utf-8").strip()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                continue
            raise
        expected = checksum_text.split()[0].lower()
        if len(expected) != SHA_HEX_LENGTHS[algorithm] or not re.fullmatch(r"[0-9a-f]+", expected):
            raise ValueError(f"Maven Central devolvió un checksum {algorithm} no válido.")
        actual = hashlib.new(algorithm, artifact_bytes).hexdigest()
        return algorithm, expected, actual
    raise ValueError("Maven Central no publicó un checksum SHA-512, SHA-256 o SHA-1 para el artefacto.")


def parse_maven_dependencies(pom_path: Path, namespace: str) -> tuple[list[dict[str, str]], list[str]]:
    root = ET.parse(pom_path).getroot()
    properties_element = xml_child(root, "properties", namespace)
    properties = {
        child.tag.removeprefix(f"{{{namespace}}}"): (child.text or "").strip()
        for child in (list(properties_element) if properties_element is not None else [])
    }
    dependencies_element = xml_child(root, "dependencies", namespace)
    dependencies: list[dict[str, str]] = []
    errors: list[str] = []
    if dependencies_element is None:
        return dependencies, errors
    for dependency in dependencies_element.findall(f"{{{namespace}}}dependency"):
        group_element = xml_child(dependency, "groupId", namespace)
        artifact_element = xml_child(dependency, "artifactId", namespace)
        group_id = resolve_maven_property((group_element.text or "").strip(), properties) if group_element is not None else ""
        artifact_id = resolve_maven_property((artifact_element.text or "").strip(), properties) if artifact_element is not None else ""
        version_element = xml_child(dependency, "version", namespace)
        raw_version = (version_element.text or "").strip() if version_element is not None else ""
        version = resolve_maven_property(raw_version, properties)
        type_element = xml_child(dependency, "type", namespace)
        classifier_element = xml_child(dependency, "classifier", namespace)
        artifact_type = (type_element.text or "jar").strip() if type_element is not None else "jar"
        classifier = (classifier_element.text or "").strip() if classifier_element is not None else ""
        if (
            not group_id
            or not artifact_id
            or "${" in group_id
            or "${" in artifact_id
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", group_id)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", artifact_id)
            or not version
            or "${" in version
            or not re.fullmatch(r"[0-9][A-Za-z0-9._+-]*", version)
        ):
            errors.append(f"Coordenadas Maven sin versión exacta verificable: {group_id}:{artifact_id}:{raw_version}")
            continue
        dependencies.append({
            "groupId": group_id,
            "artifactId": artifact_id,
            "version": version,
            "type": artifact_type,
            "classifier": classifier,
            "scope": (xml_child(dependency, "scope", namespace).text or "compile").strip() if xml_child(dependency, "scope", namespace) is not None else "compile",
        })
    return dependencies, errors


def check_maven_project(project: Path, policy: dict[str, Any], temp_dir: Path, cosign: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    settings = policy["nonNpmIntegrity"]
    dependencies, errors = parse_maven_dependencies(project / "pom.xml", "http://maven.apache.org/POM/4.0.0")
    for message in errors:
        add_finding(
            findings,
            "maven_version_pin",
            policy["dependencyIntegrity"]["verificationFailureDecision"],
            message,
            {"file": str(project / "pom.xml")},
        )
    if not dependencies and not errors:
        return {
            "ecosystem": "maven",
            "status": "not_applicable",
            "directDependencies": [],
            "findings": [],
            "reason": "El POM no declara dependencias directas verificables.",
        }
    repository = settings["mavenRepository"].rstrip("/")
    if not host_is_allowed(repository, set(settings["mavenAllowedHosts"])):
        add_finding(
            findings,
            "maven_registry_origin",
            "bloquear",
            "El repositorio Maven configurado no está en la lista permitida.",
            {"repository": repository},
        )
        return {"ecosystem": "maven", "status": "blocked_by_preflight", "directDependencies": [], "findings": findings}

    for dependency in dependencies:
        group_path = dependency["groupId"].replace(".", "/")
        artifact = dependency["artifactId"]
        version = dependency["version"]
        if dependency["type"] not in {"jar", "test-jar"}:
            add_finding(
                findings,
                "maven_artifact_integrity",
                policy["dependencyIntegrity"]["verificationFailureDecision"],
                "El tipo de artefacto Maven no está cubierto por el verificador de JAR.",
                {"dependency": dependency},
            )
            continue
        classifier = f"-{dependency['classifier']}" if dependency["classifier"] else ""
        filename = f"{artifact}-{version}{classifier}.jar"
        artifact_url = f"{repository}/{group_path}/{artifact}/{version}/{filename}"
        record: dict[str, Any] = {**dependency, "source": artifact_url}
        try:
            artifact_bytes = request_bytes(artifact_url)
            artifact_path = temp_dir / filename
            artifact_path.write_bytes(artifact_bytes)
            algorithm, expected, actual = fetch_maven_checksum(artifact_url, artifact_bytes)
            record.update({
                "digestAlgorithm": algorithm,
                "publishedDigest": expected,
                "actualDigest": actual,
                "matches": actual == expected,
            })
            if actual != expected:
                add_finding(
                    findings,
                    "maven_artifact_integrity",
                    policy["dependencyIntegrity"]["artifactMismatchDecision"],
                    "Los bytes del artefacto Maven no coinciden con el checksum publicado por Maven Central.",
                    record.copy(),
                )
            elif algorithm == "sha1":
                add_finding(
                    findings,
                    "maven_checksum_strength",
                    policy["dependencyIntegrity"]["weakDigestDecision"],
                    "Maven Central solo publicó SHA-1 para este artefacto; el checksum coincide, pero requiere revisión por su algoritmo débil.",
                    record.copy(),
                )
            verify_sigstore_sidecar(artifact_path, artifact_url, policy, findings, record, temp_dir, cosign)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError, OSError) as error:
            record["status"] = "unverified"
            record["error"] = str(error)
            add_finding(
                findings,
                "maven_artifact_integrity",
                policy["dependencyIntegrity"]["verificationFailureDecision"],
                "No se pudo obtener o verificar el artefacto Maven desde Maven Central.",
                {"dependency": dependency, "source": artifact_url, "error": str(error)},
            )
        records.append(record)
    return {"ecosystem": "maven", "status": "review" if findings else "verified", "directDependencies": records, "findings": findings}


def evaluate(project: Path, policy: dict[str, Any], cosign: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "project": str(project),
        "observedAt": datetime.now(timezone.utc).isoformat(),
        "status": "not_applicable",
        "directDependencies": [],
        "findings": [],
        "scope": "dependencias directas declaradas; no instala paquetes ni resuelve dependencias transitivas",
    }
    if (project / "package.json").is_file():
        report["reason"] = "Los proyectos npm se verifican con el control npm específico."
        return report
    with tempfile.TemporaryDirectory(prefix="non-npm-integrity-") as temp_name:
        temp_dir = Path(temp_name)
        if (project / "Gemfile").is_file() and (project / "Gemfile.lock").is_file():
            result = check_ruby_project(project, policy, temp_dir, cosign)
        elif (project / "pom.xml").is_file():
            result = check_maven_project(project, policy, temp_dir, cosign)
        else:
            report["reason"] = "No se encontró un manifiesto RubyGems ni Maven compatible."
            return report
    report.update(result)
    decisions = {item["decision"] for item in result["findings"]}
    report["status"] = "failed" if "bloquear" in decisions else "review" if decisions else (
        "not_applicable" if result.get("status") == "not_applicable" else "passed"
    )
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
    print(f"{args.project}: non-npm integrity {report['status']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, ET.ParseError) as error:
        print(f"Error de verificación no-npm: {error}", file=sys.stderr)
        raise SystemExit(2)
