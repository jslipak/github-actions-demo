## Resumen de decisiones

| Escenario | Decisión | Hallazgos |
|---|---:|---:|
| s0 | **permitir** | 0 |
| s1 | **bloquear** | 8 |
| s2 | **bloquear** | 16 |
| s3 | **bloquear** | 1 |
| s4 | **bloquear** | 1 |
| s5 | **bloquear** | 4 |
| s6 | **revision manual** | 1 |
| s7 | **bloquear** | 2 |
| s8 | **revision manual** | 8 |
| s9 | **bloquear** | 18 |
| s10 | **bloquear** | 4 |

### Detalle de s0

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | not_applicable | El escenario no es un proyecto npm con lockfile. |
| Integridad directa rubygems | passed | bootsnap@1.26.1 sha256=coincide Sigstore=no_bundle_published; puma@8.0.2 sha256=coincide Sigstore=no_bundle_published; rails@8.1.4.1 sha256=coincide Sigstore=no_bundle_published; sqlite3@2.10.2 sha256=coincide Sigstore=no_bundle_published |
| Cosign / Sigstore | not_applicable | El escenario no versiona artefactos binarios para verificar con Cosign. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| — | Sin hallazgos en los controles ejecutados | — | permitir |

### Detalle de s1

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | not_applicable | El escenario no es un proyecto npm con lockfile. |
| Integridad directa maven | review | log4j-core@2.14.1 sha1=coincide Sigstore=no_bundle_published; log4j-api@2.14.1 sha1=coincide Sigstore=no_bundle_published; slf4j-api@1.7.36 sha1=coincide Sigstore=no_bundle_published; junit-jupiter@5.10.2 sha512=coincide Sigstore=no_bundle_published |
| Cosign / Sigstore | not_applicable | El escenario no versiona artefactos binarios para verificar con Cosign. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| maven_checksum_strength | Maven Central solo publicó SHA-1 para este artefacto; el checksum coincide, pero requiere revisión por su algoritmo débil. | {"actualDigest": "9141212b8507ab50a45525b545b39d224614528b", "artifactId": "log4j-core", "digestAlgorithm": "sha1", "groupId": "org.apache.logging.log4j", "matches": true, "publishedDigest": "9141212b8507ab50a45525b545b39d224614528b", "source": "https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar", "type": "jar", "version": "2.14.1"} | revision manual |
| maven_checksum_strength | Maven Central solo publicó SHA-1 para este artefacto; el checksum coincide, pero requiere revisión por su algoritmo débil. | {"actualDigest": "cd8858fbbde69f46bce8db1152c18a43328aae78", "artifactId": "log4j-api", "digestAlgorithm": "sha1", "groupId": "org.apache.logging.log4j", "matches": true, "publishedDigest": "cd8858fbbde69f46bce8db1152c18a43328aae78", "source": "https://repo.maven.apache.org/maven2/org/apache/logging/log4j/log4j-api/2.14.1/log4j-api-2.14.1.jar", "type": "jar", "version": "2.14.1"} | revision manual |
| maven_checksum_strength | Maven Central solo publicó SHA-1 para este artefacto; el checksum coincide, pero requiere revisión por su algoritmo débil. | {"actualDigest": "6c62681a2f655b49963a5983b8b0950a6120ae14", "artifactId": "slf4j-api", "digestAlgorithm": "sha1", "groupId": "org.slf4j", "matches": true, "publishedDigest": "6c62681a2f655b49963a5983b8b0950a6120ae14", "source": "https://repo.maven.apache.org/maven2/org/slf4j/slf4j-api/1.7.36/slf4j-api-1.7.36.jar", "type": "jar", "version": "1.7.36"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de bloqueo. | {"cvss": 10.0, "installedVersion": "2.14.1", "package": "org.apache.logging.log4j:log4j-core", "severity": "CRITICAL", "vulnerabilityId": "CVE-2021-44228"} | bloquear |
| vulnerability | Vulnerabilidad sobre el umbral de bloqueo. | {"cvss": 9.1, "installedVersion": "2.14.1", "package": "org.apache.logging.log4j:log4j-core", "severity": "CRITICAL", "vulnerabilityId": "CVE-2021-45046"} | bloquear |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 8.6, "installedVersion": "2.14.1", "package": "org.apache.logging.log4j:log4j-core", "severity": "HIGH", "vulnerabilityId": "CVE-2021-45105"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "2.14.1", "package": "org.apache.logging.log4j:log4j-core", "severity": "MEDIUM", "vulnerabilityId": "CVE-2026-34479"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "2.14.1", "package": "org.apache.logging.log4j:log4j-core", "severity": "MEDIUM", "vulnerabilityId": "CVE-2026-34480"} | revision manual |

### Detalle de s2

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | skipped | Se omitió la instalación para no descargar desde fuentes no autorizadas ni resolver un lockfile inconsistente. |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/atomic-sleep", "url": "https://packages.example.invalid/atomic-sleep/-/atomic-sleep-1.0.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/chalk", "url": "https://packages.example.invalid/chalk/-/chalk-6.0.1.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/dotenv", "url": "https://packages.example.invalid/dotenv/-/dotenv-16.4.7.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/fast-redact", "url": "https://packages.example.invalid/fast-redact/-/fast-redact-3.5.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/on-exit-leak-free", "url": "https://packages.example.invalid/on-exit-leak-free/-/on-exit-leak-free-2.1.2.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/pino", "url": "https://packages.example.invalid/pino/-/pino-9.6.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/pino-abstract-transport", "url": "https://packages.example.invalid/pino-abstract-transport/-/pino-abstract-transport-2.0.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/pino-std-serializers", "url": "https://packages.example.invalid/pino-std-serializers/-/pino-std-serializers-7.1.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/process-warning", "url": "https://packages.example.invalid/process-warning/-/process-warning-4.0.1.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/quick-format-unescaped", "url": "https://packages.example.invalid/quick-format-unescaped/-/quick-format-unescaped-4.0.4.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/real-require", "url": "https://packages.example.invalid/real-require/-/real-require-0.2.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/safe-stable-stringify", "url": "https://packages.example.invalid/safe-stable-stringify/-/safe-stable-stringify-2.5.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/sonic-boom", "url": "https://packages.example.invalid/sonic-boom/-/sonic-boom-4.2.1.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/split2", "url": "https://packages.example.invalid/split2/-/split2-4.2.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/thread-stream", "url": "https://packages.example.invalid/thread-stream/-/thread-stream-3.2.0.tgz"} | bloquear |
| approved_registry | La configuración npm apunta a un registro no autorizado. | {"file": "esenario/s2/.npmrc", "registry": "https://packages.example.invalid/"} | bloquear |

### Detalle de s3

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | skipped | Se omitió la instalación para no descargar desde fuentes no autorizadas ni resolver un lockfile inconsistente. |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| lockfile_consistency | Las dependencias declaradas en el manifiesto no coinciden con el lockfile. | {"mismatches": {"chalk": {"lock": "6.0.1", "manifest": "5.6.2"}}} | bloquear |

### Detalle de s4

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | completada | copia temporal |
| Firmas del registro npm | verified | npm 11.19.1; verificadas=2; inválidas=0; ausentes=0 |
| Dependencias locales fuera de firmas npm | no aplicable | node_modules/lab-postinstall-fixture |
| Provenance npm | no_attestation_reported | atestaciones verificadas=0 |
| Marcador postinstall S4 | no creado | [] |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| lifecycle_script | Se encontró el evento de ciclo de vida postinstall; el comando no se ejecutó. | {"command": "node -e \"require('fs').writeFileSync('postinstall-marker.txt','executed')\"", "event": "postinstall", "file": "esenario/s4/fixtures/lab-postinstall-fixture/package.json"} | bloquear |

### Detalle de s5

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | skipped | Se omitió la instalación para no descargar desde fuentes no autorizadas ni resolver un lockfile inconsistente. |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/lodash", "url": "https://packages.example.invalid/lodash/-/lodash-4.17.21.tgz"} | bloquear |
| artifact_integrity | Los bytes del artefacto no coinciden con la integridad publicada por el registro. | {"artifact": "esenario/s5/artifacts/lodash-4.17.21-alterado.tgz", "matches": false, "package": "lodash", "version": "4.17.21"} | bloquear |
| vulnerability | Vulnerabilidad sobre el umbral de bloqueo. | {"cvss": 9.8, "installedVersion": "4.17.21", "package": "lodash", "severity": "HIGH", "vulnerabilityId": "CVE-2026-4800"} | bloquear |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 8.2, "installedVersion": "4.17.21", "package": "lodash", "severity": "MEDIUM", "vulnerabilityId": "CVE-2025-13465"} | revision manual |

### Detalle de s6

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | completada | copia temporal |
| Firmas del registro npm | verified | npm 11.19.1; verificadas=1; inválidas=0; ausentes=0 |
| Provenance npm | no_attestation_reported | atestaciones verificadas=0 |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| maintenance_age | La fecha del último release supera el umbral de mantenimiento de la política. | {"ageDays": 2388, "declaredVersion": "4.0.0", "package": "is-promise", "source": "https://registry.npmjs.org/is-promise", "thresholdDays": 730} | revision manual |

### Detalle de s7

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | completada | copia temporal |
| Firmas del registro npm | verified | npm 11.19.1; verificadas=3; inválidas=0; ausentes=0 |
| Provenance npm | verified | atestaciones verificadas=1 |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| license | La licencia declarada en el lockfile no está en la lista permitida. | {"license": "GPL-3.0-only", "packagePath": "node_modules/@substrate/connect-known-chains", "source": "esenario/s7/package-lock.json", "version": "1.10.3"} | bloquear |
| license | Licencia fuera de la lista permitida. | {"license": "GPL-3.0-only", "package": "@substrate/connect-known-chains"} | bloquear |

### Detalle de s8

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | completada | copia temporal |
| Firmas del registro npm | verified | npm 11.19.1; verificadas=71; inválidas=0; ausentes=0 |
| Provenance npm | verified | atestaciones verificadas=1 |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "1.20.3", "package": "body-parser", "severity": "HIGH", "vulnerabilityId": "CVE-2026-111181"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "0.1.12", "package": "path-to-regexp", "severity": "HIGH", "vulnerabilityId": "CVE-2026-4867"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "0.1.7", "package": "path-to-regexp", "severity": "HIGH", "vulnerabilityId": "CVE-2024-45296"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "0.1.7", "package": "path-to-regexp", "severity": "HIGH", "vulnerabilityId": "CVE-2024-52798"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "0.1.7", "package": "path-to-regexp", "severity": "HIGH", "vulnerabilityId": "CVE-2026-4867"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "6.13.0", "package": "qs", "severity": "MEDIUM", "vulnerabilityId": "CVE-2025-15284"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "6.13.0", "package": "qs", "severity": "MEDIUM", "vulnerabilityId": "CVE-2026-82417"} | revision manual |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 7.5, "installedVersion": "6.13.0", "package": "qs", "severity": "LOW", "vulnerabilityId": "CVE-2026-2391"} | revision manual |

### Detalle de s9

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | skipped | Se omitió la instalación para no descargar desde fuentes no autorizadas ni resolver un lockfile inconsistente. |
| Integridad directa no-npm | not_applicable | Los proyectos npm se verifican con el control npm específico. |
| Cosign / Sigstore | not_applicable | Los paquetes npm se verifican con npm audit signatures. |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/atomic-sleep", "url": "https://packages.example.invalid/atomic-sleep/-/atomic-sleep-1.0.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/dotenv", "url": "https://packages.example.invalid/dotenv/-/dotenv-16.4.7.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/fast-redact", "url": "https://packages.example.invalid/fast-redact/-/fast-redact-3.5.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/lodash", "url": "https://packages.example.invalid/lodash/-/lodash-4.17.21.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/on-exit-leak-free", "url": "https://packages.example.invalid/on-exit-leak-free/-/on-exit-leak-free-2.1.2.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/pino", "url": "https://packages.example.invalid/pino/-/pino-9.6.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/pino-abstract-transport", "url": "https://packages.example.invalid/pino-abstract-transport/-/pino-abstract-transport-2.0.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/pino-std-serializers", "url": "https://packages.example.invalid/pino-std-serializers/-/pino-std-serializers-7.1.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/process-warning", "url": "https://packages.example.invalid/process-warning/-/process-warning-4.0.1.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/quick-format-unescaped", "url": "https://packages.example.invalid/quick-format-unescaped/-/quick-format-unescaped-4.0.4.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/real-require", "url": "https://packages.example.invalid/real-require/-/real-require-0.2.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/safe-stable-stringify", "url": "https://packages.example.invalid/safe-stable-stringify/-/safe-stable-stringify-2.5.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/sonic-boom", "url": "https://packages.example.invalid/sonic-boom/-/sonic-boom-4.2.1.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/split2", "url": "https://packages.example.invalid/split2/-/split2-4.2.0.tgz"} | bloquear |
| approved_registry | El lockfile resuelve una dependencia desde un host no autorizado. | {"host": "packages.example.invalid", "packagePath": "node_modules/thread-stream", "url": "https://packages.example.invalid/thread-stream/-/thread-stream-3.2.0.tgz"} | bloquear |
| approved_registry | La configuración npm apunta a un registro no autorizado. | {"file": "esenario/s9/.npmrc", "registry": "https://packages.example.invalid/"} | bloquear |
| vulnerability | Vulnerabilidad sobre el umbral de bloqueo. | {"cvss": 9.8, "installedVersion": "4.17.21", "package": "lodash", "severity": "HIGH", "vulnerabilityId": "CVE-2026-4800"} | bloquear |
| vulnerability | Vulnerabilidad sobre el umbral de revisión. | {"cvss": 8.2, "installedVersion": "4.17.21", "package": "lodash", "severity": "MEDIUM", "vulnerabilityId": "CVE-2025-13465"} | revision manual |

### Detalle de s10

| Control de integridad/procedencia | Estado | Detalle |
|---|---|---|
| npm ci --ignore-scripts | not_applicable | El escenario no es un proyecto npm con lockfile. |
| Integridad directa rubygems | passed | bootsnap@1.26.1 sha256=coincide Sigstore=no_bundle_published; puma@8.0.2 sha256=coincide Sigstore=no_bundle_published; rails@8.1.4.1 sha256=coincide Sigstore=no_bundle_published; sqlite3@2.10.2 sha256=coincide Sigstore=no_bundle_published |
| Cosign / Sigstore | not_applicable | El escenario no versiona artefactos binarios para verificar con Cosign. |
| Pruebas Docker Compose | passed | servicio=test; exit=0 |
| Trivy imagen (paquetes OS) | analizada | ruby:3.4.10-alpine3.23@sha256:7dea4d37b9bb1002986613843f1e9906f49a76bf8bc321e08c6d8204b1e3ab7b: scanned |

| Control | Qué ocurrió | Evidencia relevante | Decisión |
|---|---|---|---:|
| container_os_vulnerability | Trivy detectó una vulnerabilidad bloqueante en un paquete del sistema operativo de la imagen. | {"cvss": 8.1, "fixedVersion": "1.2.5-r24", "image": "ruby:3.4.10-alpine3.23@sha256:7dea4d37b9bb1002986613843f1e9906f49a76bf8bc321e08c6d8204b1e3ab7b", "installedVersion": "1.2.5-r23", "package": "musl", "packageClass": "os-pkgs", "packageType": "alpine", "severity": "HIGH", "vulnerabilityId": "CVE-2026-107891"} | bloquear |
| container_os_vulnerability | Trivy detectó una vulnerabilidad bloqueante en un paquete del sistema operativo de la imagen. | {"cvss": 8.1, "fixedVersion": "1.2.5-r24", "image": "ruby:3.4.10-alpine3.23@sha256:7dea4d37b9bb1002986613843f1e9906f49a76bf8bc321e08c6d8204b1e3ab7b", "installedVersion": "1.2.5-r23", "package": "musl-utils", "packageClass": "os-pkgs", "packageType": "alpine", "severity": "HIGH", "vulnerabilityId": "CVE-2026-107891"} | bloquear |
| container_os_vulnerability | Trivy detectó una vulnerabilidad bloqueante en un paquete del sistema operativo de la imagen. | {"cvss": 8.1, "fixedVersion": "1.3.2-r1", "image": "ruby:3.4.10-alpine3.23@sha256:7dea4d37b9bb1002986613843f1e9906f49a76bf8bc321e08c6d8204b1e3ab7b", "installedVersion": "1.3.2-r0", "package": "zlib", "packageClass": "os-pkgs", "packageType": "alpine", "severity": "HIGH", "vulnerabilityId": "CVE-2026-85091"} | bloquear |
| container_os_vulnerability | Trivy detectó una vulnerabilidad para revisión en un paquete del sistema operativo de la imagen. | {"cvss": 0.0, "fixedVersion": "1.4-r0", "image": "ruby:3.4.10-alpine3.23@sha256:7dea4d37b9bb1002986613843f1e9906f49a76bf8bc321e08c6d8204b1e3ab7b", "installedVersion": "1.3.2-r0", "package": "zlib", "packageClass": "os-pkgs", "packageType": "alpine", "severity": "MEDIUM", "vulnerabilityId": "CVE-2026-4738"} | revision manual |
