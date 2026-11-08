# Fixtures de escenarios S0–S9

Cada carpeta de `esenario/` es un proyecto de laboratorio independiente con
archivos de manifiesto y lockfiles auténticos. Los fallos se producen por las
dependencias declaradas o por la inconsistencia intencional de sus archivos;
no se usan JSON de escenarios para inventar los resultados.

## Ejecución

No hace falta instalar herramientas en el equipo local. En cada push y pull
request, GitHub Actions descubre proyectos por sus manifiestos y crea jobs
independientes. Los controles están separados por propósito:

- `Dependency Resolution and Lockfile Validation`: resuelve dependencias y
  comprueba manifiestos y lockfiles.
- `Dependency Vulnerability Scan`: ejecuta `npm audit` y Trivy.
- `Dependency Configuration and Secret Scan`: analiza configuración y secretos
  con Trivy.
- `Dependency Metadata and Integrity Policy`: consulta metadatos publicados para
  contrastar integridad, fuente, licencia y estado de mantenimiento.

Los hallazgos bloqueantes hacen fallar el job del proyecto correspondiente; los
paquetes obsoletos quedan señalados para revisión manual. La lista de licencias
permitidas y el registro aprobado se configuran en
`.github/dependency-policy.json`. Los informes de metadatos se publican como
artefactos de Actions.

## Ejecución local con evidencia

Desde la raíz del repositorio, ejecuta:

```bash
./scripts/run-local-checks.sh
```

El script recorre los proyectos, ejecuta los controles disponibles y muestra al
final una tabla con código y descripción del escenario, decisión observada,
validaciones ejecutadas y sus resultados. No contiene decisiones esperadas por
escenario: el estado se deriva de los comandos y hallazgos observados. Guarda la
tabla como `summary.md`, además de `summary.csv`, logs e informes JSON en
`output/local-run/<fecha-hora-UTC>/`.
El proceso termina con código distinto de cero si algún control falla. Requiere
Node.js/npm y Trivy; Maven y Ruby/Bundler se requieren para los proyectos que
usen esos ecosistemas. `npm ci` se ejecuta con los scripts de ciclo de vida
deshabilitados.

Hay una variante Docker opcional en [`docker/README.md`](docker/README.md). Es
un candidato para evaluación académica; la primera imagen construida resultó
grande y con hallazgos de vulnerabilidades, por lo que no se presenta como
imagen endurecida ni recomendada.

Para inspeccionar un caso, abre `esenario/sN/README.md`. S0 es el caso limpio de
control y usa Rails como formato no npm. S1 usa Maven/Log4j. S3 conserva
deliberadamente una discrepancia entre
`package.json` y `package-lock.json`, por lo que `npm ci` debe fallar.

| Caso | Fixture | Resultado que representa |
|---|---|---|
| S0 | Ruby on Rails, `Gemfile` y `Gemfile.lock` | Limpio; permitir. Demuestra que el control no depende de npm/framework. |
| S1 | Maven, `log4j-core` 2.14.1 | CVE-2021-44228; bloquear |
| S2 | npm y `.npmrc` | Registro no autorizado; bloquear |
| S3 | npm | Lockfile inconsistente; `npm ci` falla |
| S4 | npm con `postinstall` | Hook de instalación; bloquear sin ejecutarlo |
| S5 | npm, `lodash` | Artefacto alterado frente al hash confiable; bloquear |
| S6 | npm, `request` | Mantenimiento obsoleto; revisión manual |
| S7 | npm, `@substrate/connect-known-chains` | Licencia no permitida; bloquear |
| S8 | npm, `path-to-regexp` 0.1.7 | Vulnerabilidad alta; revisión manual |
| S9 | npm, `lodash` | Riesgos combinados; bloquear |

Los lockfiles son parte de la evidencia y deben mantenerse junto a cada
manifiesto. Los fixtures vulnerables son muestras de laboratorio: no deben
usarse como dependencias de una aplicación real.
