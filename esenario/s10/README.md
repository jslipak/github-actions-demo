# S10 — S0 ejecutado en un contenedor con riesgo de SO

S10 conserva la aplicación Rails y las dependencias Ruby de S0. El servicio `test` definido en `compose.yaml` inicia Rails y realiza una solicitud HTTP real a `GET /health`; el resultado esperado es HTTP 200 con el mismo payload de S0.

La imagen base es `ruby:3.4.10-alpine3.23`, fijada por digest y basada en Alpine para mantenerla liviana. Trivy analiza la imagen con `--pkg-types os`, por lo que este escenario busca vulnerabilidades en paquetes del sistema operativo Alpine y no atribuye el bloqueo a las gems ni al código Rails. Trivy 0.76.2 reportó `CVE-2026-107891` (`musl`/`musl-utils`) y `CVE-2026-85091` (`zlib`), ambos `HIGH`; la política de imágenes bloquea hallazgos `HIGH` y `CRITICAL`.

Las gems y los paquetes de compilación necesarios para ejecutar la prueba se instalan dentro del contenedor efímero; no se agregan capas a la imagen base. El árbol del escenario se monta como solo lectura; los directorios `log` y `tmp` se montan en `tmpfs`. El análisis de seguridad se realiza sobre la imagen base fijada antes de ejecutar la prueba.

La prueba debe pasar, pero la evaluación consolidada de S10 queda en **bloquear** por la dependencia vulnerable del sistema operativo de la imagen. Como en los otros escenarios de laboratorio, la decisión no vuelve rojo el job de GitHub Actions.
