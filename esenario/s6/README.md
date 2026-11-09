# S6 — Señal de antigüedad de release

Proyecto npm que fija `is-promise@4.0.0`. Su último release es antiguo frente al umbral definido en la política, por lo que la señal de mantenimiento debe derivar a revisión manual. La antigüedad por sí sola no demuestra que un paquete esté abandonado.

`dependency-metadata-report.json` y el directorio `node_modules/` corresponden al fixture anterior; no son entradas del workflow actual. El directorio se excluye del escaneo y la evidencia vigente se genera en cada corrida de GitHub Actions.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
