# S3 — Lockfile inconsistente

Proyecto npm con varias dependencias normales. El lockfile fue generado para chalk 6.0.1; el manifiesto pide chalk 5.6.2. npm ci debe fallar por discrepancia, mientras el resto del lockfile mantiene integridad.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
