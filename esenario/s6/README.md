# S6 — Dependencia obsoleta

Proyecto npm que fija request 2.88.2 (paquete abandonado), más chalk, lodash y Mocha. El hallazgo de mantenimiento debe derivar a revisión manual, no a bloqueo automático.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
