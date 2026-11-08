# S1 — Vulnerabilidad crítica

Proyecto Maven con aplicación Java de logging y dependencias de prueba. Mantiene log4j-core y log4j-api 2.14.1, vulnerables a CVE-2021-44228 (Log4Shell); esas versiones son la causa bloqueante.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
