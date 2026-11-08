# S8 — Vulnerabilidad alta

Proyecto npm con path-to-regexp 0.1.7 y Express 4.21.2, además de dotenv. La versión vulnerable fijada conserva el hallazgo HIGH; se espera revisión manual.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
