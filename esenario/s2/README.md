# S2 — Registro no autorizado

Proyecto npm con dependencias funcionales (chalk, dotenv y pino), lockfile con URLs del host no autorizado y .npmrc apuntando a ese mismo host. El hallazgo se mantiene centrado en el origen, no en vulnerabilidades del paquete.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
