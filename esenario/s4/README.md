# S4 — Script de instalación

Aplicación npm con chalk y dotenv, más una dependencia local de laboratorio que declara postinstall y escribe un marcador. Inspeccionar el hook es intencional; no ejecutar npm install sin --ignore-scripts.

## Archivos

El manifiesto y el lockfile fijan las entradas del proyecto. Los scripts de ciclo de vida no se ejecutan durante la validación del pipeline. Las dependencias adicionales aportan contexto de aplicación, pero no sustituyen ni eliminan la condición principal del escenario.
