# S0 — Control limpio con Ruby on Rails

Este fixture reemplaza el ejemplo npm por una aplicación Ruby on Rails API real. `Gemfile` declara Rails, SQLite, Puma y Bootsnap; `Gemfile.lock` fija las versiones resueltas. La aplicación expone `GET /health` y devuelve un estado `ok`.

El caso mantiene el mismo propósito: actuar como control sin una condición bloqueante. Demuestra que la validación de dependencias puede aplicarse a distintos ecosistemas y frameworks; no depende de Node ni de npm.

## Archivos principales

- `Gemfile` / `Gemfile.lock`: manifiesto y resolución reproducible de gems.
- `config/`: arranque de Rails y ruta API.
- `app/controllers/health_controller.rb`: endpoint de comprobación.

El pipeline comprueba el manifiesto y el lockfile sin instalar gems ni ejecutar código de instalación en la máquina local.
