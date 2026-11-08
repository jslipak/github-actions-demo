# GitHub Actions demo

Repositorio mínimo para probar GitHub Actions.

El workflow `CI` se ejecuta en cada `push`, en pull requests hacia `main` y
manualmente desde la pestaña **Actions**. Comprueba el contenido del repo y
muestra un saludo en los logs.

Para probarlo en GitHub, crea un repositorio vacío, agrega este proyecto como
`origin` y ejecuta `git push -u origin main`. Después abre **Actions** para ver
la ejecución y sus logs.
