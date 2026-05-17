REPORT: CVE-2026-31431 — Copy Fail

Resumen técnico (en mis propias palabras):

CVE-2026-31431, conocido como "Copy Fail", es un fallo lógico en el subsistema
criptográfico del kernel Linux que permitía escribir datos controlados en páginas
que pertenecen al page cache de archivos setuid, sin modificar el archivo en disco.
El origen del problema fue una optimización de 2017 en `crypto/algif_aead.c`
que trataba de realizar operaciones AEAD in-place para mejorar rendimiento. Para
lograrlo, el código reusaba la misma scatterlist para `src` y `dst` en la
petición de cifrado/descifrado (`req->src = req->dst`). Esto provocó que, cuando
las páginas de entrada provenían de `splice()` (page cache), el kernel pudiera
usar páginas del page cache como destino de escritura para la operación
críptica.

El error concreto es peligroso porque la operación de autenticación y
descifrado escribe más allá de la región legítima de salida (por ejemplo,
`dst[assoclen + cryptlen]`), y si `dst` comparte páginas con el page cache
(un escenario posible con `splice()`), esas páginas corresponden a otros
ficheros en el sistema. El exploit aprovecha esto para plantar 4 bytes
controlados en la memoria que más tarde surten efecto al ejecutar un binario
setuid (como `/usr/bin/su`), obteniendo código o privilegios elevados sin
modificar el inodo ni el contenido persistido del archivo — de ahí su
'stealthiness'.

Conexión con conceptos del curso:
- Page cache: el bug explota el hecho de que el page cache almacena páginas
  que representan contenido de ficheros y que, en ciertos flujos, esas páginas
  pueden ser referenciadas por operaciones de E/S (como `splice()`).
- setuid: binarios setuid (como `su`) cargan en memoria y su comportamiento
  depende del contenido en memoria; corromper su imagen en memoria puede dar
  privilegios sin tocar el disco.
- Inodos y permisos: aunque el exploit no cambia el inodo ni el contenido en
  disco, invade la integridad del proceso al alterar la imagen cargada en
  memoria.

Lecciones aprendidas:
- Cambios puntuales por rendimiento (optimización in-place) pueden introducir
  vectores de corrupción cuando se asumen invariantes que no se mantienen en
  todas las rutas de E/S (p. ej. `splice()` y page cache).
- El análisis de seguridad debe revisar no solo el código lógico, sino las
  interacciones con subsistemas (p. ej. VM/page cache, sockets AF_ALG,
  llamadas splice) y modelos de memoria.
- Las mitigaciones temporales (deshabilitar módulos) son útiles para reducir
  riesgo mientras se desarrolla un parche permanente.

¿Qué hice en este ejercicio?
- Preparé la VM vulnerable, intenté el PoC público y documenté la salida.
- Apliqué y verifiqué el parche en `crypto/algif_aead.c`, recompilé el kernel
  y generé la evidencia correspondiente.

(Fin del reporte)
