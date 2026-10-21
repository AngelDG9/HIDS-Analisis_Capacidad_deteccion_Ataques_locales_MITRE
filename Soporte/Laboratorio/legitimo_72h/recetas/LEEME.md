# `recetas/` — la actividad legítima, contada en prosa

> Generado a partir de `_artefactos/scripts/construir_receta_legitima.py` (receta **v1**).
> Detalle hora→acción en **`receta_resumen.md`**; datos para las máquinas en
> **`calendario.json`** y **`bloques.env`**.

## La idea en una frase

Simular **una persona en una oficina**, no un programa que dispara comandos: llega, mira la
agenda, abre el portal, lee y responde correo, escribe un informe por secciones, lo comprime y
lo verifica, come, va a una reunión, comparte el acta en la nube, hace la copia de seguridad y
se va. **Nueve horas de reloj** con **café** y **comida** de verdad, y **tres días distintos**.

## Por qué así

1. **Realismo**: la ventana mide **falsos positivos**; lo que hay que representar es lo que hace
   una persona, con sus **ráfagas** y sus **pausas**. El intento anterior (209 acciones en 3
   minutos, día y noche) no se parecía a nadie.
2. **Determinismo**: GHOSTS **no tiene semilla** para la actividad (`new Random()` en
   `BaseHandler`, `Jitter`, `DelayExtensions`, `Bash`, `TimelineBuilder`; el único `Seed()` está
   en el Animator y **no tiene llamadores**). Por eso la receta es **JSON estático**: cero
   `random`, cero `delay-jitter`, cero handler `Curl` (inyecta UA aleatoria) y cero navegador.
   Así **dos ejecuciones dan la misma secuencia** (DT9).
3. **Legítimo por construcción**: solo binarios de oficina (`mkdir, echo, cat, cp, mv, tar, gzip,
   md5sum, sha256sum, ls, find, du, df, wc, date, curl, grep, head, tail, stat, rm`), rutas
   siempre bajo `/home/angel`, **sin `sudo`** y sin comillas dobles en los comandos.
4. **La web parece web**: la "sesión" abre el portal con **cookie jar**, pide los **requisitos**
   (CSS, JS, SVG) con **`Referer`**, navega a noticias/ayuda, descarga la plantilla y el **PDF**
   real, y verifica tamaño y huella. **Sin navegador** (descartado con datos en
   `../browser_eval.md`), **sin procesos nuevos** y **sin cambiar el recuento**.

## Cómo se reparte el día

| Bloque | Qué pasa | Acciones (D1/D2/D3) |
|---|---|---|
| **B1 Llegada** (12 min) | sello de llegada, estructura de carpetas, agenda, **abrir el portal**, primer borrador | 9 / 9 / 9 |
| **B2 Correo y mañana** (108 min) | rondas de buzón (consultar/escribir/releer), adjuntos (tar+huella+tamaño), ordenar | 26 / 32 / 22 |
| **P1 Café** (20 min) | **nada** (pausa) | 0 |
| **B3 Documentos** (160 min) | **navegar** (noticias, ayuda, plantilla, PDF), redactar 8 secciones, comprimir, consolidar, repasar | 42 / 34 / 46 |
| **P2 Comida** (60 min) | **nada** (pausa) | 0 |
| **B4 Reuniones/tarde** (135 min) | acta, compartir en la nube (`curl -T`, `PROPFIND`), portal, descargas | 22 / 30 / 16 |
| **B5 Cierre** (45 min) | copia de seguridad, huellas, subir a la nube, `du`/`df`, limpiar temporales | 12 / 12 / 12 |
| **Noche** | **nada** de GHOSTS (solo ruido del endpoint) | 0 |

- **Hueco máximo dentro de bloque: 12 min** (validado). **Hueco máximo del día: 15 h** (noche)
  ⇒ **la vigilancia no juzga fuera de 08:00–17:00 UTC**.
- **Guardián de fin de bloque**: el último evento de cada bloque duerme ~1 min **más allá** de
  `UtcTimeOff` ⇒ el handler, al volver a empezar, se encuentra fuera de ventana y **duerme hasta
  el día siguiente** (sin repetir el bloque).

## Variedad entre días

- **D1 (lunes) «cierre de informes»**: más redacción y consolidación.
- **D2 (martes) «reuniones y portal»**: más correo y adjuntos, dos actas, más nube.
- **D3 (miércoles) «revisión y copias»**: menos correo, más auditoría de ficheros (`find/du/wc/ls`)
  y copia completa con verificación de huellas.

Cambian **contenidos** (secciones, nombres con fecha, orden de las ráfagas), **volúmenes** y
**tarde**. No es «el mismo día tres veces».

## Qué NO es

- **No** simula dos aplicaciones a la vez (un solo stream): el ruido multitarea lo pone el
  sistema (auditd, syscheck, SCA, `df -P` del agente).
- **No** usa navegador, DNS ni TLS (no hay infraestructura local para ello; ver §4.6 del plan).
- **No** incluye ninguna acción `df` **de telemetría**: la sonda que proponía la v1 se **eliminó**.
  El disco lo vigila el **agente** (`df -P` cada 6 min). **Sí** hay **`df -h /` de usuario**: **4** en
  los tres días — 1 en **B5** de D1, 1 en **B5** de D2 y **2** en D3 (**B3** y **B5**): es una acción
  legítima (el usuario mira el disco al repasar y al cerrar), **presente y declarada**, no instrumentación.
