# `recetas/` — la actividad legítima, contada en prosa

> Generado a partir de `_artefactos/scripts/construir_receta_legitima.py` (receta **v2**, bloque
> `legitimo-v3`). Detalle hora→acción en **`receta_resumen.md`**; datos para las máquinas en
> **`calendario.json`** y **`bloques.env`**. La **campaña** de falsos positivos (`B6`, T2) se
> **genera desde `../campana/campana_casos.csv`** y va **incluida** en `d1/d2/d3.json` como un
> sexto handler declarado (`17:05-17:50Z`); su definición y su tabla están en `../campana/`.

## La idea en una frase

Simular **una persona en una oficina**, no un programa que dispara comandos: llega, mira la
agenda, abre el portal, lee y responde correo, escribe un informe por secciones, lo comprime y
lo verifica, come, va a una reunión, comparte el acta en la nube, hace la copia de seguridad y
se va. **Nueve horas de reloj** con **café** y **comida** de verdad, **tres días distintos** y
—desde la v2— **con prisa, con algún error y desde su carpeta**.

## Qué cambia la v2 (T1, mejoras M1–M4 del plan §5.1)

| # | Mejora | En una frase |
|---|---|---|
| **M1** | **`cwd` realista** | cada comando se lanza como `cd <carpeta coherente> && <comando>`: `~/Documentos`, `~/Descargas`, `~/Documentos/informes`, `~/Documentos/actas`… **Ninguna** acción se ejecuta en el directorio del cliente. `cd` es *builtin*: no añade `execve`. |
| **M2** | **Ritmo irregular fijo** | tabla de jitter **literal** en el generador (`INTRA`, `RAFAGAS`, `HUECOS`, `PAUSA_LARGA`), **sin `random`**: ráfagas de **1–6**, huecos de **41 s a 22 min** y **dos pausas largas** (20–22 min), una en `B3` y otra en `B4`. |
| **M3** | **Errores con reintento** | **10/día** de 6 familias (ruta mal escrita, `cp` a carpeta inexistente, `gzip` repetido, `rm` inexistente, `cat` de una carpeta, opción inválida). Cada fallo va **seguido del reintento correcto** y los dos dejan línea en **`~/Documentos/errores.log`** (`ts · tipo · familia · comando · rc`). El `rc` se captura con `$?`. |
| **M4** | **Herramientas del corpus** | **12 binarios nuevos** elegidos por el corpus de ataques (`xargs`, `timeout`, `sed`, `ip`, `openssl`, `tee`, `free`, `logger`, `seq`, `rsync`, `shred`, `wget`). Lista blanca: **34**. Cobertura del corpus: **23/50 = 46 %**. |

## Por qué así

1. **Realismo**: la ventana mide **falsos positivos**; lo que hay que representar es lo que hace
   una persona, con sus **ráfagas**, sus **pausas** y sus **meteduras de pata**. El intento
   anterior (209 acciones en 3 minutos, día y noche) no se parecía a nadie.
2. **Determinismo**: GHOSTS **no tiene semilla** para la actividad (`new Random()` en
   `BaseHandler`, `Jitter`, `DelayExtensions`, `Bash`, `TimelineBuilder`; el único `Seed()` está
   en el Animator y **no tiene llamadores**). Por eso la receta es **JSON estático**: cero
   `random`, cero `delay-jitter`, cero handler `Curl` (inyecta UA aleatoria) y cero navegador.
   Así **dos generaciones son byte-idénticas** y dos ejecuciones dan la misma secuencia (DT9).
3. **Legítimo por construcción**: solo binarios de oficina y de doble uso **elegidos por el
   corpus**, rutas siempre bajo `/home/angel`, **sin `sudo`**, **sin pipes** (GHOSTS pierde el
   reporte: DT9) y sin comillas dobles en los comandos.
4. **La web parece web**: la "sesión" abre el portal con **cookie jar**, pide los **requisitos**
   (CSS, JS, SVG) con **`Referer`**, navega a noticias/ayuda, descarga la plantilla y el **PDF**
   real, y verifica tamaño y huella. **Sin navegador** (descartado con datos en
   `../browser_eval.md`), **sin procesos nuevos** y **sin cambiar el recuento**.

## Cómo se reparte el día

| Bloque | Qué pasa | Acciones (D1/D2/D3) |
|---|---|---|
| **B1 Llegada** (12 min) | estructura de carpetas, sello de llegada, agenda, **abrir el portal**, primer borrador | 11 / 11 / 11 |
| **B2 Correo y mañana** (108 min) | rondas de buzón, adjuntos (tar+huella+tamaño), ordenar, **mirar la red** (`ip`) | 33 / 39 / 29 |
| **P1 Café** (20 min) | **nada** (pausa) | 0 |
| **B3 Documentos** (160 min) | **navegar**, normalizar un CSV (`sed`), redactar 8 secciones, comprimir, **numerar lotes** (`seq`+`xargs`), consolidar, **anotar en la bitácora** (`tee`) | 56 / 48 / 60 |
| **P2 Comida** (60 min) | **nada** (pausa) | 0 |
| **B4 Reuniones/tarde** (135 min) | acta, **sincronizar copias** (`rsync`), compartir en la nube, **descargar con `wget`**, acotar la espera (`timeout`), **destruir un borrador** (`shred`) | 35 / 43 / 29 |
| **B5 Cierre** (45 min) | copia de seguridad, huellas, subir a la nube, `du`/`df`, limpiar temporales | 12 / 12 / 12 |
| **B6 Campaña** (17:05–17:50Z) | **repaso del sistema**: 11 casos legítimos no mutantes (T2), con marcas y evidencia; **no es jornada de trabajo** | 16 / 25 / 22 |
| **Noche** | **nada** de GHOSTS (solo ruido del endpoint) | 0 |

- **Hueco máximo dentro de un bloque: 22 min** (validado: ≤ 1320 s, mín ≥ 40 s). Los huecos
  **grandes** son dos, uno en `B3` y otro en `B4` (20–22 min). Entre `B2` y `B3` el hueco es de
  **21 min** (1 min de cola + el café de 20). El **único** hueco mayor es la **comida** (60 min),
  que es una pausa **declarada** y que **ni el keepalive ni el `watch` juzgan** (solo evalúan
  dentro de bloques de trabajo). **Noche: 15 h** sin actividad, tampoco juzgada.
- **Guardián de fin de bloque**: el último evento de cada bloque duerme ~1 min **más allá** de
  `UtcTimeOff` ⇒ el handler, al volver a empezar, se encuentra fuera de ventana y **duerme hasta
  el día siguiente** (sin repetir el bloque).
- **`cwd`**: la carpeta es la del primer fichero que toca el comando (así `informe.txt` ⇒
  `~/Documentos/informes` y `llegada_<fecha>.txt` ⇒ `~/Documentos`); `mkdir -p` arranca en `~` y
  los `curl` en `~/Descargas` (la caché web es un **destino**, no un sitio donde uno trabaje).

## Variedad entre días

- **D1 (lunes) «cierre de informes»**: más redacción y consolidación.
- **D2 (martes) «reuniones y portal»**: más correo y adjuntos, dos actas, más nube.
- **D3 (miércoles) «revisión y copias»**: menos correo, más auditoría de ficheros (`find/du/wc/ls`)
  y copia completa con verificación de huellas.

Cambian **contenidos** (secciones, nombres con fecha, orden de las ráfagas), **volúmenes**,
**tarde** y los **huecos** (la tabla de jitter se recorre con un desplazamiento distinto cada
día). No es «el mismo día tres veces».

## Nada de fechas

`TFG_MAPA_DIAS` **no** está hardcodeado: se pasa con `--t0 AAAA-MM-DD` (o `--mapa-dias`) y se
**fija al cerrar T4**. Sin ese parámetro, `mapa_dias` queda **vacío** en `calendario.json` y
`bloques.env` (y `--check` lo avisa, no lo considera fallo). Poner la fecha **no** cambia
`d1/d2/d3`: solo esos dos ficheros.

```bash
python _artefactos/scripts/construir_receta_legitima.py --t0 2026-11-02     # fija la ventana
python _artefactos/scripts/construir_receta_legitima.py --check --t0 2026-11-02
python _artefactos/scripts/cobertura_exes.py                               # 23/50
```

## Qué NO es

- **No** simula dos aplicaciones a la vez (un solo stream): el ruido multitarea lo pone el
  sistema (auditd, syscheck, SCA, `df -P` del agente).
- **No** usa navegador, DNS ni TLS (no hay infraestructura local para ello; ver §4.6 del plan).
- **No** incluye ninguna acción `df` **de telemetría**: la sonda que proponía la v1 se **eliminó**.
  El disco lo vigila el **agente** (`df -P` cada 6 min). **Sí** hay **`df -h /` de usuario**: **2**
  en D1, **2** en D2 y **3** en D3 (al repasar, al cerrar y en el reintento del error `df
  --max-depth`): acción legítima, **presente y declarada**, no instrumentación.
