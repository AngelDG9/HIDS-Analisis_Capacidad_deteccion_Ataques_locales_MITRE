# `receta_resumen.md` — receta de actividad legítima **v2** (3 días)

> Generado por `_artefactos/scripts/construir_receta_legitima.py` (receta **v2**, bloque
> `legitimo-v3`, plan §5.1). Jornada **09:00–18:00 local** (08:00–17:00 UTC), con **café**
> (20 min) y **comida** (60 min). Solo handler `Command`; **cero** `random`, **cero**
> `Curl`, **cero** navegador, **cero** pipes (DT9).
> **`cwd` por acción**: `cd <carpeta coherente> && <comando>` (ninguna en el directorio del cliente).
> **Sin fecha**: `TFG_MAPA_DIAS` se pasa con `--t0` y se fija al cerrar **T4**.
> **Campaña `B6`** (T2): 11 casos no mutantes en `17:05-17:50Z`, reparto **3/4/4** e
> inicio con **jitter fijo** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11). Se genera desde
> `campana/campana_casos.csv`; se publica aparte y **no** recalcula `M`.

## Qué cambia respecto de la v1 (M1–M4)

| Mejora | Qué hace | Cómo se comprueba |
|---|---|---|
| **M1 `cwd`** | Cada comando arranca en su carpeta (`~/Documentos`, `~/Descargas`,
  `~/Documentos/informes`, …) con `cd <carpeta> && `; `cd` es builtin (0 `execve` extra) |
  `--check` exige el prefijo y que la carpeta esté en la lista; `audit_cwd` en E0 |
| **M2 ritmo** | Tabla de jitter **literal** (`INTRA`, `RAFAGAS`, `HUECOS`, `PAUSA_LARGA`):
  ráfagas 1–6, intra 41–62 s, huecos 80 s–22 min y 2 pausas largas (B3/B4) |
  `--check` valida hueco ∈ [40, 1320] s, ráfagas ≤ 6 y ≥ 2 huecos ≥ 20 min |
| **M3 errores** | 10 errores/día de 6 familias, **cada uno con su reintento correcto** y
  registro en `~/Documentos/errores.log` (`ts · tipo · familia · comando · rc`) |
  `--check` cuenta los pares y el `rc` se lee de `$?` en ejecución |
| **M4 corpus** | 12 binarios nuevos con uso de oficina: `xargs`, `timeout`, `sed`, `ip`,
  `openssl`, `tee`, `free`, `logger`, `seq`, `rsync`, `shred`, `wget` |
  `cobertura_exes.py` (receta v2 = 23/50 del corpus) |
| **M5 campaña `B6`** | 11 casos legítimos **no mutantes** dentro de la ventana, con
  `inicio`/`fin`/`hecho` por caso y esperado **por umbral** (`N ≥ 7` = 0; `N ≥ 3` = `80792`) |
  `campana.py --check` + `construir_receta_legitima.py --check` (CA-27) |

## Bloques y recuentos

| Bloque | UTC | Local | Tipo | D1 | D2 | D3 |
|---|---|---|---|---|---|---|
| B1 Llegada | 08:00–08:12 | 09:00-09:12 | trabajo | 11 | 11 | 11 |
| B2 Correo y mañana | 08:12–10:00 | 09:12-11:00 | trabajo | 33 | 39 | 29 |
| P1 Café | 10:00–10:20 | 11:00-11:20 | pausa | 0 | 0 | 0 |
| B3 Documentos | 10:20–13:00 | 11:20-14:00 | trabajo | 56 | 48 | 60 |
| P2 Comida | 13:00–14:00 | 14:00-15:00 | pausa | 0 | 0 | 0 |
| B4 Reuniones y tarde | 14:00–16:15 | 15:00-17:15 | trabajo | 35 | 43 | 29 |
| B5 Cierre | 16:15–17:00 | 17:15-18:00 | trabajo | 12 | 12 | 12 |
| B6 Repaso del sistema | 17:05–17:50 | 18:05-18:50 | campana | 16 | 25 | 22 |
| **Total jornada** | 08:00–17:00 | 09:00–18:00 | trabajo | **147** | **153** | **141** |
| **Total con B6** | 08:00–17:50 | 09:00–18:50 | — | **163** | **178** | **163** |

**Total ventana (3 días): 441 acciones de jornada + 63 de la campaña = 504 acciones GHOSTS** (v1: 333; +108 por M3/M4, ≈ 32 %).

## Campaña de falsos positivos (`B6`, T2)

**11 casos** no mutantes, **reparto 3/4/4** y **jitter fijo de inicio** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11). Separación mínima **180 s**; atribución `[ini − 10 s, fin + 60 s]`. **63 acciones** y **103 `execve`** ({1: 25, 2: 34, 3: 44}). Definición y comandos literales: `campana/casos.md` + `campana/campana_casos.csv`.

| Día | Inicio | Casos | Acciones B6 | Último `fin` | Huecos entre casos |
|---|---|---|---|---|---|
| d1 | 17:06 | 3 | 16 | 17:25 | 520 s, 531 s |
| d2 | 17:17 | 4 | 25 | 17:41 | 465 s, 415 s, 461 s |
| d3 | 17:11 | 4 | 22 | 17:35 | 470 s, 424 s, 473 s |

> `B6` **no es jornada de trabajo**: está declarado en `bloques.env` y la vigilancia no lo juzga como un bloque de oficina. Los casos se publican **aparte** (`campana_fp.csv`); **no** se recalcula `M` ni se da un FPR alternativo.

## Ritmo medido (tabla de jitter fija)

| Día | Bloque | Acciones | Ráfagas | Hueco mín | Hueco máx | ≥ 20 min |
|---|---|---|---|---|---|---|
| d1 | B1 | 11 | 4 | 41 s | 1.8 min | 0 |
| d1 | B2 | 33 | 12 | 41 s | 19.0 min | 0 |
| d1 | B3 | 56 | 20 | 41 s | 20.8 min | 1 |
| d1 | B4 | 35 | 13 | 41 s | 20.2 min | 1 |
| d1 | B5 | 12 | 5 | 41 s | 11.6 min | 0 |
| d2 | B1 | 11 | 4 | 41 s | 1.9 min | 0 |
| d2 | B2 | 39 | 15 | 41 s | 13.8 min | 0 |
| d2 | B3 | 48 | 17 | 41 s | 20.8 min | 1 |
| d2 | B4 | 43 | 17 | 41 s | 20.2 min | 1 |
| d2 | B5 | 12 | 6 | 43 s | 9.7 min | 0 |
| d3 | B1 | 11 | 4 | 41 s | 1.8 min | 0 |
| d3 | B2 | 29 | 10 | 41 s | 18.5 min | 0 |
| d3 | B3 | 60 | 22 | 41 s | 20.8 min | 1 |
| d3 | B4 | 29 | 11 | 41 s | 20.2 min | 1 |
| d3 | B5 | 12 | 5 | 41 s | 11.5 min | 0 |

## Errores humanos (M3, 10/día, con reintento)

| # | Bloque | Familia | Comando que FALLA | Comando del reintento |
|---|---|---|---|---|
| 1 | B1 | `error/ruta_mal` | `ls -la /home/angel/Documentos/informe` | `ls -la /home/angel/Documentos/informes` |
| 2 | B2 | `error/opcion` | `df -h --max-depth=1 /` | `df -h /` |
| 3 | B2 | `error/cp_dir` | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak` | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 4 | B2 | `error/ruta_mal` | `stat /home/angel/Documentos/informes/informe_2026.txt` | `stat /home/angel/Documentos/informes/informe.txt` |
| 5 | B3 | `error/gzip` | `gzip -d /home/angel/Documentos/informes/informe.txt` | `gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 6 | B3 | `error/rm_inexistente` | `rm /home/angel/Descargas/tmp_borradores.csv` | `rm -f /home/angel/Descargas/tmp_borradores.csv` |
| 7 | B4 | `error/cat_dir` | `cat /home/angel/Documentos/actas` | `cat /home/angel/Documentos/informes/informe.bak` |
| 8 | B4 | `error/cp_dir` | `cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/` | `cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt` |
| 9 | B4 | `error/opcion` | `ls -la --clasificar /home/angel/Documentos` | `ls -la --classify /home/angel/Documentos` |
| 10 | B4 | `error/gzip` | `gzip -d /home/angel/Documentos/informes/informe.bak` | `gzip -kf /home/angel/Documentos/informes/informe.bak` |

## Binarios declarados (lista blanca: 34; usados: 33)

`cat`, `cp`, `curl`, `date`, `df`, `du`, `echo`, `find`, `free`, `grep`, `gzip`, `head`, `ip`, `logger`, `ls`, `md5sum`, `mkdir`, `mv`, `openssl`, `rm`, `rsync`, `sed`, `seq`, `sha256sum`, `shred`, `stat`, `tail`, `tar`, `tee`, `timeout`, `wc`, `wget`, `xargs`

**Justificación** (plan §5.2.1 / corpus de ataques: 50 `basenames` distintos en
`audit_command`): de los 22 de la v1, **11** tienen gemelo en el corpus (`curl`,
`cat`, `sha256sum`, `cp`, `tar`, `find`, `gzip`, `mkdir`, `grep`, `head`, `rm`).
Los **12 nuevos son los que el corpus usa y un oficinista puede usar**: `xargs`
(2 497 detecciones), `timeout` (96), `ip` (73), `openssl` (16), `sed` (14), `rsync`
(10), `free` (5), `seq`/`tee`/`wget` (4) y `logger`/`shred` (2). Con ellos la receta
cubre **23/50 = 46 %** (T2 añadirá `systemctl`/`crontab` en la campaña ⇒ 25/50).
Quedan fuera, **a propósito**: `systemctl`/`crontab` (solo campaña), `git`, `dd`,
`passwd`, `nc.openbsd`, `perl`, `busybox`, `sqlite3` y todo lo que exige root o GUI.

## Día 1 — «cierre de informes» (147 + 16 = 163 acciones)

| # | UTC | Bloque | Familia | cwd | Comando |
|---|---|---|---|---|---|
| 1 | 08:00 | B1 | estructura | `~` | `cd /home/angel && mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Documentos/copias /home/angel/Documentos/correo /home/angel/Descargas /home/angel/.cache/tfg-web` |
| 2 | 08:00 | B1 | llegada | `~/Documentos` | `cd /home/angel/Documentos && date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 3 | 08:02 | B1 | listar | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos` |
| 4 | 08:03 | B1 | agenda | `~/Documentos` | `cd /home/angel/Documentos && echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | 08:04 | B1 | error | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos/informe 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error ruta_mal 'ls -la /home/angel/Documentos/informe' $r >> /home/angel/Documentos/errores.log; }` |
| 6 | 08:05 | B1 | reintento | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos/informes && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento ruta_mal 'ls -la /home/angel/Documentos/informes' $r >> /home/angel/Documentos/errores.log; }` |
| 7 | 08:06 | B1 | agenda | `~/Documentos` | `cd /home/angel/Documentos && cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 8 | 08:08 | B1 | web-sesion | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| 9 | 08:09 | B1 | web-requisitos | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles.css -w '%{http_code}' http://intranet.local:8080/styles.css && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal.js -w '%{http_code}' http://intranet.local:8080/portal.js && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/logo.svg -w '%{http_code}' http://intranet.local:8080/assets/logo.svg` |
| 10 | 08:09 | B1 | web-huella | `~/.cache/tfg-web` | `cd /home/angel/.cache/tfg-web && wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles.css` |
| 11 | 08:11 | B1 | correo | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 're: estado del informe mensual' > /home/angel/Documentos/correo/borrador_1.txt` |
| 12 | 08:12 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r1' -o /home/angel/.cache/tfg-web/buzon_1.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 13 | 08:12 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_1.txt` |
| 14 | 08:13 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_1.txt` |
| 15 | 08:20 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r2' -o /home/angel/.cache/tfg-web/buzon_2.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 16 | 08:24 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_2.txt` |
| 17 | 08:25 | B2 | red | `~` | `cd /home/angel && ip -brief addr` |
| 18 | 08:26 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_2.txt` |
| 19 | 08:27 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r3' -o /home/angel/.cache/tfg-web/buzon_3.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 20 | 08:27 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_3.txt` |
| 21 | 08:38 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_3.txt` |
| 22 | 08:39 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r4' -o /home/angel/.cache/tfg-web/buzon_4.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 23 | 08:44 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 4: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_4.txt` |
| 24 | 08:45 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_4.txt` |
| 25 | 08:46 | B2 | informe | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'informe del area - jornada 1' > /home/angel/Documentos/informes/informe.txt` |
| 26 | 08:46 | B2 | adjunto | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tar -czf /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 27 | 09:01 | B2 | error | `~` | `cd /home/angel && df -h --max-depth=1 / 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error opcion 'df -h --max-depth=1 /' $r >> /home/angel/Documentos/errores.log; }` |
| 28 | 09:06 | B2 | reintento | `~` | `cd /home/angel && df -h / && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento opcion 'df -h /' $r >> /home/angel/Documentos/errores.log; }` |
| 29 | 09:07 | B2 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cp_dir 'cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 30 | 09:08 | B2 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cp_dir 'cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 31 | 09:13 | B2 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 32 | 09:14 | B2 | tamano | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && du -sh /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 33 | 09:18 | B2 | listar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && ls -la /home/angel/Documentos/informes` |
| 34 | 09:19 | B2 | adjunto | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tar -czf /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 35 | 09:20 | B2 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 36 | 09:21 | B2 | tamano | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && du -sh /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 37 | 09:22 | B2 | listar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && ls -la /home/angel/Documentos/informes` |
| 38 | 09:28 | B2 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 39 | 09:47 | B2 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe_2026.txt 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error ruta_mal 'stat /home/angel/Documentos/informes/informe_2026.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 40 | 09:48 | B2 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento ruta_mal 'stat /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 41 | 09:56 | B2 | renombrar | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1.txt` |
| 42 | 09:57 | B2 | contar | `~/Documentos` | `cd /home/angel/Documentos && find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt` |
| 43 | 09:57 | B2 | listar | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && ls -la /home/angel/Documentos/correo` |
| 44 | 09:59 | B2 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 45 | 10:20 | B3 | web-navegar | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/index.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/noticias.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 46 | 10:20 | B3 | web-navegar | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 47 | 10:25 | B3 | web-descarga | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/plantilla_informe.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 48 | 10:32 | B3 | web-pdf | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/manual_empleado.pdf -w '%{http_code}' http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 49 | 10:32 | B3 | web-huella | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/manual_empleado.pdf && sha256sum /home/angel/Descargas/manual_empleado.pdf` |
| 50 | 10:33 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'referencia;area;importe' > /home/angel/Documentos/informes/export.csv` |
| 51 | 10:34 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sed -i 's/;/,/g' /home/angel/Documentos/informes/export.csv` |
| 52 | 10:37 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sed -n '1,5p' /home/angel/Documentos/informes/export.csv` |
| 53 | 10:38 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '1. alcance del informe (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 54 | 10:39 | B3 | huella | `~/Descargas` | `cd /home/angel/Descargas && openssl dgst -sha256 /home/angel/Descargas/manual_empleado.pdf` |
| 55 | 10:45 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 56 | 10:46 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 57 | 10:54 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '2. actividades del area (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 58 | 10:55 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 59 | 10:56 | B3 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -d /home/angel/Documentos/informes/informe.txt 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error gzip 'gzip -d /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 60 | 10:56 | B3 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento gzip 'gzip -kf /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 61 | 10:57 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 62 | 10:58 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '3. incidencias de la semana (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 63 | 11:02 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 64 | 11:07 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 65 | 11:08 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '4. indicadores del mes (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 66 | 11:08 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 67 | 11:11 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 68 | 11:12 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '5. riesgos identificados (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 69 | 11:19 | B3 | estado | `~` | `cd /home/angel && free -m` |
| 70 | 11:20 | B3 | registro | `~` | `cd /home/angel && logger -t ofimatica 'repaso del informe del area'` |
| 71 | 11:21 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 72 | 11:21 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 73 | 11:26 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '6. plan de accion (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 74 | 11:46 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 75 | 11:48 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 76 | 11:48 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '7. conclusiones (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 77 | 11:49 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 78 | 11:50 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 79 | 11:54 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '8. anexo de datos (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 80 | 11:55 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 81 | 12:03 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 82 | 12:03 | B3 | comprimir | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 83 | 12:04 | B3 | error | `~/Descargas` | `cd /home/angel/Descargas && rm /home/angel/Descargas/tmp_borradores.csv 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error rm_inexistente 'rm /home/angel/Descargas/tmp_borradores.csv' $r >> /home/angel/Documentos/errores.log; }` |
| 84 | 12:08 | B3 | reintento | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_borradores.csv && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento rm_inexistente 'rm -f /home/angel/Descargas/tmp_borradores.csv' $r >> /home/angel/Documentos/errores.log; }` |
| 85 | 12:11 | B3 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && md5sum /home/angel/Documentos/informes/informe.txt.gz` |
| 86 | 12:12 | B3 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/informe.txt.gz` |
| 87 | 12:13 | B3 | lotes | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && seq 1 12 > /home/angel/.cache/tfg-web/lotes.txt` |
| 88 | 12:14 | B3 | lotes | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && xargs -a /home/angel/.cache/tfg-web/lotes.txt -I{} cp /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/lote_{}.txt` |
| 89 | 12:21 | B3 | listar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && ls -la /home/angel/Documentos/informes` |
| 90 | 12:22 | B3 | tamano | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && du -sh /home/angel/Documentos/informes` |
| 91 | 12:35 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt.gz` |
| 92 | 12:35 | B3 | consolidar | `~/Descargas` | `cd /home/angel/Descargas && tar -czf /home/angel/Descargas/informes.tar.gz -C /home/angel/Documentos informes` |
| 93 | 12:36 | B3 | copia | `~/Descargas` | `cd /home/angel/Descargas && cp -f /home/angel/Descargas/informes.tar.gz /home/angel/Descargas/informes_copia_1.tar.gz` |
| 94 | 12:37 | B3 | huella | `~/Descargas` | `cd /home/angel/Descargas && sha256sum /home/angel/Descargas/informes.tar.gz` |
| 95 | 12:38 | B3 | bitacora | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'pendiente: firmar el acta de la reunion' > /home/angel/Documentos/informes/nota.txt` |
| 96 | 12:39 | B3 | bitacora | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tee -a /home/angel/Documentos/informes/bitacora.txt < /home/angel/Documentos/informes/nota.txt` |
| 97 | 12:42 | B3 | contar | `~/Documentos` | `cd /home/angel/Documentos && find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros_d1.txt` |
| 98 | 12:57 | B3 | tamano | `~/Descargas` | `cd /home/angel/Descargas && du -sh /home/angel/Descargas` |
| 99 | 12:58 | B3 | listar | `~/Descargas` | `cd /home/angel/Descargas && ls -la /home/angel/Descargas` |
| 100 | 12:59 | B3 | revisar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && grep -c 'informe' /home/angel/Documentos/informes/informe.txt` |
| 101 | 14:00 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && echo 'acta de reunion 1 del area (dia 1)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 102 | 14:01 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 103 | 14:11 | B4 | error | `~/Documentos` | `cd /home/angel/Documentos && cat /home/angel/Documentos/actas 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cat_dir 'cat /home/angel/Documentos/actas' $r >> /home/angel/Documentos/errores.log; }` |
| 104 | 14:11 | B4 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cat_dir 'cat /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 105 | 14:12 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 106 | 14:13 | B4 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && rsync -a --delete /home/angel/Documentos/informes/ /home/angel/Documentos/copias/informes/` |
| 107 | 14:14 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 108 | 14:22 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 109 | 14:31 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && ls -la /home/angel/Documentos/actas` |
| 110 | 14:32 | B4 | borrador | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'borrador previo del informe del area' > /home/angel/Documentos/informes/borrador_previo.txt` |
| 111 | 14:33 | B4 | borrador | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && shred -n 1 -z -u /home/angel/Documentos/informes/borrador_previo.txt` |
| 112 | 14:34 | B4 | error | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/ 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cp_dir 'cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/' $r >> /home/angel/Documentos/errores.log; }` |
| 113 | 14:35 | B4 | reintento | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cp_dir 'cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 114 | 14:36 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 115 | 14:56 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && wget -q -O /home/angel/Descargas/manual_empleado_wget.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 116 | 14:57 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_listado.txt -w '%{http_code}' http://nube.local:9092/nube/` |
| 117 | 14:58 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/informes/informe.txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/informes/` |
| 118 | 15:08 | B4 | error | `~/Documentos` | `cd /home/angel/Documentos && ls -la --clasificar /home/angel/Documentos 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error opcion 'ls -la --clasificar /home/angel/Documentos' $r >> /home/angel/Documentos/errores.log; }` |
| 119 | 15:14 | B4 | reintento | `~/Documentos` | `cd /home/angel/Documentos && ls -la --classify /home/angel/Documentos && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento opcion 'ls -la --classify /home/angel/Documentos' $r >> /home/angel/Documentos/errores.log; }` |
| 120 | 15:15 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_actas.txt -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 121 | 15:16 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 122 | 15:17 | B4 | red | `~/Descargas` | `cd /home/angel/Descargas && timeout 5 curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -o /home/angel/.cache/tfg-web/intranet_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 123 | 15:18 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/noticias_tarde.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 124 | 15:18 | B4 | informe | `~/Descargas` | `cd /home/angel/Descargas && tar -czf /home/angel/Descargas/informe_dia1.tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 125 | 15:34 | B4 | huella | `~/Descargas` | `cd /home/angel/Descargas && sha256sum /home/angel/Descargas/informe_dia1.tar.gz` |
| 126 | 15:35 | B4 | tamano | `~/Descargas` | `cd /home/angel/Descargas && du -sh /home/angel/Descargas/informe_dia1.tar.gz` |
| 127 | 15:43 | B4 | listar | `~/Descargas` | `cd /home/angel/Descargas && ls -la /home/angel/Descargas` |
| 128 | 15:55 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/plantilla_dia1.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 129 | 15:56 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/plantilla_dia1.csv` |
| 130 | 15:57 | B4 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -d /home/angel/Documentos/informes/informe.bak 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error gzip 'gzip -d /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 131 | 15:58 | B4 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento gzip 'gzip -kf /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 132 | 16:02 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && sha256sum /home/angel/Descargas/plantilla_dia1.csv` |
| 133 | 16:03 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/ayuda_tarde.html -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 134 | 16:13 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles_tarde.css -w '%{http_code}' http://intranet.local:8080/styles.css` |
| 135 | 16:14 | B4 | portal | `~/.cache/tfg-web` | `cd /home/angel/.cache/tfg-web && wc -l /home/angel/.cache/tfg-web/ayuda_tarde.html` |
| 136 | 16:15 | B5 | copia | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Documentos informes actas` |
| 137 | 16:15 | B5 | huella | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz` |
| 138 | 16:16 | B5 | huella | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256` |
| 139 | 16:17 | B5 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 140 | 16:27 | B5 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/copias_nube.txt -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 141 | 16:28 | B5 | tamano | `~/Documentos` | `cd /home/angel/Documentos && du -sh /home/angel/Documentos` |
| 142 | 16:37 | B5 | disco | `~` | `cd /home/angel && df -h /` |
| 143 | 16:38 | B5 | copia | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copia_final_1.tar.gz` |
| 144 | 16:38 | B5 | tamano | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/copia_final_1.tar.gz` |
| 145 | 16:46 | B5 | limpiar | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_*.csv` |
| 146 | 16:57 | B5 | cierre | `~` | `cd /home/angel && date -u +%FT%TZ` |
| 147 | 16:59 | B5 | cierre | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos /home/angel/Descargas` |
| 148 | 17:06:00 | B6/C-01 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-01 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-01/inicio.txt` |
| 149 | 17:06:08 | B6/C-01 | comando | `~/Documentos/campana_fp/C-01` | `cd /home/angel/Documentos/campana_fp/C-01 && free -m > /home/angel/Documentos/campana_fp/C-01/free.txt` |
| 150 | 17:06:14 | B6/C-01 | comando | `~/Documentos/campana_fp/C-01` | `cd /home/angel/Documentos/campana_fp/C-01 && systemctl --failed --no-pager > /home/angel/Documentos/campana_fp/C-01/fallidos.txt` |
| 151 | 17:06:24 | B6/C-01 | comando | `~/Documentos/campana_fp/C-01` | `cd /home/angel/Documentos/campana_fp/C-01 && systemctl list-units --type=service --state=running --no-pager > /home/angel/Documentos/campana_fp/C-01/servicios.txt` |
| 152 | 17:06:31 | B6/C-01 | evidencia | `~/Documentos/campana_fp/C-01` | `cd /home/angel/Documentos/campana_fp/C-01 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-01/hecho.txt && wc -l /home/angel/Documentos/campana_fp/C-01/servicios.txt /home/angel/Documentos/campana_fp/C-01/free.txt /home/angel/Documentos/campana_fp/C-01/fallidos.txt >> /home/angel/Documentos/campana_fp/C-01/hecho.txt && cat /home/angel/Documentos/campana_fp/C-01/hecho.txt` |
| 153 | 17:06:40 | B6/C-01 | fin | `~/Documentos/campana_fp/C-01` | `cd /home/angel/Documentos/campana_fp/C-01 && rm -f /home/angel/Documentos/campana_fp/C-01/servicios.txt /home/angel/Documentos/campana_fp/C-01/free.txt /home/angel/Documentos/campana_fp/C-01/fallidos.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-01/fin.txt` |
| 154 | 17:15:20 | B6/C-02 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-02 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-02/inicio.txt` |
| 155 | 17:15:27 | B6/C-02 | comando | `~/Documentos/campana_fp/C-02` | `cd /home/angel/Documentos/campana_fp/C-02 && ip -brief addr > /home/angel/Documentos/campana_fp/C-02/ip_addr.txt` |
| 156 | 17:15:36 | B6/C-02 | comando | `~/Documentos/campana_fp/C-02` | `cd /home/angel/Documentos/campana_fp/C-02 && ip route > /home/angel/Documentos/campana_fp/C-02/ip_route.txt` |
| 157 | 17:15:41 | B6/C-02 | evidencia | `~/Documentos/campana_fp/C-02` | `cd /home/angel/Documentos/campana_fp/C-02 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-02/hecho.txt && grep '192.168.65.' /home/angel/Documentos/campana_fp/C-02/ip_addr.txt >> /home/angel/Documentos/campana_fp/C-02/hecho.txt && cat /home/angel/Documentos/campana_fp/C-02/ip_route.txt >> /home/angel/Documentos/campana_fp/C-02/hecho.txt` |
| 158 | 17:15:49 | B6/C-02 | fin | `~/Documentos/campana_fp/C-02` | `cd /home/angel/Documentos/campana_fp/C-02 && rm -f /home/angel/Documentos/campana_fp/C-02/ip_addr.txt /home/angel/Documentos/campana_fp/C-02/ip_route.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-02/fin.txt` |
| 159 | 17:24:40 | B6/C-03 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-03 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-03/inicio.txt` |
| 160 | 17:24:48 | B6/C-03 | comando | `~/Documentos/campana_fp/C-03` | `cd /home/angel/Documentos/campana_fp/C-03 && systemctl list-timers --all --no-pager > /home/angel/Documentos/campana_fp/C-03/timers.txt` |
| 161 | 17:24:55 | B6/C-03 | comando | `~/Documentos/campana_fp/C-03` | `cd /home/angel/Documentos/campana_fp/C-03 && crontab -l > /home/angel/Documentos/campana_fp/C-03/crontab.txt 2>/dev/null || printf 'crontab_rc=%s\n' $? > /home/angel/Documentos/campana_fp/C-03/crontab_rc.txt` |
| 162 | 17:25:04 | B6/C-03 | evidencia | `~/Documentos/campana_fp/C-03` | `cd /home/angel/Documentos/campana_fp/C-03 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-03/hecho.txt && wc -l /home/angel/Documentos/campana_fp/C-03/timers.txt >> /home/angel/Documentos/campana_fp/C-03/hecho.txt && cat /home/angel/Documentos/campana_fp/C-03/crontab_rc.txt >> /home/angel/Documentos/campana_fp/C-03/hecho.txt` |
| 163 | 17:25:09 | B6/C-03 | fin | `~/Documentos/campana_fp/C-03` | `cd /home/angel/Documentos/campana_fp/C-03 && rm -f /home/angel/Documentos/campana_fp/C-03/timers.txt /home/angel/Documentos/campana_fp/C-03/crontab.txt /home/angel/Documentos/campana_fp/C-03/crontab_rc.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-03/fin.txt` |

## Día 2 — «reuniones y portal» (153 + 25 = 178 acciones)

| # | UTC | Bloque | Familia | cwd | Comando |
|---|---|---|---|---|---|
| 1 | 08:00 | B1 | estructura | `~` | `cd /home/angel && mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Documentos/copias /home/angel/Documentos/correo /home/angel/Descargas /home/angel/.cache/tfg-web` |
| 2 | 08:00 | B1 | llegada | `~/Documentos` | `cd /home/angel/Documentos && date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 3 | 08:01 | B1 | listar | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos` |
| 4 | 08:02 | B1 | agenda | `~/Documentos` | `cd /home/angel/Documentos && echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | 08:04 | B1 | error | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos/informe 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error ruta_mal 'ls -la /home/angel/Documentos/informe' $r >> /home/angel/Documentos/errores.log; }` |
| 6 | 08:05 | B1 | reintento | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos/informes && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento ruta_mal 'ls -la /home/angel/Documentos/informes' $r >> /home/angel/Documentos/errores.log; }` |
| 7 | 08:06 | B1 | agenda | `~/Documentos` | `cd /home/angel/Documentos && cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 8 | 08:07 | B1 | web-sesion | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| 9 | 08:08 | B1 | web-requisitos | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles.css -w '%{http_code}' http://intranet.local:8080/styles.css && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal.js -w '%{http_code}' http://intranet.local:8080/portal.js && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/logo.svg -w '%{http_code}' http://intranet.local:8080/assets/logo.svg` |
| 10 | 08:10 | B1 | web-huella | `~/.cache/tfg-web` | `cd /home/angel/.cache/tfg-web && wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles.css` |
| 11 | 08:11 | B1 | correo | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 're: confirmacion de la reunion de area' > /home/angel/Documentos/correo/borrador_1.txt` |
| 12 | 08:12 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r1' -o /home/angel/.cache/tfg-web/buzon_1.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 13 | 08:12 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_1.txt` |
| 14 | 08:16 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_1.txt` |
| 15 | 08:17 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r2' -o /home/angel/.cache/tfg-web/buzon_2.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 16 | 08:17 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_2.txt` |
| 17 | 08:18 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_2.txt` |
| 18 | 08:23 | B2 | red | `~` | `cd /home/angel && ip -brief addr` |
| 19 | 08:37 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r3' -o /home/angel/.cache/tfg-web/buzon_3.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 20 | 08:37 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_3.txt` |
| 21 | 08:38 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_3.txt` |
| 22 | 08:44 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r4' -o /home/angel/.cache/tfg-web/buzon_4.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 23 | 08:45 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 4: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_4.txt` |
| 24 | 08:53 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_4.txt` |
| 25 | 08:54 | B2 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 26 | 08:54 | B2 | renombrar | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1.txt` |
| 27 | 08:55 | B2 | contar | `~/Documentos` | `cd /home/angel/Documentos && find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt` |
| 28 | 08:56 | B2 | listar | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && ls -la /home/angel/Documentos/correo` |
| 29 | 08:59 | B2 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 30 | 09:11 | B2 | leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/enviado_1.txt` |
| 31 | 09:12 | B2 | error | `~` | `cd /home/angel && df -h --max-depth=1 / 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error opcion 'df -h --max-depth=1 /' $r >> /home/angel/Documentos/errores.log; }` |
| 32 | 09:16 | B2 | reintento | `~` | `cd /home/angel && df -h / && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento opcion 'df -h /' $r >> /home/angel/Documentos/errores.log; }` |
| 33 | 09:17 | B2 | tamano | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && du -sh /home/angel/Documentos/correo` |
| 34 | 09:18 | B2 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Descargas/informe_copia_2.txt` |
| 35 | 09:18 | B2 | limpiar | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_borradores.csv` |
| 36 | 09:22 | B2 | agenda | `~/Documentos` | `cd /home/angel/Documentos && echo 'revisado el buzon de la manana' >> /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 37 | 09:31 | B2 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && md5sum /home/angel/Documentos/informes/informe.bak` |
| 38 | 09:33 | B2 | listar | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos` |
| 39 | 09:33 | B2 | informe | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'informe del area - jornada 2' > /home/angel/Documentos/informes/informe.txt` |
| 40 | 09:38 | B2 | adjunto | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tar -czf /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 41 | 09:39 | B2 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cp_dir 'cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 42 | 09:42 | B2 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cp_dir 'cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 43 | 09:43 | B2 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 44 | 09:44 | B2 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe_2026.txt 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error ruta_mal 'stat /home/angel/Documentos/informes/informe_2026.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 45 | 09:44 | B2 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento ruta_mal 'stat /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 46 | 09:45 | B2 | tamano | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && du -sh /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 47 | 09:46 | B2 | listar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && ls -la /home/angel/Documentos/informes` |
| 48 | 09:54 | B2 | adjunto | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tar -czf /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 49 | 09:57 | B2 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 50 | 09:59 | B2 | tamano | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && du -sh /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 51 | 10:20 | B3 | web-navegar | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/index.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/noticias.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 52 | 10:20 | B3 | web-navegar | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 53 | 10:21 | B3 | web-descarga | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/plantilla_informe.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 54 | 10:25 | B3 | web-pdf | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/manual_empleado.pdf -w '%{http_code}' http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 55 | 10:26 | B3 | web-huella | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/manual_empleado.pdf && sha256sum /home/angel/Descargas/manual_empleado.pdf` |
| 56 | 10:34 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'referencia;area;importe' > /home/angel/Documentos/informes/export.csv` |
| 57 | 10:35 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sed -i 's/;/,/g' /home/angel/Documentos/informes/export.csv` |
| 58 | 10:35 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sed -n '1,5p' /home/angel/Documentos/informes/export.csv` |
| 59 | 10:36 | B3 | comprimir | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 60 | 10:37 | B3 | huella | `~/Descargas` | `cd /home/angel/Descargas && openssl dgst -sha256 /home/angel/Descargas/manual_empleado.pdf` |
| 61 | 10:38 | B3 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && md5sum /home/angel/Documentos/informes/informe.txt.gz` |
| 62 | 10:43 | B3 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/informe.txt.gz` |
| 63 | 10:50 | B3 | lotes | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && seq 1 12 > /home/angel/.cache/tfg-web/lotes.txt` |
| 64 | 10:51 | B3 | lotes | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && xargs -a /home/angel/.cache/tfg-web/lotes.txt -I{} cp /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/lote_{}.txt` |
| 65 | 10:52 | B3 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -d /home/angel/Documentos/informes/informe.txt 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error gzip 'gzip -d /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 66 | 10:56 | B3 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento gzip 'gzip -kf /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 67 | 10:57 | B3 | listar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && ls -la /home/angel/Documentos/informes` |
| 68 | 11:07 | B3 | tamano | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && du -sh /home/angel/Documentos/informes` |
| 69 | 11:08 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt.gz` |
| 70 | 11:09 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '1. alcance del informe (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 71 | 11:10 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 72 | 11:13 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 73 | 11:18 | B3 | estado | `~` | `cd /home/angel && free -m` |
| 74 | 11:19 | B3 | registro | `~` | `cd /home/angel && logger -t ofimatica 'repaso del informe del area'` |
| 75 | 11:20 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '2. actividades del area (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 76 | 11:21 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 77 | 11:22 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 78 | 11:43 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '3. incidencias de la semana (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 79 | 11:43 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 80 | 11:59 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 81 | 12:00 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '4. indicadores del mes (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 82 | 12:00 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 83 | 12:04 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 84 | 12:23 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '5. riesgos identificados (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 85 | 12:24 | B3 | error | `~/Descargas` | `cd /home/angel/Descargas && rm /home/angel/Descargas/tmp_borradores.csv 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error rm_inexistente 'rm /home/angel/Descargas/tmp_borradores.csv' $r >> /home/angel/Documentos/errores.log; }` |
| 86 | 12:24 | B3 | reintento | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_borradores.csv && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento rm_inexistente 'rm -f /home/angel/Descargas/tmp_borradores.csv' $r >> /home/angel/Documentos/errores.log; }` |
| 87 | 12:25 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 88 | 12:33 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 89 | 12:33 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '6. plan de accion (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 90 | 12:44 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 91 | 12:45 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 92 | 12:46 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '7. conclusiones (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 93 | 12:47 | B3 | bitacora | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'pendiente: firmar el acta de la reunion' > /home/angel/Documentos/informes/nota.txt` |
| 94 | 12:47 | B3 | bitacora | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tee -a /home/angel/Documentos/informes/bitacora.txt < /home/angel/Documentos/informes/nota.txt` |
| 95 | 12:48 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 96 | 12:54 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 97 | 12:58 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '8. anexo de datos (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 98 | 12:59 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 99 | 14:00 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && echo 'acta de reunion 1 del area (dia 2)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 100 | 14:00 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 101 | 14:10 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 102 | 14:11 | B4 | error | `~/Documentos` | `cd /home/angel/Documentos && cat /home/angel/Documentos/actas 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cat_dir 'cat /home/angel/Documentos/actas' $r >> /home/angel/Documentos/errores.log; }` |
| 103 | 14:12 | B4 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cat_dir 'cat /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 104 | 14:13 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 105 | 14:18 | B4 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && rsync -a --delete /home/angel/Documentos/informes/ /home/angel/Documentos/copias/informes/` |
| 106 | 14:19 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 107 | 14:20 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && ls -la /home/angel/Documentos/actas` |
| 108 | 14:28 | B4 | borrador | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'borrador previo del informe del area' > /home/angel/Documentos/informes/borrador_previo.txt` |
| 109 | 14:31 | B4 | borrador | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && shred -n 1 -z -u /home/angel/Documentos/informes/borrador_previo.txt` |
| 110 | 14:32 | B4 | error | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/ 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cp_dir 'cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/' $r >> /home/angel/Documentos/errores.log; }` |
| 111 | 14:33 | B4 | reintento | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cp_dir 'cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 112 | 14:33 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && echo 'acta de reunion 1 del area (dia 2)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 113 | 14:34 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 114 | 14:35 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 115 | 14:41 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 116 | 14:42 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && wget -q -O /home/angel/Descargas/manual_empleado_wget.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 117 | 15:03 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 118 | 15:12 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && ls -la /home/angel/Documentos/actas` |
| 119 | 15:13 | B4 | error | `~/Documentos` | `cd /home/angel/Documentos && ls -la --clasificar /home/angel/Documentos 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error opcion 'ls -la --clasificar /home/angel/Documentos' $r >> /home/angel/Documentos/errores.log; }` |
| 120 | 15:14 | B4 | reintento | `~/Documentos` | `cd /home/angel/Documentos && ls -la --classify /home/angel/Documentos && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento opcion 'ls -la --classify /home/angel/Documentos' $r >> /home/angel/Documentos/errores.log; }` |
| 121 | 15:15 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && echo 'acta de reunion 2 del area (dia 2)' > /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt` |
| 122 | 15:22 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cat /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt` |
| 123 | 15:23 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && wc -c /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt` |
| 124 | 15:26 | B4 | red | `~/Descargas` | `cd /home/angel/Descargas && timeout 5 curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -o /home/angel/.cache/tfg-web/intranet_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 125 | 15:27 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_2.txt` |
| 126 | 15:28 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && sha256sum /home/angel/Documentos/actas/compartida_2.txt` |
| 127 | 15:37 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && ls -la /home/angel/Documentos/actas` |
| 128 | 15:39 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 129 | 15:40 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_listado.txt -w '%{http_code}' http://nube.local:9092/nube/` |
| 130 | 15:41 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/informes/informe.txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/informes/` |
| 131 | 15:42 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_actas.txt -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 132 | 15:42 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 133 | 15:49 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/noticias_tarde.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 134 | 15:50 | B4 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -d /home/angel/Documentos/informes/informe.bak 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error gzip 'gzip -d /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 135 | 15:55 | B4 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento gzip 'gzip -kf /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 136 | 15:56 | B4 | informe | `~/Descargas` | `cd /home/angel/Descargas && tar -czf /home/angel/Descargas/informe_dia2.tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 137 | 15:57 | B4 | huella | `~/Descargas` | `cd /home/angel/Descargas && sha256sum /home/angel/Descargas/informe_dia2.tar.gz` |
| 138 | 16:02 | B4 | tamano | `~/Descargas` | `cd /home/angel/Descargas && du -sh /home/angel/Descargas/informe_dia2.tar.gz` |
| 139 | 16:04 | B4 | listar | `~/Descargas` | `cd /home/angel/Descargas && ls -la /home/angel/Descargas` |
| 140 | 16:05 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/plantilla_dia2.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 141 | 16:14 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/plantilla_dia2.csv` |
| 142 | 16:15 | B5 | copia | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Documentos informes actas` |
| 143 | 16:23 | B5 | huella | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz` |
| 144 | 16:24 | B5 | huella | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256` |
| 145 | 16:25 | B5 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 146 | 16:26 | B5 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/copias_nube.txt -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 147 | 16:33 | B5 | tamano | `~/Documentos` | `cd /home/angel/Documentos && du -sh /home/angel/Documentos` |
| 148 | 16:34 | B5 | disco | `~` | `cd /home/angel && df -h /` |
| 149 | 16:40 | B5 | copia | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copia_final_2.tar.gz` |
| 150 | 16:41 | B5 | tamano | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/copia_final_2.tar.gz` |
| 151 | 16:42 | B5 | limpiar | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_*.csv` |
| 152 | 16:52 | B5 | cierre | `~` | `cd /home/angel && date -u +%FT%TZ` |
| 153 | 16:59 | B5 | cierre | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos /home/angel/Descargas` |
| 154 | 17:17:00 | B6/C-05 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-05 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-05/inicio.txt` |
| 155 | 17:17:08 | B6/C-05 | comando | `~/Documentos/campana_fp/C-05` | `cd /home/angel/Documentos/campana_fp/C-05 && echo 'informe del area: datos de cliente, importe 1200' > /home/angel/Documentos/campana_fp/C-05/informe.txt` |
| 156 | 17:17:14 | B6/C-05 | comando | `~/Documentos/campana_fp/C-05` | `cd /home/angel/Documentos/campana_fp/C-05 && openssl enc -aes-256-cbc -pbkdf2 -salt -in /home/angel/Documentos/campana_fp/C-05/informe.txt -out /home/angel/Documentos/campana_fp/C-05/informe.txt.enc -pass pass:demo-c05` |
| 157 | 17:17:24 | B6/C-05 | comando | `~/Documentos/campana_fp/C-05` | `cd /home/angel/Documentos/campana_fp/C-05 && openssl enc -d -aes-256-cbc -pbkdf2 -in /home/angel/Documentos/campana_fp/C-05/informe.txt.enc -out /home/angel/Documentos/campana_fp/C-05/informe.txt.rec -pass pass:demo-c05` |
| 158 | 17:17:31 | B6/C-05 | comando | `~/Documentos/campana_fp/C-05` | `cd /home/angel/Documentos/campana_fp/C-05 && sha256sum /home/angel/Documentos/campana_fp/C-05/informe.txt /home/angel/Documentos/campana_fp/C-05/informe.txt.rec > /home/angel/Documentos/campana_fp/C-05/huellas.txt` |
| 159 | 17:17:40 | B6/C-05 | evidencia | `~/Documentos/campana_fp/C-05` | `cd /home/angel/Documentos/campana_fp/C-05 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-05/hecho.txt && cat /home/angel/Documentos/campana_fp/C-05/huellas.txt >> /home/angel/Documentos/campana_fp/C-05/hecho.txt` |
| 160 | 17:17:45 | B6/C-05 | fin | `~/Documentos/campana_fp/C-05` | `cd /home/angel/Documentos/campana_fp/C-05 && rm -f /home/angel/Documentos/campana_fp/C-05/informe.txt /home/angel/Documentos/campana_fp/C-05/informe.txt.enc /home/angel/Documentos/campana_fp/C-05/informe.txt.rec /home/angel/Documentos/campana_fp/C-05/huellas.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-05/fin.txt` |
| 161 | 17:25:30 | B6/C-06 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-06 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-06/inicio.txt` |
| 162 | 17:25:37 | B6/C-06 | comando | `~/Documentos/campana_fp/C-06` | `cd /home/angel/Documentos/campana_fp/C-06 && mkdir -p /home/angel/Documentos/campana_fp/C-06/tmp && echo 'temporal del dia' > /home/angel/Documentos/campana_fp/C-06/tmp/borrador_tmp.txt && echo 'borrador con datos personales' > /home/angel/Documentos/campana_fp/C-06/borrador.txt` |
| 163 | 17:25:46 | B6/C-06 | comando | `~/Documentos/campana_fp/C-06` | `cd /home/angel/Documentos/campana_fp/C-06 && stat -c %s /home/angel/Documentos/campana_fp/C-06/borrador.txt > /home/angel/Documentos/campana_fp/C-06/antes.txt` |
| 164 | 17:25:51 | B6/C-06 | comando | `~/Documentos/campana_fp/C-06` | `cd /home/angel/Documentos/campana_fp/C-06 && rm -rf /home/angel/Documentos/campana_fp/C-06/tmp` |
| 165 | 17:25:59 | B6/C-06 | comando | `~/Documentos/campana_fp/C-06` | `cd /home/angel/Documentos/campana_fp/C-06 && shred -n 1 -z -u /home/angel/Documentos/campana_fp/C-06/borrador.txt` |
| 166 | 17:26:06 | B6/C-06 | evidencia | `~/Documentos/campana_fp/C-06` | `cd /home/angel/Documentos/campana_fp/C-06 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-06/hecho.txt && cat /home/angel/Documentos/campana_fp/C-06/antes.txt >> /home/angel/Documentos/campana_fp/C-06/hecho.txt && stat -c %s /home/angel/Documentos/campana_fp/C-06/borrador.txt 2>/dev/null || echo 'borrador_ausente=1' >> /home/angel/Documentos/campana_fp/C-06/hecho.txt` |
| 167 | 17:26:15 | B6/C-06 | fin | `~/Documentos/campana_fp/C-06` | `cd /home/angel/Documentos/campana_fp/C-06 && rm -f /home/angel/Documentos/campana_fp/C-06/antes.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-06/fin.txt` |
| 168 | 17:33:10 | B6/C-07 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-07 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-07/inicio.txt` |
| 169 | 17:33:18 | B6/C-07 | comando | `~/Documentos/campana_fp/C-07` | `cd /home/angel/Documentos/campana_fp/C-07 && mkdir -p /home/angel/Documentos/campana_fp/C-07/origen /home/angel/Documentos/campana_fp/C-07/destino && echo 'informe uno' > /home/angel/Documentos/campana_fp/C-07/origen/informe_1.txt && echo 'informe dos' > /home/angel/Documentos/campana_fp/C-07/origen/informe_2.txt && echo 'copia obsoleta' > /home/angel/Documentos/campana_fp/C-07/destino/obsoleto.txt` |
| 170 | 17:33:25 | B6/C-07 | comando | `~/Documentos/campana_fp/C-07` | `cd /home/angel/Documentos/campana_fp/C-07 && rsync -a --delete /home/angel/Documentos/campana_fp/C-07/origen/ /home/angel/Documentos/campana_fp/C-07/destino/` |
| 171 | 17:33:34 | B6/C-07 | evidencia | `~/Documentos/campana_fp/C-07` | `cd /home/angel/Documentos/campana_fp/C-07 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-07/hecho.txt && du -sb /home/angel/Documentos/campana_fp/C-07/origen /home/angel/Documentos/campana_fp/C-07/destino >> /home/angel/Documentos/campana_fp/C-07/hecho.txt && ls -la /home/angel/Documentos/campana_fp/C-07/destino >> /home/angel/Documentos/campana_fp/C-07/hecho.txt` |
| 172 | 17:33:39 | B6/C-07 | fin | `~/Documentos/campana_fp/C-07` | `cd /home/angel/Documentos/campana_fp/C-07 && rm -rf /home/angel/Documentos/campana_fp/C-07/origen /home/angel/Documentos/campana_fp/C-07/destino && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-07/fin.txt` |
| 173 | 17:41:20 | B6/C-08 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-08 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-08/inicio.txt` |
| 174 | 17:41:25 | B6/C-08 | comando | `~/Documentos/campana_fp/C-08` | `cd /home/angel/Documentos/campana_fp/C-08 && echo 'referencia;area;importe' > /home/angel/Documentos/campana_fp/C-08/export.csv && echo 'A-01;compras;1200' >> /home/angel/Documentos/campana_fp/C-08/export.csv && echo 'A-02;ventas;980' >> /home/angel/Documentos/campana_fp/C-08/export.csv` |
| 175 | 17:41:33 | B6/C-08 | comando | `~/Documentos/campana_fp/C-08` | `cd /home/angel/Documentos/campana_fp/C-08 && sed -i 's/;/,/g' /home/angel/Documentos/campana_fp/C-08/export.csv` |
| 176 | 17:41:39 | B6/C-08 | comando | `~/Documentos/campana_fp/C-08` | `cd /home/angel/Documentos/campana_fp/C-08 && sed -n '1,5p' /home/angel/Documentos/campana_fp/C-08/export.csv > /home/angel/Documentos/campana_fp/C-08/export_normalizado.txt` |
| 177 | 17:41:49 | B6/C-08 | evidencia | `~/Documentos/campana_fp/C-08` | `cd /home/angel/Documentos/campana_fp/C-08 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-08/hecho.txt && head -1 /home/angel/Documentos/campana_fp/C-08/export.csv >> /home/angel/Documentos/campana_fp/C-08/hecho.txt && grep -c ';' /home/angel/Documentos/campana_fp/C-08/export.csv >> /home/angel/Documentos/campana_fp/C-08/hecho.txt || true` |
| 178 | 17:41:56 | B6/C-08 | fin | `~/Documentos/campana_fp/C-08` | `cd /home/angel/Documentos/campana_fp/C-08 && rm -f /home/angel/Documentos/campana_fp/C-08/export.csv /home/angel/Documentos/campana_fp/C-08/export_normalizado.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-08/fin.txt` |

## Día 3 — «revisión y copias» (141 + 22 = 163 acciones)

| # | UTC | Bloque | Familia | cwd | Comando |
|---|---|---|---|---|---|
| 1 | 08:00 | B1 | estructura | `~` | `cd /home/angel && mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Documentos/copias /home/angel/Documentos/correo /home/angel/Descargas /home/angel/.cache/tfg-web` |
| 2 | 08:00 | B1 | llegada | `~/Documentos` | `cd /home/angel/Documentos && date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 3 | 08:02 | B1 | listar | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos` |
| 4 | 08:03 | B1 | agenda | `~/Documentos` | `cd /home/angel/Documentos && echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | 08:04 | B1 | error | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos/informe 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error ruta_mal 'ls -la /home/angel/Documentos/informe' $r >> /home/angel/Documentos/errores.log; }` |
| 6 | 08:04 | B1 | reintento | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos/informes && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento ruta_mal 'ls -la /home/angel/Documentos/informes' $r >> /home/angel/Documentos/errores.log; }` |
| 7 | 08:06 | B1 | agenda | `~/Documentos` | `cd /home/angel/Documentos && cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 8 | 08:07 | B1 | web-sesion | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| 9 | 08:09 | B1 | web-requisitos | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles.css -w '%{http_code}' http://intranet.local:8080/styles.css && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal.js -w '%{http_code}' http://intranet.local:8080/portal.js && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/logo.svg -w '%{http_code}' http://intranet.local:8080/assets/logo.svg` |
| 10 | 08:10 | B1 | web-huella | `~/.cache/tfg-web` | `cd /home/angel/.cache/tfg-web && wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles.css` |
| 11 | 08:11 | B1 | correo | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 're: revision de las copias de seguridad' > /home/angel/Documentos/correo/borrador_1.txt` |
| 12 | 08:12 | B2 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 13 | 08:12 | B2 | renombrar | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1.txt` |
| 14 | 08:13 | B2 | contar | `~/Documentos` | `cd /home/angel/Documentos && find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt` |
| 15 | 08:21 | B2 | listar | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && ls -la /home/angel/Documentos/correo` |
| 16 | 08:22 | B2 | red | `~` | `cd /home/angel && ip -brief addr` |
| 17 | 08:28 | B2 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 18 | 08:29 | B2 | leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/enviado_1.txt` |
| 19 | 08:30 | B2 | tamano | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && du -sh /home/angel/Documentos/correo` |
| 20 | 08:31 | B2 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Descargas/informe_copia_3.txt` |
| 21 | 08:32 | B2 | limpiar | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_borradores.csv` |
| 22 | 08:48 | B2 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cp_dir 'cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes_2026/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 23 | 08:57 | B2 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cp_dir 'cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 24 | 08:58 | B2 | agenda | `~/Documentos` | `cd /home/angel/Documentos && echo 'revisado el buzon de la manana' >> /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 25 | 09:03 | B2 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && md5sum /home/angel/Documentos/informes/informe.bak` |
| 26 | 09:04 | B2 | listar | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos` |
| 27 | 09:05 | B2 | error | `~` | `cd /home/angel && df -h --max-depth=1 / 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error opcion 'df -h --max-depth=1 /' $r >> /home/angel/Documentos/errores.log; }` |
| 28 | 09:06 | B2 | reintento | `~` | `cd /home/angel && df -h / && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento opcion 'df -h /' $r >> /home/angel/Documentos/errores.log; }` |
| 29 | 09:19 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r1' -o /home/angel/.cache/tfg-web/buzon_1.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 30 | 09:26 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_1.txt` |
| 31 | 09:27 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_1.txt` |
| 32 | 09:28 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r2' -o /home/angel/.cache/tfg-web/buzon_2.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 33 | 09:46 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_2.txt` |
| 34 | 09:47 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_2.txt` |
| 35 | 09:54 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r3' -o /home/angel/.cache/tfg-web/buzon_3.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 36 | 09:55 | B2 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe_2026.txt 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error ruta_mal 'stat /home/angel/Documentos/informes/informe_2026.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 37 | 09:56 | B2 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento ruta_mal 'stat /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 38 | 09:57 | B2 | correo-escribir | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_3.txt` |
| 39 | 09:57 | B2 | correo-leer | `~/Documentos/correo` | `cd /home/angel/Documentos/correo && cat /home/angel/Documentos/correo/borrador_3.txt` |
| 40 | 09:59 | B2 | correo-buzon | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r4' -o /home/angel/.cache/tfg-web/buzon_4.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 41 | 10:20 | B3 | web-navegar | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/index.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/noticias.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 42 | 10:23 | B3 | web-navegar | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 43 | 10:24 | B3 | web-descarga | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/plantilla_informe.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 44 | 10:25 | B3 | web-pdf | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/manual_empleado.pdf -w '%{http_code}' http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 45 | 10:30 | B3 | web-huella | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/manual_empleado.pdf && sha256sum /home/angel/Descargas/manual_empleado.pdf` |
| 46 | 10:31 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'referencia;area;importe' > /home/angel/Documentos/informes/export.csv` |
| 47 | 10:41 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sed -i 's/;/,/g' /home/angel/Documentos/informes/export.csv` |
| 48 | 10:42 | B3 | csv | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sed -n '1,5p' /home/angel/Documentos/informes/export.csv` |
| 49 | 10:43 | B3 | revisar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && grep -c 'informe' /home/angel/Documentos/informes/informe.txt` |
| 50 | 10:44 | B3 | huella | `~/Descargas` | `cd /home/angel/Descargas && openssl dgst -sha256 /home/angel/Descargas/manual_empleado.pdf` |
| 51 | 10:46 | B3 | revisar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && head -n 5 /home/angel/Documentos/informes/informe.txt` |
| 52 | 10:58 | B3 | revisar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tail -n 5 /home/angel/Documentos/informes/informe.txt` |
| 53 | 10:59 | B3 | revisar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 54 | 11:00 | B3 | listar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && ls -la /home/angel/Documentos/informes` |
| 55 | 11:01 | B3 | disco | `~` | `cd /home/angel && df -h /` |
| 56 | 11:02 | B3 | estado | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && stat /home/angel/Documentos/informes/informe.txt` |
| 57 | 11:06 | B3 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -d /home/angel/Documentos/informes/informe.txt 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error gzip 'gzip -d /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 58 | 11:07 | B3 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento gzip 'gzip -kf /home/angel/Documentos/informes/informe.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 59 | 11:14 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.bak` |
| 60 | 11:15 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '1. alcance del informe (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 61 | 11:16 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 62 | 11:19 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 63 | 11:22 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '2. actividades del area (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 64 | 11:23 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 65 | 11:23 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 66 | 11:24 | B3 | estado | `~` | `cd /home/angel && free -m` |
| 67 | 11:33 | B3 | registro | `~` | `cd /home/angel && logger -t ofimatica 'repaso del informe del area'` |
| 68 | 11:34 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '3. incidencias de la semana (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 69 | 11:54 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 70 | 11:55 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 71 | 11:56 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '4. indicadores del mes (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 72 | 11:57 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 73 | 11:58 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 74 | 11:59 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '5. riesgos identificados (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 75 | 12:02 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 76 | 12:13 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 77 | 12:14 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '6. plan de accion (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 78 | 12:15 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 79 | 12:18 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 80 | 12:19 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '7. conclusiones (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 81 | 12:25 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 82 | 12:25 | B3 | error | `~/Descargas` | `cd /home/angel/Descargas && rm /home/angel/Descargas/tmp_borradores.csv 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error rm_inexistente 'rm /home/angel/Descargas/tmp_borradores.csv' $r >> /home/angel/Documentos/errores.log; }` |
| 83 | 12:26 | B3 | reintento | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_borradores.csv && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento rm_inexistente 'rm -f /home/angel/Descargas/tmp_borradores.csv' $r >> /home/angel/Documentos/errores.log; }` |
| 84 | 12:27 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 85 | 12:29 | B3 | redactar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo '8. anexo de datos (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 86 | 12:30 | B3 | leer | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.txt` |
| 87 | 12:35 | B3 | contar | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && wc -l /home/angel/Documentos/informes/informe.txt` |
| 88 | 12:36 | B3 | consolidar | `~/Descargas` | `cd /home/angel/Descargas && tar -czf /home/angel/Descargas/informes.tar.gz -C /home/angel/Documentos informes` |
| 89 | 12:37 | B3 | copia | `~/Descargas` | `cd /home/angel/Descargas && cp -f /home/angel/Descargas/informes.tar.gz /home/angel/Descargas/informes_copia_3.tar.gz` |
| 90 | 12:37 | B3 | huella | `~/Descargas` | `cd /home/angel/Descargas && sha256sum /home/angel/Descargas/informes.tar.gz` |
| 91 | 12:44 | B3 | contar | `~/Documentos` | `cd /home/angel/Documentos && find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros_d3.txt` |
| 92 | 12:47 | B3 | tamano | `~/Descargas` | `cd /home/angel/Descargas && du -sh /home/angel/Descargas` |
| 93 | 12:48 | B3 | bitacora | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'pendiente: firmar el acta de la reunion' > /home/angel/Documentos/informes/nota.txt` |
| 94 | 12:49 | B3 | bitacora | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && tee -a /home/angel/Documentos/informes/bitacora.txt < /home/angel/Documentos/informes/nota.txt` |
| 95 | 12:53 | B3 | listar | `~/Descargas` | `cd /home/angel/Descargas && ls -la /home/angel/Descargas` |
| 96 | 12:54 | B3 | comprimir | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 97 | 12:54 | B3 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && md5sum /home/angel/Documentos/informes/informe.txt.gz` |
| 98 | 12:55 | B3 | huella | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && sha256sum /home/angel/Documentos/informes/informe.txt.gz` |
| 99 | 12:56 | B3 | lotes | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && seq 1 12 > /home/angel/.cache/tfg-web/lotes.txt` |
| 100 | 12:59 | B3 | lotes | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && xargs -a /home/angel/.cache/tfg-web/lotes.txt -I{} cp /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/lote_{}.txt` |
| 101 | 14:00 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && echo 'acta de reunion 1 del area (dia 3)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 102 | 14:13 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 103 | 14:14 | B4 | copia | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && rsync -a --delete /home/angel/Documentos/informes/ /home/angel/Documentos/copias/informes/` |
| 104 | 14:14 | B4 | error | `~/Documentos` | `cd /home/angel/Documentos && cat /home/angel/Documentos/actas 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cat_dir 'cat /home/angel/Documentos/actas' $r >> /home/angel/Documentos/errores.log; }` |
| 105 | 14:15 | B4 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && cat /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cat_dir 'cat /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 106 | 14:16 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 107 | 14:17 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 108 | 14:23 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 109 | 14:24 | B4 | descarga | `~/Descargas` | `cd /home/angel/Descargas && wget -q -O /home/angel/Descargas/manual_empleado_wget.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 110 | 14:40 | B4 | acta | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && ls -la /home/angel/Documentos/actas` |
| 111 | 15:00 | B4 | borrador | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && echo 'borrador previo del informe del area' > /home/angel/Documentos/informes/borrador_previo.txt` |
| 112 | 15:01 | B4 | borrador | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && shred -n 1 -z -u /home/angel/Documentos/informes/borrador_previo.txt` |
| 113 | 15:02 | B4 | error | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/ 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error cp_dir 'cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/compartidas/' $r >> /home/angel/Documentos/errores.log; }` |
| 114 | 15:02 | B4 | reintento | `~/Documentos/actas` | `cd /home/angel/Documentos/actas && cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento cp_dir 'cp -f /home/angel/Documentos/actas/compartida_1.txt /home/angel/Documentos/actas/compartida_copia.txt' $r >> /home/angel/Documentos/errores.log; }` |
| 115 | 15:15 | B4 | error | `~/Documentos` | `cd /home/angel/Documentos && ls -la --clasificar /home/angel/Documentos 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error opcion 'ls -la --clasificar /home/angel/Documentos' $r >> /home/angel/Documentos/errores.log; }` |
| 116 | 15:15 | B4 | reintento | `~/Documentos` | `cd /home/angel/Documentos && ls -la --classify /home/angel/Documentos && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento opcion 'ls -la --classify /home/angel/Documentos' $r >> /home/angel/Documentos/errores.log; }` |
| 117 | 15:25 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 118 | 15:26 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_listado.txt -w '%{http_code}' http://nube.local:9092/nube/` |
| 119 | 15:26 | B4 | red | `~/Descargas` | `cd /home/angel/Descargas && timeout 5 curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -o /home/angel/.cache/tfg-web/intranet_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 120 | 15:37 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/informes/informe.txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/informes/` |
| 121 | 15:40 | B4 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_actas.txt -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 122 | 15:40 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 123 | 15:41 | B4 | portal | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/noticias_tarde.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 124 | 15:42 | B4 | informe | `~/Descargas` | `cd /home/angel/Descargas && tar -czf /home/angel/Descargas/informe_dia3.tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 125 | 15:43 | B4 | error | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -d /home/angel/Documentos/informes/informe.bak 2>/dev/null || { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) error gzip 'gzip -d /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 126 | 15:59 | B4 | reintento | `~/Documentos/informes` | `cd /home/angel/Documentos/informes && gzip -kf /home/angel/Documentos/informes/informe.bak && { r=$?; printf '%s\t%s\t%s\t%s\trc=%s\n' $(date -u +%FT%TZ) reintento gzip 'gzip -kf /home/angel/Documentos/informes/informe.bak' $r >> /home/angel/Documentos/errores.log; }` |
| 127 | 16:00 | B4 | huella | `~/Descargas` | `cd /home/angel/Descargas && sha256sum /home/angel/Descargas/informe_dia3.tar.gz` |
| 128 | 16:13 | B4 | tamano | `~/Descargas` | `cd /home/angel/Descargas && du -sh /home/angel/Descargas/informe_dia3.tar.gz` |
| 129 | 16:14 | B4 | listar | `~/Descargas` | `cd /home/angel/Descargas && ls -la /home/angel/Descargas` |
| 130 | 16:15 | B5 | copia | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Documentos informes actas` |
| 131 | 16:15 | B5 | huella | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz` |
| 132 | 16:16 | B5 | huella | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256` |
| 133 | 16:26 | B5 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 134 | 16:35 | B5 | nube | `~/Descargas` | `cd /home/angel/Descargas && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/copias_nube.txt -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 135 | 16:36 | B5 | tamano | `~/Documentos` | `cd /home/angel/Documentos && du -sh /home/angel/Documentos` |
| 136 | 16:37 | B5 | disco | `~` | `cd /home/angel && df -h /` |
| 137 | 16:38 | B5 | copia | `~/Documentos/copias` | `cd /home/angel/Documentos/copias && cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copia_final_3.tar.gz` |
| 138 | 16:45 | B5 | tamano | `~/Descargas` | `cd /home/angel/Descargas && wc -c /home/angel/Descargas/copia_final_3.tar.gz` |
| 139 | 16:46 | B5 | limpiar | `~/Descargas` | `cd /home/angel/Descargas && rm -f /home/angel/Descargas/tmp_*.csv` |
| 140 | 16:58 | B5 | cierre | `~` | `cd /home/angel && date -u +%FT%TZ` |
| 141 | 16:59 | B5 | cierre | `~/Documentos` | `cd /home/angel/Documentos && ls -la /home/angel/Documentos /home/angel/Descargas` |
| 142 | 17:11:00 | B6/C-09 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-09 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-09/inicio.txt` |
| 143 | 17:11:08 | B6/C-09 | comando | `~/Documentos/campana_fp/C-09` | `cd /home/angel/Documentos/campana_fp/C-09 && curl -sS --max-time 3 -o /home/angel/Documentos/campana_fp/C-09/intranet.html -w '%{http_code}\n' http://intranet.local:8080/ > /home/angel/Documentos/campana_fp/C-09/http_code.txt` |
| 144 | 17:11:14 | B6/C-09 | comando | `~/Documentos/campana_fp/C-09` | `cd /home/angel/Documentos/campana_fp/C-09 && curl -sS --max-time 2 http://intranet.local:8081/ 2>/dev/null || printf 'RC_FALLO=%s\n' $? > /home/angel/Documentos/campana_fp/C-09/fallo_rc.txt` |
| 145 | 17:11:24 | B6/C-09 | comando | `~/Documentos/campana_fp/C-09` | `cd /home/angel/Documentos/campana_fp/C-09 && timeout 5 curl -sS -o /home/angel/Documentos/campana_fp/C-09/reintento.html http://intranet.local:8080/ && echo 'RC_REINTENTO=0' > /home/angel/Documentos/campana_fp/C-09/reintento_rc.txt` |
| 146 | 17:11:31 | B6/C-09 | evidencia | `~/Documentos/campana_fp/C-09` | `cd /home/angel/Documentos/campana_fp/C-09 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-09/hecho.txt && cat /home/angel/Documentos/campana_fp/C-09/http_code.txt /home/angel/Documentos/campana_fp/C-09/fallo_rc.txt /home/angel/Documentos/campana_fp/C-09/reintento_rc.txt >> /home/angel/Documentos/campana_fp/C-09/hecho.txt && wc -c /home/angel/Documentos/campana_fp/C-09/intranet.html >> /home/angel/Documentos/campana_fp/C-09/hecho.txt` |
| 147 | 17:11:40 | B6/C-09 | fin | `~/Documentos/campana_fp/C-09` | `cd /home/angel/Documentos/campana_fp/C-09 && rm -f /home/angel/Documentos/campana_fp/C-09/intranet.html /home/angel/Documentos/campana_fp/C-09/reintento.html /home/angel/Documentos/campana_fp/C-09/http_code.txt /home/angel/Documentos/campana_fp/C-09/fallo_rc.txt /home/angel/Documentos/campana_fp/C-09/reintento_rc.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-09/fin.txt` |
| 148 | 17:19:30 | B6/C-10 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-10 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-10/inicio.txt` |
| 149 | 17:19:37 | B6/C-10 | comando | `~/Documentos/campana_fp/C-10` | `cd /home/angel/Documentos/campana_fp/C-10 && echo 'plantilla del informe del mes' > /home/angel/Documentos/campana_fp/C-10/plantilla.txt && seq 1 12 > /home/angel/Documentos/campana_fp/C-10/lotes.txt` |
| 150 | 17:19:46 | B6/C-10 | comando | `~/Documentos/campana_fp/C-10` | `cd /home/angel/Documentos/campana_fp/C-10 && xargs -a /home/angel/Documentos/campana_fp/C-10/lotes.txt -I{} cp /home/angel/Documentos/campana_fp/C-10/plantilla.txt /home/angel/Documentos/campana_fp/C-10/lote_{}.txt` |
| 151 | 17:19:51 | B6/C-10 | comando | `~/Documentos/campana_fp/C-10` | `cd /home/angel/Documentos/campana_fp/C-10 && wc -l /home/angel/Documentos/campana_fp/C-10/lote_1.txt > /home/angel/Documentos/campana_fp/C-10/lote1_wc.txt` |
| 152 | 17:19:59 | B6/C-10 | evidencia | `~/Documentos/campana_fp/C-10` | `cd /home/angel/Documentos/campana_fp/C-10 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-10/hecho.txt && stat -c %s /home/angel/Documentos/campana_fp/C-10/lote_12.txt >> /home/angel/Documentos/campana_fp/C-10/hecho.txt && ls -l /home/angel/Documentos/campana_fp/C-10/lote_*.txt >> /home/angel/Documentos/campana_fp/C-10/hecho.txt` |
| 153 | 17:20:06 | B6/C-10 | fin | `~/Documentos/campana_fp/C-10` | `cd /home/angel/Documentos/campana_fp/C-10 && rm -f /home/angel/Documentos/campana_fp/C-10/lote_*.txt /home/angel/Documentos/campana_fp/C-10/lotes.txt /home/angel/Documentos/campana_fp/C-10/plantilla.txt /home/angel/Documentos/campana_fp/C-10/lote1_wc.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-10/fin.txt` |
| 154 | 17:27:10 | B6/C-11 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-11 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-11/inicio.txt` |
| 155 | 17:27:18 | B6/C-11 | comando | `~/Documentos/campana_fp/C-11` | `cd /home/angel/Documentos/campana_fp/C-11 && echo 'C-11: incidencia cerrada; copia del dia revisada' > /home/angel/Documentos/campana_fp/C-11/nota.txt` |
| 156 | 17:27:25 | B6/C-11 | comando | `~/Documentos/campana_fp/C-11` | `cd /home/angel/Documentos/campana_fp/C-11 && logger -t ofimatica 'C-11: incidencia cerrada; copia del dia revisada'` |
| 157 | 17:27:34 | B6/C-11 | comando | `~/Documentos/campana_fp/C-11` | `cd /home/angel/Documentos/campana_fp/C-11 && tee -a /home/angel/Documentos/campana_fp/C-11/registro.log < /home/angel/Documentos/campana_fp/C-11/nota.txt` |
| 158 | 17:27:39 | B6/C-11 | evidencia | `~/Documentos/campana_fp/C-11` | `cd /home/angel/Documentos/campana_fp/C-11 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-11/hecho.txt && tail -3 /home/angel/Documentos/campana_fp/C-11/registro.log >> /home/angel/Documentos/campana_fp/C-11/hecho.txt` |
| 159 | 17:27:47 | B6/C-11 | fin | `~/Documentos/campana_fp/C-11` | `cd /home/angel/Documentos/campana_fp/C-11 && rm -f /home/angel/Documentos/campana_fp/C-11/nota.txt /home/angel/Documentos/campana_fp/C-11/registro.log && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-11/fin.txt` |
| 160 | 17:35:40 | B6/C-12 | inicio | `~/Documentos/campana_fp` | `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-12 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-12/inicio.txt` |
| 161 | 17:35:45 | B6/C-12 | comando | `~/Documentos/campana_fp/C-12` | `cd /home/angel/Documentos/campana_fp/C-12 && wget -q -O /home/angel/Documentos/campana_fp/C-12/manual.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 162 | 17:35:53 | B6/C-12 | evidencia | `~/Documentos/campana_fp/C-12` | `cd /home/angel/Documentos/campana_fp/C-12 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-12/hecho.txt && stat -c %s /home/angel/Documentos/campana_fp/C-12/manual.pdf >> /home/angel/Documentos/campana_fp/C-12/hecho.txt` |
| 163 | 17:35:59 | B6/C-12 | fin | `~/Documentos/campana_fp/C-12` | `cd /home/angel/Documentos/campana_fp/C-12 && rm -f /home/angel/Documentos/campana_fp/C-12/manual.pdf && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-12/fin.txt` |

