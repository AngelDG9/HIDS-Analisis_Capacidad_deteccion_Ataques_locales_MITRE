# `receta_resumen.md` — receta de actividad legítima (3 días)

> Generado por `_artefactos/scripts/construir_receta_legitima.py` (receta v1).
> Jornada **09:00–18:00 local** (08:00–17:00 UTC), con **café** (20 min) y **comida** (60 min).
> Solo handler `Command`; **cero** `random`, **cero** `Curl`, **cero** navegador.

| Bloque | UTC | Local | Tipo | D1 | D2 | D3 |
|---|---|---|---|---|---|---|
| B1 Llegada | 08:00–08:12 | 09:00-09:12 | trabajo | 9 | 9 | 9 |
| B2 Correo y mañana | 08:12–10:00 | 09:12-11:00 | trabajo | 26 | 32 | 22 |
| P1 Café | 10:00–10:20 | 11:00-11:20 | pausa | 0 | 0 | 0 |
| B3 Documentos | 10:20–13:00 | 11:20-14:00 | trabajo | 42 | 34 | 46 |
| P2 Comida | 13:00–14:00 | 14:00-15:00 | pausa | 0 | 0 | 0 |
| B4 Reuniones y tarde | 14:00–16:15 | 15:00-17:15 | trabajo | 22 | 30 | 16 |
| B5 Cierre | 16:15–17:00 | 17:15-18:00 | trabajo | 12 | 12 | 12 |
| **Total** | 08:00–17:00 | 09:00–18:00 | — | **111** | **117** | **105** |

**Total ventana (3 días): 333 acciones.**

## Día 1 — «cierre de informes» (111 acciones)

| # | UTC | Bloque | Familia | Comando |
|---|---|---|---|---|
| 1 | 08:00 | B1 | llegada | `date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 2 | 08:00 | B1 | listar | `ls -la /home/angel/Documentos` |
| 3 | 08:01 | B1 | estructura | `mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Documentos/copias /home/angel/Documentos/correo /home/angel/Descargas /home/angel/.cache/tfg-web` |
| 4 | 08:04 | B1 | agenda | `echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | 08:05 | B1 | agenda | `cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 6 | 08:05 | B1 | web-sesion | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| 7 | 08:08 | B1 | web-requisitos | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles.css -w '%{http_code}' http://intranet.local:8080/styles.css && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal.js -w '%{http_code}' http://intranet.local:8080/portal.js && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/logo.svg -w '%{http_code}' http://intranet.local:8080/assets/logo.svg` |
| 8 | 08:09 | B1 | web-huella | `wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles.css` |
| 9 | 08:10 | B1 | correo | `echo 're: estado del informe mensual' > /home/angel/Documentos/correo/borrador_1.txt` |
| 10 | 08:12 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r1' -o /home/angel/.cache/tfg-web/buzon_1.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 11 | 08:12 | B2 | correo-escribir | `echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_1.txt` |
| 12 | 08:13 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_1.txt` |
| 13 | 08:23 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r2' -o /home/angel/.cache/tfg-web/buzon_2.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 14 | 08:24 | B2 | correo-escribir | `echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_2.txt` |
| 15 | 08:25 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_2.txt` |
| 16 | 08:35 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r3' -o /home/angel/.cache/tfg-web/buzon_3.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 17 | 08:36 | B2 | correo-escribir | `echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_3.txt` |
| 18 | 08:37 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_3.txt` |
| 19 | 08:47 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d1_r4' -o /home/angel/.cache/tfg-web/buzon_4.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 20 | 08:48 | B2 | correo-escribir | `echo 'ronda 4: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_4.txt` |
| 21 | 08:49 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_4.txt` |
| 22 | 08:59 | B2 | informe | `echo 'informe del area - jornada 1' > /home/angel/Documentos/informes/informe.txt` |
| 23 | 09:00 | B2 | adjunto | `tar -czf /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 24 | 09:01 | B2 | huella | `sha256sum /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 25 | 09:11 | B2 | tamano | `du -sh /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 26 | 09:12 | B2 | listar | `ls -la /home/angel/Documentos/informes` |
| 27 | 09:13 | B2 | adjunto | `tar -czf /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 28 | 09:23 | B2 | huella | `sha256sum /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 29 | 09:24 | B2 | tamano | `du -sh /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 30 | 09:34 | B2 | listar | `ls -la /home/angel/Documentos/informes` |
| 31 | 09:35 | B2 | copia | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 32 | 09:46 | B2 | renombrar | `mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1.txt` |
| 33 | 09:46 | B2 | contar | `find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt` |
| 34 | 09:57 | B2 | listar | `ls -la /home/angel/Documentos/correo` |
| 35 | 09:58 | B2 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 36 | 10:20 | B3 | web-navegar | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/index.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/noticias.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 37 | 10:20 | B3 | web-navegar | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 38 | 10:21 | B3 | web-descarga | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/plantilla_informe.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 39 | 10:22 | B3 | web-pdf | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/manual_empleado.pdf -w '%{http_code}' http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 40 | 10:33 | B3 | web-huella | `wc -c /home/angel/Descargas/manual_empleado.pdf && sha256sum /home/angel/Descargas/manual_empleado.pdf` |
| 41 | 10:34 | B3 | redactar | `echo '1. alcance del informe (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 42 | 10:35 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 43 | 10:36 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 44 | 10:47 | B3 | redactar | `echo '2. actividades del area (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 45 | 10:48 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 46 | 10:48 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 47 | 10:49 | B3 | redactar | `echo '3. incidencias de la semana (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 48 | 11:00 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 49 | 11:01 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 50 | 11:02 | B3 | redactar | `echo '4. indicadores del mes (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 51 | 11:13 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 52 | 11:14 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 53 | 11:15 | B3 | redactar | `echo '5. riesgos identificados (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 54 | 11:26 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 55 | 11:27 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 56 | 11:28 | B3 | redactar | `echo '6. plan de accion (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 57 | 11:39 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 58 | 11:40 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 59 | 11:41 | B3 | redactar | `echo '7. conclusiones (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 60 | 11:52 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 61 | 11:53 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 62 | 11:53 | B3 | redactar | `echo '8. anexo de datos (dia 1)' >> /home/angel/Documentos/informes/informe.txt` |
| 63 | 12:05 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 64 | 12:05 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 65 | 12:06 | B3 | comprimir | `gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 66 | 12:17 | B3 | huella | `md5sum /home/angel/Documentos/informes/informe.txt.gz` |
| 67 | 12:18 | B3 | huella | `sha256sum /home/angel/Documentos/informes/informe.txt.gz` |
| 68 | 12:19 | B3 | listar | `ls -la /home/angel/Documentos/informes` |
| 69 | 12:30 | B3 | tamano | `du -sh /home/angel/Documentos/informes` |
| 70 | 12:31 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt.gz` |
| 71 | 12:32 | B3 | consolidar | `tar -czf /home/angel/Descargas/informes.tar.gz -C /home/angel/Documentos informes` |
| 72 | 12:43 | B3 | copia | `cp -f /home/angel/Descargas/informes.tar.gz /home/angel/Descargas/informes_copia_1.tar.gz` |
| 73 | 12:44 | B3 | huella | `sha256sum /home/angel/Descargas/informes.tar.gz` |
| 74 | 12:45 | B3 | contar | `find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros_d1.txt` |
| 75 | 12:56 | B3 | tamano | `du -sh /home/angel/Descargas` |
| 76 | 12:57 | B3 | listar | `ls -la /home/angel/Descargas` |
| 77 | 12:57 | B3 | revisar | `grep -c 'informe' /home/angel/Documentos/informes/informe.txt` |
| 78 | 14:00 | B4 | acta | `echo 'acta de reunion 1 del area (dia 1)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 79 | 14:00 | B4 | acta | `cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 80 | 14:12 | B4 | acta | `wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 81 | 14:13 | B4 | acta | `cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 82 | 14:24 | B4 | acta | `sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 83 | 14:25 | B4 | acta | `ls -la /home/angel/Documentos/actas` |
| 84 | 14:36 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 85 | 14:37 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_listado.txt -w '%{http_code}' http://nube.local:9092/nube/` |
| 86 | 14:48 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/informes/informe.txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/informes/` |
| 87 | 14:49 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_actas.txt -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 88 | 15:00 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 89 | 15:01 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/noticias_tarde.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 90 | 15:13 | B4 | informe | `tar -czf /home/angel/Descargas/informe_dia1.tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 91 | 15:13 | B4 | huella | `sha256sum /home/angel/Descargas/informe_dia1.tar.gz` |
| 92 | 15:25 | B4 | tamano | `du -sh /home/angel/Descargas/informe_dia1.tar.gz` |
| 93 | 15:26 | B4 | listar | `ls -la /home/angel/Descargas` |
| 94 | 15:37 | B4 | descarga | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/plantilla_dia1.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 95 | 15:38 | B4 | descarga | `wc -c /home/angel/Descargas/plantilla_dia1.csv` |
| 96 | 15:49 | B4 | descarga | `sha256sum /home/angel/Descargas/plantilla_dia1.csv` |
| 97 | 15:50 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/ayuda_tarde.html -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 98 | 16:01 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles_tarde.css -w '%{http_code}' http://intranet.local:8080/styles.css` |
| 99 | 16:13 | B4 | portal | `wc -l /home/angel/.cache/tfg-web/ayuda_tarde.html` |
| 100 | 16:15 | B5 | copia | `tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Documentos informes actas` |
| 101 | 16:15 | B5 | huella | `sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz` |
| 102 | 16:23 | B5 | huella | `cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256` |
| 103 | 16:24 | B5 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 104 | 16:31 | B5 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/copias_nube.txt -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 105 | 16:32 | B5 | tamano | `du -sh /home/angel/Documentos` |
| 106 | 16:40 | B5 | disco | `df -h /` |
| 107 | 16:41 | B5 | copia | `cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copia_final_1.tar.gz` |
| 108 | 16:48 | B5 | tamano | `wc -c /home/angel/Descargas/copia_final_1.tar.gz` |
| 109 | 16:49 | B5 | limpiar | `rm -f /home/angel/Descargas/tmp_*.csv` |
| 110 | 16:57 | B5 | cierre | `date -u +%FT%TZ` |
| 111 | 16:58 | B5 | cierre | `ls -la /home/angel/Documentos /home/angel/Descargas` |

## Día 2 — «reuniones y portal» (117 acciones)

| # | UTC | Bloque | Familia | Comando |
|---|---|---|---|---|
| 1 | 08:00 | B1 | llegada | `date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 2 | 08:00 | B1 | listar | `ls -la /home/angel/Documentos` |
| 3 | 08:01 | B1 | estructura | `mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Documentos/copias /home/angel/Documentos/correo /home/angel/Descargas /home/angel/.cache/tfg-web` |
| 4 | 08:04 | B1 | agenda | `echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | 08:05 | B1 | agenda | `cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 6 | 08:05 | B1 | web-sesion | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| 7 | 08:08 | B1 | web-requisitos | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles.css -w '%{http_code}' http://intranet.local:8080/styles.css && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal.js -w '%{http_code}' http://intranet.local:8080/portal.js && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/logo.svg -w '%{http_code}' http://intranet.local:8080/assets/logo.svg` |
| 8 | 08:09 | B1 | web-huella | `wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles.css` |
| 9 | 08:10 | B1 | correo | `echo 're: confirmacion de la reunion de area' > /home/angel/Documentos/correo/borrador_1.txt` |
| 10 | 08:12 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r1' -o /home/angel/.cache/tfg-web/buzon_1.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 11 | 08:12 | B2 | correo-escribir | `echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_1.txt` |
| 12 | 08:13 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_1.txt` |
| 13 | 08:14 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r2' -o /home/angel/.cache/tfg-web/buzon_2.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 14 | 08:24 | B2 | correo-escribir | `echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_2.txt` |
| 15 | 08:25 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_2.txt` |
| 16 | 08:25 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r3' -o /home/angel/.cache/tfg-web/buzon_3.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 17 | 08:26 | B2 | correo-escribir | `echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_3.txt` |
| 18 | 08:36 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_3.txt` |
| 19 | 08:37 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d2_r4' -o /home/angel/.cache/tfg-web/buzon_4.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 20 | 08:38 | B2 | correo-escribir | `echo 'ronda 4: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_4.txt` |
| 21 | 08:47 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_4.txt` |
| 22 | 08:48 | B2 | copia | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 23 | 08:49 | B2 | renombrar | `mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1.txt` |
| 24 | 08:59 | B2 | contar | `find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt` |
| 25 | 09:00 | B2 | listar | `ls -la /home/angel/Documentos/correo` |
| 26 | 09:00 | B2 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 27 | 09:10 | B2 | leer | `cat /home/angel/Documentos/correo/enviado_1.txt` |
| 28 | 09:11 | B2 | tamano | `du -sh /home/angel/Documentos/correo` |
| 29 | 09:12 | B2 | copia | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Descargas/informe_copia_2.txt` |
| 30 | 09:22 | B2 | limpiar | `rm -f /home/angel/Descargas/tmp_borradores.csv` |
| 31 | 09:22 | B2 | agenda | `echo 'revisado el buzon de la manana' >> /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 32 | 09:23 | B2 | huella | `md5sum /home/angel/Documentos/informes/informe.bak` |
| 33 | 09:33 | B2 | listar | `ls -la /home/angel/Documentos` |
| 34 | 09:34 | B2 | informe | `echo 'informe del area - jornada 2' > /home/angel/Documentos/informes/informe.txt` |
| 35 | 09:35 | B2 | adjunto | `tar -czf /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 36 | 09:44 | B2 | huella | `sha256sum /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 37 | 09:45 | B2 | tamano | `du -sh /home/angel/Documentos/informes/adjunto_1_$(date -u +%F).tar.gz` |
| 38 | 09:46 | B2 | listar | `ls -la /home/angel/Documentos/informes` |
| 39 | 09:56 | B2 | adjunto | `tar -czf /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 40 | 09:57 | B2 | huella | `sha256sum /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 41 | 09:57 | B2 | tamano | `du -sh /home/angel/Documentos/informes/adjunto_2_$(date -u +%F).tar.gz` |
| 42 | 10:20 | B3 | web-navegar | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/index.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/noticias.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 43 | 10:20 | B3 | web-navegar | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 44 | 10:21 | B3 | web-descarga | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/plantilla_informe.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 45 | 10:33 | B3 | web-pdf | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/manual_empleado.pdf -w '%{http_code}' http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 46 | 10:34 | B3 | web-huella | `wc -c /home/angel/Descargas/manual_empleado.pdf && sha256sum /home/angel/Descargas/manual_empleado.pdf` |
| 47 | 10:35 | B3 | comprimir | `gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 48 | 10:46 | B3 | huella | `md5sum /home/angel/Documentos/informes/informe.txt.gz` |
| 49 | 10:47 | B3 | huella | `sha256sum /home/angel/Documentos/informes/informe.txt.gz` |
| 50 | 10:48 | B3 | listar | `ls -la /home/angel/Documentos/informes` |
| 51 | 11:00 | B3 | tamano | `du -sh /home/angel/Documentos/informes` |
| 52 | 11:00 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt.gz` |
| 53 | 11:01 | B3 | redactar | `echo '1. alcance del informe (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 54 | 11:13 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 55 | 11:14 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 56 | 11:15 | B3 | redactar | `echo '2. actividades del area (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 57 | 11:26 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 58 | 11:27 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 59 | 11:28 | B3 | redactar | `echo '3. incidencias de la semana (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 60 | 11:40 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 61 | 11:41 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 62 | 11:41 | B3 | redactar | `echo '4. indicadores del mes (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 63 | 11:53 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 64 | 11:54 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 65 | 11:55 | B3 | redactar | `echo '5. riesgos identificados (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 66 | 12:06 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 67 | 12:07 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 68 | 12:19 | B3 | redactar | `echo '6. plan de accion (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 69 | 12:20 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 70 | 12:32 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 71 | 12:32 | B3 | redactar | `echo '7. conclusiones (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 72 | 12:44 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 73 | 12:45 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 74 | 12:57 | B3 | redactar | `echo '8. anexo de datos (dia 2)' >> /home/angel/Documentos/informes/informe.txt` |
| 75 | 12:57 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 76 | 14:00 | B4 | acta | `echo 'acta de reunion 1 del area (dia 2)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 77 | 14:00 | B4 | acta | `cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 78 | 14:01 | B4 | acta | `wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 79 | 14:12 | B4 | acta | `cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 80 | 14:13 | B4 | acta | `sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 81 | 14:14 | B4 | acta | `ls -la /home/angel/Documentos/actas` |
| 82 | 14:24 | B4 | acta | `echo 'acta de reunion 1 del area (dia 2)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 83 | 14:25 | B4 | acta | `cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 84 | 14:26 | B4 | acta | `wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 85 | 14:37 | B4 | acta | `cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 86 | 14:38 | B4 | acta | `sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 87 | 14:38 | B4 | acta | `ls -la /home/angel/Documentos/actas` |
| 88 | 14:49 | B4 | acta | `echo 'acta de reunion 2 del area (dia 2)' > /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt` |
| 89 | 14:50 | B4 | acta | `cat /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt` |
| 90 | 14:51 | B4 | acta | `wc -c /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt` |
| 91 | 15:02 | B4 | acta | `cp -f /home/angel/Documentos/actas/acta_2_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_2.txt` |
| 92 | 15:02 | B4 | acta | `sha256sum /home/angel/Documentos/actas/compartida_2.txt` |
| 93 | 15:03 | B4 | acta | `ls -la /home/angel/Documentos/actas` |
| 94 | 15:14 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 95 | 15:15 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_listado.txt -w '%{http_code}' http://nube.local:9092/nube/` |
| 96 | 15:25 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/informes/informe.txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/informes/` |
| 97 | 15:26 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_actas.txt -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 98 | 15:37 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 99 | 15:38 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/noticias_tarde.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 100 | 15:49 | B4 | informe | `tar -czf /home/angel/Descargas/informe_dia2.tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 101 | 15:49 | B4 | huella | `sha256sum /home/angel/Descargas/informe_dia2.tar.gz` |
| 102 | 16:00 | B4 | tamano | `du -sh /home/angel/Descargas/informe_dia2.tar.gz` |
| 103 | 16:01 | B4 | listar | `ls -la /home/angel/Descargas` |
| 104 | 16:12 | B4 | descarga | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/plantilla_dia2.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 105 | 16:13 | B4 | descarga | `wc -c /home/angel/Descargas/plantilla_dia2.csv` |
| 106 | 16:15 | B5 | copia | `tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Documentos informes actas` |
| 107 | 16:15 | B5 | huella | `sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz` |
| 108 | 16:23 | B5 | huella | `cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256` |
| 109 | 16:24 | B5 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 110 | 16:31 | B5 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/copias_nube.txt -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 111 | 16:32 | B5 | tamano | `du -sh /home/angel/Documentos` |
| 112 | 16:40 | B5 | disco | `df -h /` |
| 113 | 16:41 | B5 | copia | `cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copia_final_2.tar.gz` |
| 114 | 16:48 | B5 | tamano | `wc -c /home/angel/Descargas/copia_final_2.tar.gz` |
| 115 | 16:49 | B5 | limpiar | `rm -f /home/angel/Descargas/tmp_*.csv` |
| 116 | 16:57 | B5 | cierre | `date -u +%FT%TZ` |
| 117 | 16:58 | B5 | cierre | `ls -la /home/angel/Documentos /home/angel/Descargas` |

## Día 3 — «revisión y copias» (105 acciones)

| # | UTC | Bloque | Familia | Comando |
|---|---|---|---|---|
| 1 | 08:00 | B1 | llegada | `date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 2 | 08:00 | B1 | listar | `ls -la /home/angel/Documentos` |
| 3 | 08:01 | B1 | estructura | `mkdir -p /home/angel/Documentos/informes /home/angel/Documentos/actas /home/angel/Documentos/copias /home/angel/Documentos/correo /home/angel/Descargas /home/angel/.cache/tfg-web` |
| 4 | 08:04 | B1 | agenda | `echo '09:30 reunion de area; 12:00 informe; 17:00 cierre' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | 08:05 | B1 | agenda | `cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 6 | 08:05 | B1 | web-sesion | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| 7 | 08:08 | B1 | web-requisitos | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/styles.css -w '%{http_code}' http://intranet.local:8080/styles.css && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal.js -w '%{http_code}' http://intranet.local:8080/portal.js && curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/logo.svg -w '%{http_code}' http://intranet.local:8080/assets/logo.svg` |
| 8 | 08:09 | B1 | web-huella | `wc -c /home/angel/.cache/tfg-web/index.html && sha256sum /home/angel/.cache/tfg-web/styles.css` |
| 9 | 08:10 | B1 | correo | `echo 're: revision de las copias de seguridad' > /home/angel/Documentos/correo/borrador_1.txt` |
| 10 | 08:12 | B2 | copia | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Documentos/informes/informe.bak` |
| 11 | 08:12 | B2 | renombrar | `mv -f /home/angel/Documentos/correo/borrador_1.txt /home/angel/Documentos/correo/enviado_1.txt` |
| 12 | 08:13 | B2 | contar | `find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros.txt` |
| 13 | 08:24 | B2 | listar | `ls -la /home/angel/Documentos/correo` |
| 14 | 08:25 | B2 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 15 | 08:26 | B2 | leer | `cat /home/angel/Documentos/correo/enviado_1.txt` |
| 16 | 08:36 | B2 | tamano | `du -sh /home/angel/Documentos/correo` |
| 17 | 08:37 | B2 | copia | `cp -f /home/angel/Documentos/informes/informe.txt /home/angel/Descargas/informe_copia_3.txt` |
| 18 | 08:48 | B2 | limpiar | `rm -f /home/angel/Descargas/tmp_borradores.csv` |
| 19 | 08:49 | B2 | agenda | `echo 'revisado el buzon de la manana' >> /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 20 | 08:59 | B2 | huella | `md5sum /home/angel/Documentos/informes/informe.bak` |
| 21 | 09:00 | B2 | listar | `ls -la /home/angel/Documentos` |
| 22 | 09:11 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r1' -o /home/angel/.cache/tfg-web/buzon_1.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 23 | 09:12 | B2 | correo-escribir | `echo 'ronda 1: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_1.txt` |
| 24 | 09:22 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_1.txt` |
| 25 | 09:23 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r2' -o /home/angel/.cache/tfg-web/buzon_2.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 26 | 09:34 | B2 | correo-escribir | `echo 'ronda 2: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_2.txt` |
| 27 | 09:35 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_2.txt` |
| 28 | 09:45 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r3' -o /home/angel/.cache/tfg-web/buzon_3.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 29 | 09:46 | B2 | correo-escribir | `echo 'ronda 3: pendiente de revisar el informe del area' >> /home/angel/Documentos/correo/borrador_3.txt` |
| 30 | 09:57 | B2 | correo-leer | `cat /home/angel/Documentos/correo/borrador_3.txt` |
| 31 | 09:58 | B2 | correo-buzon | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/plain;q=0.9,*/*;q=0.8' -X POST --data 'consulta_buzon_d3_r4' -o /home/angel/.cache/tfg-web/buzon_4.txt -w '%{http_code}' http://intranet.local:9090/paste` |
| 32 | 10:20 | B3 | web-navegar | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/index.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/noticias.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 33 | 10:20 | B3 | web-navegar | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| 34 | 10:21 | B3 | web-descarga | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/plantilla_informe.csv -w '%{http_code}' http://intranet.local:8080/descargas/plantilla_informe.csv` |
| 35 | 10:22 | B3 | web-pdf | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/Descargas/noticias.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/Descargas/manual_empleado.pdf -w '%{http_code}' http://intranet.local:8080/descargas/manual_empleado.pdf` |
| 36 | 10:33 | B3 | web-huella | `wc -c /home/angel/Descargas/manual_empleado.pdf && sha256sum /home/angel/Descargas/manual_empleado.pdf` |
| 37 | 10:34 | B3 | revisar | `grep -c 'informe' /home/angel/Documentos/informes/informe.txt` |
| 38 | 10:35 | B3 | revisar | `head -n 5 /home/angel/Documentos/informes/informe.txt` |
| 39 | 10:35 | B3 | revisar | `tail -n 5 /home/angel/Documentos/informes/informe.txt` |
| 40 | 10:46 | B3 | revisar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 41 | 10:47 | B3 | listar | `ls -la /home/angel/Documentos/informes` |
| 42 | 10:48 | B3 | disco | `df -h /` |
| 43 | 10:49 | B3 | estado | `stat /home/angel/Documentos/informes/informe.txt` |
| 44 | 11:00 | B3 | leer | `cat /home/angel/Documentos/informes/informe.bak` |
| 45 | 11:00 | B3 | redactar | `echo '1. alcance del informe (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 46 | 11:01 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 47 | 11:02 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 48 | 11:13 | B3 | redactar | `echo '2. actividades del area (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 49 | 11:14 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 50 | 11:15 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 51 | 11:15 | B3 | redactar | `echo '3. incidencias de la semana (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 52 | 11:26 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 53 | 11:27 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 54 | 11:28 | B3 | redactar | `echo '4. indicadores del mes (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 55 | 11:29 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 56 | 11:40 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 57 | 11:41 | B3 | redactar | `echo '5. riesgos identificados (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 58 | 11:41 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 59 | 11:42 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 60 | 11:53 | B3 | redactar | `echo '6. plan de accion (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 61 | 11:54 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 62 | 11:55 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 63 | 12:06 | B3 | redactar | `echo '7. conclusiones (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 64 | 12:06 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 65 | 12:07 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 66 | 12:18 | B3 | redactar | `echo '8. anexo de datos (dia 3)' >> /home/angel/Documentos/informes/informe.txt` |
| 67 | 12:19 | B3 | leer | `cat /home/angel/Documentos/informes/informe.txt` |
| 68 | 12:20 | B3 | contar | `wc -l /home/angel/Documentos/informes/informe.txt` |
| 69 | 12:31 | B3 | consolidar | `tar -czf /home/angel/Descargas/informes.tar.gz -C /home/angel/Documentos informes` |
| 70 | 12:32 | B3 | copia | `cp -f /home/angel/Descargas/informes.tar.gz /home/angel/Descargas/informes_copia_3.tar.gz` |
| 71 | 12:32 | B3 | huella | `sha256sum /home/angel/Descargas/informes.tar.gz` |
| 72 | 12:43 | B3 | contar | `find /home/angel/Documentos -type f > /home/angel/.cache/tfg-web/lista_ficheros_d3.txt` |
| 73 | 12:44 | B3 | tamano | `du -sh /home/angel/Descargas` |
| 74 | 12:45 | B3 | listar | `ls -la /home/angel/Descargas` |
| 75 | 12:56 | B3 | comprimir | `gzip -kf /home/angel/Documentos/informes/informe.txt` |
| 76 | 12:57 | B3 | huella | `md5sum /home/angel/Documentos/informes/informe.txt.gz` |
| 77 | 12:57 | B3 | huella | `sha256sum /home/angel/Documentos/informes/informe.txt.gz` |
| 78 | 14:00 | B4 | acta | `echo 'acta de reunion 1 del area (dia 3)' > /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 79 | 14:00 | B4 | acta | `cat /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 80 | 14:12 | B4 | acta | `wc -c /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt` |
| 81 | 14:13 | B4 | acta | `cp -f /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt /home/angel/Documentos/actas/compartida_1.txt` |
| 82 | 14:25 | B4 | acta | `sha256sum /home/angel/Documentos/actas/compartida_1.txt` |
| 83 | 14:26 | B4 | acta | `ls -la /home/angel/Documentos/actas` |
| 84 | 14:37 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/actas/acta_1_$(date -u +%F).txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 85 | 14:38 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_listado.txt -w '%{http_code}' http://nube.local:9092/nube/` |
| 86 | 14:50 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/informes/informe.txt -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/informes/` |
| 87 | 15:02 | B4 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/nube_actas.txt -w '%{http_code}' http://nube.local:9092/nube/actas/` |
| 88 | 15:14 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e http://intranet.local:8080/ayuda.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/portal_tarde.html -w '%{http_code}' http://intranet.local:8080/` |
| 89 | 15:25 | B4 | portal | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -e /home/angel/.cache/tfg-web/portal_tarde.html -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: es-ES,es;q=0.9,en;q=0.5' --compressed -o /home/angel/.cache/tfg-web/noticias_tarde.html -w '%{http_code}' http://intranet.local:8080/noticias.html` |
| 90 | 15:37 | B4 | informe | `tar -czf /home/angel/Descargas/informe_dia3.tar.gz -C /home/angel/Documentos/informes informe.txt` |
| 91 | 15:49 | B4 | huella | `sha256sum /home/angel/Descargas/informe_dia3.tar.gz` |
| 92 | 16:01 | B4 | tamano | `du -sh /home/angel/Descargas/informe_dia3.tar.gz` |
| 93 | 16:12 | B4 | listar | `ls -la /home/angel/Descargas` |
| 94 | 16:15 | B5 | copia | `tar -czf /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -C /home/angel/Documentos informes actas` |
| 95 | 16:15 | B5 | huella | `sha256sum /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz` |
| 96 | 16:23 | B5 | huella | `cat /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz.sha256` |
| 97 | 16:24 | B5 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -T /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz -o /dev/null -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 98 | 16:31 | B5 | nube | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -b /home/angel/.cache/tfg-web/cookies.txt -X PROPFIND -H 'Depth: 1' -o /home/angel/.cache/tfg-web/copias_nube.txt -w '%{http_code}' http://nube.local:9092/nube/copias/` |
| 99 | 16:32 | B5 | tamano | `du -sh /home/angel/Documentos` |
| 100 | 16:40 | B5 | disco | `df -h /` |
| 101 | 16:41 | B5 | copia | `cp -f /home/angel/Documentos/copias/copia_$(date -u +%F).tar.gz /home/angel/Descargas/copia_final_3.tar.gz` |
| 102 | 16:48 | B5 | tamano | `wc -c /home/angel/Descargas/copia_final_3.tar.gz` |
| 103 | 16:49 | B5 | limpiar | `rm -f /home/angel/Descargas/tmp_*.csv` |
| 104 | 16:57 | B5 | cierre | `date -u +%FT%TZ` |
| 105 | 16:58 | B5 | cierre | `ls -la /home/angel/Documentos /home/angel/Descargas` |

