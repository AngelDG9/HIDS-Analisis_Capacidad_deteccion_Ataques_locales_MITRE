# `casos.md` — campaña de falsos positivos (`B6`, 11 casos)

> **Pre-registro firmado antes de `t0`** (plan §5.2.6, §10). Este fichero se **genera**
> desde `campana_casos.csv` (fuente única: comandos literales y metadatos); su
> `sha256` se **sella en la cabecera del CSV**. No se edita a mano.
> Bloque **`B6` «repaso del sistema» = 17:05–17:50Z** (18:05–18:50 local), **11 casos**
> en **3/4/4** días, inicio con **jitter fijo** (`d1` 17:06 · `d2` 17:17 · `d3` 17:11) y
> separación **≥ 3 min** entre casos. Atribución: `timestamp ∈ [ini − 10 s, fin + 60 s]`.
> **63 acciones GHOSTS** (22 de ellas son las marcas `inicio`/`fin`).

## Qué mide y por qué está dentro de la ventana

La campaña **no** fabrica ataques: hace **11 tareas de oficina corrientes** que un
empleado ejecutaría en el mismo portátil, con las **mismas herramientas** que el corpus
usa en sus ataques. Se ejecuta **dentro** de `[t0, t1]`, en un bloque **declarado**,
y se publica **aparte** (`campana_fp.csv`), sin recalcular `M` ni un FPR alternativo.

**No mutante** (definición operativa, §5.2.1.4): todo lo que se crea vive bajo
`/home/angel/Documentos/campana_fp/C-XX/` y **se borra dentro del propio caso**; no se toca `crontab`, `/etc`,
servicios, unidades, repositorios, credenciales ni rutas del sistema.

**Efectos declarados fuera de la carpeta** (son los **dos únicos**; los sella
`calendario.json` → `campana.efectos_declarados`):

- **`logger`** — una línea en el journal del sistema (C-11); no se borra (borrarla sería otra mutación).
- **`descargas_http`** — cuatro peticiones HTTP a la intranet local (C-09: dos a `:8080` y un intento a `:8081`; C-12: una a `:8080`); las **tres** que llegan al 8080 dejan rastro en el `web_access.log` del **servidor**, fuera de la víctima.

## Resumen (11 casos · `N ≥ 7` = 0 en todos)

| # | Caso | Día | Hora (UTC) | Binarios | Se confunde con | `N ≥ 7` | `N ≥ 3` | ¿Muta? | Coste |
|---|---|---|---|---|---|---|---|---|---|
| **C-01** | El equipo va lento: miro memoria y servicios | d1 | **17:06:00** | `free`, `systemctl` | ATA004 T1489, ATA045 T1499.001, ATA038 T1529 | **0** | 80792 L3 x3 | **No** | 3 min · <1 MB |
| **C-02** | No me va la intranet: miro la red | d1 | **17:15:20** | `ip` | ATA054 T1498.002, ATA055 T1557.003 | **0** | 80792 L3 x2 | **No** | 2 min · <1 MB |
| **C-03** | Compruebo si la copia esta programada | d1 | **17:24:40** | `systemctl`, `crontab` | ATA021 T1029, ATA004 T1489 | **0** | 80792 L3 x2 (y 0 2832) | **No** | 2 min · <1 MB |
| **C-05** | Protejo el informe con contrasena antes de enviarlo | d2 | **17:17:00** | `openssl` | ATA001 T1486, ATA019 T1048.001, ATA041 T1048.002 | **0** | 80792 L3 x2 (+2 sha256sum) | **No** | 4 min · <1 MB |
| **C-06** | Limpio temporales y destruyo un borrador | d2 | **17:25:30** | `rm`, `shred` | ATA003 T1490, ATA005 T1561 | **0** | 80792 L3 x2 + 80791 L3 x2-6 | **No** | 2 min · <1 MB |
| **C-07** | Sincronizo los informes con la carpeta de copias | d2 | **17:33:10** | `rsync` | ATA039 T1039, ATA040 T1074.002 | **0** | 80792 L3 x1 (+ 80790/80791 L3 por fichero) | **No** | 3 min · <1 MB |
| **C-08** | Normalizo el CSV del informe | d2 | **17:41:20** | `sed` | ATA006 T1565, ATA032 T1565.001, ATA026 T1565.002, ATA017 T1657 | **0** | 80792 L3 x2 (+ 80790/80791 L3 temporal) | **No** | 2 min · <1 MB |
| **C-09** | La intranet no responde: acoto el tiempo y reintento | d3 | **17:11:00** | `curl`, `timeout` | ATA025 T1496.001, ATA009 T1567, ATA010 T1041, ATA020 T1020, ATA023 T1496.002, ATA028 T1056.003, ATA041 T1048.002, ATA050 T1567.003 | **0** | 80792 L3 x4 | **No** | 3 min · <1 MB |
| **C-10** | Preparo el lote de plantillas del mes | d3 | **17:19:30** | `seq`, `xargs`, `cp` | ATA046 T1499.003, ATA047 T1499.002 | **0** | 80792 L3 x14 (1 seq, 1 xargs, 12 cp) | **No** | 4 min · <1 MB |
| **C-11** | Dejo constancia de la incidencia en el registro | d3 | **17:27:10** | `logger`, `tee` | ATA018 T1056.001 | **0** | 80792 L3 x2 (y 0 por syslog 40700) | **No** | 2 min · <1 MB |
| **C-12** | Descargo el manual con wget | d3 | **17:35:40** | `wget` | ATA008 T1048, ATA043 T1567.004 | **0** | 80792 L3 x1 (+ 80791 si borra temporales) | **No** | 2 min · <1 MB |

> **Cómo leer los umbrales.** `N ≥ 7` decide si el caso es un FP «de verdad»
> (`P2` o superior); `N ≥ 3` es donde **todo** `execve` alerta por `80792` (hipótesis
> H-A). Se pre-registran los dos. **No** se promete el número exacto de filas (el corpus
> muestra 1–3 por `execve`); lo falsable es el **conjunto de `rule_id`** y el `level`.
> Si un caso alerta a `N ≥ 7`, **es un hallazgo** y se publica; no se re-ejecuta.
> Si un caso **no** alerta ni a `N ≥ 3`, el `80792` no llegó: **no se ejecutó**.

## Fichas

### C-01 · El equipo va lento: miro memoria y servicios

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d1` · **17:06:00** |
| Binarios | `free`, `systemctl` |
| Se confunde con | ATA004 (T1489); ATA045 (T1499.001); ATA038 (T1529) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x3** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-01/`) |
| Evidencia de efecto | hecho.txt con wc -l: servicios.txt > 10 lineas y free.txt > 3 lineas |
| Coste · disco | 3 min · <1 MB |
| Por qué es legítimo | Cualquier empleado mira la memoria y los servicios cuando el portatil va lento, antes de abrir una incidencia. Solo lectura; no se nombra al agente. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-01 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-01/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-01 && free -m > /home/angel/Documentos/campana_fp/C-01/free.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-01 && systemctl --failed --no-pager > /home/angel/Documentos/campana_fp/C-01/fallidos.txt`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-01 && systemctl list-units --type=service --state=running --no-pager > /home/angel/Documentos/campana_fp/C-01/servicios.txt`
5. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-01 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-01/hecho.txt && wc -l /home/angel/Documentos/campana_fp/C-01/servicios.txt /home/angel/Documentos/campana_fp/C-01/free.txt /home/angel/Documentos/campana_fp/C-01/fallidos.txt >> /home/angel/Documentos/campana_fp/C-01/hecho.txt && cat /home/angel/Documentos/campana_fp/C-01/hecho.txt`
6. `fin` — `cd /home/angel/Documentos/campana_fp/C-01 && rm -f /home/angel/Documentos/campana_fp/C-01/servicios.txt /home/angel/Documentos/campana_fp/C-01/free.txt /home/angel/Documentos/campana_fp/C-01/fallidos.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-01/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-02 · No me va la intranet: miro la red

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d1` · **17:15:20** |
| Binarios | `ip` |
| Se confunde con | ATA054 (T1498.002); ATA055 (T1557.003) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x2** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-02/`) |
| Evidencia de efecto | hecho.txt con la IPv4 192.168.65.x (grep) y la tabla de rutas |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Comprobar la IP y la puerta de enlace es el primer paso de cualquier usuario ofimatico cuando una web interna no carga. `ip` se usa sin `set`/`add`: no se cambia nada. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-02 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-02/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-02 && ip -brief addr > /home/angel/Documentos/campana_fp/C-02/ip_addr.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-02 && ip route > /home/angel/Documentos/campana_fp/C-02/ip_route.txt`
4. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-02 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-02/hecho.txt && grep '192.168.65.' /home/angel/Documentos/campana_fp/C-02/ip_addr.txt >> /home/angel/Documentos/campana_fp/C-02/hecho.txt && cat /home/angel/Documentos/campana_fp/C-02/ip_route.txt >> /home/angel/Documentos/campana_fp/C-02/hecho.txt`
5. `fin` — `cd /home/angel/Documentos/campana_fp/C-02 && rm -f /home/angel/Documentos/campana_fp/C-02/ip_addr.txt /home/angel/Documentos/campana_fp/C-02/ip_route.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-02/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-03 · Compruebo si la copia esta programada

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d1` · **17:24:40** |
| Binarios | `systemctl`, `crontab` |
| Se confunde con | ATA021 (T1029); ATA004 (T1489) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x2 (y 0 2832)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-03/`) |
| Evidencia de efecto | hecho.txt con el nº de timers (wc -l) y crontab_rc=1 |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Comprobar si la copia automatica esta programada es una duda corriente. `crontab -l` solo lee; con el crontab vacio devuelve rc=1 (no crontab for angel), que es un exit distinto de cero realista. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-03 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-03/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-03 && systemctl list-timers --all --no-pager > /home/angel/Documentos/campana_fp/C-03/timers.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-03 && crontab -l > /home/angel/Documentos/campana_fp/C-03/crontab.txt 2>/dev/null || printf 'crontab_rc=%s\n' $? > /home/angel/Documentos/campana_fp/C-03/crontab_rc.txt`
4. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-03 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-03/hecho.txt && wc -l /home/angel/Documentos/campana_fp/C-03/timers.txt >> /home/angel/Documentos/campana_fp/C-03/hecho.txt && cat /home/angel/Documentos/campana_fp/C-03/crontab_rc.txt >> /home/angel/Documentos/campana_fp/C-03/hecho.txt`
5. `fin` — `cd /home/angel/Documentos/campana_fp/C-03 && rm -f /home/angel/Documentos/campana_fp/C-03/timers.txt /home/angel/Documentos/campana_fp/C-03/crontab.txt /home/angel/Documentos/campana_fp/C-03/crontab_rc.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-03/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-05 · Protejo el informe con contrasena antes de enviarlo

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:17:00** |
| Binarios | `openssl` |
| Se confunde con | ATA001 (T1486); ATA019 (T1048.001); ATA041 (T1048.002) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x2 (+2 sha256sum)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-05/`) |
| Evidencia de efecto | hecho.txt con las dos huellas sha256 (original == descifrado) |
| Coste · disco | 4 min · <1 MB |
| Por qué es legítimo | Proteger con contrasena un informe con datos de clientes antes de enviarlo por correo es una practica real de oficina. El fichero es de juguete y la contrasena es simbolica (`demo-c05`), como en ATA001. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-05 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-05/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-05 && echo 'informe del area: datos de cliente, importe 1200' > /home/angel/Documentos/campana_fp/C-05/informe.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-05 && openssl enc -aes-256-cbc -pbkdf2 -salt -in /home/angel/Documentos/campana_fp/C-05/informe.txt -out /home/angel/Documentos/campana_fp/C-05/informe.txt.enc -pass pass:demo-c05`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-05 && openssl enc -d -aes-256-cbc -pbkdf2 -in /home/angel/Documentos/campana_fp/C-05/informe.txt.enc -out /home/angel/Documentos/campana_fp/C-05/informe.txt.rec -pass pass:demo-c05`
5. `comando` — `cd /home/angel/Documentos/campana_fp/C-05 && sha256sum /home/angel/Documentos/campana_fp/C-05/informe.txt /home/angel/Documentos/campana_fp/C-05/informe.txt.rec > /home/angel/Documentos/campana_fp/C-05/huellas.txt`
6. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-05 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-05/hecho.txt && cat /home/angel/Documentos/campana_fp/C-05/huellas.txt >> /home/angel/Documentos/campana_fp/C-05/hecho.txt`
7. `fin` — `cd /home/angel/Documentos/campana_fp/C-05 && rm -f /home/angel/Documentos/campana_fp/C-05/informe.txt /home/angel/Documentos/campana_fp/C-05/informe.txt.enc /home/angel/Documentos/campana_fp/C-05/informe.txt.rec /home/angel/Documentos/campana_fp/C-05/huellas.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-05/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-06 · Limpio temporales y destruyo un borrador

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:25:30** |
| Binarios | `rm`, `shred` |
| Se confunde con | ATA003 (T1490); ATA005 (T1561) |
| `rule_id` pre-registrados | `80792`, `80791` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x2 + 80791 L3 x2-6** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-06/`) |
| Evidencia de efecto | hecho.txt con el tamano previo y borrador_ausente=1 tras shred |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Borrar temporales y destruir un borrador con datos personales es lo que recomienda cualquier manual de proteccion de datos. Los dos objetos los crea el propio caso. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-06 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-06/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-06 && mkdir -p /home/angel/Documentos/campana_fp/C-06/tmp && echo 'temporal del dia' > /home/angel/Documentos/campana_fp/C-06/tmp/borrador_tmp.txt && echo 'borrador con datos personales' > /home/angel/Documentos/campana_fp/C-06/borrador.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-06 && stat -c %s /home/angel/Documentos/campana_fp/C-06/borrador.txt > /home/angel/Documentos/campana_fp/C-06/antes.txt`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-06 && rm -rf /home/angel/Documentos/campana_fp/C-06/tmp`
5. `comando` — `cd /home/angel/Documentos/campana_fp/C-06 && shred -n 1 -z -u /home/angel/Documentos/campana_fp/C-06/borrador.txt`
6. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-06 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-06/hecho.txt && cat /home/angel/Documentos/campana_fp/C-06/antes.txt >> /home/angel/Documentos/campana_fp/C-06/hecho.txt && stat -c %s /home/angel/Documentos/campana_fp/C-06/borrador.txt 2>/dev/null || echo 'borrador_ausente=1' >> /home/angel/Documentos/campana_fp/C-06/hecho.txt`
7. `fin` — `cd /home/angel/Documentos/campana_fp/C-06 && rm -f /home/angel/Documentos/campana_fp/C-06/antes.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-06/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-07 · Sincronizo los informes con la carpeta de copias

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:33:10** |
| Binarios | `rsync` |
| Se confunde con | ATA039 (T1039); ATA040 (T1074.002) |
| `rule_id` pre-registrados | `80792`, `80790`, `80791` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x1 (+ 80790/80791 L3 por fichero)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-07/`) |
| Evidencia de efecto | hecho.txt con du -sb de origen y destino (iguales) y ls de destino |
| Coste · disco | 3 min · <1 MB |
| Por qué es legítimo | Sincronizar la carpeta de informes con la de copias es lo que hace cualquiera que haya perdido un fichero una vez. Origen y destino son del caso; `--delete` solo afecta a `C-07/destino/`. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-07 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-07/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-07 && mkdir -p /home/angel/Documentos/campana_fp/C-07/origen /home/angel/Documentos/campana_fp/C-07/destino && echo 'informe uno' > /home/angel/Documentos/campana_fp/C-07/origen/informe_1.txt && echo 'informe dos' > /home/angel/Documentos/campana_fp/C-07/origen/informe_2.txt && echo 'copia obsoleta' > /home/angel/Documentos/campana_fp/C-07/destino/obsoleto.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-07 && rsync -a --delete /home/angel/Documentos/campana_fp/C-07/origen/ /home/angel/Documentos/campana_fp/C-07/destino/`
4. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-07 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-07/hecho.txt && du -sb /home/angel/Documentos/campana_fp/C-07/origen /home/angel/Documentos/campana_fp/C-07/destino >> /home/angel/Documentos/campana_fp/C-07/hecho.txt && ls -la /home/angel/Documentos/campana_fp/C-07/destino >> /home/angel/Documentos/campana_fp/C-07/hecho.txt`
5. `fin` — `cd /home/angel/Documentos/campana_fp/C-07 && rm -rf /home/angel/Documentos/campana_fp/C-07/origen /home/angel/Documentos/campana_fp/C-07/destino && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-07/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-08 · Normalizo el CSV del informe

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d2` · **17:41:20** |
| Binarios | `sed` |
| Se confunde con | ATA006 (T1565); ATA032 (T1565.001); ATA026 (T1565.002); ATA017 (T1657) |
| `rule_id` pre-registrados | `80792`, `80790`, `80791` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x2 (+ 80790/80791 L3 temporal)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-08/`) |
| Evidencia de efecto | hecho.txt con la cabecera con comas y grep -c ';' = 0 |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Cambiar el separador de un CSV exportado para poder abrirlo es la operacion ofimatica mas comun que existe. La copia es propia; el original del informe no se toca. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-08 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-08/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-08 && echo 'referencia;area;importe' > /home/angel/Documentos/campana_fp/C-08/export.csv && echo 'A-01;compras;1200' >> /home/angel/Documentos/campana_fp/C-08/export.csv && echo 'A-02;ventas;980' >> /home/angel/Documentos/campana_fp/C-08/export.csv`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-08 && sed -i 's/;/,/g' /home/angel/Documentos/campana_fp/C-08/export.csv`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-08 && sed -n '1,5p' /home/angel/Documentos/campana_fp/C-08/export.csv > /home/angel/Documentos/campana_fp/C-08/export_normalizado.txt`
5. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-08 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-08/hecho.txt && head -1 /home/angel/Documentos/campana_fp/C-08/export.csv >> /home/angel/Documentos/campana_fp/C-08/hecho.txt && grep -c ';' /home/angel/Documentos/campana_fp/C-08/export.csv >> /home/angel/Documentos/campana_fp/C-08/hecho.txt || true`
6. `fin` — `cd /home/angel/Documentos/campana_fp/C-08 && rm -f /home/angel/Documentos/campana_fp/C-08/export.csv /home/angel/Documentos/campana_fp/C-08/export_normalizado.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-08/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-09 · La intranet no responde: acoto el tiempo y reintento

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:11:00** |
| Binarios | `curl`, `timeout` |
| Se confunde con | ATA025 (T1496.001); ATA009 (T1567); ATA010 (T1041); ATA020 (T1020); ATA023 (T1496.002); ATA028 (T1056.003); ATA041 (T1048.002); ATA050 (T1567.003) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x4** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-09/`) |
| Evidencia de efecto | hecho.txt con HTTP=200, RC_FALLO=7 y RC_REINTENTO=0 |
| Coste · disco | 3 min · <1 MB |
| Por qué es legítimo | Cuando una web interna no carga, el usuario acota el tiempo de espera, comprueba si el puerto responde y reintenta. Solo GET a la intranet local y a un puerto cerrado (8081); no se toca ningun servicio. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-09 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-09/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-09 && curl -sS --max-time 3 -o /home/angel/Documentos/campana_fp/C-09/intranet.html -w '%{http_code}\n' http://intranet.local:8080/ > /home/angel/Documentos/campana_fp/C-09/http_code.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-09 && curl -sS --max-time 2 http://intranet.local:8081/ 2>/dev/null || printf 'RC_FALLO=%s\n' $? > /home/angel/Documentos/campana_fp/C-09/fallo_rc.txt`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-09 && timeout 5 curl -sS -o /home/angel/Documentos/campana_fp/C-09/reintento.html http://intranet.local:8080/ && echo 'RC_REINTENTO=0' > /home/angel/Documentos/campana_fp/C-09/reintento_rc.txt`
5. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-09 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-09/hecho.txt && cat /home/angel/Documentos/campana_fp/C-09/http_code.txt /home/angel/Documentos/campana_fp/C-09/fallo_rc.txt /home/angel/Documentos/campana_fp/C-09/reintento_rc.txt >> /home/angel/Documentos/campana_fp/C-09/hecho.txt && wc -c /home/angel/Documentos/campana_fp/C-09/intranet.html >> /home/angel/Documentos/campana_fp/C-09/hecho.txt`
6. `fin` — `cd /home/angel/Documentos/campana_fp/C-09 && rm -f /home/angel/Documentos/campana_fp/C-09/intranet.html /home/angel/Documentos/campana_fp/C-09/reintento.html /home/angel/Documentos/campana_fp/C-09/http_code.txt /home/angel/Documentos/campana_fp/C-09/fallo_rc.txt /home/angel/Documentos/campana_fp/C-09/reintento_rc.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-09/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-10 · Preparo el lote de plantillas del mes

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:19:30** |
| Binarios | `seq`, `xargs`, `cp` |
| Se confunde con | ATA046 (T1499.003); ATA047 (T1499.002) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x14 (1 seq, 1 xargs, 12 cp)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-10/`) |
| Evidencia de efecto | hecho.txt con el tamano de lote_12.txt y las 12 rutas |
| Coste · disco | 4 min · <1 MB |
| Por qué es legítimo | Generar N copias numeradas de una plantilla es una operacion de lote corriente. `xargs` va con `-a fichero` (no con pipe: el validador lo prohibe y DT9 demostro que GHOSTS pierde el reporte); la plantilla la crea el propio caso. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-10 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-10/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-10 && echo 'plantilla del informe del mes' > /home/angel/Documentos/campana_fp/C-10/plantilla.txt && seq 1 12 > /home/angel/Documentos/campana_fp/C-10/lotes.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-10 && xargs -a /home/angel/Documentos/campana_fp/C-10/lotes.txt -I{} cp /home/angel/Documentos/campana_fp/C-10/plantilla.txt /home/angel/Documentos/campana_fp/C-10/lote_{}.txt`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-10 && wc -l /home/angel/Documentos/campana_fp/C-10/lote_1.txt > /home/angel/Documentos/campana_fp/C-10/lote1_wc.txt`
5. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-10 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-10/hecho.txt && stat -c %s /home/angel/Documentos/campana_fp/C-10/lote_12.txt >> /home/angel/Documentos/campana_fp/C-10/hecho.txt && ls -l /home/angel/Documentos/campana_fp/C-10/lote_*.txt >> /home/angel/Documentos/campana_fp/C-10/hecho.txt`
6. `fin` — `cd /home/angel/Documentos/campana_fp/C-10 && rm -f /home/angel/Documentos/campana_fp/C-10/lote_*.txt /home/angel/Documentos/campana_fp/C-10/lotes.txt /home/angel/Documentos/campana_fp/C-10/plantilla.txt /home/angel/Documentos/campana_fp/C-10/lote1_wc.txt && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-10/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-11 · Dejo constancia de la incidencia en el registro

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:27:10** |
| Binarios | `logger`, `tee` |
| Se confunde con | ATA018 (T1056.001) |
| `rule_id` pre-registrados | `80792` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x2 (y 0 por syslog 40700)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-11/`) |
| Evidencia de efecto | hecho.txt con tail -3 de registro.log (la nota) |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | Anotar en el registro del sistema que se ha cerrado una incidencia es una costumbre extendida. `tee` va con redireccion de entrada (sin pipe). Mide el punto ciego conocido (`40700`, L0) en el plano legitimo. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-11 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-11/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-11 && echo 'C-11: incidencia cerrada; copia del dia revisada' > /home/angel/Documentos/campana_fp/C-11/nota.txt`
3. `comando` — `cd /home/angel/Documentos/campana_fp/C-11 && logger -t ofimatica 'C-11: incidencia cerrada; copia del dia revisada'`
4. `comando` — `cd /home/angel/Documentos/campana_fp/C-11 && tee -a /home/angel/Documentos/campana_fp/C-11/registro.log < /home/angel/Documentos/campana_fp/C-11/nota.txt`
5. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-11 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-11/hecho.txt && tail -3 /home/angel/Documentos/campana_fp/C-11/registro.log >> /home/angel/Documentos/campana_fp/C-11/hecho.txt`
6. `fin` — `cd /home/angel/Documentos/campana_fp/C-11 && rm -f /home/angel/Documentos/campana_fp/C-11/nota.txt /home/angel/Documentos/campana_fp/C-11/registro.log && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-11/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

### C-12 · Descargo el manual con wget

| Campo | Valor |
|---|---|
| Día · hora (UTC) | `d3` · **17:35:40** |
| Binarios | `wget` |
| Se confunde con | ATA008 (T1048); ATA043 (T1567.004) |
| `rule_id` pre-registrados | `80792`, `80791` |
| **Esperado `N ≥ 7`** | **0 alertas** (ningún FP «de verdad») |
| **Esperado `N ≥ 3`** | **80792 L3 x1 (+ 80791 si borra temporales)** (todo `execve` alerta: H-A) |
| ¿Cambia la máquina? | **No** (solo escribe bajo `/home/angel/Documentos/campana_fp/C-12/`) |
| Evidencia de efecto | hecho.txt con el tamano de manual.pdf (> 1000 bytes) |
| Coste · disco | 2 min · <1 MB |
| Por qué es legítimo | El manual de empleado se descarga con la herramienta que haya; `wget` es la alternativa de consola a `curl`. La URL y el fichero son los que la receta ya usa a diario. |

**Comandos literales** (en este orden; las marcas van **primero** y **última**):

1. `inicio` — `cd /home/angel/Documentos/campana_fp && mkdir -p /home/angel/Documentos/campana_fp/C-12 && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-12/inicio.txt`
2. `comando` — `cd /home/angel/Documentos/campana_fp/C-12 && wget -q -O /home/angel/Documentos/campana_fp/C-12/manual.pdf http://intranet.local:8080/descargas/manual_empleado.pdf`
3. `evidencia` — `cd /home/angel/Documentos/campana_fp/C-12 && echo 'RESULTADO=OK' > /home/angel/Documentos/campana_fp/C-12/hecho.txt && stat -c %s /home/angel/Documentos/campana_fp/C-12/manual.pdf >> /home/angel/Documentos/campana_fp/C-12/hecho.txt`
4. `fin` — `cd /home/angel/Documentos/campana_fp/C-12 && rm -f /home/angel/Documentos/campana_fp/C-12/manual.pdf && date -u +%FT%TZ > /home/angel/Documentos/campana_fp/C-12/fin.txt`

**Evidencia:** `hecho.txt` debe contener `RESULTADO=OK` y el predicado de la fila «Evidencia de efecto». Un caso sin `hecho.txt` es `NO_EJECUTADO`, no un 0-alerta.

## Orden, marcas y atribución

- **Por caso (rígido):** `inicio.txt` → preparación y comandos → **evidencia** (`hecho.txt`) → limpieza → `fin.txt`. Nada del caso se ejecuta después de `fin`.
- **Marcas:** `date -u +%FT%TZ > …/inicio.txt` y `…/fin.txt`; **11 × 2 = 22** marcas (22 `execve` de `date`). La acción de inicio crea además la carpeta (`mkdir -p`, 11 `execve` más, declarados).
- **Atribución:** alerta del agente `001` (`victima-linux`) con `timestamp ∈ [ini − 10 s, fin + 60 s]`. Se cuenta **todo** lo que caiga dentro (incluido el keepalive, declarado) y se distingue `audit_exe`/`rule_id` esperados.
- **Evidencia de efecto (obligatoria):** cada caso termina dejando `hecho.txt` con `RESULTADO=OK` y el predicado de su ficha. Sin `hecho.txt` el caso es `NO_EJECUTADO`, no un 0-alerta.
- **Limpieza:** los temporales del caso se borran **antes** de `fin.txt` (van en la misma acción que la marca de fin); solo sobreviven `inicio.txt`, `hecho.txt` y `fin.txt`.

## Volumen declarado (acciones y `execve`)

- **Acciones GHOSTS:** **63** (**22** son marcas `inicio`/`fin`; las otras **41** son preparación de insumos, comandos propios, evidencia y limpieza).
- **`execve` reales (proyección determinista):** **103** (d1 **25** · d2 **34** · d3 **44**).
  Cómo se cuenta: primer token por segmento, sin builtins (cd/echo/printf/true), +12 cp de xargs y +1 curl de timeout. Los *builtins* del shell (`cd`, `echo`, `printf`, `true`) **no** generan `execve`.
- **Hijos declarados:** `cp` ×12, `curl` ×1.
- **Desglose por binario:** `cat 6`, `cp 12`, `crontab 1`, `curl 3`, `date 22`, `du 1`, `free 1`, `grep 2`, `head 1`, `ip 2`, `logger 1`, `ls 2`, `mkdir 13`, `openssl 2`, `rm 12`, `rsync 1`, `sed 2`, `seq 1`, `sha256sum 1`, `shred 1`, `stat 4`, `systemctl 3`, `tail 1`, `tee 1`, `timeout 1`, `wc 4`, `wget 1`, `xargs 1`.
- **B10 lo sella:** esta previsión se compara con lo observado (`nº acciones` y `nº eventos` de `campana_fp.csv`) y se fija en el sello. **No** es una cifra copiada de fuera: sale de los comandos literales del CSV.

## Prerrequisitos en el invitado (T3/E0)

> **Bloqueante:** `~/Documentos/campana_fp/` debe **existir y ser escribible** por
> `angel` **antes de B6**. Todas las acciones empiezan por `cd …/campana_fp…`; si la
> carpeta no existe, el `cd` falla, **no se escribe ninguna marca** y los **11 casos
> se pierden** (`NO_EJECUTADO`). El **deploy (T3)** la crea (`mkdir -p` + propietario
> `angel:angel`) y **E0** lo comprueba. No se borra entre días: las marcas y
> `hecho.txt` viven ahí.

| Comprobación (E0) | Comando | Criterio |
|---|---|---|
| Carpeta de campaña | `test -w /home/angel/Documentos/campana_fp` | rc=0 |
| Binarios (17) | `command -v free systemctl ip crontab openssl rm shred rsync sed curl timeout seq xargs cp logger tee wget` | todos resuelven |
| `crontab` vacío | `crontab -l` | rc=1 («no crontab for angel») |
| Red | `ip -brief addr` · `ip route` | IPv4 `192.168.65.x` · ruta no vacía |
| Intranet | `curl -sS -o /dev/null -w '%{http_code}' http://intranet.local:8080/` | `200` |
| Puerto cerrado | `curl -sS --max-time 2 http://intranet.local:8081/` | rc=7 |
| `logger` | `logger -t ofimatica prueba` + `journalctl -t ofimatica -n 1` | aparece la línea |
| `shred` | `shred --version` | coreutils ≥ 8 |
| `openssl` | `openssl version` | ≥ 1.1.1 (`-pbkdf2`) |
| PDF del manual | `wget -q -O /dev/null http://intranet.local:8080/descargas/manual_empleado.pdf` | descarga > 1 000 bytes |
| Disco | `df -Pk /home/angel/Documentos` | ≥ 40 MB libres (tope declarado) |

> Si falla la carpeta o un binario, **no se arranca B6**: los casos se marcarían
> `NO_EJECUTADO`. Se corrige el deploy y se repite E0.

## Desviaciones respecto del plan (declaradas)

| # | Plan | Artefacto | Por qué |
|---|---|---|---|
| D-1 | «~47-55 acciones» (§5.2.6) | **63** | 11 evidencias + 11 limpiezas + 6 preparaciones, todas declaradas; el número exacto lo fija el CSV y lo sella B10 |
| D-2 | «~59-65 `execve`» (§5.2.6) | **103** | mismos motivos + los 12 `cp` de `xargs` y el `curl` de `timeout`; sigue siendo < 0,01 % de `M`; B10 lo sella |
| D-3 | «`BINARIOS_OK` = 36» (§15.2) | **34** | errata: §5.2.1.5 **prohíbe** `systemctl`/`crontab` en la lista de la receta. Son **34**; **36** es `BINARIOS_CAMPANA` (34 + los 2 de B6), que solo valida la campaña |
| D-4 | no figura en §15.1 | **`campana.py`** (nuevo) | el plan pide «validador de campaña» y generar B6 desde el CSV; se aísla en un módulo para no engordar el generador de la receta |
| D-5 | C-10 copia `informes/informe.txt` | **plantilla propia** (`C-10/plantilla.txt`) | un caso no debe depender de un fichero que crea la receta: prepara su insumo y lo borra |
| D-6 | C-05 con `sha256sum` ×2 | **un solo `sha256sum f1 f2`** | una acción deja las dos huellas; el predicado (iguales) se ve en `hecho.txt` |

> Ninguna desviación cambia el diseño: no añade mutación, ni `sudo`, ni pipes, ni red
> fuera de la intranet local; solo declara el volumen real y dos decisiones de
> implementación.

## Qué NO entra (y por qué)

- **C-04 — «programo mi copia mensual y la quito»** (`crontab` + `crontab -r`): **retirada en v4** por decisión humana. Escribe estado en el `crontab` del usuario, fuera de `campana_fp/`, y la campaña es **no mutante**. Se pierde la única medición legítima de **`2832` (L5)**; se declara como límite (§1.9.4, §17.4). **No se sustituye** por otra escritura de sistema.
- `ps`, `id`, `whoami`, `uname`, `journalctl`: **no aparecen** en el corpus de ataques (no hay ataque con el que confundirlos).
- `passwd`, `useradd`, `mount`, `losetup`, `dd`: exigen root, cambian credenciales o no son actividad de oficina.

## Cómo se comprueba

```bash
python _artefactos/scripts/campana.py --check      # 11 casos, 0 mutación, 22 marcas
python _artefactos/scripts/construir_receta_legitima.py --check   # receta + B6
python _artefactos/scripts/cobertura_exes.py --campana Soporte/Laboratorio/legitimo_72h/campana/campana_casos.csv
```

---

> **Sellado.** El `sha256` de este fichero está en la **primera línea** de
> `campana_casos.csv`. Cualquier cambio en el pre-registro obliga a regenerar ambos
> (`campana.py --docs`) **y a firmarlos otra vez antes de `t0`**.
