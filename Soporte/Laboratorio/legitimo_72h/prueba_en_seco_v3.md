# `prueba_en_seco_v3.md` — pruebas en seco del bloque `legitimo-v3`

> **Tanda final (tras cerrar H-1).** Dos pruebas **reales** sobre el **`lab-listo-legit-v3`
> provisional (`Snapshot6`)**, con `prep` y la pila completa (manager + GHOSTS + internet
> local). Horas **UTC**. Salida **literal recortada**. Artefactos de apoyo (fuera del repo):
> `%TEMP%\opencode\h1_d1.uno.json`, `h1_b6.json`, `h1_evidencia\campana_fp\`,
> `h1_ventanas.tsv`, `h1_acciones_raw.tsv`, `alertas_b6.csv`, `h1_campana_fp.csv`.
>
> **Cronología (D-3):** estas pruebas se ejecutaron sobre el **v3 provisional**, que se
> **borró** al recrear `v3` con los artefactos corregidos (**`Snapshot7`**, 2026-10-28
> 03:47:51). El **v3 final** se reconstruyó desde `v2` con **el mismo deploy** (idempotente)
> y se verificó aparte (`verificar_arreglos` **PASS**, `snapshot_v3.md`); **E0 repetirá P1/P2
> sobre el `v3` final** antes de la ventana. Lo que aquí se valida es el **contenido**
> (comandos, conteos, marcas y `cwd`), no la identidad del snapshot que estaba montado.
>
> **Disciplina:** entre el inicio y el fin de cada prueba **no se abrió ninguna sesión SSH
> a la víctima** (evidencia: `/var/log/auth.log`). El `prep`, la colocación de la timeline
> y la recogida son anteriores/posteriores a la ventana de la prueba.

## Preparación común

```powershell
# prep (por prueba): T0 falso + -Test (solo omite G-10-WU; NO registra tareas ni toca WU)
powershell -NoProfile -ExecutionPolicy Bypass -File `
  Soporte\Laboratorio\legitimo_72h\legitimo_host_control.ps1 `
  -Phase prep -T0 2026-10-28T00:00:00Z -T1 2026-10-31T00:00:00Z -Test

# cierre (por prueba)
... -Phase stop    -T0 2026-10-28T00:00:00Z -T1 2026-10-31T00:00:00Z
... -Phase cleanup -T0 2026-10-28T00:00:00Z -T1 2026-10-31T00:00:00Z
```

- `lab-listo-legit-v3` **provisional (`Snapshot6`)** verificado (`snapshot_v3.md`); `lab-listo-legit-v2` **intacto**.
  El `v3` final (`Snapshot7`) se reconstruyó después y se verificó aparte (ver D-3 arriba).
- El *dry* de la receta (`--dry`) reparte la jornada en **5 handlers comprimidos**; GHOSTS
  llama a `WorkingHours.Is()` antes de cada evento y, al pasar `UtcTimeOff`, duerme hasta el
  día siguiente. En modo comprimido eso **trunca la cola** de cada bloque (artefacto del dry,
  **no** de la receta real de 8 h). Para P1 se aplana la misma secuencia en **un handler** con
  ventana amplia (`comprimir_timeline_prueba.py`): mismos comandos y mismos huecos.

---

## P1 — jornada del día 1 (147 acciones, **sin B6**)

> **Precisión (D-3):** esto es la **jornada** del día 1 (`--dry`, 147 acciones), **no** el
> `d1.json` completo: el `d1` real son **163** acciones (147 de jornada + **16 de B6**).
> La campaña `B6` se probó **aparte** en P2. El título anterior («día 1 completo») era
> inexacto.

**Timeline:** `h1_d1.uno.json` (147 acciones de jornada, `01:49:00`→`01:55:33`, 393 s).
**Ventana real:** `2026-10-28T01:49:00Z` → `01:55:33Z` (setup `01:46:52Z`, parada `01:59:04Z`).

### Comandos

```powershell
python _artefactos\scripts\construir_receta_legitima.py --dry --day 1 --base 01:49Z --out h1_d1.dry.json
python _artefactos\scripts\comprimir_timeline_prueba.py --in h1_d1.dry.json --base 01:49Z --out h1_d1.uno.json
# scp -> victima:/tmp ; cp a config/timeline.json ; client_ctl.sh start
# ... 01:49:00-01:55:33: NADA se toca en el invitado ...
# client_ctl.sh stop (01:59:04Z) y recogida
```

### Resultados

| # | Comprobación | Veredicto | Evidencia |
|---|---|---|---|
| P1-1 | **147 acciones** | **PASA** | `Spawning bash` = **147**; `Command line:` = **147**; audit `data.audit.exe=bash` = **147** |
| P1-2 | **147/147 reportadas a la BD** | **PASA (H-1 cerrado)** | `select count(*) from history_timeline` = **147**; multiconjunto `faltan=0 sobran=0` |
| P1-3 | **`exit≠0` no corta la ráfaga** | **PASA** | 10 fallos + 10 reintentos en `errores.log`; siguen ejecutándose acciones (147 `Spawning`) |
| P1-4 | **12 binarios nuevos existen y corren** | **PASA** | `command -v` 12/12; audit: `xargs:37`, `timeout:4`, `sed:9`, `ip:1`, `openssl:1`, `tee:1`, `free:1`, `logger:1`, `seq:1`, `rsync:21`, `shred:22`, `wget:1` |
| P1-5 | **`errores.log`: 20 líneas × 5 campos TAB** | **PASA** | `wc -l` = **20**; `awk -F'\t' 'NF!=5'` = **0**; 4 TAB por línea |
| P1-6 | **`cwd` real** | **PASA** | 13 `cwd` distintos; `cwd_ghosts_client=0` |
| P1-7 | **`watch` sin AVISO con huecos ≤ 21 min** | **PASA** | 21 min → `OK`; 26 → `AVISO`; 36 → `ALARMA` (misma versión del script; prueba hecha en esta tanda) |
| P1-8 | **0 accesos del host durante la prueba** | **PASA** | `auth.log`: setup **01:43/01:46** y recogida **01:59**; nada en `[01:49:00, 01:55:33]` |

### Salidas clave (literales)

```text
# comparación multiconjunto timeline (147) vs history_timeline (147)
timeline 147 db 147 faltan 0 sobran 0
db_con_pipe 0

$ wc -l < ~/Documentos/errores.log
20
$ awk -F'\t' 'NF!=5{n++} END{print n+0}' ~/Documentos/errores.log
0
$ head -1 ~/Documentos/errores.log | cat -A
2026-10-28T01:49:09Z^Ierror^Iruta_mal^Ils -la /home/angel/Documentos/informe^Irc=2$
$ tail -1 ~/Documentos/errores.log | cat -A
2026-10-28T01:54:38Z^Ireintento^Igzip^Igzip -kf /home/angel/Documentos/informes/informe.bak^Irc=0$
```

```text
# archives (agente 001), ventana [01:48:30, 01:56:00]
eventos_audit=668
binarios=... bash:147 ... xargs:37 timeout:4 sed:9 ip:1 openssl:1 tee:1 free:1
         logger:1 seq:1 rsync:21 shred:22 wget:1 ...
cwd_distintos=13
  cwd=/home/angel n=193
  cwd=/home/angel/Documentos/informes n=140
  cwd=/var/ossec n=108
  cwd=/home/angel/Descargas n=61
  cwd=/home/angel/Documentos n=20
  cwd=/home/angel/Documentos/copias/informes n=20
  cwd=/home/angel/Documentos/actas n=13
  cwd=/home/angel/Documentos/copias n=11
  cwd=/home/angel/Documentos/correo n=7
  cwd=/home/angel/.cache/tfg-web n=3
  ...
cwd_ghosts_client=0
```

```text
# watch (misma versión; una pasada real por umbral, con doing_age simulado por SQL y restaurado)
[00:46:06Z] estado=OK     doing_age=21m bloque=si ... notas=
[00:46:12Z] estado=AVISO  doing_age=26m bloque=si ... notas=doing>25m
[00:46:18Z] estado=ALARMA doing_age=36m bloque=si ... notas=doing>35m
# (el fichero ALARMA_...txt generado por la prueba se borró)
```

---

## P2 — campaña `B6` completa (3 días comprimidos)

**Timeline:** `h1_b6.json` — 1 handler, **63 acciones**, **11 casos**, **22 marcas**,
`02:02:00Z` → `02:40:05Z` (2285 s), separación entre casos **190 s** (> 180).
**Ventana real:** `02:02:00Z` → `02:40:05Z` (setup `01:59:18Z`, parada `02:42:11Z`).
Comandos extraídos de `d1/d2/d3.json` y verificados contra `campana.acciones_b6()`.

### Comandos

```powershell
python _artefactos\scripts\prueba_b6_comprimida.py --base 02:02Z --out h1_b6.json
# scp -> victima:/tmp ; cp a config/timeline.json ; client_ctl.sh start
# ... 02:02:00-02:40:05: NADA se toca en el invitado ...
# client_ctl.sh stop (02:42:11Z); scp -r Documentos/campana_fp -> host; extracción
python _artefactos\scripts\extraer_campana.py --solo-ventanas --evidencia <ev>\campana_fp --out h1_ventanas.tsv
# export por acción de history_timeline (63 filas) + alertas 80792 de Wazuh
python _artefactos\scripts\extraer_campana.py --ventanas h1_ventanas.tsv --acciones h1_acciones_raw.tsv `
    --alertas alertas_b6.csv --evidencia <ev>\campana_fp --out h1_campana_fp.csv
python _artefactos\scripts\extraer_campana.py --test
```

### Resultados

| # | Comprobación | Veredicto | Evidencia |
|---|---|---|---|
| P2-1 | **11 casos ejecutados** | **PASA** | 11 carpetas `C-*`; `Spawning bash` del bloque = **63** |
| P2-2 | **22 marcas con UTC** | **PASA** | `n_marcas=22`; `formato_mal=0` (ISO `…T..:..:..Z`) |
| P2-3 | **11 `hecho.txt` con `RESULTADO=OK`** | **PASA** | `grep -rl 'RESULTADO=OK' …/hecho.txt \| wc -l` = **11** |
| P2-4 | **`campana_fp/` solo con los 33 ficheros** | **PASA** | `find … -type f \| wc -l` = **33** (11 × `inicio/fin/hecho`) |
| P2-5 | **`n_acciones` correcto** | **PASA** | C-03=**5**, C-06=**7**, C-08=**6**, C-09=**6**; total **63** |
| P2-6 | **`campana_ventanas.tsv` + tabla por caso** | **PASA** | 11 casos / 22 marcas; **11/11 `esperado_cumplido=SI`**, `level=3` (`80792`) |
| P2-7 | **`extraer_campana.py --test`** | **PASA** | `autotest: OK` |
| P2-8 | **0 accesos del host durante la prueba** | **PASA** | `auth.log`: setup **01:59:18Z**, fin **02:40:05Z**, recogida **02:42:11Z** |
| P2-9 | **No mutación** | **PASA** | `crontab -l` → `no crontab for angel`, rc=1 (igual que antes) |

### Salidas clave (literales)

```text
C-01 ini=2026-10-28T02:02:00Z fin=2026-10-28T02:02:40Z
C-02 ini=2026-10-28T02:05:50Z fin=2026-10-28T02:06:19Z
C-03 ini=2026-10-28T02:09:29Z fin=2026-10-28T02:09:58Z
C-05 ini=2026-10-28T02:13:08Z fin=2026-10-28T02:13:53Z
C-06 ini=2026-10-28T02:17:03Z fin=2026-10-28T02:17:48Z
C-07 ini=2026-10-28T02:20:58Z fin=2026-10-28T02:21:27Z
C-08 ini=2026-10-28T02:24:37Z fin=2026-10-28T02:25:13Z
C-09 ini=2026-10-28T02:28:23Z fin=2026-10-28T02:29:05Z
C-10 ini=2026-10-28T02:32:15Z fin=2026-10-28T02:32:51Z
C-11 ini=2026-10-28T02:36:01Z fin=2026-10-28T02:36:38Z
C-12 ini=2026-10-28T02:39:48Z fin=2026-10-28T02:40:07Z
```

```text
$ extraer_campana.py --ventanas h1_ventanas.tsv --acciones h1_acciones_raw.tsv --alertas alertas_b6.csv ...
acciones: columna 'createdutc' -> {'C-01': 6, 'C-02': 5, 'C-03': 5, 'C-05': 7, 'C-06': 7,
 'C-07': 5, 'C-08': 6, 'C-09': 6, 'C-10': 6, 'C-11': 6, 'C-12': 4} (sin_timestamp=0)
alertas: C-01=49, C-02=44, C-03=47, C-05=60, C-06=69, C-07=48, C-08=56, C-09=56, C-10=109,
 C-11=54, C-12=38
casos=11 · NO_EJECUTADO=0 [] · esperado_no=0 []
RESULT=PASS
```

| Caso | `n_acciones` | alertas | `rule_id` | `level` | `esperado_cumplido` |
|---|---|---|---|---|---|
| C-01 | 6 | 49 | 80780;80791;80792 | 3 | **SI** |
| C-02 | 5 | 44 | 80780;80791;80792 | 3 | **SI** |
| C-03 | **5** | 47 | 80780;80791;80792 | 3 | **SI** |
| C-05 | 7 | 60 | 80780;80791;80792 | 3 | **SI** |
| C-06 | **7** | 69 | 80780;80791;80792 | 3 | **SI** |
| C-07 | 5 | 48 | 80780;80791;80792 | 3 | **SI** |
| C-08 | **6** | 56 | 80780;80791;80792 | 3 | **SI** |
| C-09 | **6** | 56 | 80780;80791;80792 | 3 | **SI** |
| C-10 | 6 | 109 | 80780;80791;80792 | 3 | **SI** |
| C-11 | 6 | 54 | 80780;80791;80792 | 3 | **SI** |
| C-12 | 4 | 38 | 80780;80791;80792 | 3 | **SI** |

```text
$ cat C-03/hecho.txt          $ cat C-06/hecho.txt
RESULTADO=OK                  RESULTADO=OK
18 …/timers.txt               30
crontab_rc=1                  borrador_ausente=1

$ cat C-08/hecho.txt          $ cat C-09/hecho.txt
RESULTADO=OK                  RESULTADO=OK
referencia,area,importe       200
0                             RC_FALLO=28
                              RC_REINTENTO=0
                              1749 …/intranet.html
```

---

## Hallazgos y desviaciones

| # | Qué | Estado |
|---|---|---|
| **H-1** | **GHOSTS no reportaba comandos con `\|`**. La API parte cada línea de resultado por `\|` (`QueueSyncService.cs:178`); los 10 errores/día usaban `\|\|` ⇒ 137/147. **Corregido**: receta (`pareja_error`) y campaña (C-03/06/08/09) reescritas sin `\|`; `[` es builtin (0 `execve`); validador rechaza cualquier `\|`. **Verificado: 147/147** (`faltan=0 sobran=0`, `db_con_pipe=0`). | **CERRADO** |
| **H-2** | El `--dry` de 5 handlers trunca colas al cruzar `UtcTimeOff` (142/147). | **Solo prueba**: se aplana en 1 handler (`comprimir_timeline_prueba.py`) → 147/147. No afecta a la ventana real. |
| **H-3** | C-09 devuelve **`RC_FALLO=28`** (timeout), no `7` (refused): el 8081 cerrado está **filtrado**. | **Declarado** en `casos.md`: se acepta `7` **o** `28`. La evidencia real dio `28`. |
| **H-4** | Huella de timeline rota con el JSON compacto del cliente (`Command[^:]*:` + `:` en comandos). | **Corregido** en `verificar_arreglos.sh` y `tfg_keepalive.sh`; probado con timeline compacta → `PASS`. |
| **H-5** | La primera pasada de P1 (T3 inicial) se hizo con PostgreSQL caído (el proceso murió al matar la sesión de `prep` colgada). | **Solo de la prueba**; las pasadas válidas se hicieron con la pila estable (`pg_isready` OK). |
| **D-1** | `prep` con **`-Test`** para no tocar Windows Update (T4). `-Test` **solo** salta G-10-WU. | Declarado. |
| **D-2** | `watch` con `-Test -ForzarBloque` (switches que **no** viajan a la ventana). | Declarado. |
| **D-3** | `doing_age` 21/26/36 min **simulado** desplazando `createdutc` y restaurado (máx. vuelta a `00:42:34`). | Declarado. |

## Estado final

```text
Total running VMs: 0
<logall_json>no</logall_json>
CONFIG_IDENTICA
Total snapshots: 6
  base-limpia / lab-listo / lab-listo-legit / fallo-…-NO-USAR /
  lab-listo-legit-v2 (INTACTO) / lab-listo-legit-v3 (recreado)
Tareas TFG-Legit-*: 0
Reglas de firewall TFG-*: 0
```

- `cleanup` con la víctima ya apagada: `victima_en_marcha=False` y **fase remota omitida sin
  SSH** (**H1(c)**), sin el hueco de 3 min.
- La VM quedó **revertida a `lab-listo-legit-v3`** y apagada.

## Referencias a `lab-listo-legit-v2` que quedan (y por qué)

- **`legitimo_host_control.ps1`**: actualizado a **v3** (`$Snap` y G-1).
- **`prueba_en_seco.ps1`** (suite **histórica** de `legitimo-fix`): su `DT12` **crea y revierte a
  `lab-listo-legit-v2`**. **No se ha tocado**; **no ejecutar `DT12`**.
- Comentarios de `verificar_arreglos.sh` y `limpiar_cliente.sh` que citan `lab-listo-legit` (v1):
  son **contexto histórico**.

## Ficheros de esta tanda y huellas

`sha256sums.txt` actualizado y **verificado entero** (62 entradas, 0 desincronías): incluye la
receta (`d1/d2/d3`, `calendario`, `bloques`, `receta_resumen`), `campana/{campana_casos.csv,casos.md}`,
los scripts de validación/generación, `client_ctl.sh`, `deploy_client.ps1`, `tfg_keepalive.sh`,
`verificar_arreglos.sh`, la unit, `legitimo_host_control.ps1`, `snapshot_v3.md`, este documento,
`prueba_b6_comprimida.py` y `comprimir_timeline_prueba.py`.
