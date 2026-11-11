# T2b-1 — controlador v4 + correcciones del tester (evidencia)

> **Bloque:** `windows-legit-prep` · **Plan:** `plan_w3bis.md` v2 `approved_by_human` (`4237a16`).
> **Ejecutado:** 2026-11-10 por `tfg-executor`. **Sin snapshot nuevo, sin ventana, sin ataques,
> sin commits.** VM usada: snapshot **v1** `lab-listo-windows-legit` (revertida al terminar).
> **Sin secretos:** `TFG_GUEST_PW` / `TFG_MANAGER_PW` solo en memoria y borradas al cerrar.

## 1. Correcciones aplicadas

| # | Corrección | Dónde | Cómo se ve |
|---|---|---|---|
| 1 | **Mutex antes de todo** en `-Loop` | `guest/tfg_keepalive_windows.ps1` | el duplicado solo escribe `segunda_instancia`; no hay `arranque` ni `powercfg` del duplicado |
| 2 | **`ts_envio` justo antes del POST**; el sink calcula `delta_s` con él | keepalive + `legit/heartbeat_sink.py` | `delta_ref=ts_envio`; `ts_ciclo`/`ts_utc` = inicio del ciclo |
| 3 | `heartbeat.seq` fuera del manifiesto | `guest/verificar_windows.ps1` | `-Manifiesto` excluye `heartbeat.seq` y `stop.flag` |
| 4 | `stop.flag` borrado tras la parada, fuera del snapshot y en lista negra | keepalive + controlador + verificador | `parada_ordenada`; `STOP_FLAG_EXISTE=False`; `BLACKLIST_STOP_FLAG=1` |
| 5 | §16.1 corregido (raíz, no `logs\`) | `legit/snapshot_windows_legit.md` | nota añadida |

## 2. Prueba 1 — `drytest` 6 fases, VM off y VM on

`DRYTEST_RESULT=PASS` en los dos casos (**0 FALLO**). Extracto del caso **VM on**
(manager apagado a propósito fuera de WE0):

```
=== DRYTEST 2026-11-10T20:26:31Z host=DESKTOP-OIOLOPO vm_windows=on fases=prep,arm,watch,stop,cleanup,status ===
DRYTEST prep PASS_CON_SKIP (ok=8 fallos=0 skip=2)
DRYTEST arm PASS_CON_SKIP (ok=7 fallos=0 skip=3)
DRYTEST watch PASS_CON_SKIP (ok=5 fallos=0 skip=3)
  G-W8 OK hijos_vmtoolsd=0 (latido)
  G-W9 OK powercfg_ok=True (latido)
  G-W10 OK disco_invitado_mb=21304 min=4096 (latido; keepalive exige 500)
  G-W11 SKIP sin armado (latido)
  G-W13 OK HB_EDAD_MIN=1.9 max=12 seq_monotono=True ka_instancias=1 seq=3 ka_pid=2824 parcial=False
  SSH_INVITADO=0
DRYTEST stop PASS_CON_SKIP (ok=1 fallos=0 skip=1)
DRYTEST cleanup PASS_CON_SKIP (ok=4 fallos=0 skip=1)
DRYTEST status PASS_CON_SKIP (ok=10 fallos=0 skip=3)
DRYTEST_RESULT=PASS
```

Caso **VM off**: `DRYTEST_RESULT=PASS` (todos los guardarraíles del invitado `SKIP` por
“VM apagada”, `SSH_INVITADO=0`). El log completo está en `legit/evidencia/drytest.log`.

## 3. Prueba 2 — `arm` dos veces (idempotente)

Manager con `logall_json=no` y `archives.json` **inexistente** antes del primer `arm`.

**1.er `arm`** (sí ejecuta `on`):

```
[2026-11-10T20:34:32Z] [arm] arm: fijando mapa de dias con --t0 2026-11-10
[2026-11-10T20:35:48Z] [arm] arm: logall_json ON verificado (antes=no on_ejecutado=True manager_active=True daemons=2)
[2026-11-10T20:35:48Z] [arm] arm: ventana_actual.json escrito (...)
[2026-11-10T20:35:48Z] [arm] arm OK
```

**Estado de `archives.json` justo antes del 2.º `arm`** (el fichero ya está lleno):

```
-rw-r----- 2 wazuh wazuh 17355877 Nov 10 21:37 /var/ossec/logs/archives/archives.json
mtime=1794343027  sha256=209bf6e6893ae2c5e8e29f5c18a0d5572f2a2d9264bf98548c2a33568edb2e49
lineas=1631
```

**2.º `arm`** (NO ejecuta `on`):

```
[2026-11-10T20:37:35Z] [arm] arm: fijando mapa de dias con --t0 2026-11-10
[2026-11-10T20:38:12Z] [arm] arm: logall_json ya estaba yes -> NO se ejecuta on (archives.json intacto)
[2026-11-10T20:38:13Z] [arm] arm: logall_json ON verificado (antes=yes on_ejecutado=False manager_active=True daemons=2)
[2026-11-10T20:38:13Z] [arm] arm OK
```

**Estado después** (crece por el flujo normal de eventos, **no se recrea**):

```
size=41478963  mtime=1794343223
sha256=df63843a12879b5fe019ad9a302ddd3c74457103cbe5a473231692fa3986ed57
lineas=3229
primera_linea: {"timestamp":"2026-11-10T13:00:13.337+0000", ... "Starting rootcheck scan." ...}
```

La primera línea es **anterior** al 2.º `arm` (13:00 < 20:37) y el número de líneas **crece**
(1631 → 3229): si `on` se hubiera ejecutado, `logall_json_ctl.sh` habría hecho
`rm -f archives.json` y la primera línea sería posterior a 20:38. **No se borró.**

> **Recetas:** `arm` regenera `bloques_windows.env`/`calendario_windows.json` con el mapa
> de días. Tras la prueba se restauraron **byte a byte** a `HEAD` (hash previo = hash final;
> `git status` limpio en `recetas/`; `--check` PASA; espejo 504=504).

## 4. Prueba 3 — `cleanup` sin `crudo.done`

```
[2026-11-10T20:17:58Z] [cleanup] cleanup BLOQUEADO: no existe crudo.done () -> exit 84 (no se apaga logall_json sin copia)
EXIT=84
```

## 5. Prueba 4 — `watch` con latido fresco y con latido viejo

**Fresco** (latido real del bucle, `seq=3`, `ka_instancias=1`):

```
chequeo ok=5 fallos=0 skip=3 :: HB_EDAD_MIN=1.2 SEQ=3 KA_PID=2824 KA_INSTANCIAS=1 SSH_INVITADO=0
SSH_INVITADO=0
EXIT=0
```

**Viejo** (misma línea con `recv_utc`/`ts_envio` retrasados 13 min):

```
ALARMA chequeo ok=4 fallos=1 skip=3 :: G-W13=HB_EDAD_MIN=14.4 max=12 seq_monotono=True ka_instancias=1 seq=3 ka_pid=2824 parcial=False :: HB_EDAD_MIN=14.4 SEQ=3 KA_PID=2824 KA_INSTANCIAS=1 SSH_INVITADO=0
SSH_INVITADO=0
EXIT=60
```

## 6. Prueba 5 — `pytest`

```
399 passed in 31.87s
```

## 7. Chivato: `POST /test` y `delta_s` con `ts_envio`

```
POST /test        -> {"ok":true,"test":true,"len":51}
POST /heartbeat   -> {"ok":true,"cadena":"INICIO","seq":1}
linea             -> ... "ts_ciclo":"2026-11-10T20:18:13Z","ts_utc":"...","ts_envio":"...","recv_utc":"...",
                     "delta_s":0.379,"delta_ref":"ts_envio", ...
```

En el latido real del bucle: `ts_ciclo=20:23:18Z`, `ts_envio=20:23:20Z`, `delta_s=0.557`
(2 s de trabajo del ciclo **fuera** del Δ de reloj).

## 8. FIM del agente `002` (comprobado en el invitado)

`C:\Program Files (x86)\ossec-agent\ossec.conf` → `<syscheck>`:

```
<directories realtime="yes" check_all="yes">C:\lab-attack</directories>
... directorios de sistema ...
<ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>
```

`GHOSTS_CLIENT_MENCIONES=0` · `LAB_LEGIT_MENCIONES=0` ⇒ **no vigila**
`C:\Users\angel\ghosts-client` (ni su raíz ni `logs\`). **No hay que excluir nada.**
T2b-2 solo verificará que siga así tras el deploy 8.3.1.

## 9. Observación para T2b-2 / T4 — `G-W12`

Con **las dos VMs encendidas** (manager + Windows) el host queda con
`AvailableMBytes ≈ 1.409 MB` y `FreePhysicalMemory ≈ 1.446 MB`; `G-W12` (mínimo 1.500 MB)
**aborta `arm`/`watch`** (`exit 51`). En esta tanda el `arm` se ejecutó con el host liberado
(GHOSTS API parada; `AvailableMBytes=1.674 MB`). **No se cambió el umbral.** En T2b-2/T4 hay
que decidir: liberar memoria en el host, subir RAM, o revisar el umbral con justificación.

## 10. Decisiones de implementación (declaradas)

1. **`G-W7` fuera de `arm`.** `arm` es la transición (`no` → `yes`); con `G-W7` dentro, un
   2.º `arm` idempotente se abortaría por exigir `no` fuera de la ventana aunque el 1.º
   acabe de poner `yes` (contradice C-3). `arm` verifica `logall_json` antes/después y no
   ejecuta `on` si ya estaba. `watch`/`cleanup` conservan `G-W7`.
2. **Defender con `Get-MpComputerStatus` no disponible.** En el snapshot v1, con
   `DisableAntiSpyware=1`, el cmdlet devuelve “general error”. Se acepta `DEFENDER_OFF=1`
   solo si `WinDefend=Stopped` **y** `DisableAntiSpyware=1` **y**
   `DisableRealtimeMonitoring=1`; en cualquier otro caso, FALLO. Salida:
   `DEFENDER_RTP=` (n/a), `DEFENDER_SVC=Stopped`, `DEFENDER_POLITICA_OFF=True`.
3. **`stop` acepta `crudo.done` (nuevo) o `cosecha.done` (heredado).** `cleanup` exige
   `crudo.done` (exit 84), como pidió el tester.
4. **`crudo` implementado y no ejecutado** en esta tanda: sin ventana no hay `archives`
   que copiar (y `logall_json off` borra `archives.json`). Se probará en T4.
5. **`prep`**: el manifiesto se compara solo si existe `manifiesto_esperado.json` (lo sella
   T2b-2 con el deploy 8.3.1); si no, `MANIFIESTO=SKIP` declarado (no se inventa).
6. **`stop.flag`** lo borra el propio bucle al salir y el controlador tras la parada; queda
   fuera del manifiesto y en la lista negra (`BLACKLIST_STOP_FLAG=1`).

## 11. Corrección G-7 (T2b-1b): la evidencia no se cura

El `heartbeat.jsonl` de esta carpeta es el **real** (9 líneas, incluidas `ROTA_SEQ` y
`REINICIO_BUCLE`). Las líneas de **prueba manual** (las dos primeras) y los dos `-Once`
de `arm` (líneas 7-8, el defecto F-1) están **declaradas una a una** en
`heartbeat_lineas.md`; no se ha movido nada a un fichero «sintético» para limpiarlo.
La prueba limpia de T2b-1b (tras el arreglo) vive en `../t2b1b/`.

