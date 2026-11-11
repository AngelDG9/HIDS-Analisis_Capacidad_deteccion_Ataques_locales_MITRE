# T2b-2 — deploy 8.3.1, manifiesto sellado y ciclo completo — evidencia

> **Bloque:** `windows-legit-prep` · **Plan:** `plan_w3bis.md` v2 `approved_by_human` (`4237a16`)
> **Ejecución:** 2026-11-11 por `tfg-executor`.
> **Sin ventana de 72 h, sin ataques, sin snapshot nuevo, sin commits.**
> **Sin secretos:** `TFG_MANAGER_PW` solo en memoria de los procesos y borrada al terminar.
> Snapshot usado: **v1** `lab-listo-windows-legit` (7 snapshots, ninguno nuevo).

## 1. Deploy del cliente 8.3.1

```
cliente_origen=D:\TFG-VMs\material-ghosts\client-windows\build-v8.3.1\client
CLIENTE_HOST ghosts_exe=8.2.2.0 sha256=b0c5d33b9a20f8ee77a962f40f3dcd89c59f3dec33f6927249c9d18cefe44dec
CLIENTE_HOST ghosts_domain=8.2.7.90 sha256=e305cf2069e2ef9a16a2b9f10fab05a70ac6f0fef8042766cd52b15cf2eaa312
```

Verificación **en el invitado** (`verificar_version.ps1`):

```
DOMAIN_ASSEMBLY=8.2.0.0
EXE_ASSEMBLY=8.0.0.0
VERSION_SALIO=True
VERSION_STDOUT=... | ghosts:8.0.0.0 [8.2.2.0] | ... | ghosts.domain: 8.2.0.0 | ...
PROCESOS_GHOSTS=0
```

El binario arranca (`--version` devuelve su banner y la tabla de assemblies) y **no queda
ningún `ghosts.exe` vivo**.

Idempotencia (`deploy_apply2.log`):

```
DEPLOY_SKIP=1 payload_sha256=375d545fe85b484a4b3c7cde25dad96ff0bb83a630d2855475cd10435473271b manifest_sha256=62b73b16ffdb0d12fe424f759201e8a81134e335215a6723b8a2adf41a253d65
[2026-11-11T12:59:10Z] apply: SKIP (payload y manifiesto ya desplegados; no se sube ni se re-registran tareas)
```

## 2. Manifiesto sellado

`manifiesto_esperado.json` incluye **304 entradas**: payload + recetas (árbol del cliente),
campaña, `C:\lab-legit\tools`, `hosts` y el descriptor canónico de las 2 tareas.
Excluye `dia_aplicado.txt`, logs del operador, `instance\`, `client.out*`, flags,
`heartbeat.seq` y el `config\timeline.json` activo.

```
MANIFIESTO_ESPERADO_SHA256=2a4a6093a0bae1e3488d7ab70726c9d50545b9858bcbd4a40d080230dea85292
MANIFEST_FILES=304
MANIFEST_SHA256=62b73b16ffdb0d12fe424f759201e8a81134e335215a6723b8a2adf41a253d65
```

Prueba negativa (alterar `nlog.config` del payload en el invitado, append de una línea):

```
MANIFIESTO_SNAPSHOT=DIFIERE
[2026-11-11T13:00:13Z] [prep] prep -SoloManifiesto FALLO: manifiesto DIFIERE (esperado=62b73b16... actual=5f742cfc...) -> exit 46
EXIT=46
```

Restaurado el fichero desde la copia:

```
MANIFIESTO_SNAPSHOT=OK
[2026-11-11T13:00:22Z] [prep] prep -SoloManifiesto OK (62b73b16...)
EXIT=0
```

> `-SoloManifiesto` es READ-ONLY y no despliega. En el `prep` normal el `deploy` idempotente
> repara primero el payload; por eso la prueba negativa se hace en modo lectura (si no, el
> propio deploy restauraría la alteración antes de comparar).

## 3. FIM del agente `002` — sin cambios

`ossec.conf` del invitado (`fim_ossec_conf.txt`): las únicas `<directories>` son
`C:\lab-attack`, `%WINDIR%` (con `restrict`), `%WINDIR%\...` y la carpeta Startup.
**Ninguna cubre `C:\Users\angel\ghosts-client` ni `logs\`** ⇒ no se excluye nada y se declara
que **sigue así** (CA-W3b-22). `C:\lab-attack` está vacío y la lista negra lo verifica.

## 4. `prep` completo

```
[2026-11-11T13:52:26Z] [prep] prep: sink OK (POST /test ok len=51)
DEFENDER_OFF=1
SESION_ANGEL=1
LISTA_NEGRA_OK=1
[2026-11-11T13:55:49Z] [prep] prep: gate Defender/sesion OK (DEFENDER_OFF=1 SESION_ANGEL=1)
[2026-11-11T13:55:49Z] [prep] prep: lista negra 7.3 OK (0 residuos)
MANIFIESTO_SNAPSHOT=OK
[2026-11-11T13:55:52Z] [prep] prep: manifiesto OK (62b73b16...)
[2026-11-11T13:55:52Z] [prep] prep OK (NO armado)
EXIT=0
```

Lista negra: **11/11** ítems a 1. `CLIENTE_GHOSTS_DOMAIN_FILEVERSION=8.2.7.90`,
`CLIENTE_GHOSTS_EXE_FILEVERSION=8.2.2.0`.

## 5. `crudo` end-to-end (CRUDO DE PRUEBA, NO DE VENTANA)

Destino: `D:\TFG-VMs\legitimo-windows-2026-11-11\crudo\`.

| Fichero | Bytes | sha256 |
|---|---:|---|
| `archives\archives.json` | 329.013.480 | `1091e8ef3af1878e7aa4c2d743dc53e3bb31e39759deb6705cf66c503547ccb9` |
| `alerts\alerts.json` | 23.518.517 | `ab1932d990ef9a273825122cc42848f40dbfde4bb2b1bb1e5fc839dac9c6cb2a` |

`MANIFEST.tsv` sha256 = `0a0da079ab563aeefd64003538faed285b0d51455c1782a9ed07c2bfa39856c4`.
`crudo.done` escrito (`crudo_utc=2026-11-11T14:00:53Z`, `ficheros=2`, `M_rc=0`).

`M` **de la copia** con `contar_denominador.py --agent-id 002 --estricto`
(unidad = línea de `archives`, CA-W3b-23):

```
1,2,total,34820,2026-11-11T09:16:02Z,2026-11-11T14:00:36Z
1,2,endpoint,30041,2026-11-11T09:18:40Z,2026-11-11T14:00:36Z
```

**M total = 34.820 · endpoint (002) = 30.041.** Es un **crudo de prueba**: cubre solo
`09:16–14:00Z` del 11/11 (arranque del manager en esta tanda), **no** una ventana de 72 h.
No se usa para FPR.

## 6. `stop` y `cleanup`

`stop`:

```
[stop] stop: crudo=crudo.done
[stop] stop: creando stop.flag
[stop] stop: bucle_salio=True (espera <= 6 min)     # 14:01:50 -> 14:05:14 = 3m24s
[stop] sink: (ver heartbeat_sink_ctl.log)
[stop] stop OK (vmrun rc=0)
EXIT=0
```

Prueba negativa de `cleanup` (sin `crudo.done`, renombrado temporalmente):

```
[cleanup] cleanup BLOQUEADO: no existe crudo.done (...) -> exit 84 (no se apaga logall_json sin copia)
EXIT=84
```

`cleanup` real (segunda pasada, con `t1` ya vencido para que G-W7 evalúe el estado final):

```
[cleanup] cleanup: crudo.done presente (...)
[cleanup] cleanup: GHOSTS/PostgreSQL parados (api_procesos=0 postgres_parado=True)
[cleanup] cleanup: logall_json=no verificado
[cleanup] cleanup: CONFIG_IDENTICA
[cleanup] cleanup: guardarrailes fallos=0 victima_windows_off=True victima_linux_off=True manager_on=True
EXIT=0
```

> **Nota honesta:** la primera pasada de `cleanup` (con `t1=23:59:59Z`) terminó `EXIT=0`
> con `fallos=1`; el fallo era **G-W7** (`logall_json=no` con `now` dentro de la ventana
> sintética de prueba, que exige `yes`). No es un fallo funcional: `logall_json=no` y
> `CONFIG_IDENTICA` se verificaron igual. La segunda pasada con `t1` vencido da `fallos=0`.

**El `archives` se copió antes de apagarse** (`prefijo_archives_antes_off.txt`): el manager
tenía **335.125.787** bytes antes del `off`; los primeros **329.013.480** bytes hashean
exactamente igual que el crudo (`1091e8ef...`). Es decir, el crudo es un **prefijo exacto**
del archivo vivo ⇒ la copia precede al apagado.

## 7. `pytest`

```
399 passed in 47.14s
```

## 8. Cierre

- **0 VMs** (Windows y manager apagadas al final).
- Sink `:9095` **parado**; GHOSTS API **0 procesos**; PostgreSQL **sin respuesta** (`pg_rc=2`).
- **0 tareas `TFG-*`** en el host.
- `logall_json=no` y `CONFIG_IDENTICA` en el manager.
- Variables `TFG_MANAGER_PW` / `TFG_GUEST_PW` **no presentes**; `SECRET_HITS=0`.

## 9. Cambios de código (mínimos, declarados)

| Fichero | Cambio |
|---|---|
| `deploy_windows.ps1` | parámetro `-ClienteDir`; **defecto = build 8.3.1**; log de versión/sha256 del cliente de origen. |
| `guest/verificar_windows.ps1` | `-Manifiesto` amplía la huella a payload+recetas+campaña+`tools`+`hosts`+2 tareas; `-Detalle` emite `MFILE`; emite `CLIENTE_*` (versión/sha256). |
| `windows_legit_host_control.ps1` | `Test-ManifiestoEsperado` (READ-ONLY), `prep -SoloManifiesto`, línea `MANIFIESTO_SNAPSHOT=OK|DIFIERE`; `crudo` separa los dos `sudo` del staging (el `sudo1 && sudo2` fallaba sin credenciales encadenadas) y registra el stderr de `scp`. |
| `manifiesto_snapshot.ps1` | **nuevo**, sella `manifiesto_esperado.json` + `.sha256`. |
