# snapshot_windows_legit.md — snapshot `lab-listo-windows-legit` (W3)

> **⚠ Superado por `lab-listo-windows-legit-v2` (2026-11-12, T4/C6).** Se conserva como
> evidencia histórica y **no se borra**. Ficha nueva:
> `Soporte/Laboratorio/windows/legit/snapshot_windows_legit_v2.md`.
>
> **Bloque:** `windows-legit-prep` (W0), tanda **W3** — despliegue, controlador y snapshot.
> **Plan:** `_fases/windows-legit-prep/plan.md` v2 `approved_by_human` (§7 W3, §16.1).
> **Ejecutado:** 2026-11-10, por `tfg-executor`. **Sin ventana, sin campaña, sin ataques.**
> **Estado:** W3 **PASA** (veredicto al final). Sin secretos: `TFG_GUEST_PW` **borrada** al cerrar.
>
> **Corrección post-tester (2026-11-10).** El tester dio **FALLA acotada**: el snapshot es
> válido y **no se rehace**; fallaban **4 defectos del controlador** (F1–F4). Se han corregido
> y se ha re-ejecutado el `drytest` con la VM encendida y apagada. Ver §5.3 y §5.7.
>
> **Tercera pasada (2026-11-10, mismo día).** El tester volvió a fallar: **F6 (bloqueante)**
> (`G-W7` no usaba `[t0,t1]`), **F5** (`G-W6` solo detectaba gateway `192.168.65.x`), **F7**
> (`G-W5` no comprobaba el agente `002` `Active`) y las deudas **D1–D7**. Corregidos en el
> controlador **v3** (`sha256 220d7c70…a821`) y probados con el **manager encendido**
> (`arm`→`watch`→`cleanup`, §5.8). El snapshot sigue **intacto**. Ver §5.7 y §5.8.
>
> **Nota de ruta (declarada).** El plan §16.1 situaba este documento en
> `Soporte/Laboratorio/windows/`; la orden de la tanda W3 lo pide en
> `Soporte/Laboratorio/windows/legit/`. Manda la orden: está aquí y **no** se duplica.
>
> **§16.1 corregida (T2b-1, 2026-11-10).** El plan §16.1 situaba `keepalive.log` y
> `recovery.log` en `C:\Users\angel\ghosts-client\logs\`. La ruta **real** es la **raíz**
> `C:\Users\angel\ghosts-client\` (junto a `estado.json`, `heartbeat.seq`,
> `heartbeat.jsonl` y `stop.flag`); `logs\` es del cliente GHOSTS (`app.log`), no del
> keepalive. El `syscheck` del agente `002` **no vigila** `C:\Users\angel\ghosts-client`
> (solo `C:\lab-attack` en realtime y directorios de sistema), así que **no hay que
> excluir nada**; T2b-2 solo comprueba que siga así. `heartbeat.seq` y `stop.flag`
> quedan fuera de la huella del manifiesto y en la lista negra.

---

## 0. Resumen en una tabla

| Qué | Resultado |
|---|---|
| **Snapshot** | `lab-listo-windows-legit` (**7** snapshots; los 6 previos **intactos**) |
| **Contenido** | cliente GHOSTS + `recetas/` + `campana/` + 2 tareas + keepalive + `hosts` + `errores.log` |
| **Deploy** | `deploy_windows.ps1` **idempotente** (**par final** `applyG1/applyG2` = **mismo `sha256`**) y **reversible** (`REVERT_LIMPIO=1`) |
| **Control** | `windows_legit_host_control.ps1` **v3** (`sha256 220d7c70…a821`, F1–F7 + D1–D7) con `prep/arm/watch/stop/cleanup/status/drytest` y **G-W1…G-W12** |
| **Keepalive** | tarea **SYSTEM** cada 5 min; **2 h 0 min 38 s** de funcionamiento; **1 muerte provocada** ⇒ recuperación en **1 ciclo** (2 min 57 s) y `win_user` sigue siendo **`angel`**. ⚠️ **Sin evidencia primaria en el snapshot** (los logs de esa prueba se borraron antes de sellarlo; ver §5.4) |
| **Prueba real con manager** | `arm`→`watch`→`cleanup` (2026-11-10, §5.8): `logall_json=yes` **verificado**, `G-W7 OK` dentro de ventana, `cleanup` `exit 0` con `logall_json=no`, `CONFIG_IDENTICA` y GHOSTS/PostgreSQL parados |
| **Prueba del snapshot** | revert + arranque ⇒ **5/5** (tarea `Ready`, cliente presente, `Sysmon64`/`WazuhSvc` `Running`, `STANDBYIDLE=0`, sin residuos) |
| **Laboratorio** | **0 VMs**, GHOSTS/PostgreSQL parados, **0** tareas `TFG-*` en el host, `TFG_GUEST_PW`/`TFG_MANAGER_PW` borradas |

---

## 1. Qué contiene el snapshot

Creado con la **VM apagada** (`vmrun snapshot`), como los anteriores. Es hijo de
`lab-listo-windows-ataques-gui` (ver §6.1).

### 1.1 Invitado (`victima-windows`, agente `002`)

| Elemento | Ruta / valor |
|---|---|
| **Cliente GHOSTS** | `C:\Users\angel\ghosts-client\ghosts.exe` (+ 285 ficheros: libs, `config/`, `recetas/`, scripts) |
| **Configuración** | `config\application.json` (API `http://192.168.65.1:5000/api`, `DisableStartup=true`) y `nlog.config` (consola WARN, `app.log` 1 MB × 20) |
| **Receta** | `config\timeline.d1/d2/d3.json` (W1) + `config\timeline.json` = **d1** |
| **Fuente de calendario** | `recetas\bloques_windows.env` + `recetas\calendario_windows.json` (misma que el keepalive) |
| **Campaña** | `C:\lab-legit\campana\casos_windows.md` + `campana_windows.csv` (pre-registro W2; los `W-XX` los crea la receta) |
| **Registro de errores** | `C:\Users\angel\Documentos\errores.log` (vacío; la receta escribe TSV) |
| **Alias** | `192.168.65.1 intranet.local nube.local paste.local hook.local` (ya estaba; el deploy lo asegura) |
| **Tarea actividad** | `TFG-WinLegit-Actividad`: usuario **`angel`**, `LogonType=Interactive`, `RunLevel=LeastPrivilege`, **sin disparadores**, `WorkingDirectory=C:\Users\angel`, acción `cmd /c "<cliente> >> client.out 2>&1"` |
| **Tarea keepalive** | `TFG-WinLegit-Keepalive`: **SYSTEM**, cada 5 min, `tfg_keepalive_windows.ps1` |
| **Servicios** | `Sysmon64` y `WazuhSvc` `Running/Automatic` (del snapshot base) |
| **Energía** | `STANDBYIDLE=0`, `HIBERNATEIDLE=0`, `HYBRIDSLEEP=0` (AC y DC) |
| **Windows Update** | `NoAutoUpdate=1`, `wuauserv` **Stopped/Disabled** |
| **Sin residuos** | 0 marcas de campaña, 0 `armado.flag`, 0 procesos `ghosts.exe`, **sin** clave `ghosts` en `HKCU\...\Run` |

### 1.2 Host

- `D:\TFG-VMs\material-ghosts\client-windows\ghosts-client-x64-v8.0.0.zip`
  (54 734 428 B, `sha256=01a58c46cee436d6ba425b8f5e99c9fb4263c0b180f6faeb75c1eb30d2623cf1`).
- No se despliega nada del host dentro de la VM salvo lo listado.

---

## 2. Cliente GHOSTS (procedencia y una discrepancia declarada)

| Dato | Valor |
|---|---|
| Origen | release `v8.3.1` de `cmu-sei/GHOSTS` → enlace **Windows x64** de **CMU Box** (`https://cmu.box.com/s/kqo5cl7f5f2v22xgud6o2fd26xrrwtpq`) |
| Fichero | `ghosts-client-x64-v8.0.0.zip` (54,7 MB) |
| `sha256` (pin **nuestro**) | `01a58c46…623cf1` |
| `ghosts.exe` | `FileVersion 8.2.2.0`, `ProductVersion 8.0.0.0` |

> **Discrepancia declarada (D-W3-2).** El *release* se llama `v8.3.1`, pero el binario que
> sirve CMU Box es **8.0.0/8.2.2** (y el Linux del proyecto es 8.3.1). **No hay toolchain**
> en el host para compilar 8.3.1 (plan D1). Consecuencia: el espejo mantiene **API, tabla
> `history_timeline`, `HandlerType=Command` y unidad «acción»**, pero **no** la igualdad
> exacta de versión. Se declara aquí y debe arrastrarse a B10-W (`cliente_version=8.0.0/8.2.2`).

---

## 3. Scripts (W3) y hashes

| Fichero | `sha256` |
|---|---|
| `Soporte/Laboratorio/windows/deploy_windows.ps1` | `c84395ce9bb0c8ed002dcc7a879ddc20233533e404815e898a5874afa1e4c14c` |
| `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` | `220d7c7078c859ef47a2e5ce6936dec22edf0ba3cee42a18779aadee26f5a821` (v3, F1–F7 + D1–D7; la v2 era `217dc280…bbc4` y la v1 `b19c4eb4…37bd`) |
| `Soporte/Laboratorio/windows/guest/tfg_keepalive_windows.ps1` | `15a82b711d7bd31fabc2c533d6c7b314d51290df67d0dfe68749420d411907f7` |
| `Soporte/Laboratorio/windows/guest/instalar_tareas_windows.ps1` | `762b345eb880c4647b96ef3b1c673b745d4b9aa3c6655997112fe90eb33a9c51` |
| `Soporte/Laboratorio/windows/guest/verificar_windows.ps1` | `0b5cf4b18f0cbd844e90c49a452db2cfd3b30fc1761ccef851328874087c0a2e` |
| `Soporte/Laboratorio/windows/guest/preparar_invitado_windows.ps1` | `8c4fef62234d9704db11a11d4ea633fd11d868c1e7ad45f85ffcb35fa4131a64` |
| `Soporte/Laboratorio/windows/client_config/application.json` | `9dcc856231274636f882bcce4d162960b8f6c506c91405ce9228939621d469b9` |
| `Soporte/Laboratorio/windows/client_config/nlog.config` | `58cb9151938b4e61595b7e43efeee149a3daef36c434f1668cdc6c407dbb3939` |

**Huella del despliegue** (payload completo, sin logs/instance/`client.out`):
`MANIFEST_FILES=296`, `MANIFEST_SHA256=2615e9c3ddb07e9db35e469c62a6c8a7f887c86fab59933f0350652338b4855e`.
**Huella de las tareas** (definición normalizada): `57cb3ecd1e375b975d963e3b1196f965911b50fbc86c775ef933287d5a0f9719`.

---

## 4. Guardarraíles G-W1…G-W12

El plan nombra los doce guardarraíles pero **no los enumera**; se definen aquí, cada uno
atado a un criterio del plan, y se evalúan en `-Phase drytest` y en las fases reales.

| # | Qué comprueba | Criterio |
|---|---|---|
| **G-W1** | tareas `TFG-Baseline-*` del host **desactivadas o ausentes** | R-W1 / CA-W19 |
| **G-W2** | snapshot `lab-listo-windows-legit` **presente** y los 6 previos intactos | CA-W11 |
| **G-W3** | disco del host `D:` ≥ **60 GB** libres | R-W3 |
| **G-W4** | receta `--check` **PASA** + `verificar_espejo.py` (**504 = 504**) + `sha256` de `w1/w2/w3` | CA-W1 / CA-W2 |
| **G-W5** | `Sysmon64` y `WazuhSvc` `Running`; manager `active`; **agente `002` `Active`** (`agent_control -l` en el manager). **F2:** si los servicios del invitado fallan ⇒ **FALLO**, aunque el manager esté apagado; **SKIP solo por el manager**. **F7:** un agente `002` no `Active` ⇒ **FALLO** (nunca SKIP) | WE0-1 |
| **G-W6** | sin **ninguna** ruta por defecto (`Get-NetRoute -DestinationPrefix 0.0.0.0/0` vacío; si no está, regex genérica `0.0.0.0 0.0.0.0 <gw>` sobre `route print`) + alias `intranet.local` + `victima-linux` apagada. **F5:** ya no se asume `192.168.65.x` | W-V5 |
| **G-W7** | `logall_json` **según `[t0,t1]`**: `yes` si `now ∈ [t0,t1]`, `no` si `now` fuera; **sin `-T0/-T1` ⇒ SKIP declarado**. **F6:** espejo de `legitimo_host_control.ps1:510-518`; se aplica en `arm`/`watch`/`status`/`cleanup` | CA-W16 |
| **G-W8** | **0** procesos con padre `vmtoolsd.exe` (sin acceso del operador) | W-V4 / CA-W13 |
| **G-W9** | `STANDBYIDLE`/`HIBERNATEIDLE`/`HYBRIDSLEEP` = 0 | R-W4 |
| **G-W10** | disco del invitado ≥ **4 GB** (el keepalive exige además **500 MB** en cada ciclo) | R-W15 / W-L1 |
| **G-W11** | **exactamente 1** `ghosts.exe` vivo **y** dueño `angel` (lee `WIN_USER=`). **F1:** **SKIP** si no existe `armado.flag` (fuera de ventana); **0 procesos con flag ⇒ FALLO** | CA-W6 |
| **G-W12** | host: RAM libre ≥ **1500 MB** y `wuauserv` del host no `Running` | R-W4 |

**Fase → guardarraíles**: `prep` 10 · `arm` **10** · `watch` **7** · `stop` 2 · `cleanup` 5 · `status` 12.

> **D7 — el `watch` de Windows evalúa 7 guardarraíles, no las 9 señales del plan Linux.**
> Los siete son `G-W5` (servicios + manager + agente `002`), `G-W7` (`logall_json` según
> ventana), `G-W8` (hijos de `vmtoolsd.exe`), `G-W9` (suspensión), `G-W10` (disco del
> invitado), `G-W11` (un solo cliente `angel`) y `G-W12` (RAM/WU del host). Las 9 señales
> de Linux se apoyaban en telemetría que Windows no expone igual (`df` del agente,
> `auditd`, BD de GHOSTS, servicio de internet local); en Windows se sustituyen por la
> guarda local del keepalive (≥ 500 MB) y por el `watch` del host.
>
> **Corrección (2026-11-10, verificación final).** El texto anterior de **W-L1/D7** decía
> que leer el invitado desde el host exigiría `runProgramInGuest` y que por eso **no se
> vigilaba en vivo**. **Es falso y queda enmendado:** el `watch` **sí lee el invitado en
> vivo**, por **SSH** (`Get-Invitado` → `ssh … verificar_windows.ps1`), con ~7 sesiones por
> chequeo (`G-W5/G-W8/G-W9/G-W10/G-W11`). Consecuencias que hay que tratar en **W4**:
> 1. Cada chequeo genera `sshd→powershell→cmd` dentro de la ventana. Es **ruido de
>    operador**, ya tipificado en el catálogo Windows (`60106`/`67024` →
>    `ruido_conocido`); hay que **aplicar el predicado `sin_operador`** al FPR de la
>    ventana legítima o el FPR se infla.
> 2. `G-W8` solo vigila hijos de `vmtoolsd.exe`, **no** las sesiones SSH: no sirve para
>    detectar el ruido anterior (se mide y se declara, no se “arregla” con G-W8).
> 3. La memoria **no puede** publicar “el disco del invitado se lee antes/después, no en
>    vivo”: se publica la lectura por SSH y su ruido declarado.
>
> Esto es **documental**: no cambia el snapshot ni el controlador, y no invalida W3 (no se
> ha ejecutado ninguna ventana).

---

## 5. Pruebas

### 5.1 Idempotencia (2 aplicaciones = mismo `sha256`)

**Par final** (el válido: es el que dejó el snapshot ya con el deploy definitivo; no el
primer par de la sesión, que usaba una versión anterior del payload):

```
applyG1  2026-11-10T11:28:13Z → MANIFEST_FILES=296  MANIFEST_SHA256=2615e9c3…4855e  TAREAS_FINGERPRINT=57cb3ecd…f9719  RESULT=PASS
applyG2  2026-11-10T11:28:44Z → MANIFEST_FILES=296  MANIFEST_SHA256=2615e9c3…4855e  TAREAS_FINGERPRINT=57cb3ecd…f9719  RESULT=PASS
```

> El par inicial (`apply1/apply2`, 08:57–08:58Z) dio `MANIFEST_SHA256=3e3113db…bd22`
> porque el `deploy_windows.ps1` aún cambiaba. **No se usa como prueba de idempotencia**:
> la etiqueta correcta es la del **par final** (`applyG1/applyG2`), que es el que quedó
> dentro del snapshot.
La huella **excluye** lo volátil (`logs\`, `instance\`, `client.out*`, `keepalive.log`,
`recovery.log`, `estado.json`, `armado.flag`, `heartbeat.seq`, `stop.flag`). Dos aplicaciones seguidas también dejan
**el mismo** `RESULT=PASS` en `verificar_windows.ps1`.

### 5.2 Revert limpio (0 residuos)

```
deploy_windows.ps1 -Phase revert
  BORRADO C:\Users\angel\ghosts-client -> existe=False
  BORRADO C:\lab-legit\campana -> existe=False
  BORRADO C:\Users\angel\Documentos\errores.log -> existe=False
  BORRADO_DIR_VACIO … (Documentos\informes, correo, copias, actas, .cache\tfg-web, Documentos, Descargas)
  RESIDUOS=0
  REVERT_LIMPIO=1
```
No toca `C:\lab-legit\tools` (material histórico) ni la línea de `hosts` (existía antes).

### 5.3 `drytest` de cada fase (sin ventana)

**Re-ejecutado tras F1–F7 (2026-11-10 13:08:25Z VM on / 13:10:45Z VM off)** con la VM
revertida a `lab-listo-windows-legit`. Salida literal resumida (0 FALLO en todas las fases):

| Fase | Veredicto | Detalle |
|---|---|---|
| `prep` | **PASS_CON_SKIP** | 8 OK · 0 fallos · 2 SKIP (manager) |
| `arm` | **PASS_CON_SKIP** | 7 OK · 0 fallos · 3 SKIP (manager + `G-W11` sin `armado.flag`) |
| `watch` | **PASS_CON_SKIP** | 4 OK · 0 fallos · 3 SKIP (manager ×2 + `G-W11` sin flag) |
| `stop` | **PASS_CON_SKIP** | 1 OK · 0 fallos · 1 SKIP (manager) |
| `cleanup` | **PASS_CON_SKIP** | 4 OK · 0 fallos · 1 SKIP (manager) |
| `status` | **PASS_CON_SKIP** | 9 OK · 0 fallos · 3 SKIP (manager ×2 + `G-W11` sin flag) |

```
DRYTEST prep PASS_CON_SKIP (ok=8 fallos=0 skip=2)
DRYTEST arm PASS_CON_SKIP (ok=7 fallos=0 skip=3)
DRYTEST watch PASS_CON_SKIP (ok=4 fallos=0 skip=3)
DRYTEST stop PASS_CON_SKIP (ok=1 fallos=0 skip=1)
DRYTEST cleanup PASS_CON_SKIP (ok=4 fallos=0 skip=1)
DRYTEST status PASS_CON_SKIP (ok=9 fallos=0 skip=3)
DRYTEST_RESULT=PASS
```

`DRYTEST_RESULT=PASS` (`exit 0`). Los **SKIP** son solo los guardarraíles que necesitan el
**manager encendido** (`G-W5` y `G-W7`) y `G-W11` **fuera de ventana** (sin `armado.flag`).
El manager está apagado a propósito en W3 y esas comprobaciones se ejercitan en **WE0 (W4)**.

> **D1 — el `drytest` ya se registra.** La salida completa se escribe en
> `legit/evidencia/drytest.log` (versionable: excepción explícita en `.gitignore`, **D3**).
> Antes solo iba a `stdout` y `windows_legit_host_control.log` no se creaba nunca en
> `drytest`. El log final contiene **dos** bloques: `vm_windows=on` y `vm_windows=off`,
> ambos `DRYTEST_RESULT=PASS`.

**Prueba negativa de F1/G-W11 (artefacto reproducible).** Script:
`legit/evidencia/prueba_negativa_GW11.ps1`; salida: `legit/evidencia/prueba_negativa_GW11.txt`.
Con `armado.flag` creado y **0** procesos `ghosts.exe`:

```
PASO 2b flag=FLAG_SI
PASO 3 procesos_ghosts=0
  |   G-W11 FALLO procesos_ghosts=0 vivo=False win_user= dueno_angel=False
  | DRYTEST watch FAIL (ok=4 fallos=1 skip=2)
  | DRYTEST_RESULT=FAIL
PASO 4 drytest_rc=1
PASO 5 borrado_flag rc=0
RESULT=PASS (esperado: exit<>0 + 'G-W11 FALLO' + 'DRYTEST watch FAIL')
```

El `drytest` de esa prueba escribe en un log **aparte**
(`prueba_negativa_GW11_drytest.log`) para no ensuciar `drytest.log`. **Hallazgo declarado:**
las comillas dobles en un comando SSH de Git/MSYS se comen las barras invertidas; por eso el
flag se crea **sin comillas** (la misma forma que usa `Get-FlagArmado`).

**Con la VM apagada** (misma tanda, `exit 0`): `prep` 5 OK/5 SKIP · `arm` 4 OK/6 SKIP ·
`watch` 1 OK/6 SKIP · `stop` 0 OK/2 SKIP · `cleanup` 4 OK/1 SKIP · `status` 5 OK/7 SKIP.
**0 FALLO**: los guardarraíles del invitado salen **SKIP** («VM apagada (no evaluable)»),
nunca FALLO.

### 5.4 Keepalive: 2 h + 1 muerte provocada (evidencia primaria no conservada)

| Dato | Valor |
|---|---|
| **Ventana de prueba** | `2026-11-10T09:18:27Z` → `2026-11-10T11:19:05Z` = **2 h 0 min 38 s** |
| **Latido** | 1 línea TSV cada **5 min** exactos (`:20:00`, `:25:00`, …, `:15:00`), **sin huecos** |
| **Disco** | 21 277–21 283 MB libres (guarda de 500 MB **nunca** disparada en la prueba real) |
| **WU** | `wuauserv` `Stopped/Disabled`; el keepalive lo paró **1 vez** (se había auto-reparado a `Running/Manual` tras el deploy) y no volvió |
| **`win_user`** | `DESKTOP-BTMCFA5\angel` en **todos** los latidos (registro original; **sin fichero primario** en el snapshot) |
| **Muerte provocada** | `taskkill /f /im ghosts.exe` a las **10:02:11Z** |
| **Recuperación** | **10:05:08Z** ⇒ **1 ciclo** (2 min 57 s), `pid=1540`, `user=DESKTOP-BTMCFA5\angel`, `rc_run=0` |
| **Integridad tras recuperar** | `w3_groups.txt` reescrito por el cliente nuevo: **`Medium Mandatory Level` (S-1-16-8192)** |
| **Tope de `client.out`** | prueba forzada a `-ClientOutMaxMb 0`: rotación a `client.out.1` (22 488 B) + reinicio (`rotacion client_out_mb=0.02`) |
| **Guarda de disco** | prueba forzada (`-DiskMinMb 999999`): `alarma_disco` + `sin_arranque` (no arranca nada) |

**`test_il.ps1` — salida literal** (invitado revertido al snapshot; la clave va por STDIN;
las tareas `TFG-IL-*` y sus `.txt` se borran al terminar):

```
TFG-IL-Interactive REGISTRO=OK
TFG-IL-Interactive IL=Mandatory Label\Medium Mandatory Level Label S-1-16-8192
TFG-IL-Password REGISTRO=OK
TFG-IL-Password IL=Mandatory Label\High Mandatory Level Label S-1-16-12288
```

Ficheros: `legit/evidencia/test_il.ps1` + `legit/evidencia/test_il_salida.txt`. Confirma
**D-W3-3**: `Interactive` ⇒ **Medium**; `Password` ⇒ **High** (sesión 0). Cliente medido:
**`ghosts.exe` 8.0.0/8.2.2** (`FileVersion 8.2.2.0`, `ProductVersion 8.0.0.0`), ZIP
`ghosts-client-x64-v8.0.0.zip` con `sha256=01a58c46cee436d6ba425b8f5e99c9fb4263c0b180f6faeb75c1eb30d2623cf1`.

> **Laguna de evidencia (declarada).** El snapshot **no** contiene los logs de las 2 h.
> Los tres ficheros copiados a `legit/evidencia/` (`keepalive.log`, `recovery.log`,
> `estado.json`) se copiaron tras **arrancar** el snapshot
> (latidos `11:54:18Z`–`12:05:46Z`): prueban que la tarea keepalive existe, está `Ready`,
> corre como `angel`, late cada 5 min y mantiene WU parado **fuera de ventana**; **no**
> prueban la muerte provocada de `10:02:11Z` ni la recuperación de `10:05:08Z`. El
> `revert + apply` de las `11:28Z` borró `C:\Users\angel\ghosts-client`, y el snapshot se
> selló **después** (`Snapshot14.vmsn`, `11:29:38Z`): los logs de las 2 h **nunca estuvieron
> dentro** del snapshot. Detalle en `legit/evidencia/README.md`.

**Evidencia Sysmon (EID 1) del canal** — el proceso del cliente y sus hijos:

```
image=C:\Users\angel\ghosts-client\ghosts.exe  user=DESKTOP-BTMCFA5\angel  cwd=C:\Users\angel\  il=Medium  parent=cmd.exe
image=C:\Windows\System32\cmd.exe             user=DESKTOP-BTMCFA5\angel  cwd=C:\Users\angel\  il=Medium  parent=ghosts.exe
```

⇒ **`win_user=angel`**, **`win_cwd=C:\Users\angel`** (nunca `System32` ni el directorio del
cliente) e **`IntegrityLevel=Medium`** — el discriminante de B10-W.

### 5.5 Prueba del snapshot (revert + arranque)

```
vmrun revertToSnapshot … lab-listo-windows-legit   rc=0
vmrun start … nogui                                rc=0
```

| # | Comprobación | Resultado |
|---|---|---|
| 1 | tarea `TFG-WinLegit-Actividad` | **`Ready`** (y la de keepalive `Ready`) |
| 2 | cliente presente | **`EXE_SI`** y **0** procesos `ghosts.exe` (no arranca solo) |
| 3 | `Sysmon64` / `WazuhSvc` | **`Running/Automatic`** |
| 4 | `powercfg` | `STANDBYIDLE=0x0`, `HIBERNATEIDLE=0x0`, `HYBRIDSLEEP=0x0` |
| 5 | sin residuos | `FLAG_NO`, `PROBE_NO`, **0** marcas de campaña, **sin** clave `ghosts` en `HKCU\...\Run` |

Extra: `verificar_windows.ps1 -SinCampana` ⇒ **`RESULT=PASS`**; `HIJOS_VMTOOLSD=0`;
`wu_servicio=Stopped/Disabled`; `disco=21 272 MB`.
**Δ reloj host↔invitado = 143 ms** (VMware Tools, `tools.syncTime="TRUE"`).

### 5.6 `vigilancia_windows.log` — prueba de `watch` con la VM encendida

Línea **real** del fichero `Soporte/Laboratorio/windows/legit/evidencia/vigilancia_windows.log`
(controlador **v3**, manager encendido, `-T0 12:00Z -T1 14:00Z`, 2026-11-10):

```
[2026-11-10T13:01:28Z] chequeo ok=7 fallos=0 skip=0
```

⇒ `watch` evaluó **7** guardarraíles con el invitado y el manager encendidos: **7 OK, 0
fallos, 0 SKIP**. Incluye `G-W5` con `agente_002=Active` y `G-W7` con `logall_json=yes`
(ventana que contenía `now`). Sin `ALARMA` y sin falso positivo.

> **D2 — corrección de la cita.** La versión anterior de este §5.6 citaba
> `[2026-11-10T09:22:25Z] chequeo ok=5 fallos=0 skip=2`, que era una línea de la **v1**
> (con el manager apagado y los dos SKIP de manager). Esa línea **no** representa al
> controlador final y se sustituye por la de arriba. El fichero también se ha movido a
> `legit/evidencia/` para que sea versionable (**D3**).

### 5.7 Corrección de los defectos del controlador (F1–F7) y deudas D1–D7

`sha256` nuevo del controlador (**v3**):
`220d7c7078c859ef47a2e5ce6936dec22edf0ba3cee42a18779aadee26f5a821`.

| # | Defecto | Corrección |
|---|---|---|
| **F1** | `G-W11` no comprobaba nada: `ok = ($lineas.Count -le 1)` aceptaba **0** procesos y no validaba el dueño | Exige **exactamente 1** `ghosts.exe`, `CLIENTE_VIVO=True` y `WIN_USER` con dueño `angel`. **SKIP** solo si **no existe `armado.flag`** (fuera de ventana). Prueba negativa: con flag y 0 procesos ⇒ **FALLO** (§5.3) |
| **F2** | `G-W5` enmascaraba un fallo como SKIP (`if ($mgr.skip) { ok=$svc; skip=$true }`) | Si `Sysmon64`/`WazuhSvc` fallan ⇒ **FALLO** aunque el manager esté apagado. **SKIP solo por el manager** |
| **F3** | `arm` encendía `logall_json` con la clave del **invitado Windows** (`$Key`) mientras `Get-ManagerEstado` usaba la del **laboratorio Linux** | Una sola credencial (`Get-ManagerKey` = `id_ed25519_tfg_lab`) para `status`/`on`/`off`/`diff`; tras `on` se **verifica** `logall_json=yes` y solo entonces se registra `arm: logall_json ON verificado`; si no cuadra ⇒ `exit 55` |
| **F3b** | (defecto extra detectado al implementar F3) el script se invocaba como `bash D:\…\logall_json_ctl.sh` en una **VM Linux** | Se copia a `/tmp/logall_json_ctl.sh` con `scp` (`Push-ManagerScript`) y se ejecuta esa ruta; `Get-ManagerEstado` reintenta tras copiarlo si falta |
| **F4** | `cleanup` no restauraba la telemetría | Ejecuta `logall_json off`, **verifica** `logall_json=no` y `CONFIG_IDENTICA` (`diff` contra `ossec.conf.tfg-bak`); si no cuadra ⇒ `exit 81/82`. Si el manager no es accesible ⇒ **AVISO** explícito (no verificable) |
| **F5** | `G-W6` solo detectaba gateway `192.168.65.x` (`route print` + regex de esa subred): una ruta por defecto a **cualquier** otra IP pasaba como «aislado» | Pregunta a `Get-NetRoute -DestinationPrefix 0.0.0.0/0` (vacío ⇒ sin ruta) y, si no está, usa la regex **genérica** `0\.0\.0\.0\s+0\.0\.0\.0\s+\S+`. Probado: `sin_ruta_defecto=True (Get-NetRoute=0)` |
| **F6** | `G-W7` exigía `logall_json=no` en **todas** las fases salvo `arm`; `$T0`/`$T1` existían sin usarse ⇒ el `watch` **siempre** fallaba en ventana | Decide por **ventana**, no por fase: `now ∈ [t0,t1]` ⇒ exige `yes`; `now` fuera ⇒ exige `no`; **sin `-T0/-T1` ⇒ SKIP declarado**. Espejo de `legitimo_host_control.ps1:510-518`. Se aplica en `arm`/`watch`/`status`/`cleanup` |
| **F7** | `G-W5` no comprobaba el agente `002` `Active` (solo servicios + manager) | Añade `Get-Agente002` (`agent_control -l` **en el manager**, con la credencial del manager): si `002` no está `Active` ⇒ **FALLO**, nunca SKIP. Se ve en `watch`: `agente_002=Active` |
| **C-1** | (defecto extra, detectado al probar `cleanup` con el manager encendido) `cleanup` exigía `Total running VMs: 0`, pero el manager **tiene que seguir encendido** para hacer `logall_json off` y `CONFIG_IDENTICA` ⇒ `exit 80` falso | `cleanup` exige **`victima-windows` y `victima-linux` apagadas** y registra `manager_on=True`; el «0 VMs» (CA-W21) es del **cierre del laboratorio** (paso posterior). Ver §5.8 |

> **Deudas D1–D7 (cerradas).** **D1** `drytest` escribe en `legit/evidencia/drytest.log` y
> la prueba negativa de `G-W11` es un script reproducible (`prueba_negativa_GW11.ps1`) con su
> salida. **D2** §5.6 cita la línea del controlador final (no la de la v1). **D3**
> `.gitignore` tiene excepción explícita para `Soporte/Laboratorio/windows/legit/evidencia/`
> (sin desactivar `*.log`). **D4** `sha256sums.txt` incluye `deploy_windows.ps1`,
> `windows_legit_host_control.ps1`, `guest/*` y `client_config/*`. **D5** `cleanup` llama a
> `stop_ghosts.ps1` (GHOSTS API + PostgreSQL) y lo verifica. **D6** `Get-ManagerPw` ya **no**
> cae a `TFG_GUEST_PW`: en WE0 hay que definir **`TFG_MANAGER_PW`** explícita. **D7**
> declarado arriba: el `watch` evalúa **7** guardarraíles, no las 9 señales del plan.

> **Alcance de la prueba (v3).** F1 se ha probado en vivo en los dos sentidos: **SKIP sin
> flag**, **FALLO con flag y 0 procesos** (§5.3) y **OK con 1 proceso y dueño `angel`**
> (`watch` con el cliente vivo, §5.8). F2 se probó con el manager apagado (servicios OK ⇒
> SKIP solo por manager). **F3/F3b/F4/F5/F6/F7 y C-1 se han ejecutado con el manager
> encendido** en la prueba real `arm`→`watch`→`cleanup` de §5.8: `logall_json ON
> verificado`, `G-W7` en sus dos ramas, `agente_002=Active`, `logall_json=no` +
> `CONFIG_IDENTICA` y `cleanup exit 0` con GHOSTS/PostgreSQL parados.

---

### 5.8 Prueba real `arm` → `watch` → `cleanup` (manager encendido, sin ventana)

**Alcance declarado.** Para que `arm` pueda re-desplegar y verificar, el invitado
**Windows** tiene que estar encendido; lo que **no** se enciende es `victima-linux`
(agente `001`), que es el aislamiento que exige el plan. El manager es
`wazuh-server` (`192.168.65.128`). **No se ejecutó la ventana ni la campaña.**

| # | Paso | Salida literal |
|---|---|---|
| 1 | Encender manager + invitado Windows (revertido a `lab-listo-windows-legit`); `victima-linux` **off** | `agent_control -l` ⇒ `ID: 002, Name: victima-windows, IP: any, Active` |
| 2 | `arm -T0 2026-11-10T15:00:00Z -T1 2026-11-13T15:00:00Z` (**t0 futuro ⇒ `now` fuera**) | `arm OK` (`exit 0`). `G-W7` en esa rama: `G-W7 OK logall_json=no (now fuera de [t0,t1] exige no)` |
| 3 | `logall_json` **real** y registro **después** de comprobarlo | `conf: <logall_json>yes</logall_json>` / `manager=active` / `daemons_remoted_analysisd=2`; log: `[2026-11-10T13:00:34Z] [arm] arm: logall_json ON verificado (manager_active=True daemons=2)` |
| 4 | `watch -T0 2026-11-10T12:00:00Z -T1 2026-11-10T14:00:00Z` (**ventana contiene `now`**) | `chequeo ok=7 fallos=0 skip=0` (`exit 0`). Detalle: `G-W5 OK … agente_002=Active` y `G-W7 OK logall_json=yes (now dentro de [t0,t1] exige yes)` |
| 5 | `cleanup` | `cleanup: GHOSTS/PostgreSQL parados (api_procesos=0 postgres_parado=True)`, `logall_json=no verificado`, `CONFIG_IDENTICA`, `victima_windows_off=True victima_linux_off=True manager_on=True` ⇒ **`exit 0`** |
| 6 | Apagar manager + revertir el invitado | `Total running VMs: 0`; 0 tareas `TFG-*`; GHOSTS/PostgreSQL parados |

**C-1 en vivo (declarado).** El **primer** `cleanup` dio `exit 80`
(`vms_cero=False`) porque contaba también el manager, que debe seguir encendido para el
`logall_json off`. Se corrigió la comprobación (solo las VMs de medida) y el segundo
`cleanup` dio `exit 0`. Ambas ejecuciones quedan en
`legit/evidencia/windows_legit_host_control.log`.

**Observación declarada (no bloqueante).** El cliente GHOSTS se reinició una vez entre el
`watch` y el `drytest` de cortesía (el keepalive lo relanzó en ~1 ciclo; `client.out` muestra
dos arranques). El `watch` real, que es el que manda, pasó con **1** `ghosts.exe` y dueño
`angel`. En la ventana real `t0` es el inicio y no hay *catch-up*; aun así, `G-W11` es
sensible a esa recuperación y así se declara.

**Estado restaurado.** Recetas `w1/w2/w3`, `calendario_windows.json` y `bloques_windows.env`
restauradas **byte-idénticas** (hashes `05dbf6…`, `bc6525…`, `8ed8fa…`, `f306c2…`, `1a008a…`);
invitado revertido al snapshot; manager apagado; variables `TFG_*_PW` borradas.

---

## 6. Desviaciones declaradas (W3)

1. **D-W3-1 — snapshot base.** El plan (D5) decía «hijo de `lab-listo-windows`». Se ha
   hecho hijo de **`lab-listo-windows-ataques-gui`** porque es el único que trae el canal
   **SSH** (necesario para desplegar sin `vmrun`) y **autologon + sesión de consola**
   (necesario para la tarea `Interactive`). Los 6 snapshots previos quedan intactos.
2. **D-W3-2 — versión del cliente** (§2): binario **8.0.0/8.2.2**, no 8.3.1.
3. **D-W3-3 — la tarea corre `Interactive`, no con contraseña guardada.** **Medido**: con
   `LogonType=Password` el proceso arranca en **sesión 0** con token **completo**
   (`IntegrityLevel=High`, S-1-16-12288), aunque se pida `-RunLevel Limited`; con
   `Interactive` sale **`Medium`** (S-1-16-8192), que es lo que exige B10-W. **Coste:** la
   tarea necesita una sesión abierta de `angel`; el snapshot la tiene por autologon y el
   keepalive registra `ALARMA sin_sesion_angel` si desaparece. **Ventaja:** no se guarda
   ninguna contraseña (AC-W20) y el proceso vive en la **sesión 1 (Console)**, más realista.
4. **D-W3-4 — `app.publish` fuera del payload** (copia de publicación ClickOnce; `ghosts.exe`
   no la usa). Se excluyen también `logs/`, `instance/` y `client.out*`.
5. **D-W3-5 — nombre de máquina GHOSTS = hostname** (`desktop-btmcfa5`), igual que Linux usó
   el suyo (`victima-linux`). No se toca el `.vmx` ni el nombre del equipo.
6. **D-W3-6 — el cliente GHOSTS VACÍA `%TEMP%` del usuario** (observado: los scripts de
   apoyo dejados en `C:\Users\angel\AppData\Local\Temp` desaparecieron con el cliente vivo).
   Por eso el deploy usa **`C:\Windows\Temp`** y borra sus ficheros al terminar.
7. **D-W3-7 — autoarranque del cliente.** El cliente se registra en
   `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (`ghosts`). Se pone
   **`DisableStartup=true`** y el snapshot se crea **sin** esa clave: el cliente **solo**
   arranca con `arm`/keepalive, como pide el plan (y así el `prep` deja el cliente parado).
8. **D-W3-8 — WU del invitado.** No hay `pausar_wu_invitado.ps1` separado: la guarda de WU
   está **dentro del keepalive** (cada 5 min re-aplica `NoAutoUpdate=1`, para `wuauserv` y
   lo deja `Disabled`). Es más simple y se ejecuta 288 veces/día.
9. **D-W3-9 — nombre del verificador.** `verificar_windows.ps1` (el plan §16.1 decía
   `verificar_arreglos_windows.ps1`); hace lo mismo y además `-Manifiesto` y
   `HIJOS_VMTOOLSD` (señal de W-V4).
10. **D-W3-10 — ruta de este documento** (§0).
11. **D-W3-11 — `eventcreate`.** Probado como `angel` **elevado** (SSH): funciona. A
    `Medium` **no** se ha probado aquí (es WE0-7). Si falla, el plan ya prevé degradar
    W-10 a lectura.

---

## 7. Residuos

- **En el snapshot:** ninguno (0 marcas, 0 `armado.flag`, 0 procesos, sin clave `Run`,
  logs del cliente vacíos). El `instance/id.json` se creará en el primer arranque del
  cliente (es estado legítimo, no residuo).
- **En el host:** `D:\TFG-VMs\material-ghosts\client-windows\` (ZIP + extracción, fuera del
  repo), staging borrado (`%TEMP%\opencode\tfg-win-legit`). **0 VMs**, **0** tareas `TFG-*`,
  GHOSTS/PostgreSQL parados, `TFG_GUEST_PW`/`TFG_MANAGER_PW` borradas.
- **En el repo:** solo los ficheros de §3 + este documento + la evidencia versionable de
  `legit/evidencia/` (`windows_legit_host_control.log`, `vigilancia_windows.log`,
  `drytest.log`, `prueba_negativa_GW11.ps1`, `prueba_negativa_GW11.txt`,
  `prueba_negativa_GW11_drytest.log`) y los ficheros históricos de la prueba de integridad.

---

## 8. Pendiente para W4 (WE0)

1. **WE0-1…WE0-12** completos (el manager encendido): `M` de 60 min y decisión §6.3,
   `eventcreate` a `Medium`, `where` de herramientas (WE0-2b), 10 patrones de
   `errores.log`, no mutación.
2. **`arm` real**: `--t0`, mapa de días, `logall_json=yes`; y `stop`/`cleanup` reales.
   *(La mecánica `arm`→`watch`→`cleanup` ya está probada en §5.8; falta el `stop` con
   `cosecha.done` y la ventana real.)*
3. **B10-W**: añadir `cliente_version=8.0.0/8.2.2` (`FileVersion 8.2.2.0`,
   `ProductVersion 8.0.0.0`), `IntegrityLevel=Medium` (medido con `test_il.ps1`),
   `win_user=angel`, el `sha256` del ZIP del cliente
   (`01a58c46cee436d6ba425b8f5e99c9fb4263c0b180f6faeb75c1eb30d2623cf1`) y el de este despliegue.
4. **Fecha de la ventana** (regla ≥ 48 h, lunes→jueves) y **`WE0 ≤ 7 días`** antes de `t0`.
5. **Laguna de las 2 h (§5.4).** El snapshot no trae los logs de la prueba de 2 h. Decidir
   antes de `t0`: (a) **repetir** la prueba de 2 h + 1 muerte en WE0 y guardar la evidencia,
   o (b) aceptar la laguna **declarada**. No se puede cerrar con el snapshot actual.
6. **`TFG_MANAGER_PW` explícita** (D6): el fallback a `TFG_GUEST_PW` **se ha retirado**. En
   WE0 hay que exportarla antes de `arm`/`watch`/`cleanup`/`status`; sin ella, el manager
   sale `SKIP`.

---

## 9. Reproducción

```powershell
# HOST (VM arrancada, canal SSH de B1.0)
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\deploy_windows.ps1 -Phase apply
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\deploy_windows.ps1 -Phase hash
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\windows_legit_host_control.ps1 -Phase drytest
# Prueba negativa de G-W11 (VM encendida, sin cliente vivo):
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\legit\evidencia\prueba_negativa_GW11.ps1
# Con manager (WE0): exportar TFG_MANAGER_PW (D6) y pasar -T0/-T1 a arm/watch/status:
#   $env:TFG_MANAGER_PW = '<oculto>'
#   ... -Phase arm -T0 <t0> -T1 <t1>
# Invitado (a mano, solo prueba)
#   powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\angel\ghosts-client\tfg_keepalive_windows.ps1
#   schtasks /run /tn TFG-WinLegit-Actividad      (tras crear armado.flag)
# Cierre
powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\windows\deploy_windows.ps1 -Phase revert
```

---

## 10. Veredicto

> **W3 PASA (tras F1–F7 y D1–D7).** El snapshot `lab-listo-windows-legit` es válido y
> **no se ha rehecho** (7 snapshots, los 6 previos intactos). El despliegue es idempotente
> (**par final** `applyG1/applyG2`, mismo `sha256`) y reversible (0 residuos). El controlador
> **v3** (`220d7c70…a821`) tiene las 7 fases y los 12 guardarraíles, con **F5/F6/F7**
> corregidos; `G-W6` detecta **cualquier** ruta por defecto, `G-W7` decide por `[t0,t1]` y
> `G-W5` exige **agente `002` `Active`**. El `drytest` pasa en **las 6 fases con la VM
> encendida** y **con la VM apagada** (`DRYTEST_RESULT=PASS`, 0 FALLO; log en
> `legit/evidencia/drytest.log`). `G-W11` **falla** con 0 procesos y flag (prueba negativa
> reproducible) y **pasa** con 1 proceso de `angel`. La prueba real `arm`→`watch`→`cleanup`
> con el manager (§5.8) cierra `logall_json ON verificado` → `chequeo ok=7 fallos=0 skip=0`
> → `cleanup exit 0` (`logall_json=no`, `CONFIG_IDENTICA`, GHOSTS/PostgreSQL parados).
> `test_il.ps1` mide **Medium** (`Interactive`) y **High** (`Password`).
>
> **Lo que no cuadra (para W4):** (a) el binario del cliente es **8.0.0/8.2.2**, no 8.3.1
> (§2); (b) la tarea va en **`Interactive`** y depende de la sesión de `angel` (§6.3);
> (c) el `watch` evalúa **7** guardarraíles, no las 9 señales del plan (**D7**, §4);
> (d) **laguna de evidencia de las 2 h** (§5.4): el snapshot no contiene `keepalive.log`
> ni `estado.json` de esa prueba; (e) `G-W11` es sensible a la recuperación del cliente
> (§5.8). Nada de esto impide armar, pero (a)-(c) deben estar en
> B10-W/`ensayo_WE0.md` y (d) exige decisión humana antes de `t0` (§8.5).
