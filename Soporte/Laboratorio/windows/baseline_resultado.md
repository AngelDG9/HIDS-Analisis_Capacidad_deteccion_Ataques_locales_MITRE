# Baseline Windows — resultado operativo (host-side) · `fase-02b-baseline`

> **Autor:** `tfg-executor`. **Plan:** `plan.md` (raíz, `approved_by_human`, 2026-10-07).
> **Naturaleza:** preparación **antes de `t0`** + evidencia de ejecución **después de `t1`**.
> **Sin secretos. Sin commit.**
> **Estado:** 🔴 **VENTANA v1 (noche del 07/10) INVÁLIDA** (suspensión del invitado) → **causa
> corregida + snapshot recreado + salvaguarda añadida** (§9). 🛑 **La tarde del 07/10 se CANCELA**
> (decisión del humano, 2026-10-07: la ventana de la tarde ya había arrancado sin que la noche fuera
> válida). Ambas ventanas se **reprograman al 2026-10-08** (noche + tarde, **el mismo día**, coherencia
> con Linux) → **re-armado completo (host + invitado + snapshot)** en **§10**.

---

## 1. Ventanas (UTC / local Madrid CEST +02:00)

| Ventana | `t0` (UTC) | `t1` (UTC) | Duración | Local |
|---|---|---|---|---|
| **v1 — noche** | `2026-10-08 00:45:00Z` | `2026-10-08 04:45:00Z` | 240 min | 02:45 → 06:45 |
| **v2 — tarde** | `2026-10-08 12:00:00Z` | `2026-10-08 16:00:00Z` | 240 min | 14:00 → 18:00 |

Ambas el **mismo día** (paridad con Linux). Filtro de extracción en **UTC**.
**Fecha vigente: 2026-10-08** (la noche del 07/10 quedó inválida y la tarde del 07/10 se canceló; §9-§10).

---

## 2. Tareas programadas del HOST (Programador de tareas de Windows)

Ejecutan `Soporte/Laboratorio/windows/baseline_host_control.ps1` (`vmrun`, local).
**Usuario:** `angel` (Interactive, `RunLevel Highest`); **log** → `%TEMP%\opencode\baseline_host_control.log`.

| Tarea | Disparo (local) | Acción (`vmrun`) |
|---|---|---|
| `TFG-Baseline-Night-Start` | **02:30** | revert víctima → `lab-listo-windows-baseline` · start víctima (nogui) · **start manager** |
| `TFG-Baseline-Night-Stop` | **06:50** | stop víctima (soft). **El manager SIGUE encendido** (plan §1.3) |
| `TFG-Baseline-Afternoon-Start` | **13:45** | revert víctima → `lab-listo-windows-baseline` · start víctima · start manager (idempotente) |
| `TFG-Baseline-Afternoon-Stop` | **18:05** | stop víctima (soft) · stop manager (soft) |

**Evidencia (estado `Ready` y próximo disparo):**

```
TFG-Baseline-Night-Start     | Ready | next=07/10/2026 2:30:30
TFG-Baseline-Night-Stop      | Ready | next=07/10/2026 6:50:50
TFG-Baseline-Afternoon-Start | Ready | next=07/10/2026 13:45:45
TFG-Baseline-Afternoon-Stop  | Ready | next=07/10/2026 18:05:05
Trigger declarado: 2026-10-07T02:30:00+02:00 / 06:50 / 13:45 / 18:05
```

> **Nota (arranque ≥ 15 min antes de `t0`):** 02:30 → `t0`=02:45 (15 min); 13:45 → `t0`=14:00 (15 min).
> El ruido de arranque cae **antes** de `t0` (criterio v2; diferencia declarada con Linux).
>
> **Nota (manager encendido continuo):** el plan §1.3 fija que el **manager no se apaga** entre
> las dos ventanas; solo se apaga tras `t1(v2)` (18:05). Así se evita el cabo conocido
> `wazuh-indexer` (arranque lento/timeout; `state.md:17`) **sin tocar Linux** (solo lectura).

---

## 3. Actividad legítima (§1.5)

- **Script:** `Soporte/Wazuh/Scripts/baseline_actividad_windows.ps1`
  - **`sha256` (repo) = `EB60DF9D6213E483CCD57DF7DDD5F51AE3D56307AEB98E6C48CE6F8DC667263E`**
  - `sha256` **repo == invitado** verificado (post-snapshot).
- **Tarea del invitado:** `TFG-Baseline-Legit` — **principal `SYSTEM`** (ServiceAccount, Highest),
  `StartWhenAvailable`, `MultipleInstances IgnoreNew`, límite 5 h.
  - **2 disparos:** `2026-10-07T02:40:00+02:00` y `2026-10-07T13:55:00+02:00` (= `t0 − 5 min`).
  - **Duración por ejecución:** `-DurationMin 248` (≈ 240 min de ventana + 8 min de margen).
  - **Carpeta:** `C:\lab-legit\` (`work\`, `backup\`, `tools\`); log `C:\lab-legit\baseline_log.txt` (UTC).
- **Ciclo en seco** (fuera de ventana, carpeta `C:\lab-legit-smoke` y borrada): **OK**
  (`START`/`CYCLE 1`/`END`, zip, `.sha256`, `.txt`); `C:\lab-legit` quedó **limpio** (sin log).

> **Desviación declarada (menor):** el plan proponía `260 min`. Se usa **248 min** para que el
> script escriba `END` **antes** del apagado del host (`t1+5`: 06:50 / 18:05) y así cumplir la
> evidencia de §1.5.5 (`END ≥ t1`). Con 260 min el `END` (07:00 / 18:15) caería **después** del
> apagado y no se escribiría.

---

## 4. Snapshot ↔ material (§1.5.4) — orden elegido

**Problema:** la ventana arranca con `revertToSnapshot`; si el material se instalara *después* del
snapshot, la reversión lo borraría.

**Solución (más robusta; preserva los snapshots originales):**

1. Ahora (antes de `t0`): encender la víctima → instalar `C:\lab-legit\` + script + **tarea
   `TFG-Baseline-Legit`** → verificar → apagar.
2. Crear un snapshot **nuevo** **`lab-listo-windows-baseline`** (hijo de `lab-listo-windows`) con
   el material **incluido**.
3. Las tareas del host revierten a **`lab-listo-windows-baseline`** (no a `lab-listo-windows`).

**Snapshots tras la preparación (los originales INTACTOS):**

```
victima-windows:  base-limpia · lab-listo-windows · lab-listo-windows-baseline   (3)
wazuh-server:     base-limpia · lab-listo                                        (2)
```

**Verificación post-snapshot** (revert al nuevo + arranque): dentro del snapshot existen la tarea
`Ready` (SYSTEM, disparos 02:40/13:55, `NextRun=02:40:40`), el script (sha `EB60…`) y
`WazuhSvc=Running`, `Sysmon64=Running`; `baseline_log.txt` **no existe** (log limpio para la ventana).

> **Por qué un snapshot nuevo y no recrear `lab-listo-windows`:** el plan exige (CA8) *snapshots
> intactos*; un snapshot **hermano** deja `lab-listo-windows` y `base-limpia` **sin tocar** y evita
> que `fase-03b` arrastre el material de baseline. Es una **desviación declarada** del nombre.

---

## 5. FIM forzado desde el manager (Parte D) — **NO ejecutado aún**

Comando a lanzar **desde el manager** durante cada ventana (**no toca la VM**):

```bash
# en wazuh-server (192.168.65.128), usuario angel
echo '<contraseña del laboratorio>' | sudo -S /var/ossec/bin/agent_control -r -u 002
```

- **Cuándo:** dentro de `[t0,t1]`, ~15 min tras `t0`: **v1 → ~01:00Z (03:00 local)**;
  **v2 → ~12:15Z (14:15 local)**.
- **Antes:** verificar el `frequency` real del `ossec.conf` del agente (`<syscheck><frequency>`);
  confirmar `agent_control -l` con el agente `002` `Active`.
- **Esperado:** **0** alertas FIM nuevas (el baseline escribe en `C:\lab-legit`, **fuera** de las
  rutas vigiladas); las rutas vigiladas no cambian. Se declara el resultado real al cerrar.
- **Nota:** se prepara pero **no** se ejecuta ahora (no se toca Linux salvo lectura).

---

## 6. Suspensión del PC (host)

- **Estado verificado:** plan de energía **Equilibrado**; en **CA**: *Suspender tras* = **0 (nunca)**,
  *Hibernar tras* = **0 (nunca)**, *Apagar pantalla* = **0 (nunca)**.
- **Acción:** reafirmado de forma **idempotente** (`standby-timeout-ac 0`, `hibernate-timeout-ac 0`,
  `disk-timeout-ac 0`). **Ya estaba** en "nunca suspender" en CA → **no se cambió ningún valor**.
- **PC del humano:** encendido y en CA durante las ventanas (aceptado por el humano).

> **(2026-10-07)** El fallo de la ventana de noche **NO** fue el PC del host (nunca se suspende):
> fue el **sueño del INVITADO** a los 30 min de inactividad. Corrección y salvaguarda en **§9**.

---

## 7. Disciplina durante `[t0,t1]`

- **Cero** acceso al invitado: ni RDP/SSH, ni `runProgramInGuest`/`copyFile*`, ni consola, ni
  snapshot. La tarea `TFG-Baseline-Legit` corre **sola** (actividad del propio invitado).
- **Prueba anti-contaminación (post-hoc):** buscar logon/sesión del operador desde `192.168.65.1`
  dentro de `[t0,t1]`; si los hay → **ventana INVÁLIDA** (§4.3).

---

## 8. Pendiente (tras `t1`)

1. Recuperar el log del invitado (`C:\lab-legit\baseline_log.txt`) → `Dataset/Legitimo/windows/baseline_log_ventanaN.txt`.
2. Registrar `Get-ScheduledTaskInfo` (`LastRunTime`/`LastTaskResult=0`) + nº de ciclos.
3. Extracción del **fichero diario** del manager (después; **no** ahora).

---

## 9. Incidencia y corrección — ventana v1 (noche) INVÁLIDA (2026-10-07)

### 9.1 Qué pasó (ventana INVÁLIDA → se repite)

- La **ventana v1 (noche, `00:45:00–04:45:00Z`)** es **INVÁLIDA**.
- **Causa raíz:** el **Windows invitado se durmió** por inactividad a los **30 min** — plan
  **Equilibrado**: *Suspender tras* = `0x00000708` (**1800 s = 30 min**) en CA y `0x00000384` (900 s)
  en CC. La **VM se suspendió a `01:00:42Z`**.
- Solo hubo **~15 min** de telemetría: última alerta del agente a **`00:58:44Z`**.
- El **manager** marcó **`504 agent disconnected`** a **`01:16Z`**.
- La actividad legítima del invitado solo completó **5 ciclos** (`START 00:40:02Z`, `CYCLE 1…5`,
  último `01:00:04Z`), **sin `END`** (`C:\lab-legit\baseline_log.txt`).
- **Regla del plan §4.3:** *ventana parcial → se descarta y se **repite entera***. **No se extrae**
  nada de esta ventana. El log del intento fallido se preserva **fuera del repo**:
  `%TEMP%\opencode\baseline_fix\failed_window_2026-10-07_baseline_log.txt`.

### 9.2 Corrección aplicada en el invitado (`powercfg`, esquema **Equilibrado**)

| Ajuste | Antes | Después |
|---|---|---|
| `STANDBYIDLE` (Sleep after) **CA** | `0x00000708` (1800 s = **30 min**) | **`0x00000000`** (nunca) |
| `STANDBYIDLE` (Sleep after) **CC** | `0x00000384` (900 s) | **`0x00000000`** |
| `HIBERNATEIDLE` (Hibernate after) CA/CC | `0x0` / `0x0` | **`0x0` / `0x0`** |
| `HYBRIDSLEEP` (Allow hybrid sleep) CA/CC | `0x1` / `0x1` (**On**) | **`0x0` / `0x0`** (**Off**) |
| `UNATTENDSLEEP` | no expuesto (oculto en el esquema) | no expuesto (intento rc=0; **irrelevante** con `STANDBYIDLE=0`) |

- Comandos: `powercfg /change standby-timeout-ac 0` · `…-dc 0` · `hibernate-timeout-ac 0` ·
  `hibernate-timeout-dc 0` · `powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP UNATTENDSLEEP 0` ·
  `/setdcvalueindex … UNATTENDSLEEP 0` · `/setacvalueindex … HYBRIDSLEEP 0` · `/setdcvalueindex …
  HYBRIDSLEEP 0` · `powercfg /S SCHEME_CURRENT`. Todos `rc=0`.
- **Evidencia cruda (host, fuera del repo):** `%TEMP%\opencode\baseline_fix\sleep_before.txt`,
  `sleep_after.txt`, `sleep_extra.txt`.

### 9.3 Snapshot `lab-listo-windows-baseline` **recreado con la corrección**

- Con la VM **apagada**: `deleteSnapshot` + `snapshot` de **`lab-listo-windows-baseline`**.
  **`base-limpia` y `lab-listo-windows` NO se tocan** (`listSnapshots` = 3).
- Antes de snapshotear se **limpió el residuo** del intento fallido (`baseline_log.txt`, `work\*`,
  `backup\*`); se conserva `tools\baseline_actividad_windows.ps1` (sha `EB60DF9D…`). Así la nueva
  ventana empieza con **log limpio**.
- **Verificación DENTRO del snapshot** (revert + arranque): `STANDBYIDLE` CA/CC = **`0x0`** ✔,
  `HIBERNATEIDLE` = `0x0`, `HYBRIDSLEEP` = Off, `baseline_log.txt` **no existe**, tarea `Ready`
  (`NextRun=13:55`), `WazuhSvc`/`Sysmon64` = Running, NAT `Disconnected`.
  Evidencia: `%TEMP%\opencode\baseline_fix\verify_snapshot.txt`.

### 9.4 Salvaguarda: chequeo de suspensión al arrancar **cada** ventana

`Soporte/Laboratorio/windows/baseline_host_control.ps1` (fases `*-start`) ahora, **tras arrancar la
víctima y antes de `t0`**, ejecuta una consulta **de solo lectura**
`powercfg /q SCHEME_CURRENT SUB_SLEEP STANDBYIDLE` **en el invitado** y registra el veredicto en el
log del host + `%TEMP%\opencode\sleepcheck_guest_<fase>.txt`. **Sin secretos en el fichero ni en el
log** (credenciales por entorno `TFG_GUEST_USER` / `TFG_GUEST_PW`; si falta la contraseña, el chequeo
se **omite y se anota**, sin abortar la ventana).

- **Pruebas reales** (host `2026-10-07`):
  - `05:59:58Z` → `SLEEPCHECK(night-start) STANDBYIDLE AC=0x00000000 DC=0x00000000 => OK`
  - `06:04:09Z` → `SLEEPCHECK(afternoon-start) STANDBYIDLE AC=0x00000000 DC=0x00000000 => OK`

### 9.5 Repetición

La **ventana v1 (noche) se repetirá entera** (snapshot fresco + 4 h) tras la corrección. Los
disparadores del host y del invitado son **instantes absolutos del 2026-10-07** → habrá que
**re-armarlos** con las horas de la nueva noche.

### 9.6 Cierre operativo de esta sesión

- **Víctima `victima-windows`: APAGADA** (`stop soft`). **Manager `wazuh-server`: ENCENDIDO** (sigue
  vivo hasta la ventana de la tarde).
- **Sin commit / sin push.** `_recursos/` y Linux **intactos** (manager solo lectura). Contraseña
  **solo en memoria** (nunca en ficheros ni en el log; se redacta en los logs del host).

---

## 10. Cancelación de la tarde del 07/10 y re-armado al 08/10 (2026-10-07)

> **Decisión del humano (2026-10-07):** la **ventana de la tarde del 07/10 se CANCELA** y las **2
> ventanas se reprograman al MISMO día 2026-10-08** (noche + tarde), por coherencia con el baseline
> de Linux. La tarde del 07/10 **no cuenta**. **No se extrae** nada de la media hora caída.

### 10.1 Parada inmediata de la ventana de hoy (07/10)

- El **disparador del host** `TFG-Baseline-Afternoon-Start` había disparado a las **11:45Z**
  (13:45 local) y la **víctima + manager estaban arrancando**.
- **Parada inmediata** (11:48Z): `vmrun stop <victima>.vmx soft` → **rc=0**; `vmrun stop
  <wazuh-server>.vmx soft` → **rc=0**. `vmrun list` → **Total running VMs: 0**.
- **No se extrajo** nada de la fracción de ventana caída (no hay `baseline_detalle_v2` de hoy).
- `TFG-Baseline-Afternoon-Stop` **re-programada** (no pudo dispararse a las 18:05 de hoy) → `NextRun`
  pasa al **08/10 18:05** (ver §10.2).

### 10.2 Re-armado de las 4 tareas del HOST (08/10)

Se reescribió el `StartBoundary` de cada tarea (disable → `Set-ScheduledTask` → enable):

| Tarea | `StartBoundary` nuevo | `NextRun` verificado |
|---|---|---|
| `TFG-Baseline-Night-Start` | `2026-10-08T02:30:00+02:00` | `08/10/2026 2:30:30` |
| `TFG-Baseline-Night-Stop` | `2026-10-08T06:50:00+02:00` | `08/10/2026 6:50:50` |
| `TFG-Baseline-Afternoon-Start` | `2026-10-08T13:45:00+02:00` | `08/10/2026 13:45:45` |
| `TFG-Baseline-Afternoon-Stop` | `2026-10-08T18:05:00+02:00` | `08/10/2026 18:05:05` |

Las 4 en estado **`Ready`**. El resto de la definición (acción `baseline_host_control.ps1`, principal
`angel` Interactive/`Highest`) **sin cambios**.

### 10.3 Re-armado de la tarea del INVITADO `TFG-Baseline-Legit` (dentro del snapshot)

- Se **encendió la víctima** desde `lab-listo-windows-baseline` (revert + `start nogui`).
- **⚠️ Incidencia detectada y corregida:** al arrancar el invitado, el disparador **absoluto del
  07/10 13:55** (aún en el pasado inmediato) **se disparó** → la tarea quedó **`Running`** y escribió
  residuo en `C:\lab-legit\`. Se **paró** (`Stop-ScheduledTask`), se **limpió** el residuo
  (`backup\`, `work\`, `baseline_log.txt`; se conserva `tools\`) y **quedó limpio**.
- Se actualizaron los **disparadores a instantes absolutos del 08/10** y se **quitó
  `StartWhenAvailable`** (para que **no** vuelva a dispararse fuera de horario al arrancar por un
  disparador ya pasado):

  | Campo | Antes | Después |
  |---|---|---|
  | Disparador 1 | `2026-10-07T02:40:00+02:00` | `2026-10-08T02:40:00+02:00` |
  | Disparador 2 | `2026-10-07T13:55:00+02:00` | `2026-10-08T13:55:00+02:00` |
  | `StartWhenAvailable` | `True` | **`False`** |

- Acción y principal **sin cambios** (`powershell.exe … baseline_actividad_windows.ps1 -DurationMin
  248`; principal `SYSTEM` `S-1-5-18`, `HighestAvailable`).
- Se **apagó** la víctima y se **re-creó** el snapshot **`lab-listo-windows-baseline`**
  (`deleteSnapshot` + `snapshot`), de modo que la nueva programación queda **dentro** del snapshot.
  `listSnapshots` = **3** (`base-limpia` · `lab-listo-windows` · `lab-listo-windows-baseline`);
  los **originales intactos**.

### 10.4 Verificación DENTRO del snapshot (revert + arranque)

Evidencia (host, fuera del repo: `%TEMP%\opencode\rearm\verify_snapshot.txt`):

- **Disparadores = `2026-10-08T02:40:00+02:00` y `2026-10-08T13:55:00+02:00`** ✔
- **`StartWhenAvailable` ausente (= `False`)** ✔
- **`STANDBYIDLE` (Sleep after) AC = `0x00000000` · DC = `0x00000000`** ✔
- **`C:\lab-legit\baseline_log.txt` NO existe** (log limpio) ✔
- `C:\lab-legit\` contiene **solo** `tools\baseline_actividad_windows.ps1`
  (`sha256` = `EB60DF9D…` = repo) · **0 procesos** de actividad residuales.

### 10.5 Estado final

- **Víctima `victima-windows`: APAGADA** · **Manager `wazuh-server`: APAGADO** (`vmrun list` →
  **Total running VMs: 0**).
- **Sin extracción, sin catálogo, sin commit, sin push.** Linux **intacto** (no se tocó).
  `_recursos/` intacto. Contraseña **solo en memoria** (nunca en ficheros ni en el log).
- **Próximo hito:** las **2 ventanas del 08/10** (noche `00:45–04:45Z` · tarde `12:00–16:00Z`).

---

## 11. Ventana 1 (noche del 08/10) — EJECUTADA y EXTRAÍDA (2026-10-08)

### 11.1 Ejecución (host)

- `night-start` **2026-10-08T00:30:00Z** (revert → `lab-listo-windows-baseline` · start víctima ·
  start manager · rc=0). Arranque `06:30` local, **15 min antes de `t0`** ✔.
- `night-stop` **2026-10-08T04:50:00Z** (stop víctima `soft`, rc=0). El manager **siguió
  encendido**.
- **Sin acceso al invitado dentro de `[t0,t1]`** (disciplina §1.2). El chequeo de suspensión se
  **omitió** por falta de `TFG_GUEST_PW` en el entorno de la tarea (no bloqueó la ventana).
- Al terminar la extracción se **encendió la víctima SIN revertir** (para leer el log, ver §11.3)
  y se **apagó `soft`** de nuevo (**queda APAGADA** con vistas a la ventana 2).

### 11.2 Extracción (manager, solo lectura)

- Fuente: `/var/ossec/logs/alerts/2026/Oct/ossec-alerts-08.json` (diario). Extractor
  `extraer_alertas.py` **sin modificar** (sha256 repo==manager `4019fda8…`).
- **Resultado ventana 1:** **72 alertas** · **4 `rule.id`** · **0 `UNKNOWN`** · RS1 100 %.
  Primera `00:45:15.681Z` (`67027`) · última `04:39:46.048Z` (`67027`).
- **Anti-contaminación:** **0** eventos con IP `192.168.65.1` en la ventana. **Ventana VÁLIDA.**
- Detalle: `Dataset/Legitimo/windows/baseline_meta.md` §5-§7.

### 11.3 Actividad legítima (log del invitado)

- `C:\lab-legit\baseline_log.txt` → `Dataset/Legitimo/windows/baseline_log_ventana1.txt`:
  `START 2026-10-08T00:40:01Z` · **50 ciclos** (`CYCLE 1…50`, cada ~5 min) · `END 04:48:01Z`.
- `Get-ScheduledTaskInfo`: `LastRunTime = 08/10/2026 02:40:40` · **`LastTaskResult = 0`** ·
  `NumberOfMissedRuns = 0` · `NextRunTime = 08/10/2026 13:55:55` (ventana 2).

### 11.4 Estado y desviaciones

- **Víctima `victima-windows`: APAGADA** · **Manager `wazuh-server`: ENCENDIDO** (no se revierte).
- **🔴 Desviación declarada:** el **FIM forzado** (`agent_control -r -u 002`) **NO se ejecutó** en
  la ventana 1 (estaba preparado); **se hará en la ventana de la tarde**.
- Sin commit / sin push. Linux intacto (manager solo lectura). Contraseña **solo en memoria**.

---

## 12. Ventana 2 (tarde del 08/10) — EJECUTADA y EXTRAÍDA (2026-10-08)

### 12.1 Ejecución (host)

- `afternoon-start` **2026-10-08T11:45:00Z** (rc=0): revert víctima → `lab-listo-windows-baseline` ·
  start víctima (`11:45:03Z`) · start manager (`11:45:03Z`). Arranque `= t0 − 15 min` (`t0`=14:00
  local) ✔.
- `afternoon-stop` **2026-10-08T16:05:00Z** (rc=0): stop víctima `soft` (`16:05:39Z`, rc=0) · stop
  manager `soft` (`16:06:55Z`, rc=0). **Apagado limpio** ✔. **Ambas VMs quedan APAGADAS.**
- **Sin acceso al invitado dentro de `[t0,t1]`** (disciplina §1.2). El chequeo de suspensión se
  **omitió** por falta de `TFG_GUEST_PW` en el entorno de la tarea (no bloqueó la ventana).
- **Frontera usada = la del plan** `12:00:00Z–16:00:00Z` (`t0`=14:00 local). La tarea del host
  arranca 15 min antes (`11:45Z`) para el asentamiento; ver `baseline_meta.md` §1 (nota de fronteras).

### 12.2 Extracción (manager, solo lectura)

- Fuente: `/var/ossec/logs/alerts/2026/Oct/ossec-alerts-08.json` (diario). Extractor
  `extraer_alertas.py` **sin modificar** (sha256 repo==manager `4019fda8…`).
- **Resultado ventana 2:** **87 alertas** · **7 `rule.id`** · **0 `UNKNOWN`** · RS1 100 %.
  Primera `12:00:32.134Z` (`67027`) · última `15:59:46.160Z` (`67027`). Aislamiento: 158 crudas
  (todos los agentes) → **87** del agente `002` (71 del manager `000` excluidas).
- **FIM forzado** (`agent_control -r -u 002`, 12:11:00Z): **20 alertas** (`594`×6, `750`×10,
  `598`×4) en `12:11:09–12:11:11Z` — **no fueron 0** (el FIM de Windows vigila registro). Declarado
  en `baseline_meta.md` §8.1.
- **Anti-contaminación:** **0** eventos con IP `192.168.65.1` en el **detalle filtrado del agente
  `002`**; los **8** `5715` (*sshd auth success*) del agente `000` (manager) con `srcip=192.168.65.1`
  en `12:10:49–12:12:52Z` son **el acceso declarado del operador al MANAGER** (acción FIM) y quedan
  **excluidos** del catálogo. **0** `503/504` en la ventana. **Ventana VÁLIDA.**
- Detalle y catálogo unido: `Dataset/Legitimo/windows/baseline_meta.md` §5-§11.

### 12.3 Actividad legítima (log del invitado)

- `C:\lab-legit\baseline_log.txt` → `Dataset/Legitimo/windows/baseline_log_ventana2.txt`:
  `START 2026-10-08T11:55:01Z` · **50 ciclos** (`CYCLE 1…50`, cada ~5 min) · `END 16:03:02Z`.
  Cubre `[t0,t1]` (`START ≤ t0`, `END ≥ t1`) ✔.
- `Get-ScheduledTaskInfo`: `LastRunTime = 10/8/2026 1:55:55 PM` · **`LastTaskResult = 0`** ·
  `NumberOfMissedRuns = 0` · `NextRunTime` vacío (sin más disparos).
- El log se recuperó **fuera** de la ventana: se encendió la víctima **sin revertir**, se copió
  `C:\lab-legit\baseline_log.txt` (`copyFileFromGuestToHost`) y se volvió a apagar (`stop soft`).

### 12.4 Cierre del baseline y estado

- **Catálogo unido** (`ruleids_legitimos.csv`): **7 `rule.id`** (4 en ambas + 3 solo v2: FIM) ·
  **159 alertas** (72 + 87). **Estabilidad:** 4 estables / 3 variables (las de FIM).
- **Víctima `victima-windows`: APAGADA** · **Manager `wazuh-server`: APAGADO** (`vmrun list` → **0**).
- Sin commit / sin push. Linux intacto (manager solo lectura). `_recursos/` intacto. Contraseña
  **solo en memoria** (nunca en ficheros ni en logs).
