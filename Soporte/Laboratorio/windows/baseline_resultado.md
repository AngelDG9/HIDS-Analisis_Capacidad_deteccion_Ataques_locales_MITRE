# Baseline Windows — resultado operativo (host-side) · `fase-02b-baseline`

> **Autor:** `tfg-executor`. **Plan:** `plan.md` (raíz, `approved_by_human`, 2026-10-07).
> **Naturaleza:** preparación **antes de `t0`** + evidencia de ejecución **después de `t1`**.
> **Sin secretos. Sin commit.**
> **Estado:** 🟡 **PREPARADO** (a 2026-10-07 ~00:10Z). Se completará al cerrar las ventanas.

---

## 1. Ventanas (UTC / local Madrid CEST +02:00)

| Ventana | `t0` (UTC) | `t1` (UTC) | Duración | Local |
|---|---|---|---|---|
| **v1 — noche** | `2026-10-07 00:45:00Z` | `2026-10-07 04:45:00Z` | 240 min | 02:45 → 06:45 |
| **v2 — tarde** | `2026-10-07 12:00:00Z` | `2026-10-07 16:00:00Z` | 240 min | 14:00 → 18:00 |

Ambas el **mismo día** (paridad con Linux). Filtro de extracción en **UTC**.

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
