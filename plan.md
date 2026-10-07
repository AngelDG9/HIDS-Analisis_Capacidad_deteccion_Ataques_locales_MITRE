---
bloque: fase-02b-baseline
fase: 2b — Laboratorio Windows
nombre: Línea base de Windows (actividad legítima + ruido normal, 2 ventanas × 4 h)
version: 2
status: approved_by_human
fecha: 2026-10-07
fecha_aprobacion: 2026-10-07
aprobado_por: humano
autor: tfg-planner
gate: **APROBADO (2026-10-07)**. Decisiones: ventanas **idénticas a Linux** (`00:45–04:45Z` y `12:00–16:00Z`, **mismo día**) · **arranque ≥15 min antes de `t0`** (diferencia con Linux, **declarada**) · **script de actividad legítima** Windows + **tarea programada** · **FIM forzado desde el manager** · **PC encendido sin suspensión** · **no tocar el extractor** + helper aparte · **catálogo completo + estabilidad medida** · **ventana inválida → se repite** · **las 6 diferencias con Linux, declaradas**.
gate: |
  **PENDIENTE de aprobación humana.** Diseño propuesto: **2 ventanas × 4 h en UTC**
  (`00:45:00–04:45:00Z` noche · `12:00:00–16:00:00Z` tarde), **mismas franjas que Linux y el
  mismo día** por comparabilidad · **actividad legítima programada** (script Windows + **Programador
  de tareas**, lanzado **antes de `t0`**; equivalente a `baseline_actividad.sh`) · **disciplina de no
  acceso** a la VM durante la ventana · **arranque ≥ 15 min antes de `t0`** (ruido de arranque fuera;
  **diferencia con Linux, declarada**) · **catálogo completo por `rule.id`** (no top-N) + **resumen por
  origen** · **aislamiento por agente `victima-windows` (id 002)** · extracción del **fichero diario** del
  manager · **sin tocar** `extraer_alertas.py`/`filtrar_ruido.py` · **FIM forzado** desde el manager.
  **v2:** añade la actividad legítima (que faltaba) y la **comparación punto por punto con Linux** (§1.6).
---

# Bloque `fase-02b-baseline` — Línea base de Windows

> **Naturaleza del bloque:** **observación con actividad legítima programada** (no reposo pasivo). Se
> enciende la víctima Windows, se deja que una **tarea legítima se ejecute sola** durante dos ventanas
> de 4 h y se **recoge del manager** el "ruido normal" (sin ataques). Es el **espejo** del baseline de
> Linux (`_fases/fase-02/change-doc.md` §3.2; `Dataset/Legitimo/baseline_meta.md`).
> **No se ataca nada.** **No se toca Linux.** **No se modifican** `extraer_alertas.py` ni
> `filtrar_ruido.py`. Los **commits** los hace el orquestador.
>
> **Corrección v2 (decidida por el humano, 2026-10-07):** (1) la v1 describía **observación pasiva**
> (máquina en reposo) → **no era equivalente a Linux** y dejaba el baseline **incompleto**; se añade
> un **script de actividad legítima para Windows** + el modo de lanzarlo **sin tocar la VM** (§1.5).
> (2) Se **confirma** el arranque **≥ 15 min antes de `t0`** y se **declara** como **diferencia con
> Linux** (§1.3). (3) Se añade la **comparación punto por punto con el baseline de Linux** (§1.6).

---

## 0. Objetivo, contexto verificado y alcance

### 0.1 Objetivo

Grabar la **línea base de Windows** = el **"ruido normal"** del sistema **sin ataques**, **con
actividad legítima variada**, para usarla después como **referencia de falsos positivos** en `fase-03b`
(`Soporte/Laboratorio/windows/README.md` §7.4; `state.md:16`). Entregable: un **catálogo de ruido** por
`rule.id` (dos ventanas + unión) bajo `Dataset/Legitimo/windows/`, con su **medida de estabilidad**
entre ventanas.

### 0.2 Contexto verificado (leído, no supuesto)

| Hecho | Fuente |
|---|---|
| **Lab Windows OPERATIVO** (bloque `fase-02b-construccion`) | `state.md:11-17`; `Soporte/Laboratorio/windows/construccion_resultado.md` |
| VM `victima-windows`, Win10 Pro, `192.168.65.130`, VMnet1, **NAT off** | `construccion_resultado.md` §1, §2.4 |
| Agente Wazuh **4.14.7 ID `002` `active`** (`victima-windows`) | `construccion_resultado.md` §2.1 |
| Telemetría: **Sysmon v15.22** (SwiftOnSecurity) + **Security (4688 cmdline)** + **PowerShell 4104** + **FIM** (`C:\lab-attack` realtime) | `construccion_resultado.md` §1; `telemetria_windows.md` §3 |
| **Defender OFF**, telemetría mínima, Update por política | `construccion_resultado.md` §1, §3.1 |
| **Reloj corregido** (Romance Standard Time, Δ≈2 s); snapshot **`lab-listo-windows`** recreado | `construccion_resultado.md` §5 |
| **Snapshots** `base-limpia` y `lab-listo-windows` existen | `vmrun`: `victima-windows-Snapshot2.vmsn`, `victima-windows-Snapshot5.vmsn` |
| Baseline **Linux**: 2 ventanas × 4 h → **12 `rule.id`, 13.574 alertas, 0 UNKNOWN, ruido ESTABLE** | `_fases/fase-02/change-doc.md` §3.2; `Dataset/Legitimo/ruleids_legitimos.csv` |
| **Actividad legítima Linux**: script `baseline_actividad.sh` (ciclo ~5 min en `/home/angel/lab-legit/`, log UTC `START/CYCLE/END`) | `Soporte/Wazuh/Scripts/baseline_actividad.sh`; `baseline_meta.md` §5 |
| **FIM forzado dentro de la ventana Linux** (`agent_control -r -u 001`; ciclo por defecto 12 h) | `baseline_meta.md` §6, §12.3 |
| **~54 %** del ruido Linux era **auto-ruido del propio HIDS** | `Dataset/Legitimo/baseline_meta.md` §14.5 |
| **Regla operativa dura:** extraer del **fichero diario**, **NO** de `alerts.json` | `state.md:83`; `piloto_procedimiento.md` §9 |
| **Criterio v2 de los ataques**: `t0` se sella **tras el asentamiento** (≥ 60–90 s; en la práctica, arranque aparte) | `_fases/fase-03-afinado/plan.md` §48, §90; `_fases/fase-03-escalado/plan.md:295` |
| **`vmrun`** y rutas de VM (host); lección: no fiarse de procesos en segundo plano → usar **Programador de tareas** | `vmrun_config.md` §1-3, §7 |
| **RS en Windows**: RS1 (default Windows), **RS2 vacía**, RS3/RS4 (reserva) | `Soporte/Wazuh/Configuracion/rulesets_diseno.md` §10 |
| **Windows genera mucho más ruido** (Sysmon) → exige config curada + baseline | `Soporte/Laboratorio/windows/README.md` §5; `roadmap.md:192` |

> **Nota de ruta (verificada).** El fichero diario del manager es
> **`/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json`** (`state.md:83`,
> `Dataset/Legitimo/baseline_detalle_v1.csv:1`, `piloto_procedimiento.md:184`). Si en algún
> documento apareciera `/var/log/ossec/...`, es una variante **incorrecta**; se usa la ruta
> verificada.

### 0.3 Alcance

**Entra:** diseñar y ejecutar la **captura con actividad legítima** de las 2 ventanas, extraer y
catalogar el ruido del agente `victima-windows`, medir la estabilidad y documentarlo. **Sale:** los
ataques (`fase-03b`), la calibración/perfil Windows del filtro, y todo lo de Linux (ver §8).

---

## 1. Diseño de la línea base

### 1.1 Las dos ventanas (UTC, idénticas a Linux; el mismo día)

Decisión humana: **coherencia/comparabilidad** con el baseline Linux (`_fases/fase-02/change-doc.md`
§3.2). Mismas franjas, mismo tamaño y **el mismo día**:

| Ventana | `t0` (UTC) | `t1` (UTC) | Duración | Hora local Madrid (CEST, +02:00) |
|---|---|---|---|---|
| **v1 — noche** | `00:45:00Z` | `04:45:00Z` | 240 min | 02:45 → 06:45 |
| **v2 — tarde** | `12:00:00Z` | `16:00:00Z` | 240 min | 14:00 → 18:00 |

- **Ambas el mismo día** (paridad con Linux, que hizo noche + tarde el mismo día). La **fecha
  concreta** es un detalle de ejecución.
- Las ventanas se **sellan con instantes UTC fijos**; el filtro de extracción es
  `timestamp ∈ [t0,t1]` en **UTC** (los `timestamp` de Wazuh ya vienen en UTC; `state.md:94`).

### 1.2 Disciplina: "solo dejar la máquina viva y trabajando"

- **NO se ataca nada.** La víctima ejecuta **solo** la **actividad legítima programada** (§1.5) y la
  actividad natural del sistema.
- **PROHIBIDO tocar la VM durante `[t0,t1]`**: ni **RDP**, ni **SSH**, ni **`vmrun
  runProgramInGuest`/`copyFileFromHostToGuest`**, ni abrir la **consola GUI**, ni **snapshotar**.
  Cualquier acceso nuestro genera eventos (logon `4624/4625`, Sysmon de sesión) y **ensucia** la
  ventana (en Linux hubo que excluir la sesión del operador; `politica_filtrado_ruido.md` §3.bis).
  El **script legítimo se arma ANTES de `t0`** y corre **solo** (§1.5.4).
- El **manager** (`wazuh-server` `.128`) permanece **encendido y sin revertir** durante las dos
  ventanas (conserva las alertas; `vmrun_config.md` §4).

### 1.3 Qué se enciende y cuándo (**arranque ≥ 15 min antes de `t0`**)

| Máquina | Estado durante las ventanas | Cuándo actúa el ejecutor (host) |
|---|---|---|
| **`wazuh-server`** `.128` | **ENCENDIDO** (todo el bloque, sin revertir) | `start` **antes** de `t0(v1)`; verificar servicios; **no** se apaga hasta después de `t1(v2)` |
| **`victima-windows`** `.130` | **ENCENDIDA**, ejecutando la tarea legítima | `revertToSnapshot … lab-listo-windows` → `start` **≥ 15 min antes de cada `t0`** → armar el script (§1.5.4) → (silencio) → `stop soft` **después de `t1`** |
| **`victima-linux`** `.129` | **APAGADA** | **No se enciende** (riesgo de RAM: host 16 GB; `roadmap.md:162`, `Soporte/Laboratorio/windows/README.md` §5) |

- **Asentamiento (paridad con el criterio v2 de los ataques).** La víctima se enciende **≥ 15 min
  antes de `t0`** (recomendado **20 min** de margen práctico) para que el **ruido de arranque**
  (Sysmon/GPO/servicios/`4688` en ráfaga + primer scan FIM del agente) caiga **antes** de `t0` y
  `[t0,t1]` sea **régimen**. Mismo principio que el sello `t0` tras el asentamiento en los ataques
  (`_fases/fase-03-afinado/plan.md` §48, §90; `state.md:212`).
- **⚠️ Diferencia con Linux — DECLARADA.** En Linux, `t0` coincidió con el inicio del script y el
  **churn de puesta en marcha quedó DENTRO de la ventana** (`baseline_meta.md` §10.3: pico de **572**
  alertas a las `00:46Z`, "arranque del ciclo + scan FIM forzado"). En Windows se adopta el criterio
  v2 (`t0` **tras** el asentamiento) → el arranque queda **FUERA**. Es una **mejora declarada**: la
  ventana Windows mide **régimen**, no arranque. Se documenta como divergencia metodológica en
  `baseline_meta.md`.
- **PC del humano:** encendido y **sin suspensión** durante las ventanas (aceptado por el humano).

### 1.4 Cómo se sella el inicio/fin de cada ventana

Como **no se toca el invitado durante la ventana**, `t0`/`t1` **no** se escriben desde la VM a esa
hora (eso sería "tocar la VM"). El sellado es:

1. **Instantes UTC fijos** (§1.1) como fronteras canónicas de la ventana.
2. **Reloj del host** (sobremesa, sincronizado) para la secuencia operativa, registrado **fuera del
   invitado**:
   - `start_utc` = hora UTC del host al **completar** `vmrun start` (debe ser ≤ `t0 − 15 min`);
   - `stop_utc` = hora UTC del host al **completar** `vmrun stop` (debe ser ≥ `t1`).
3. **Evidencia en el manager:** la primera/última alerta del agente `002` dentro de `[t0,t1]`
   (sanity check de que la telemetría cubrió la ventana entera).
4. **Evidencia en el invitado (sin acceso en ventana):** el log de la actividad legítima
   (§1.5.5) demuestra que la tarea corrió a caballo de `[t0,t1]`.

Resultado: fichero de evidencia operativa `Soporte/Laboratorio/windows/baseline_resultado.md`
(host-side) + `Dataset/Legitimo/windows/baseline_meta.md` (ficha). **La hora autoritativa del filtro
es la del manager** (UTC).

### 1.5 Actividad legítima en Windows (**equivalente a Linux** — lo que faltaba)

> **Motivo (decidido por el humano).** La v1 dejaba la máquina **en reposo**: eso **no reproduce** el
> baseline de Linux (`baseline_actividad.sh`) y el catálogo quedaría **incompleto** (el ruido lo
> generaría solo el sistema, no un "uso legítimo" variado). Se añade un **script de actividad
> legítima para Windows** homólogo al de Linux.

#### 1.5.1 Qué hace (ciclo de tareas benignas)

Script **`Soporte/Wazuh/Scripts/baseline_actividad_windows.ps1`** (PowerShell). Cada **ciclo (~5 min,
igual que Linux)** repite, sobre una carpeta "legítima" del laboratorio:

1. **crear** varios ficheros de texto en `…\work\`;
2. **leer** los ficheros;
3. **escribir/append** en uno de ellos;
4. **compresión/backup legítimo** de `work\` → `…\backup\backup_ciclo_<N>.zip` (`Compress-Archive`,
   equivalente Windows del `tar` de Linux);
5. **copiar/mover/borrar** un temporal;
6. **búsqueda/filtrado/listado** (`Get-ChildItem -Recurse`, `Select-String`) y **hash**
   (`Get-FileHash`, equivalente de `sha256sum`);
7. **lectura del registro de eventos del sistema** (`Get-WinEvent -LogName System -MaxEvents 20`;
   equivalente de `journalctl`);
8. **inventario de programas instalados** (consulta de las claves `…\Uninstall\*` del registro;
   equivalente de `apt list --installed`);
9. **limpieza legítima**: conservar solo los **5 backups** más recientes.

- **Sin usar herramientas del ataque.** Se emplean **cmdlets nativos de PowerShell** (FileSystem,
  `Compress-Archive`, `Get-FileHash`, `Get-WinEvent`, `Get-ItemProperty`). **No** se usan utilidades
  de las técnicas de `fase-03b` (p. ej. `vssadmin`, `bcdedit`, `wbadmin`, `cipher`, `reg save`).
  La lista exacta de cmdlets queda **fijada y aprobada** en el gate (§9).
- **Determinista** (sin aleatoriedad), **sin secretos**, **re-ejecutable**; el `sha256` del script se
  registra (repo vs invitado, lección de sincronía `state.md:71`).

#### 1.5.2 Dónde escribe

- Carpeta base: **`C:\lab-legit\`** (equivalente de `/home/angel/lab-legit/`).
- Subcarpetas `work\` y `backup\`; el **log** en la raíz: **`C:\lab-legit\baseline_log.txt`**
  (timestamps **UTC**), con el formato espejo de Linux:
  `# duracion_min=<N>` · `START <UTC>` · `CYCLE <n> <UTC>` · … · `END <UTC>`.
- `C:\lab-legit\` **no** está en las rutas FIM vigiladas (igual que Linux, donde FIM **no** vigilaba
  `lab-legit`): la firma de la actividad llega por **Sysmon** (proceso/fichero) y **Seguridad 4688**,
  no por el scan FIM. Se declara.

#### 1.5.3 Cada cuánto y durante cuánto

- **Ciclo cada ~300 s (5 min)**, igual que Linux.
- **Duración 260 min** por ventana (240 min de ventana + margen), para **cubrir `[t0,t1]` entera**.

#### 1.5.4 Cómo se lanza **SIN tocar la VM** (Programador de tareas)

> El mecanismo elegido por el humano: una **tarea programada** que **arranca antes de `t0`** y corre
> **sola** durante la ventana → **no accedemos al invitado durante `[t0,t1]`**.

1. **Durante el asentamiento (antes de `t0`, con la VM ya encendida** y el agente `Active`), el
   ejecutor **arma** la actividad con `vmrun` + VMware Tools (`copyFileFromHostToGuest` /
   `runProgramInGuest`):
   - crea `C:\lab-legit\` (y `work\`, `backup\`, `tools\`);
   - **copia** `baseline_actividad_windows.ps1` a `C:\lab-legit\tools\`;
   - **registra** la tarea `TFG-Baseline-Legit` con un **disparador a una hora fija antes de `t0`**
     (propuesta: `t0 − 5 min`; p. ej. 02:40 local para v1, 13:55 local para v2), **principal
     `SYSTEM`** (*service account*, **sin guardar contraseña**), `StartWhenAvailable` y
     "no iniciar otra instancia si ya corre", con límite de ejecución ≥ 5 h.
   - Ejemplo (a ejecutar en el invitado, `runProgramInGuest`):
     ```powershell
     $a = New-ScheduledTaskAction -Execute "powershell.exe" `
          -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\lab-legit\tools\baseline_actividad_windows.ps1 -DurationMin 260"
     $t = New-ScheduledTaskTrigger -Once -At "<t0 menos 5 min, hora local>"
     $p = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
     $s = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
          -ExecutionTimeLimit (New-TimeSpan -Hours 5)
     Register-ScheduledTask -TaskName "TFG-Baseline-Legit" -Action $a -Trigger $t -Principal $p -Settings $s -Force
     ```
2. **Comprobación previa (antes de `t0`):** la tarea está **`Ready`** (`Get-ScheduledTask`), el
   script y la carpeta existen; **todos** estos pasos generan eventos **antes de `t0`** (no
   contaminan).
3. **Durante `[t0,t1]`:** la tarea corre **sola**; **cero** acceso del ejecutor al invitado.
4. **Después de `t1`:** se **recupera** el log del invitado (`copyFileFromGuestToHost`) **fuera** de
   la ventana.

- **Riesgo de disparador perdido:** cubierto con `-StartWhenAvailable` + margen de encendido
  (≥ 15 min). Si aun así la tarea **no arranca**, la ventana es **INVÁLIDA** (§4.3).

#### 1.5.5 Cómo se demuestra que corrió

1. **Log del invitado** `C:\lab-legit\baseline_log.txt` con `START`/`CYCLE <n>`/`END` en **UTC** →
   copiado al repo como `Dataset/Legitimo/windows/baseline_log_ventanaN.txt` (espejo de
   `baseline_log_ventana1.txt` de Linux).
2. **Estado de la tarea**: `Get-ScheduledTaskInfo` → `LastRunTime` dentro de la ventana y
   `LastTaskResult = 0`.
3. **Telemetría del manager**: alertas del agente `002` atribuibles a la actividad
   (Sysmon/4688 sobre `powershell.exe` y sobre `C:\lab-legit\`), y **cobertura temporal** (primera y
   última alerta del agente dentro de `[t0,t1]`).
4. **Recuento de ciclos**: nº de `CYCLE` ≈ 52 esperados en 260 min; se declara el número real.

### 1.6 Comparación punto por punto con el baseline de Linux

> Recorrido de los elementos del baseline Linux (`_fases/fase-02/plan.md` §3.8; `change-doc.md` §3.2;
> `Dataset/Legitimo/baseline_meta.md`) marcando **igual / distinto (y por qué) / falta**. Toda
> diferencia que se mantiene queda **justificada y declarada**.

| # | Punto | Linux (baseline real) | Windows (esta v2) | Veredicto |
|---|---|---|---|---|
| 1 | **Actividad legítima (script)** | `baseline_actividad.sh`: ciclo ~5 min en `/home/angel/lab-legit/`; lanzado por `nohup` vía SSH; log UTC `START/CYCLE/END` | `baseline_actividad_windows.ps1`: mismo tipo de tareas, ciclo ~5 min en `C:\lab-legit\`; lanzado por **Programador de tareas** (sin `nohup`/SSH); log UTC homólogo | **Distinto (mecanismo), igual (espíritu)** — declarado (§1.5) |
| 2 | **Actividad natural** | systemd, cron, SSH, rootcheck, auditd, mantenimiento diario (`cron.daily` ~04:25Z) | servicios del SO, **Task Scheduler** nativo, eventos de sistema/logon, Sysmon, `wuauserv` (auto-reparado) | **Igual en espíritu, distinta en naturaleza** — Windows no tiene `auditd`/`cron`; se declaran las fuentes nativas |
| 3 | **Forzar un scan FIM dentro de la ventana** | **SÍ**: `agent_control -r -u 001` (ciclo por defecto 12 h); resultado **0** alertas FIM | **SÍ**, **desde el manager** `agent_control -r -u 002` (**no toca la VM**); verificar antes el `frequency` real del `ossec.conf` del agente; resultado esperado **0** (se declara) | **Igual** (mismo método manager-side) |
| 4 | **Registro `t0`/`t1` (UTC/local) + requisito `t1−t0 ≥ 4 h`** | En `baseline_meta.md` §1/§12; 240 min ✔ | Igual: `t0`/`t1` en **UTC y local**, requisito `≥ 4 h` (= 240 min) en `baseline_meta.md` | **Igual** |
| 5 | **Esquema del catálogo** | `rule_id,rule_level,rule_description,groups,count,first_seen,last_seen,rs_origen`; unión `…,count_v1,count_v2,count_total,ventanas` | **Idéntico** (mismo `CSV_HEADER` del extractor congelado + unión del helper) | **Igual** |
| 6 | **Dónde vive el catálogo** | `Dataset/Legitimo/` (plano) | **`Dataset/Legitimo/windows/`** (subárbol nuevo) | **Distinto (ubicación)** — no se mueve Linux (`README.md` §9); declarado |
| 7 | **Fuente de extracción** | `alerts.json` (Fase 2; la regla del **fichero diario** es posterior, `state.md:83`) | **Fichero diario** `/var/ossec/logs/alerts/…/ossec-alerts-<DD>.json` | **Distinto (más estricto)** — Windows aplica ya la regla operativa vigente; declarado |
| 8 | **Filtro por agente** | **No** filtró: incluyó ~15 alertas del **manager** (`baseline_meta.md` §8) | **Aislamiento estricto**: solo `agent_name == victima-windows` + cruce `agent.id == 002` | **Distinto** — evita mezclar el ruido de Linux/manager; declarado |
| 9 | **Regla de medianoche** | No aplicó (ninguna ventana cruza) | Igual: ninguna cruza; **regla declarada** si ocurriera (partir el diario en DD/DD+1) | **Igual** |
| 10 | **UTC** | Filtro en UTC (`state.md:94`) | Igual | **Igual** |
| 11 | **2 ventanas (noche/tarde)** | `00:45–04:45Z` y `12:00–16:00Z` | **Idénticas y el mismo día** | **Igual** |
| 12 | **Medida de estabilidad** | §14: tipos ambas/solo-v1/solo-v2, Δ frecuencia, ritmo, capas, auto-ruido, veredicto | **Misma batería**; se **mide y se declara** (no se fuerza "estable"); se espera **más varianza** (Sysmon) | **Igual (diseño); Windows más ruidoso** — declarado |
| 13 | **RS activos durante la ventana** | RS1 + RS2 (auditd); RS3/RS4 vacías (`baseline_meta.md` §4) | RS1 (default Windows); **RS2 VACÍA**; RS3/RS4 vacías (`rulesets_diseno.md` §10) | **Distinto** — sin `auditd` no hay RS2; declarado |
| 14 | **NAT desconectado** | Sí (`ens37` DOWN) | Sí (`ethernet1.startConnected="FALSE"`) | **Igual** |
| 15 | **Snapshot de la víctima** | `lab-listo` (Linux) | `lab-listo-windows` | **Igual (distinto nombre)** |
| 16 | **Manager no revertido** | Sí (conserva alertas) | Sí | **Igual** |
| 17 | **Uso posterior (FP)** | El catálogo **acota**, **no etiqueta** (`plan.md` §3.8; `baseline_meta.md` §9) | Igual: referencia **acotada** de FP, pertenencia ≠ FP automático | **Igual** |
| 18 | **Ruido de arranque dentro/fuera** | **Dentro**: `t0` = inicio del script; primer ciclo + FIM → pico 572 a `00:46Z` | **Fuera**: arranque ≥ 15 min antes de `t0` (criterio v2) | **Distinto** — mejora declarada (§1.3) |
| 19 | **Log de la ventana** | `baseline_log_ventana{1,2}.txt` (copia del log del invitado) | `Dataset/Legitimo/windows/baseline_log_ventana{1,2}.txt` | **Igual** (ubicación nueva) |
| 20 | **`vulnerability-detector` del manager** | Sin NAT → solo errores de log, **0 alertas**; no contamina | **Heredado**: es el **mismo manager** Linux → mismo comportamiento documentado | **Igual (heredado)** |

**Resumen:** las diferencias **reales** son: (1) mecanismo de la actividad (Programador de tareas vs
`nohup`), (6) ubicación del catálogo, (7) fuente diaria (más estricta), (8) aislamiento por agente,
(13) RS2 vacía, (18) arranque fuera de ventana. Todas **declaradas**; ninguna rompe la comparabilidad
(las franjas, el esquema, la batería de estabilidad y el uso posterior son idénticos).

### 1.7 Qué se mide (esencia)

El **catálogo de ruido** = conjunto de `rule.id` que el agente `002` dispara en régimen, **sin
ataque**, con actividad legítima. Se mide su **estabilidad** entre las dos ventanas y se **declara**
el veredicto, sin forzarlo.

---

## 2. Extracción del catálogo

### 2.1 De dónde y con qué

- **Fuente:** fichero **diario** del manager
  **`/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json`** (**NO** `alerts.json`; `state.md:83`).
  Es **más estricto** que el baseline Linux de Fase 2 (que usó `alerts.json`); se declara (§1.6 fila 7).
- **Herramienta:** `_artefactos/scripts/extraer_alertas.py` (**sin modificar**), con copia
  desplegada en el manager (`/home/angel/extraer_alertas.py`). **Verificar `sha256` repo == manager**
  antes de extraer (`state.md:71`). Extracción en el manager como `root` (lectura de `/var/ossec`),
  contraseña **solo en memoria** (nunca en ficheros).
- **UTC:** `--desde`/`--hasta` en UTC (§1.1). Las fronteras son las de §1.1.

> **Decisión de diseño — no tocar el extractor.** **NO** se añade a `extraer_alertas.py` ningún
> parámetro nuevo: su `sha256` está citado en las bitácoras de Fase 3 (p. ej. `Bitacora/ATA024.json`
> "extractor … sha256 … `4019fda8…`"). Modificarlo **rompería la trazabilidad** de la cadena de
> huellas de Linux. El aislamiento por agente se hace **post-extracción** (§2.2).

### 2.2 Aislamiento por agente (id `002`)

`extraer_alertas.py` **no** filtra por agente; su `--detail` **sí** emite `agent_name`
(`piloto_procedimiento.md` §9, líneas 194-217). Procedimiento por ventana:

1. **Detalle crudo** (todos los agentes):
   `sudo python3 /home/angel/extraer_alertas.py --alerts <DIARIO> --desde <t0> --hasta <t1> --detail /tmp/baseline_win_vN_raw.csv`
2. **Filtro a `agent_name == victima-windows`** con el **snippet canónico** (stdlib, salta la línea
   `#` de cabecera; `piloto_procedimiento.md:197-205`), parametrizado a `victima-windows` →
   `baseline_win_vN_det.csv`.
3. **Cruce por `agent.id == 002`** como comprobación (el nombre es estable; el `id` confirma).

- **Aislamiento duro:** las filas de **otros agentes** (el propio **manager** `000`, y el agente
  `001` de Linux si por error estuviera encendido) **nunca** entran al catálogo. Es una **diferencia
  declarada** con Linux (que sí incluía ~15 alertas del manager; §1.6 fila 8).

### 2.3 Producto de la extracción

Por cada ventana:

- **Detalle filtrado** (evidencia por alerta): `Dataset/Legitimo/windows/baseline_detalle_vN.csv`.
- **Catálogo por `rule.id`** (agregado): `Dataset/Legitimo/windows/ruleids_legitimos_vN.csv`.
  - **Cómo se agrega sin tocar el extractor:** se filtra el fichero **diario a líneas del agente
    002 + ventana** a un JSONL temporal (`/tmp/baseline_win_vN.jsonl`) y se ejecuta
    `extraer_alertas.py --alerts <temp> --desde <t0> --hasta <t1> --out <catalogo_vN.csv>` — reutiliza
    la **lógica de agregación congelada** (`CSV_HEADER`: `rule_id, rule_level, rule_description,
    groups, count, first_seen, last_seen, rs_origen`).
- **Log de la actividad legítima**: `Dataset/Legitimo/windows/baseline_log_ventanaN.txt` (copia del
  `C:\lab-legit\baseline_log.txt`).
- **Unión v1+v2** (`ruleids_legitimos.csv`): **helper nuevo mínimo**
  `_artefactos/scripts/unir_catalogo_ruido.py` (+ tests) que fusiona los dos catálogos por ventana en
  el **esquema idéntico al Linux** (`ruleids_legitimos.csv`: `… count_v1,count_v2,count_total,
  ventanas`), con línea `#` de cabecera descriptiva. Determinista (misma entrada → mismos bytes).

### 2.4 Ventanas que crucen medianoche UTC

Ninguna de las dos ventanas elegidas cruza medianoche UTC. **Regla declarada** por si se necesitara:
si una ventana cruzara medianoche, el **fichero diario se parte en dos** (`ossec-alerts-<DD>` y
`ossec-alerts-<DD+1>`); se extraen **ambos** con el mismo `[t0,t1]` (cada uno cubre su tramo) y se
**fusionan** los catálogos con el helper de §2.3 (que acepta varios ficheros). No aplica aquí; se
documenta para no improvisar.

### 2.5 Uso posterior (Fase 3b) — acota, no etiqueta

Igual que Linux (`_fases/fase-02/plan.md` §3.8; `baseline_meta.md` §9): el catálogo es la **referencia
de ruido normal**. En `fase-03b`, una alerta de un ataque cuyo `rule.id` **coincide** con el baseline
y **no** es atribuible al Data Component de la técnica se marca como **candidata a FP** (revisión
humana); el baseline **no** etiqueta automáticamente: **acota**. El catálogo Windows será un
**superconjunto** del ruido esperable en un ataque (el script no correrá en Fase 3b).

---

## 3. El catálogo de Windows

### 3.1 Estructura y ubicación

Todo bajo **`Dataset/Legitimo/windows/`** (subárbol **nuevo**; no se toca el baseline Linux;
`Soporte/Laboratorio/windows/README.md` §9):

| Fichero | Contenido |
|---|---|
| `ruleids_legitimos.csv` | **Unión** v1+v2 (esquema idéntico a `Dataset/Legitimo/ruleids_legitimos.csv`), con línea `#` de metadatos |
| `ruleids_legitimos_v1.csv` / `_v2.csv` | Catálogo **por ventana** (traza + comparación) |
| `resumen_por_origen.csv` | **Vista** por origen/capa (ver §3.2) |
| `baseline_detalle_v1.csv` / `_v2.csv` | Detalle por alerta **filtrado a `victima-windows`** (evidencia) |
| `baseline_log_ventana1.txt` / `_ventana2.txt` | Copia del log de la actividad legítima (48+ ciclos, `START`/`END` UTC) |
| `baseline_meta.md` | **Ficha** del baseline (ventanas, config, resultados, estabilidad, limitaciones) |

### 3.2 Qué estructura (por `rule.id` + vista por origen)

- **El entregable es el catálogo COMPLETO por `rule.id`** — **no un top-N**. El filtro de FP de
  Fase 3b necesita la **pertenencia exacta** (`rule_id ∈ catálogo`), igual que Linux
  (`politica_filtrado_ruido.md` §2 paso 6-7). Un top-N **sería lossy** → no puede ser el catálogo.
- **El ruido de Windows será MUCHO mayor que los 12 `rule.id` de Linux** (Sysmon + Security +
  PowerShell; `Soporte/Laboratorio/windows/README.md` §5). Por eso se añade, **sin sustituir** al
  catálogo, una **vista de resumen por origen** (`resumen_por_origen.csv`), agrupando por:
  - **`rs_origen`** (RS1 = default, incluye todo el ruleset Windows; **RS2 vacía en Windows**;
    RS3/RS4 según `rulesets_diseno.md` §10);
  - **canal/layer** derivado de `rule_groups`: **Sysmon** (`sysmon`), **Security**
    (`windows`/`security`), **PowerShell** (`powershell`), **FIM/syscheck** (`syscheck`),
    **Wazuh interno** (estado del agente / `rule_id 11`).
  - Columnas: `origen, rule_ids_distintos, alertas, %_del_total, top_rule_ids`.
- La vista **no** elimina filas del catálogo: es solo legible para humanos y para dimensionar el ruido.

### 3.3 Cómo se mide la ESTABILIDAD entre las 2 ventanas (paridad con Linux §14)

Misma batería que Linux (`Dataset/Legitimo/baseline_meta.md` §14), pero **declarando honestamente**
que Sysmon es más variable:

1. **Tipos de alerta:** `rule.id` en **ambas** / **solo v1** / **solo v2** (§14.1).
2. **Frecuencia por regla:** `count_v1`, `count_v2`, Δ absoluto y Δ % (§14.2).
3. **Ritmo:** alertas/min en **régimen** (§14.3). Ojo: la actividad legítima corre **toda** la
   ventana (no hay "arranque del script" en v1 salvo el primer ciclo), así que "régimen" excluye solo
   el residuo de arranque del SO.
4. **Reparto por capa/origen** v1 vs v2 (§14.4).
5. **Auto-ruido:** atribución por campos (`win_image`/`rule_groups`) del ruido del propio HIDS
   (estado del agente `503/506`, `rule_id 11` de `stats`, `wazuh-agent.exe`) (§14.5).
6. **Veredicto:** **ESTABLE / PARCIALMENTE ESTABLE / INESTABLE**, con **divergencias declaradas sin
   maquillar** (igual que Linux §14.6).

> **Umbral orientativo (no ciego):** sin cambios **estructurales** (no aparece/desaparece un origen
> entero) y con Δ total **≤ ~10 %** se hablará de "estable en régimen"; por encima, "parcialmente
> estable" con las reglas divergentes listadas. **Windows es más ruidoso** → se espera más varianza
> que el −1,5 % de Linux; el plan **no** fuerza un pass/fail: **mide y declara**.

---

## 4. Operativa

### 4.1 Quién enciende/apaga y arma la actividad

- El **`tfg-executor`**, **desde el host (sobremesa)** con **`vmrun`**
  (`C:\Program Files\VMware\VMware Workstation\vmrun.exe`; `vmrun_config.md` §1-3):
  - `wazuh-server`: `start`/`stop` (no se revierte).
  - `victima-windows` (`D:\TFG-VMs\victima-windows\victima-windows.vmx`):
    `revertToSnapshot … lab-listo-windows` → `start … nogui` → *(asentamiento ≥ 15 min)* →
    **armar** el script + tarea (§1.5.4) → *(silencio)* → `stop … soft`.
- El **humano**: mantiene el **PC encendido y sin suspensión**; **no** entra en la VM.
- **Nadie** entra en la víctima durante `[t0,t1]` (§1.2). La **tarea programada** sí corre (es
  actividad del propio invitado, no acceso nuestro).

### 4.2 Cómo se evita el acceso durante la ventana

- **Regla dura:** durante `[t0,t1]` **no** hay ninguna conexión ni comando contra `victima-windows`.
  El ejecutor **no** usa `runProgramInGuest`/`copyFile*` en esa franja.
- **Chequeos previos (antes de `t0`, dentro del asentamiento):** Defender OFF, telemetría mínima,
  NAT desconectado, agente `002 active`, Sysmon `Running`, reloj correcto, `frequency` de syscheck,
  tarea `Ready`, `C:\lab-legit\` creada. **Todos** antes de `t0` (sus eventos caen **antes** de `t0`).
- **Prueba anti-contaminación (post-hoc):** en el detalle filtrado, buscar eventos de **logon/sesión
  del operador** (`4624/4625/4672`, RDP/`wsmprovhost`) **desde la IP del host `192.168.65.1`** dentro
  de `[t0,t1]`. Si los hay → **ventana contaminada** (§4.3).

### 4.3 Qué pasa si algo se corta

| Corte | Regla |
|---|---|
| La **víctima** se apaga/crashea, o el **agente `002`** pierde conexión dentro de `[t0,t1]` | **Ventana INVÁLIDA** → se descarta y se **repite entera** (snapshot fresco + 4 h nuevas) |
| El **manager** se cae o no escribe el fichero diario | **Ventana INVÁLIDA** → se repite |
| Se detecta **acceso del operador** dentro de `[t0,t1]` | **Ventana INVÁLIDA** → se repite (la contaminación no se "resta") |
| La **tarea legítima no corre** o cubre < `[t0,t1]` | **Ventana INVÁLIDA** → se repite |
| El **asentamiento** fue insuficiente (pico de arranque dentro de `[t0,t1]`) | **Ventana INVÁLIDA** (o se documenta y se decide repetir) |
| El **PC se suspende** | **Ventana INVÁLIDA** → se repite |
| Un fallo de la **herramienta** (extracción) | Se **re-extrae** del diario (idempotente); la ventana sigue válida si el diario está íntegro |

Regla general: **una ventana parcial o dudosa no vale**; se repite **desde cero** (paridad con la
exigencia de ventana completa de Linux, `state.md:212`). Las **incidencias se registran**.

---

## 5. Entregables y ficheros que se tocarán

**Nuevos:**

- `Soporte/Wazuh/Scripts/baseline_actividad_windows.ps1` (**actividad legítima Windows**, §1.5)
- `Dataset/Legitimo/windows/ruleids_legitimos.csv`
- `Dataset/Legitimo/windows/ruleids_legitimos_v1.csv`, `ruleids_legitimos_v2.csv`
- `Dataset/Legitimo/windows/resumen_por_origen.csv`
- `Dataset/Legitimo/windows/baseline_detalle_v1.csv`, `baseline_detalle_v2.csv`
- `Dataset/Legitimo/windows/baseline_log_ventana1.txt`, `baseline_log_ventana2.txt`
- `Dataset/Legitimo/windows/baseline_meta.md`
- `Soporte/Laboratorio/windows/baseline_resultado.md` (evidencia operativa host-side)
- `_artefactos/scripts/unir_catalogo_ruido.py` (+ tests en la suite `pytest`)

**Actualizados (aditivo, sin tocar Linux):**

- `Soporte/Laboratorio/windows/README.md`: registrar el procedimiento (tarea programada, carpeta
  `C:\lab-legit\`) y la línea base.
- `state.md`, `roadmap.md`, `change-doc.md` (los cierra el orquestador).

**Sin tocar:** `_artefactos/scripts/extraer_alertas.py`, `_artefactos/scripts/filtrar_ruido.py`, `Bitacora/`,
`Dataset/Legitimo/` (raíz, Linux), `_recursos/`. **Sin `git commit`** (lo hace el orquestador).

---

## 6. Verificación y criterios de aceptación

### 6.1 Qué comprueba el `tfg-tester`

1. **Recuento independiente:** recalcular alertas y `rule.id` por ventana desde el **fichero diario**
   (manager) y comprobar que **cuadra al dígito** con los catálogos.
2. **Fuente correcta:** evidencia de que se usó el **fichero diario** (ruta citada), **no** `alerts.json`.
3. **Aislamiento por agente:** **0** filas con `agent_name != victima-windows` en el detalle; cruce
   con `agent.id == 002`; y `n_filtrado ≤ n_raw`.
4. **UTC:** fronteras en UTC; ventanas dentro del mismo día UTC (o el caso medianoche tratado).
5. **Anti-contaminación:** **0** logon/sesión del operador desde `192.168.65.1` dentro de `[t0,t1]`.
6. **Actividad legítima ejecutada (§1.5):** existe `baseline_log_ventanaN.txt` con `START` ≤ `t0` y
   `END` ≥ `t1`; `Get-ScheduledTaskInfo` (`LastTaskResult=0`) documentado; nº de ciclos declarado.
7. **Determinismo:** `unir_catalogo_ruido.py` reproducible (mismos bytes); `pytest` verde.
8. **Integridad:** `extraer_alertas.py`/`filtrar_ruido.py` **sin cambios** (`sha256`); manager **no
   revertido**; el diario contiene ambas ventanas; script legítimo con `sha256` repo == invitado.
9. **Higiene:** nada de Linux tocado; `_recursos/` intacto; **sin secretos**; **sin commit**;
   snapshots `base-limpia`/`lab-listo-windows` intactos; NAT off; Defender off.
10. **Estabilidad:** existe el análisis (ambas/solo-v1/solo-v2, Δ, ritmo, capas) y un veredicto.

### 6.2 Criterios de aceptación (CA)

- **CA1.** **2 ventanas × 4 h** en UTC, **mismas franjas que Linux** (`00:45–04:45Z`, `12:00–16:00Z`),
  extraídas del **fichero diario** y **aisladas** a `victima-windows` (id `002`).
- **CA2.** Catálogo **completo por `rule.id`** (v1, v2 y unión) con **esquema idéntico al de Linux** +
  `resumen_por_origen.csv`; cifras **recomputables al dígito**.
- **CA3.** **0** filas de agentes ajenos; **0 `UNKNOWN`** o justificados.
- **CA4.** **Medida de estabilidad** con veredicto honesto y divergencias declaradas.
- **CA5.** `baseline_meta.md` + `baseline_resultado.md` completos (ventanas, config, limitaciones).
- **CA6.** Ninguna ventana **contaminada** por acceso del operador (evidencia); si lo estuvo,
  **invalidada y repetida**.
- **CA7.** **Actividad legítima** ejecutada y evidenciada en **ambas** ventanas (§1.5.5).
- **CA8.** Nada de Linux tocado; `_recursos/` intacto; **sin secretos**; **sin commit**; snapshots
  intactos; NAT off; Defender off.
- **CA9.** Herramientas **deterministas**; `extraer_alertas.py`/`filtrar_ruido.py` **sin modificar**.
- **CA10.** `plan.md` en `status: approved_by_human` **antes** de que el ejecutor actúe.

---

## 7. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| **PC se suspende** durante la ventana | Humano desactiva suspensión; plan de energía; PC en corriente; verificar antes de `t0` |
| **La tarea programada no arranca** (disparador perdido) | `-StartWhenAvailable`; arranque ≥ 15 min antes; verificar `Ready` antes de `t0`; si falla → ventana inválida |
| **La tarea corre como SYSTEM y no ve `C:\lab-legit\`** | Crear la carpeta con permisos antes de `t0`; verificar un ciclo en seco (fuera de ventana) |
| **`wazuh-indexer` arranca lento/timeout** (cabo conocido) | No afecta al **fichero diario**; verificar servicios y, si hace falta, `systemctl restart wazuh-indexer` **antes** de `t0`; documentar |
| **Sysmon inunda** (muchos `rule.id`, volumen alto) | Catálogo **completo** + **resumen por origen**; **vigilar el disco** del manager; **no** cambiar la config dentro de la ventana |
| **Disco del manager lleno** | Monitorizar espacio libre antes/durante; alerta temprana; si se llena, ventana inválida |
| **Reloj** (`w32time` off; depende de VMware Tools) | Los `timestamp` del manager son UTC (seguros); declarar el posible desfase de `data.win.system.systemTime` |
| **DST / hora local del disparador** | El disparador es a hora **local** (Romance); 2026-10-07 es **CEST (+02:00)**; verificar `tz` del invitado antes de armar; `StartWhenAvailable` como red |
| **Windows Update se auto-repara** (`wuauserv`) | NAT off impide descargar; el ruido de mantenimiento **forma parte** del baseline; declarar |
| **Contaminación por nuestro acceso** | Disciplina dura de no acceso + prueba anti-contaminación (CA6) |
| **Asentamiento insuficiente** (arranque dentro de la ventana) | Encender **≥ 15 min antes** de `t0`; verificar ausencia de pico al inicio |
| **Windows 10 EOL** (2025-10-14) | Limitación **ya declarada** del laboratorio (`Soporte/Laboratorio/windows/README.md` §3.2) |
| **Ruido Windows ≠ ruido Linux** | El catálogo es **referencia acotada** (igual que Linux, `baseline_meta.md` §9), **no** oráculo de FP |

---

## 8. Fuera de alcance (lo que NO entra)

- **No** se ejecuta ningún **ataque** ni prueba ART (eso es `fase-03b`).
- **No** se **calibra** ni se implementa el **perfil Windows** de `filtrar_ruido.py` (Fase 3b; aquí
  solo se produce el catálogo).
- **No** se **modifican** `extraer_alertas.py` ni `filtrar_ruido.py` (por integridad de huellas).
- **No** se toca **Linux** (ni datos, ni scripts, ni huellas, ni carpetas). **No se mueve nada.**
- **No** se modifica `_recursos/` (solo lectura).
- **No** se abre **P2** ni el bloque de **evasión**.
- **No** se mide con **Defender ON**.
- **No** se usa ninguna herramienta de las técnicas de `fase-03b` en la actividad legítima.
- **No** se hace **`git commit`/`push`** (el commit lo hace el orquestador; el `push`, el humano).

---

## 9. Gate humano (decisiones en lenguaje sencillo)

1. **Q1 — Actividad legítima (script Windows).** Se añade `baseline_actividad_windows.ps1` (ciclo
   ~5 min en `C:\lab-legit\`, mismas tareas que el script de Linux: crear/leer/escribir, comprimir,
   copiar/mover/borrar, buscar, hashear, listar programas). ¿De acuerdo con **la lista de tareas y
   cmdlets** (sin utilidades del ataque)?
2. **Q2 — Lanzamiento sin tocar la VM.** Se arma **antes de `t0`** una **tarea programada** (como
   `SYSTEM`) que arranca en `t0 − 5 min` y corre 260 min. ¿De acuerdo?
3. **Q3 — Arranque ≥ 15 min antes de `t0`.** Se enciende la víctima ≥ 15 min antes de cada `t0` para
   que el **ruido de arranque quede fuera** (criterio v2 de los ataques). Es **una diferencia con
   Linux** (que lo tuvo dentro) — **declarada**. ¿De acuerdo?
4. **Q4 — PC encendido.** Confirmas que el **sobremesa queda encendido y sin suspensión** durante las
   dos ventanas (8 h + asentamientos). **No se toca la VM** en ese tiempo.
5. **Q5 — FIM forzado.** Se fuerza un scan FIM dentro de cada ventana **desde el manager**
   (`agent_control -r -u 002`, igual que Linux; **no toca la VM**). ¿De acuerdo? (Alternativa: no
   forzarlo y declararlo.)
6. **Q6 — Programación.** Las ventanas son **en tiempo real**; un proceso en segundo plano **no** es
   fiable (`vmrun_config.md` §7). Se gobierna con el **Programador de tareas**. ¿De acuerdo?
7. **Q7 — Herramienta.** **No** tocar `extraer_alertas.py`; aislar al agente `002` con el **snippet**
   ya usado en Linux y añadir **un helper mínimo** (`unir_catalogo_ruido.py`) para la unión. ¿De acuerdo?
8. **Q8 — Catálogo.** Confirmas el catálogo **completo por `rule.id`** (no top-N) + **resumen por
   origen**, y que la **estabilidad** se **mide y se declara** (sin forzar "estable").
9. **Q9 — Ventana inválida.** ¿De acuerdo en que una ventana **parcial o contaminada** se **descarta y
   se repite entera**?
10. **Q10 — Diferencias declaradas.** Confirmas las **6 diferencias reales** con Linux (§1.6:
    mecanismo de la actividad · ubicación · fuente diaria · aislamiento por agente · RS2 vacía ·
    arranque fuera de ventana), todas **justificadas y declaradas**.

---

## 10. Referencias

- Estado vivo: `state.md` (línea base pendiente `:16`; regla del fichero diario `:83`; baseline
  Linux `:74`; lección de sincronía `:71`; anti-contaminación `:94`; criterio v2 `:212`).
- Roadmap: `roadmap.md:86-108`, `roadmap.md:129-143`.
- Linux (espejo): `_fases/fase-02/plan.md` §3.8; `_fases/fase-02/change-doc.md` §3.2 y §4;
  `Soporte/Wazuh/Scripts/baseline_actividad.sh`; `Dataset/Legitimo/ruleids_legitimos.csv`;
  `Dataset/Legitimo/baseline_meta.md` §5, §6, §14-§15.
- Windows: `Soporte/Laboratorio/windows/README.md` (D1–D7, §5, §7, §9),
  `construccion_resultado.md`, `telemetria_windows.md`, `prestaging_material.md`.
- Herramientas: `_artefactos/scripts/extraer_alertas.py` (`CSV_HEADER`, `DETAIL_HEADER`);
  `_artefactos/scripts/filtrar_ruido.py`; snippet de aislamiento por agente
  (`Soporte/Ataques/piloto_procedimiento.md` §9).
- Infra: `Soporte/Laboratorio/vmrun_config.md` (§1-4, §7); `Soporte/Wazuh/Configuracion/rulesets_diseno.md` §10.
- Criterio v2: `_fases/fase-03-afinado/plan.md` §48, §90; `_fases/fase-03-escalado/plan.md:295`.
