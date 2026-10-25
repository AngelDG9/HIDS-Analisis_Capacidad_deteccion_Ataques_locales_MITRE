# Ensayo E0 — armado de punta a punta (obligatorio antes de `t0`)

> **Bloque:** `legitimo-72h-v2` · **Plan:** `plan.md` §4.3 (E0-1…E0-6) · **Gate:** `approved_by_human` (2026-10-25).
> **Ventana objetivo:** `t0 = 2026-10-26T00:00:00Z` → `t1 = 2026-10-29T00:00:00Z`.
> **Ejecución del ensayo:** **2026-10-25, 20:44Z → 21:39Z** (≈ 55 min, hora del host: 21:44 → 22:39 local, CET = UTC+1).
> **Veredicto: PASS** (con **4 salvedades declaradas**, todas externas al mecanismo; ver §4).

---

## 1. Qué se probó (y qué no)

| Cubierto por E0 | Ya estaba probado (no se repite) |
|---|---|
| `arm` completo (nunca ejecutado antes, §3 del plan) | `prep` (3× con EXIT=0 el 21/10) |
| Instalación del **timer del invitado** (`tfg-ghosts-legit.timer`) | La receta y su `--check` (DT9/DT10/DT11) |
| **Disparo** del timer y **arranque del keepalive v3** | La vigilancia (DT4/DT6/DT7) |
| **Rotación diaria + reinicio del cliente** (camino completo) | La extracción (DT8) y el snapshot (DT12) |
| **Encadenado real de las 4 tareas** del Programador + `NextRun` UTC | |
| `stop` + `cleanup` + `revert` a `lab-listo-legit-v2` | |

---

## 2. Resultado por paso

### E0-1 — `prep` (T0 real) → **PASS**

```
[2026-10-25T20:44:17Z] [prep] === START prep (host UTC 2026-10-25T20:44:17Z) t0=2026-10-26T00:00:00Z t1=2026-10-29T00:00:00Z ===
[prep] G-1 OK: snapshot 'lab-listo-legit-v2' presente | Total snapshots: 5 base-limpia lab-listo lab-listo-legit fallo-2026-10-19-disco-lleno-NO-USAR lab-listo-legit-v2
[prep] G-10: D_libre_gb=183.3 wuauserv_StartType=Disabled sesion=angel
[prep] G-4 --check:
RESULT=PASS
[prep] G-4 OK: d1=8e4de7f8 d2=c041d71b d3=d9bf437f mapa 26/27/28 -> d1/d2/d3
[prep] vmrun -T ws revertToSnapshot ... lab-listo-legit-v2 -> rc=0
[prep] vmrun -T ws start ...victima-linux.vmx nogui -> rc=0
[prep] vmrun -T ws start ...wazuh-server.vmx nogui -> rc=0
[prep] G-12: ram_free_mb=2511 swap_mb=1915 ram_min_mb=1500
[prep] G-12 AVISO (declarado): swap_mb=1915 != 0 (el plan asumia 0; no se toca la VM)
[20:48:43Z] G-2: df_free_mb=4529 inodos_libres_pct=84
[20:48:43Z] G-3 verificar_arreglos: ... RESULT=PASS
[20:50:06Z] G-7: conf: <logall_json>yes</logall_json> manager=active daemons_remoted_analysisd=2
[20:50:37Z] G-8: ... 8080 root: 200 | 9090 paste: 200 | 9092 put: 201 | example.com: FALLA (ok, aislado) | 1.1.1.1: FALLA (ok, aislado) | RUTA: 192.168.65.0/24 dev ens33   (sin `default`)
[20:50:38Z] G-5: agentd_procs=1 | ... Status: Active ... disco=21G libre (56% usado)
[20:50:39Z] G-11: machineids de victima-linux = 7c33a13a-fe89-4a56-bf3c-fcd499e1e557
[20:50:40Z] prep: timeline activa = 8e4de7f8 (esperado d1=8e4de7f8)
[20:50:40Z] prep: rotacion.estado = 2026-10-26 (día 1 ya colocado; no se rota el día 1)
[20:50:41Z] G-6 OK: muestras 'df -P' del agente 001 en archives.json
[2026-10-25T20:50:41Z] [prep] === END prep (laboratorio LISTO, cliente PARADO) ===
```

**12/12 guardarraíles en OK** (G-1, G-2, G-3, G-4, G-5, G-6, G-7, G-8, G-10, G-11, G-12; G-9 es informativo y salió vacío — no había `.gz`
previo, coherente con una ventana que aún no ha empezado). Ningún código de aborto.

### E0-2 — `arm` con T0 falso → **PASS** (con salvedad S-1/S-2)

`T0_falso = 2026-10-25T21:40:34Z` (ahora + 16 min ⇒ timer a `T0−5` = 21:35:34Z).

```
[arm] bash /tmp/instalar_tarea_invitado.sh 2026-10-25T21:40:34Z 8e4de7f8… c041d71b… d9bf437f…; echo rc=$?
T0=2026-10-25T21:40:34Z  ->  OnCalendar=2026-10-25 21:35:34 UTC
receta d1: 8e4de7f8 presente / d2: c041d71b presente / d3: d9bf437f presente
== enabled ==   enabled
== timers ==    NEXT Sun 2026-10-25 22:35:34 CET   LEFT 10min   tfg-ghosts-legit.timer -> tfg-ghosts-legit.service
== unit-files == tfg-ghosts-legit.service disabled / tfg-ghosts-legit.timer enabled
== ExecStart ==  ExecStart=/home/angel/ghosts-client/tfg_keepalive.sh 74 2026-10-25T21:40:34Z
== fecha UTC de la victima == Sun Oct 25 09:24:37 PM UTC 2026 (CET 22:24)  [reloj del invitado correcto]
rc=0
[arm] === END arm ===
```

- `instalar_tarea_invitado.sh` **rc=0** ✅ · timer `enabled` ✅ · `NEXT` = `T0_falso−5 min` **en UTC** ✅ · `ExecStart` con el T0 correcto ✅.
- Clausura del cliente: `pgrep` **1** proceso (`./ghosts.client.linux`), vivo a las 21:25:59Z (`client_ctl: vivo pids=17245`).
- **S-1 (declarada):** la lista de comprobación del `arm` imprimió `GHOSTS: maquinas victima-linux=0` y `cliente:` vacío, y la purga
  de `machine_updates` falló con `psql: Connection refused`. **Causa: PostgreSQL había muerto** por el *kill* del árbol de procesos al
  vencer el *pipe* del arnés de ejecución durante `prep` (ver `postgres.log`: `redo done … end-of-recovery` = parada abrupta). No es un
  defecto del `arm`. Se reinició PostgreSQL (`pg_ctl start`, `pg_isready` OK), se purgó `machine_updates` (`DELETE 0`) y el cliente
  quedó `Up` con `lastReportedUtc` fresco. **En la ventana real la tarea lanza `powershell.exe` directamente (sin pipe): el riesgo no existe.**

### E0-3 — disparo del timer → **PASS** (con salvedad S-3)

```
● tfg-ghosts-legit.service - TFG legitimo — cliente GHOSTS (keepalive v3) [invitado]
     Active: active (running) since Sun 2026-10-25 22:35:37 CET; 1min 14s ago
   Main PID: 17620 (tfg_keepalive.s)
             ├─17620 /bin/bash /home/angel/ghosts-client/tfg_keepalive.sh 74 2026-10-25T21:40:34Z
             ├─17752 ./ghosts.client.linux
             └─17997 sleep 30
--- keepalive.log ---
2026-10-25T21:35:37Z keepalive: inicio (dur_h=74 t0=2026-10-25T21:40:34Z calendario=10 bloques test=0)
2026-10-25T21:35:40Z keepalive: ROTACION dia=1 sha=8e4de7f8 pid=17752
2026-10-25T21:35:41Z keepalive: ram_free_mb=2378 swap_mb=1915 bloque=fuera edad_app_min=0 free_mb=4525
--- recovery.log ---
2026-10-25T21:35:41Z accion=rotacion dia=1 sha_timeline=8e4de7f8 huella=6f0cdb4a pid_nuevo=17752 resultado=ok
--- procs --- 17752 ./ghosts.client.linux   (1 solo proceso)
```

- Timer disparado a **22:35:37 local / 21:35:37Z** (`T0_falso−5 min` + 3 s) ✅ · servicio `active` ✅ · `keepalive.log` con `inicio` ✅ ·
  **1** proceso del cliente ✅ · `calendario=10` bloques leídos ✅ · `ram_free_mb` post-hoc funcionando ✅.
- **S-3 (declarada, importante):** `recovery.log` **no** salió vacío: hubo **`accion=rotacion dia=1`**. Es un **artefacto del T0 falso**:
  `prep` dejó `rotacion.estado = 2026-10-26` (T0 real) pero el servicio llevaba `fecha_t0 = 2026-10-25`, así que a las 21:35Z del 25/10
  (`hoy == fecha_t0`, `≥ 07:45Z`) el keepalive concluyó que faltaba colocar el día 1 y rotó a `timeline.d1` (mismo contenido; reinició
  el cliente: `pid 17752`). **En la ventana real no puede ocurrir**: el disparo es a `t0−5` = **2026-10-25T23:55Z**, con
  `hoy (2026-10-25) < fecha_t0 (2026-10-26)` ⇒ `rotar_diaria` **sale sin rotar**; el 26/10 a 07:45Z `hoy == rotacion.estado` ⇒ tampoco.
  Se deja escrito y se comprobará en el primer chequeo de la ventana. **Efecto colateral positivo:** queda probado de punta a punta el
  camino de **rotación + reinicio del cliente** (que en la ventana solo debe ocurrir el 27 y el 28).

### E0-4 — `stop` + `cleanup` → **PASS**

```
[stop]    vmrun -T ws stop ...victima-linux.vmx soft -> rc=0
[cleanup] valor aplicado: <logall_json>no</logall_json> · manager=active (intento 1) agent_control=OK
[cleanup] conf: <logall_json>no</logall_json> · manager=active · daemons_remoted_analysisd=2
[cleanup] CONFIG_IDENTICA
[cleanup] vmrun -T ws stop ...wazuh-server.vmx soft -> rc=0
[cleanup] firewall: regla TFG-ghosts-5000 retirada
[cleanup] vmrun -T ws list -> rc=0 Total running VMs: 0
[cleanup] === END cleanup ===
```

- `logall_json` **no** ✅ · `CONFIG_IDENTICA` ✅ · manager `active` con 2 daemons ✅ · **0 VMs** ✅ · **0** reglas `TFG-*` ✅ ·
  GHOSTS API y PostgreSQL detenidos ✅ · los 3 sinks de "internet local" detenidos (8080/9090/9092) ✅.
- El cliente y el keepalive mueren con la VM (el `cleanup` para el cliente antes de apagar; el servicio queda dentro del snapshot).
- Nota: `archives.json` desaparece al apagar `logall_json` (comportamiento **conocido y documentado**, §6.1 del plan: por eso se copia **antes**).

### E0-5 — `registrar_tareas.ps1 -T0 real` + verificación → **PASS**

```
registrada: TFG-Legit-Prep  -> prep   local=2026-10-26 00:15  UTC=2026-10-25T23:15:00Z
registrada: TFG-Legit-Arm   -> arm    local=2026-10-26 00:40  UTC=2026-10-25T23:40:00Z
registrada: TFG-Legit-Watch -> watch  local=2026-10-26 01:00  UTC=2026-10-26T00:00:00Z
registrada: TFG-Legit-Stop  -> stop   local=2026-10-29 01:05  UTC=2026-10-29T00:05:00Z

TaskName        NextRun_local        NextRun_UTC            State
TFG-Legit-Arm   26/10/2026 0:40:40   2026-10-25T23:40:40Z   Ready
TFG-Legit-Watch 26/10/2026 1:00:00    2026-10-26T00:00:00Z   Ready
TFG-Legit-Stop  29/10/2026 1:05:05   2026-10-29T00:05:05Z   Ready
TFG-Legit-Prep  26/10/2026 0:15:15   2026-10-25T23:15:15Z   Ready
```

- Las **4** tareas `Ready` ✅ · `NextRun` dentro de **±1 min** de `t0−45`, `t0−20`, `t0`, `t1+5` ✅ · **UTC correcto** ✅.
- Acción verificada (`Export-ScheduledTask`):
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File "...\legitimo_host_control.ps1" -Phase <prep|arm|watch|stop> -T0 2026-10-26T00:00:00Z -T1 2026-10-29T00:00:00Z`;
  principal `InteractiveToken` + `HighestAvailable`; `StartWhenAvailable=true`; `ExecutionTimeLimit` 2 h (Watch 1 h); Watch repite `PT30M`.
- **S-4 (declarada):** `StartBoundary` lleva **segundos** (`00:15:15`, `00:40:40`, `01:05:05`) porque el Programador redondea el instante de
  registro. Desfase ≤ 40 s, muy por debajo de la tolerancia de `CA-01` (±5 min).

### E0-6 — revert a `lab-listo-legit-v2` → **PASS**

```
vmrun -T ws revertToSnapshot ...victima-linux.vmx lab-listo-legit-v2 -> rc=0
Total snapshots: 5  (base-limpia, lab-listo, lab-listo-legit, fallo-2026-10-19-disco-lleno-NO-USAR, lab-listo-legit-v2)
Total running VMs: 0
```

- Snapshot **intacto** ✅ · **0 VMs** ✅ · el invitado vuelve al estado limpio (sin timer, sin `keepalive.log`, sin `recovery.log`, con
  `timeline.json` = `d1` del snapshot). El ensayo **no ensucia**.

---

## 3. Precondiciones del host antes de armar (P-1…P-6)

| # | Comprobación | Resultado |
|---|---|---|
| **P-1** | Windows Update re-pausado | **PASS** — `pausar_windows_update.ps1 pausar` a las **20:44:11Z** y **21:39:02Z** (tras E0): `wuauserv` = **Stopped/Disabled**, `NoAutoUpdate=1`, `NoAutoRebootWithLoggedOnUsers=1` |
| **P-2** | `TFG_GUEST_PW` disponible | **PASS** — variable **de usuario** presente (10 caracteres); usada solo por entorno/STDIN, nunca al log ni a fichero |
| **P-3** | Disco del manager ≥ 10 GB | **PASS** — medido en `prep` (G-5): **21 GB libres (56 % usado)** |
| **P-4** | Energía sin suspensión | **PASS** — `STANDBYIDLE` AC = **0x00000000**, `HIBERNATEIDLE` AC = **0x00000000** |
| **P-5** | Sin restos | **PASS** — 0 VMs, 0 reglas `TFG-*`, 0 procesos `postgres/dotnet/python`; 4 tareas `TFG-Legit-*` **armadas** (es el objetivo) |
| **P-6** | Estado del `watch` limpio | **PASS** — `%TEMP%\opencode\tfg_watch_estado.json` borrado (solo ese fichero) |

Estado del host tras E0: `D:` **183,4 GB** libres · `LastBootUpTime` = **2026-10-22 14:31:52** (muy anterior a `t0` ⇒ V8 en condiciones) ·
`logall_json=no` + `ossec.conf` `CONFIG_IDENTICA` · snapshots 5/5 · 0 VMs.

---

## 4. Salvedades declaradas (ninguna invalida el E0)

| # | Salvedad | Efecto en la ventana |
|---|---|---|
| **S-1** | PostgreSQL murió por el *kill* del **arnés de ejecución** (pipe), no por el `arm`; se reinició y el cliente quedó `Up` | **Ninguno**: la tarea `TFG-Legit-Arm` ejecuta `powershell.exe` sin pipe |
| **S-2** | `T0_falso` = ahora + **16 min** (el plan decía +25) | **Ninguno**: solo acorta la espera del disparo (11 min); el objeto de la prueba es el mismo |
| **S-3** | `rotacion dia=1` en el disparo (mezcla de `rotacion.estado` real con `fecha_t0` falsa) | **Ninguno** (razonado arriba: el disparo real es a las 23:55Z del 25/10, con `hoy < fecha_t0`). Se comprueba en el primer chequeo |
| **S-4** | `NextRun` con segundos (≤ 40 s) | **Ninguno** (±5 min de `CA-01`) |

**No** se ha tocado: receta, ruleset, `ossec.conf` (salvo `logall_json`, que quedó **no**), `_recursos/`, corpus, `Hojas/`, `Dataset/`,
`Soporte/Metrica/`, `extraer_alertas.py`, `sha256sums.txt` ni los snapshots. Sin commits ni secretos.

> `sha256sums.txt` **no** se regenera aquí: §8.3 lo asigna al **cierre** del bloque (añadirá este `ensayo_E0.md` junto con `b10_sellado.md` v3
> y el `exportar_acciones.sh` tras MC-1).

---

## 5. Veredicto y consecuencia

**E0 = PASS.** El único eslabón no probado del plan (`arm` + timer del invitado + keepalive + encadenado de tareas) **funciona de punta a
punta** y se ha revertido a `lab-listo-legit-v2` sin dejar rastro.

⇒ **Se arma la ventana real** `2026-10-26T00:00:00Z → 2026-10-29T00:00:00Z` (§4.4 del plan):
4 tareas `TFG-Legit-*` `Ready` con `NextRun` 26/10 **00:15 / 00:40 / 01:00** y 29/10 **01:05** (local), `TFG_GUEST_PW` conservada,
Windows Update re-pausado y `logall_json=no` (se activa solo a las 00:15, dentro de `prep`).

**A partir de aquí, nadie toca `victima-linux` hasta `t1+2`.**
