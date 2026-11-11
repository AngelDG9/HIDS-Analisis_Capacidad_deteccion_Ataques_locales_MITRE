# T4 — `windows-legit-prep` (W3-bis) · **PARADA en WE0-2 (R2)**

> **Plan:** `_fases/windows-legit-prep/plan_w3bis.md` **v2** (`status: approved_by_human`, `4237a16`).
> **Tanda:** T4 (2 h + cierre + snapshot v2). **Ejecutor:** `tfg-executor`.
> **Fecha:** 2026-11-11 (UTC), 17:32 → 18:16.
> **Motivo de la parada:** **WE0-2 = 4/5** ⇒ la regla del plan («< 5/5 ⇒ para y reporta (R2)») se activa.
> **Sin ventana de 72 h, sin ataques, sin commits. Sin secretos** (contraseñas solo en memoria; borradas).
> **Sin snapshot nuevo**: siguen **7**; `lab-listo-windows-legit` y los 6 previos **intactos**.

---

## 1. Qué se ejecutó (y qué salió bien)

| # | Paso | Resultado |
|---|---|---|
| 1 | Pila arrancada: manager `wazuh-server` + GHOSTS API `192.168.65.1:5000` + PostgreSQL `127.0.0.1:5432` | OK (`API OK 200`; `agent_control` lista `002`) |
| 2 | `prep` **real** (controlador v4) | **OK** — sink `9095` OK (`POST /test ok`), revert+arranque, deploy 8.3.1, `DEFENDER_OFF=1`, `SESION_ANGEL=1`, lista negra **0 residuos**, `MANIFIESTO_SNAPSHOT=OK` (`62b73b16…`) |
| 3 | **Revert a `lab-listo-windows-ataques-gui`** + arranque + **deploy final** (8.3.1) | OK (`revert_rc=0`, `ssh_ok=True` en 4 intentos, `apply FIN`) |
| 4 | Verificación del invitado en esa base | `DEFENDER_OFF=1`, `SESION_ANGEL=1`, `powercfg` 0/0/0, `NoAutoUpdate=1`, `LISTA_NEGRA_OK=1`, cliente **8.2.2.0 / Domain 8.2.7.90** |
| 5 | **WE0-2** (5 acciones `Command`, una con `\|` dentro de `powershell -Command`) | **4/5** ⇒ **PARADA** |
| 6 | Diagnóstico aislado (3 acciones extra: `powershell` sin pipe, `dir \| findstr`, centinela) | `powershell` **sin** pipe **sí** reporta; **cualquier** `\|` **no** reporta; el centinela posterior **sí** |
| 7 | Cierre limpio del laboratorio | bucle fuera (`stop.flag` ⇒ `Status: Ready`, 270 s), sink parado, API+PostgreSQL parados, VM revertida a `-ataques-gui` y apagada, manager `logall_json=no` + `CONFIG_IDENTICA`, **0 VMs** |

`prep` dejó un detalle declarado: con la base `-ataques-gui` el manifiesto del invitado da
**294** ficheros (`2d19e8d7…`) frente a **304** (`62b73b16…`) de la base `v1`, porque `v1`
arrastra **10 ficheros del cliente 8.0.0** que `robocopy` no purgó (`.pdb` + `Microsoft.Management.*`).
No es un defecto del deploy; se tendrá en cuenta al **re-sellar** el manifiesto del snapshot v2.

---

## 2. WE0-2 — resultado literal **4/5**

Timeline de prueba: `we02_timeline.json` (5 acciones `HandlerType=Command`, `UtcTimeOn/Off`
`00:00:00`–`23:59:59`, `Loop=false`), enviada a la máquina `desktop-btmcfa5` con
`ghosts_api.py send-timeline` a las **17:57:23Z**.

```
 id   | createdutc            | handler | command
------+-----------------------+---------+-----------------------------------------------------------
 7249 | 2026-11-11 17:57:35   | Command | cd /d C:\Users\angel && dir C:\Users\angel\Documentos > ...we02_1.txt
 7250 | 2026-11-11 17:57:39   | Command | cd /d C:\Users\angel && echo we02_accion_2 >> ...we02_2.txt
 7251 | 2026-11-11 17:57:47   | Command | cd /d C:\Users\angel\Documentos && type we02_2.txt
 7252 | 2026-11-11 17:57:51   | Command | cd /d C:\Users\angel && where curl.exe > ...we02_5.txt
(4 filas)          ← FALTA la 3.ª: `powershell -NoProfile -Command "Get-ChildItem … | Select-Object … | Out-File …"`
```

**La acción sí se ejecutó**: `we02_pipe.txt` (659 B) existe en el invitado
(`we02_ficheros_invitado.txt`), y el `app.log` del cliente registra las **5** (incluida
`Spawning cmd.exe with command powershell -NoProfile -Command "… | … | …"`). Lo que se pierde
es **el reporte**, no la ejecución.

### 2.1 Causa raíz (no es el cliente ni la compilación)

La cola de resultados del cliente es **delimitada por `|`** (`TIMELINE|<fecha>|<json>`) y el
servidor parte la línea por cada `|`; un `|` **dentro del comando** rompe el JSON:

```
TIMELINE|11/11/2026 05:57:43 PM|{"Handler":"Command","Command":"powershell -NoProfile -Command \"Get-ChildItem C:\\Users\\angel\\Documentos | Select-Object -First 3 | Out-File …\"","Result":""}
2026-11-11 18:58:01.7229|TRACE|ghosts.api.Infrastructure.Services.QueueSyncService|Bad line: Newtonsoft.Json.JsonReaderException: Unterminated string. Expected delimiter: ". Path 'Command', line 1, position 108.
   at ghosts.api.Infrastructure.Services.QueueSyncService.ProcessMachine(...) QueueSyncService.cs:line 193
```

`position 108` = el **primer `|`** del comando. Es el **mismo fenómeno que el H-1 de Linux**
(`state.md`), pero **en el servidor** (`Ghosts.Api`), no en el binario del cliente.

### 2.2 Prueba de aislamiento (3 acciones, 18:04Z)

| Acción | Ejecuta | Reporta |
|---|---|---|
| `powershell -NoProfile -Command "Get-ChildItem … > we02b_nopipe.txt"` (sin `\|`) | sí | **sí** (id **7253**) |
| `cd /d … && dir … \| findstr we02b > we02b_cmdpipe.txt` | sí (fichero 115 B) | **no** (`Bad line … position 91`) |
| `cd /d … && echo we02b_final > we02b_final.txt` (centinela posterior) | sí | **sí** (id **7254**) |

⇒ **La regla es: cualquier `|` en el texto del comando pierde el reporte** (y solo ese).
Un `Bad line` **no** bloquea las líneas siguientes de la cola.

### 2.3 Impacto medido en la receta

`w1/w2/w3.json`: **504** acciones y **1** con `|`:
`w2.json` → **W-07 / C-08** (`(Get-Content …) -replace ';',',' | Set-Content …`, bloque B6 `17:17–17:50`).
Las otras 503 **no** llevan `|` y se reportan. Riesgo para la campaña: `n_acciones` de **W-07**
saldría 0 en `history_timeline` aunque el fichero se transforme (efecto visible, reporte ausente).

---

## 3. Por qué **no** se siguió (R2)

La instrucción de la tanda y el plan son explícitos:

- `plan_w3bis.md` **R2**: «*Compila pero no reporta las 5 acciones … **WE0-2 antes de las 2 h**; < 5/5 ⇒ volver al publicado y declarar*».
- `plan.md` (§WE0-2): «*5/5 reportadas; si < 5/5 ⇒ se prohíben los pipes internos y se declara*».
- Encargo T4: «*Si <5/5 ⇒ **para y reporta** (R2)*».

**No se hizo** (por la parada): las 2 h, la muerte/recuperación, el duplicado, `G-W7` con `arm`,
`crudo`/`stop`/`cleanup`, el snapshot `lab-listo-windows-legit-v2` ni la prueba de revert.

> **Sobre «volver al publicado» (R2-b):** la causa raíz **no está en el cliente** (el payload
> llega bien al `ClientResultsController` y **es el servidor** quien no lo parsea,
> `QueueSyncService.cs:193`). El cliente publicado **8.2.1.0** usa **el mismo formato de cola**,
> así que **no** se espera que arregle el 5.º reporte. No se ha probado (no se decide aquí).

---

## 4. Ficheros de esta parada

| Fichero | Qué es |
|---|---|
| `prep.log` | salida literal de `prep` (17:32–17:35Z) |
| `deploy_ataques_gui.log` | deploy final 8.3.1 sobre `lab-listo-windows-ataques-gui` |
| `verif_base_ataques_gui.txt` | `verificar_windows.ps1 -SinCampana` en esa base |
| `we02_timeline.json` | timeline de WE0-2 (5 acciones) |
| `we02b_timeline.json` | timeline de aislamiento (3 acciones) |
| `we02_history_timeline.txt` | filas de `history_timeline` de `we02*` (6 filas) |
| `we02_ficheros_invitado.txt` | `dir` de los ficheros `we02*` creados (prueba de ejecución) |
| `we02_api_badline.txt` | líneas `Bad line` del API (con la línea de cola literal) |
| `guest_app_we02.txt` | extracto de `app.log` del cliente (las 5 acciones, incluida la del pipe) |
| `MANIFEST.sha256` | `sha256` de todos los ficheros anteriores |

`Soporte/Laboratorio/windows/legit/evidencia/historico/heartbeat_*_t4_abortada.jsonl`: latidos del
keepalive durante la preparación (no hay ventana; no se usan como medida).

---

## 5. Estado del laboratorio al cerrar

- **0 VMs**; `victima-windows` **revertida a `lab-listo-windows-ataques-gui`** y apagada.
- **7** snapshots (los mismos; **no** se creó ninguno).
- GHOSTS API + PostgreSQL **parados**; sink `9095` **parado**; **0** tareas `TFG-*` en el host.
- Manager: `logall_json=no`, `CONFIG_IDENTICA`.
- `TFG_GUEST_PW` / `TFG_MANAGER_PW` **borradas** (solo en memoria; nada en ficheros).
- Invitado sin residuos de la prueba (`we02*` borrados; `stop.flag` retirado por el propio bucle).
