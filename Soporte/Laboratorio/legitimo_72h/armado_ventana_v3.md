# Armado de la ventana `lab-listo-legit-v3` — T4-b

> **Bloque:** `legitimo-v3` (plan v5, `status: approved_by_human`) · **Tanda:** T4-b (armado)
> **Ejecución:** **2026-11-01, 16:09:22Z → 16:41Z** (≈ **32 min**; hora local CET = UTC+1).
> **Ventana fijada:** `t0 = 2026-11-02T00:00:00Z` (lunes 02/11, **01:00 local**) →
> `t1 = 2026-11-05T00:00:00Z` (jueves 05/11, 01:00 local). **72 h exactas.**
> **Host:** `angel` (D: 180,7 GB libres). **Snapshot de trabajo:** `lab-listo-legit-v3`
> (6 snapshots; **`lab-listo-legit-v2` intacta**, no se ha tocado).
> **Veredicto: PASS**, con las salvedades **H-9…H-12** (§6), ninguna achacable al mecanismo
> de la ventana.

---

## 1. Tabla de pasos (duración real / tope / resultado)

| # | Paso | Inicio → fin (UTC) | **Duración** | **Tope** | **Resultado** |
|---|---|---|---|---|---|
| **A** | Desactivar las **4 tareas heredadas** `TFG-Baseline-*` | 16:09:22 | **< 2 s** | 2 min | **PASS** — las 4 en `Disabled` |
| **B** | `pausar_windows_update.ps1 pausar` | 16:09:44 → 16:10:42 | **8 s** (2 intentos) | 2 min | **PASS al 2.º** — `wuauserv` **Stopped/Disabled** + política **1/1** (ver **H-9**) |
| **C** | `construir_receta_legitima.py --t0 2026-11-02` + `--check` (×2) + doble generación | 16:11:48 → 16:12:10 | **< 1 s / generación** | 2 min | **PASS** — `RESULT=PASS`; `d1/d2/d3` **sin cambios** |
| **D-1** | `prep -T0 2026-11-02T00:00:00Z -T1 2026-11-05T00:00:00Z` | 16:14:33 → 16:20:16 | **344 s** | 15 min | **PASS** — `rc=0`, **G-1…G-12 OK** (G-12 con aviso de swap) |
| **D-2** | **P1**: jornada d1 comprimida (147 acciones) | 16:21:44 → 16:31:44 | **393 s** de ejecución (arranque 16:21:44, última acción 16:30:34, parada 16:31:44) | 10 min | **PASS** — **147/147**, 0 pipes |
| **D-3** | `stop` + `cleanup` | 16:33:10 → 16:34:27 | **9 s** (`stop`) + **67 s** (`cleanup`) | 10 min | **PASS** — 0 VMs; `logall_json=no`; `CONFIG_IDENTICA` (ver **H-10**) |
| **D-4** | `revert` de la víctima a `lab-listo-legit-v3` | 16:34:40 → 16:35:19 | **≈ 40 s** | 5 min | **PASS** — **6 snapshots**, 0 VMs |
| **D-5** | Re-verificación del manager con evidencia (2 arranques) | 16:35:19 → 16:41 | **≈ 6 min** | 10 min | **PASS** — `logall_json=no` + `CONFIG_IDENTICA` |
| **E** | `registrar_tareas.ps1 -T0 … -T1 … -Verificar` | 16:37:09 → 16:37:20 | **11 s** | 2 min | **PASS** — 4 tareas `Ready`, `NextRun` UTC correctos (§3) |
| **F** | Estado final verificado | 16:40:51 | **< 5 s** | — | **PASS** (§4) |
| **G** | Este acta + `sha256sums.txt` | 16:41 → | — | — | **PASS** |

**Todos** los comandos SSH del host llevan `-o BatchMode=yes -o ConnectTimeout=10`; las
llamadas largas van envueltas en `timeout` remoto y con tope del lanzador (`run_to.ps1`, que
mata el árbol con `taskkill /T /F` y da **EOF** por stdin desde NUL). Ningún paso quedó colgado.

---

## 2. A · Tareas heredadas desactivadas (crítico)

Estaban las **4** en **`Ready`** con `StartWhenAvailable=True` y disparador `Once` del
**2026-10-08T…+01:00** (ya pasado) ⇒ podían dispararse **solas** al primer "hueco" y **apagar
el manager o revertir la VM** en mitad de la ventana.

**Estado tras el paso A: `Disabled` en las 4** (`Settings.Enabled=False`), verificado con
`Get-ScheduledTask` + `Get-ScheduledTaskInfo` (`NextRun` vacío en las 4).

**Acciones exactas (para restaurarlas — no se han borrado, solo deshabilitado):**

| Tarea | `Execute` | `Arguments` | Disparador (`StartBoundary`) |
|---|---|---|---|
| `TFG-Baseline-Afternoon-Start` | `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe` | `-NoProfile -ExecutionPolicy Bypass -File "D:\TFG\HIDS-Analisis_Capacidad_deteccion_Ataques_locales_MITRE\Soporte\Laboratorio\windows\baseline_host_control.ps1" -Phase afternoon-start` | `2026-10-08T12:45:00+01:00` |
| `TFG-Baseline-Afternoon-Stop` | ídem | `… -Phase afternoon-stop` | `2026-10-08T17:05:00+01:00` |
| `TFG-Baseline-Night-Start` | ídem | `… -Phase night-start` | `2026-10-08T01:30:00+01:00` |
| `TFG-Baseline-Night-Stop` | ídem | `… -Phase night-stop` | `2026-10-08T05:50:00+01:00` |

**Común a las 4:** principal `S-1-5-21-36889529-79255199-925052678-1001`,
`LogonType=InteractiveToken`, `RunLevel=HighestAvailable`;
`DisallowStartIfOnBatteries=False`, `StopIfGoingOnBatteries=False`,
`ExecutionTimeLimit=PT1H`, `MultipleInstancesPolicy=IgnoreNew`,
**`StartWhenAvailable=True`**, `UseUnifiedSchedulingEngine=True`.
**Última ejecución registrada:** 10/08/2026, `LastTaskResult=0` en las 4.

**Restaurar** (una línea, recupera el estado exacto porque las tareas siguen registradas):

```powershell
'TFG-Baseline-Afternoon-Start','TFG-Baseline-Afternoon-Stop','TFG-Baseline-Night-Start','TFG-Baseline-Night-Stop' |
  ForEach-Object { Enable-ScheduledTask -TaskName $_ }
```

---

## 3. B · Windows Update · E · Tareas reales

### B — Windows Update (host)

```
[2026-11-01T16:09:44Z] PAUSAR: previo wuauserv State=Running StartMode=Manual; AU key existia=True
[2026-11-01T16:09:44Z] PAUSAR: politica NoAutoUpdate=1 + NoAutoRebootWithLoggedOnUsers=1 aplicada
[2026-11-01T16:09:47Z] PAUSAR: wuauserv State=Running StartMode=Manual (via sc.exe)
[2026-11-01T16:09:47Z] PAUSAR FALLO: wuauserv NO ha quedado Disabled      <-- rc=1 (1.er intento)
--- 2.º intento, 51 s después -------------------------------------------
[2026-11-01T16:10:38Z] PAUSAR: previo wuauserv State=Stopped StartMode=Disabled
[2026-11-01T16:10:38Z] PAUSAR: politica NoAutoUpdate=1 + NoAutoRebootWithLoggedOnUsers=1 aplicada
[2026-11-01T16:10:41Z] PAUSAR: wuauserv State=Stopped StartMode=Disabled (via sc.exe)
[2026-11-01T16:10:41Z] PAUSAR: wuauserv detenido + StartupType=Disabled   <-- rc=0
```

**Estado final (16:40:51Z, 30 min después):** `wuauserv` **Stopped / Disabled**,
`NoAutoUpdate=1`, `NoAutoRebootWithLoggedOnUsers=1`.
**No** se ha auto-reparado en **30 min** en este arranque (matiz a **H-6** del E0: el
auto-reparado es **intermitente**, no sistemático). Aun así el `watch` re-pausa cada 30 min
(§5.1 del `ensayo_E0_v5.md`) y deja `reps=si|no|fallo` en la línea de vigilancia.

### E — Las 4 tareas reales (`-T0 2026-11-02T00:00:00Z -T1 2026-11-05T00:00:00Z`)

| Tarea | Estado | `NextRun` local (CET) | **`NextRun` UTC** | Acción (`-Phase`) |
|---|---|---|---|---|
| `TFG-Legit-Prep` | **Ready** | 02/11/2026 00:15:15 | **2026-11-01T23:15:15Z** | `prep` |
| `TFG-Legit-Arm` | **Ready** | 02/11/2026 00:40:40 | **2026-11-01T23:40:40Z** | `arm` |
| `TFG-Legit-Watch` | **Ready** | 02/11/2026 01:00:00 | **2026-11-02T00:00:00Z** | `watch` (repetición **PT30M / P3D**) |
| `TFG-Legit-Stop` | **Ready** | 05/11/2026 01:05:05 | **2026-11-05T00:05:05Z** | `stop` |

Las 4 llevan la acción
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\…\legitimo_host_control.ps1"
-Phase <prep|arm|watch|stop> -T0 2026-11-02T00:00:00Z -T1 2026-11-05T00:00:00Z`
(comprobado una a una, no solo por `NextRun`). `LastTaskResult=267011` (`0x41303` = «aún no
se ha ejecutado»), como corresponde.

---

## 4. C · Receta con fecha fija

```text
$ python _artefactos/scripts/construir_receta_legitima.py --t0 2026-11-02
d1.json  147 acciones de jornada + 16 de B6  sha256=0b2fa91c…
d2.json  153 acciones de jornada + 25 de B6  sha256=0e0329cc…
d3.json  141 acciones de jornada + 22 de B6  sha256=885a80b2…
mapa_dias=2026-11-02:1,2026-11-03:2,2026-11-04:3
RESULT=PASS

$ python … --check            -> RESULT=PASS (rc=0)
$ python … --check --t0 2026-11-02 -> RESULT=PASS (rc=0)
```

- **Doble generación** (`--out-dir` en dos carpetas de `%TEMP%`): **6/6 ficheros byte a byte
  idénticos** (`d1`, `d2`, `d3`, `calendario.json`, `bloques.env`, `receta_resumen.md`).
- **`d1/d2/d3` NO cambian**: los tres `sha256` son **los mismos** que estaban versionados
  (`0b2fa91c / 0e0329cc / 885a80b2`, los de después del arreglo **L-1**). **`receta_resumen.md`
  tampoco cambia.** Lo único que cambia en el repo son **`calendario.json`** y
  **`bloques.env`** (`TFG_MAPA_DIAS=2026-11-02:1,2026-11-03:2,2026-11-04:3`).
- `--check` acepta el mapa y **no** deja aviso de «sin fecha».

---

## 5. D · P1 repetido (la receta cambió por el arreglo L-1)

### 5.1 `prep` (344 s, `rc=0`)

Guardarraíles **G-1, G-2, G-3, G-4, G-5, G-6, G-7, G-8, G-10, G-11: OK**; **G-12 OK con aviso
declarado** (`swap_mb=1915`); **G-9** informativo y vacío. Sin códigos de aborto.

```text
[16:14:33Z] G-1 OK: snapshot 'lab-listo-legit-v3' presente | Total snapshots: 6 …
[16:14:33Z] G-10: D_libre_gb=180.7 wuauserv_StartType=Disabled sesion=angel
[16:14:34Z] G-4 OK: d1=0b2fa91c d2=0e0329cc d3=885a80b2 mapa=2026-11-02->d1,2026-11-03->d2,2026-11-04->d3
[16:15:27Z] G-12: ram_free_mb=2504 swap_mb=1915 ram_min_mb=1500   (AVISO declarado)
[16:18:32Z] G-2: df_free_mb=4515 inodos_libres_pct=84
[16:19:40Z] G-7: conf: <logall_json>yes</logall_json> manager=active daemons_remoted_analysisd=2
[16:20:05Z] servidor GHOSTS lanzado
[16:20:06Z] firewall: regla TFG-ghosts-5000 creada (TCP 5000 desde 192.168.65.0/24)
[16:20:12Z] G-8: 8080 root/pdf/zip 200; 9090 paste 200; 9092 put 201 / propfind 207; example.com FALLA; 1.1.1.1 FALLA
[16:20:13Z] G-5: agentd_procs=1 | … Agent ID: 001 … Status: Active … logall_json=<logall_json>yes</logall_json>
[16:20:13Z] G-11: machineids de victima-linux = 7c33a13a-fe89-4a56-bf3c-fcd499e1e557
[16:20:15Z] prep: timeline activa = 0b2fa91c (esperado d1=0b2fa91c) · rotacion.estado = 2026-11-02
[16:20:15Z] G-6 OK: muestras 'df -P' del agente 001 en archives.json
[16:20:16Z] H1(b) estado del watch sembrado: archives=8201977B alerts=42253106B
[16:20:16Z] === END prep (laboratorio LISTO, cliente PARADO) ===
```

`G-3 verificar_arreglos.sh` = **PASS** (`nlog_console=Warn`, `nlog_applog_archive=20`,
`client_ctl_cap=20`, `keepalive_v3=1`, `client_cwd=/home/angel`, `campana_fp=OK`, `timer=not-found`).

### 5.2 Jornada del día 1 comprimida (**393 s**, 147 acciones)

Helper ya probado: `construir_receta_legitima.py --dry --base 16:24Z` →
`comprimir_timeline_prueba.py --base 16:24Z` → `pon_timeline.sh` en el invitado
(para el cliente, comprueba que no queda vivo, copia y arranca).

```text
sha=733e86cf80d0e3332aa24a95db02c71d1b625034b9ad52c862e07c119459a6c6
eventos=147 … arranque_utc=2026-11-01T16:21:42Z
client_ctl: arrancado pid=17010  cwd=/home/angel
```

Timeline usada: **147 eventos**, `UtcTimeOn=16:24:00`, `UtcTimeOff=16:34:33`
(`duracion_s=393`), fichero en `armado_v3/d2_p1_timeline.json`.
**H-1 (E0, comillas del `pgrep`) probado a nivel de comando:** el comando exacto corregido
de `Get-ClientEstado` devuelve `17010 /home/angel/ghosts-client/ghosts.client.linux`
(antes devolvía vacío). Ver **H-12** para el alcance de esta prueba.

### 5.3 Las 5 comprobaciones de ejecución

**(a) `history_timeline`: 147/147, 0 pipes.**

```text
timeline 147 db 147 faltan 0 sobran 0
db_con_pipe=0
handler: Command|147
rango BD: 2026-11-01 16:24:00 → 16:30:34   (n=147)
```

**(b) `sha256sum` de B5 **redirige** y `cat …sha256` **no falla** (defecto **L-1**).**

```text
# comandos realmente ejecutados (history_timeline)
cd …/Documentos/copias && sha256sum …/copia_$(date -u +%F).tar.gz > …/copia_$(date -u +%F).tar.gz.sha256
cd …/Documentos/copias && cat …/copia_$(date -u +%F).tar.gz.sha256
# comprobación en el invitado (solo lectura, ya fuera de la ejecución)
-rw-rw-r-- 1 angel angel 120 Nov  1 17:30 copia_2026-11-01.tar.gz.sha256
3bce35a5…  /home/angel/Documentos/copias/copia_2026-11-01.tar.gz
/home/angel/Documentos/copias/copia_2026-11-01.tar.gz: OK        (sha256sum -c)
```

**(c) `errores.log`: 20 líneas × 5 campos, `rc` real.**

```text
lineas=20   lineas_mal=0 (awk -F'\t' 'NF!=5')   rc_distintos=rc=0 rc=1 rc=2
2026-11-01T16:24:09Z	error	ruta_mal	ls -la /home/angel/Documentos/informe	rc=2
2026-11-01T16:24:10Z	reintento	ruta_mal	ls -la /home/angel/Documentos/informes	rc=0
2026-11-01T16:29:35Z	error	gzip	gzip -d /home/angel/Documentos/informes/informe.bak	rc=2
2026-11-01T16:29:38Z	reintento	gzip	gzip -kf /home/angel/Documentos/informes/informe.bak	rc=0
```

**(d) `audit_cwd`: 0 con `ghosts-client`.**

```text
eventos_audit_con_cwd=697 · cwd_distintos=13 · cwd_ghosts_client=0
cwd=/home/angel 201 · cwd=…/Documentos/informes 140 · cwd=/ 114 · cwd=/var/ossec 103
cwd=…/Descargas 61 · cwd=…/Documentos 20 · cwd=…/copias/informes 20 · cwd=…/actas 13
cwd=…/copias 12 · cwd=…/correo 7 · cwd=…/.cache/tfg-web 3 · cwd=/root 2 · cwd=/usr/lib/sysstat 1
```

**(e) `auth.log`: 0 accesos del host durante la ejecución.**

```text
Ventana de ejecución [16:24:00Z, 16:30:34Z]  ->  0 líneas "Accepted publickey"
(las del ensayo: 16:20:14–16:21:46 = prep + setup de P1; 16:31:38–16:32:46 = recogida y
 comprobaciones post-hoc — todas FUERA de la ventana)
```

**Otros:** `app.log` = **158 393 B** en `/home/angel/ghosts-client/logs/`;
`recovery.log` **no existe** (vacío); `campana_fp` con **0 entradas** (esta tanda no corre la
campaña); `sudo -n true` → **rc=1** (confirmado: ni la receta ni la campaña usan `sudo`).

---

## 6. Estado final verificado (F)

```text
Total running VMs: 0
Total snapshots: 6   (base-limpia, lab-listo, lab-listo-legit, fallo-…-NO-USAR,
                      lab-listo-legit-v2 [INTACTA], lab-listo-legit-v3 [trabajo])
Reglas de firewall TFG-*: 0
TFG-Legit-{Prep,Arm,Watch,Stop}: Ready (NextRun §3)
TFG-Baseline-{Afternoon,Night}-{Start,Stop}: Disabled
wuauserv: Stopped / Disabled · NoAutoUpdate=1 · NoAutoRebootWithLoggedOnUsers=1
logall_json=no · CONFIG_IDENTICA (ossec.conf == ossec.conf.tfg-bak)
TFG_GUEST_PW: presente (10 caracteres) en el ENTORNO DE USUARIO (HKCU\Environment)
%TEMP%\opencode\tfg_watch_estado.json: BORRADO (lo vuelve a sembrar `prep` a las 23:15Z)
D: 180,7 GB libres · procesos postgres/dotnet/python del lab: 0 · 5000/8080/9090/9092 cerrados
```

**La víctima quedó revertida a `lab-listo-legit-v3` y apagada** (revert a las 16:34:40Z, una vez
apagada; se reutiliza el `G-3 = PASS` de `prep` de las 16:18Z como prueba del contenido del
snapshot, para no arrancar la VM una vez más).

---

## 7. Hallazgos y salvedades (ninguna invalida el armado)

| # | Tipo | Qué | Efecto / mitigación |
|---|---|---|---|
| **H-9** | **Host — importante** | **El primer `pausar` salió `rc=1`** (`wuauserv` seguía `Running/Manual`) **y el segundo, 51 s después, `rc=0`**. Un `sc.exe config/stop` manual en medio sí funcionó; en este arranque **no** se ha auto-reparado en 30 min. Causa no determinada (carrera con `WaaSMedicSvc`, que está `Running/Manual`, o estado pendiente del servicio). | **Riesgo operativo real:** si a las **23:15Z** `wuauserv` no está `Disabled`, **`prep` aborta con `exit 47`** (G-10) y **no se arma nada**. **Acción recomendada antes de t0:** comprobar `(Get-Service wuauserv).StartType` y, si no es `Disabled`, ejecutar `pausar_windows_update.ps1 pausar` (idempotente) **antes** de las 23:15Z. No se toca el script (cambio post-aprobación). |
| **H-10** | **Host — procedimiento** | En el `cleanup`, **las 3 llamadas SSH al manager devolvieron 0 bytes y tardaron exactamente 30 s cada una** (`Invoke-OnVm` no lleva `-o BatchMode`/`ConnectTimeout`). **El estado sí quedó bien**: verificado aparte (16:35–16:41) → `logall_json=no` y `CONFIG_IDENTICA`. | **Ninguno** sobre la ventana (el `cleanup` es post-ventana). **Salvedad:** el volcado del `cleanup` sale **sin** la prueba del manager. Candidato a endurecer `Invoke-OnVm` **después** de la ventana. |
| **H-11** | **Documental** | El **plan §7.1** dice `TFG-Legit-Stop = t1+10 min (tope t1+15)`; el **script** registra **`t1+5 min`** (`2026-11-05T00:05:05Z`), que es lo que pedía el encargo de T4-b. | **Ninguno**: 5 min de diferencia en el apagado, con el manager vivo para la cosecha. Declarado. |
| **H-12** | **Cobertura no ejecutada** | **`arm` no se ha ejecutado en vivo** (el encargo A–G no lo incluía, y lanzarlo a las 16:2xZ — **dentro** del bloque 08:00–17:00Z — habría arrancado el cliente con la `d1` **real** y ejecutado eventos). Se ha probado **el comando exacto corregido** de `Get-ClientEstado` (**H-1** del E0) → devuelve `pid + ruta`. **`NEXT` del timer y disparo real (H-5) siguen sin probarse en vivo.** | **Ninguno** sobre el mecanismo. **Primera prueba real:** `arm` a las **23:40Z** y el timer a las **23:55Z**; su resultado queda en `legitimo_host_control.log` (línea `cliente: …`). **Pendiente declarado**, no un fallo. |
| **S-1** | Salvedad | `swap_mb=1915` en la víctima (el plan asumía 0). | **Declarada** desde L1-fix; no se toca la VM. |
| **S-2** | Salvedad | La comprobación del manager de las 16:40 pilló `wazuh-manager` en **`activating`** (arranque en curso; el `rc=3` del script es de esa última línea). | **Ninguno**: el criterio (`logall_json=no` + `CONFIG_IDENTICA`) se leyó del fichero, no del servicio. En `prep` el manager estaba **`active`** (G-7). |

---

## 8. Qué se puede deshacer (todo, y cómo)

| Qué | Cómo se deshace | Efecto |
|---|---|---|
| **Las 4 `TFG-Baseline-*`** | `Enable-ScheduledTask -TaskName <n>` (siguen registradas; **no** se borraron) | Vuelven a `Ready` **con los disparadores del 08/10** y `StartWhenAvailable=True` ⇒ **volverían a poder dispararse solas**. Desactivarlas otra vez al terminar de usarlas. |
| **Las 4 `TFG-Legit-*`** | `registrar_tareas.ps1 -Eliminar` (o `Unregister-ScheduledTask`) | Quita la programación de la ventana. **No** toca VMs ni datos. |
| **`TFG_GUEST_PW` (y `TFG_MANAGER_PW`)** | `registrar_tareas.ps1 -ClearSecret` | Borra las variables de **usuario** (`HKCU\Environment`). **Obligatorio al cerrar la ventana.** |
| **Pausa de Windows Update** | `pausar_windows_update.ps1 restaurar` | Retira la política `AU` (`NoAutoUpdate`/`NoAutoRebootWithLoggedOnUsers`) y deja `wuauserv` en `Manual` + arrancado. |
| **Fecha en la receta** | `construir_receta_legitima.py` **sin** `--t0` (regenera `calendario.json` y `bloques.env` con el mapa **vacío**) | `d1/d2/d3` **no cambian**; solo se pierde el mapa de días. |
| **Snapshot de la víctima** | `prep` revierte a `lab-listo-legit-v3` en cada arranque; `lab-listo-legit-v2` **sigue intacta** como red de seguridad | — |

**Lo que esta tanda NO ha tocado:** `_recursos/`, corpus, `Hojas/`, `Dataset/`,
`Soporte/Metrica/`, el ruleset de Wazuh ni los snapshots `base-limpia`, `lab-listo`,
`lab-listo-legit` y `lab-listo-legit-v2`. **Sin commits.**

---

## 9. Evidencias

En `Soporte/Laboratorio/legitimo_72h/armado_v3/` (salidas literales, sin recortar; **sin
secretos**: las contraseñas van por `stdin` y no se escriben en ningún log):

| Fichero | Qué es | §  |
|---|---|---|
| `b_pausar_1.out.txt`, `b_pausar_2.out.txt` | los dos intentos de pausa de WU | 3 (H-9) |
| `c_receta_gen.txt`, `c_receta_check.txt`, `c_receta_check_t0.txt` | generación y los dos `--check` | 4 |
| `d1_prep.out.txt` / `.err.txt` | `prep` completo (G-1…G-12) | 5.1 |
| `d2_p1_inicio.txt` | colocación de la timeline + arranque del cliente | 5.2 |
| `d2_p1_timeline.json` | timeline comprimida ejecutada (147 eventos) | 5.2 |
| `d2_p1_recogida.txt` | parada del cliente, `errores.log`, `app.log`, `recovery.log` | 5.3 |
| `d2_p1_db_cmds.tsv` | los **147** comandos leídos de `history_timeline` | 5.3 (a) |
| `d2_b5_sha256.txt` | B5 en el invitado (`sha256sum -c` OK) | 5.3 (b) |
| `d2_p1_audit_cwd.txt` | `cwd` y binarios en `archives.json` | 5.3 (d) |
| `d2_p1_auth.txt` | líneas `sshd … Accepted` del periodo | 5.3 (e) |
| `d3_stop.out.txt`, `d3_cleanup.out.txt` | `stop` y `cleanup` | 1 (D-3), H-10 |
| `f_manager_verif.txt` | `logall_json=no` + `CONFIG_IDENTICA` (con evidencia) | 6 |
| `e_tareas_registrar.txt`, `e_tareas_verificar.txt` | alta de las 4 tareas y `NextRun` UTC | 3 (E) |
| `f_estado_final.txt` | estado final completo | 6 |
