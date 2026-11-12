# T4b — evidencia de la tanda 4 (C6 + T4) — 2026-11-12

> **Plan:** `_fases/windows-legit-prep/plan_w3bis.md` v2 (`approved_by_human`, `4237a16`).
> **Ficha principal:** `Soporte/Laboratorio/windows/legit/snapshot_windows_legit_v2.md`.
> **Sin secretos.** Sin commits. **No** se ejecutó la ventana de 72 h ni ataques.

## Contenido

| Fichero | Qué es |
|---|---|
| `prep_solosellos*.log`, `prep_solomanifiesto*.log`, `prep_soloparidad*.log` | gates de sello, manifiesto y paridad (todos PASS) |
| `deploy_final.log`, `deploy_snapshot.log`, `deploy_snapshot2.log` | deploy 8.3.1 sobre `-ataques-gui` y deploy final del snapshot |
| `prep_real*.log` | `prep` real (firewall + sink + reverts) |
| `we02_timeline_v2.json`, `we02_history_timeline.txt`, `we02_reexport_query.sql`, `we02_reexport.log` | WE0-2: **5/5** (incluye `powershell` sin pipe); re-exportado de la BD con las 5 filas 7255–7259 |
| `canary_history_timeline.txt`, `canary_verificacion.txt` | canary real: **22/22, 0 faltan, 0 sobran** |
| `w07_timeline.json`, `w07_history_timeline.txt`, `w07_acciones.csv` | W-07 real: **6/6** acciones reportadas |
| `w07_alertas_bruto.csv`, `w07_campana_bruto.csv`, `w07_extraer_campana.log` | W-07 **canónico bruto**: **90 alertas / `NO`** (nivel máx. 15) |
| `w07_variantes.csv` | Las **4 cifras**: canónico **90/15/NO**, `sin_ajenas` **23/15/NO**, `sin_artefactos_ps` **87/6/SI**, `sin_ambas` **20/4/SI** |
| `w07_alertas_caso_w07.csv`, `w07_campana_filtrada.csv`, `w07_extraer_campana_filtrada.log` | W-07 **sensibilidad filtrada** (no canónica): **20 alertas / `SI`** |
| `w07_exclusiones.csv`, `w07_clasificacion.log` | **70** alertas excluidas con motivo: **3 policy test** (1 **dentro** de `[t0,t1]`, acción 3; 2 a las 10:07:29Z) + **67 mantenimiento** (10:07:19–29Z, fuera) |
| `w07_LEEME.md` | mapa de nombres, criterio, declaración de artefacto y reproducción de W-07 (bruto vs variantes) |
| `w07_campana.csv`, `w07_campana_sin_policytest.csv`, `w07_alertas_detalle*.csv` | ficheros históricos; nombres ambiguos aclarados en la ficha §5 y en `w07_LEEME.md` |
| `arm.log`, `monitor.log`, `monitor.out.log`, `watch_*.log`, `vigilancia_windows.log` | ciclo `arm` → 5 `watch` → 2 h (todos `skip=0`, `SSH_INVITADO=0`) |
| `heartbeat.jsonl`, `heartbeat_2h_resumen.json`, `guest_2h/` | 2 h: 24 emitidos, 23 recibidos, `ka_instancias=1`, recuperación y duplicado |
| `heartbeat_sink_ctl.log`, `heartbeat_sink_ctl_cierre.log` | log del sink hasta 11:47Z y copia **completa** con los stops de 13:10:13Z / 13:12:54Z |
| `crudo.log`, `firewall_presente.txt`, `firewall_ausente.txt` | `crudo` y regla `TFG-hb-9095` |
| `stop.log`, `cleanup.log` | bucle fuera, tareas y `armado.flag` retirados |
| `verif_snapshot_v2.txt`, `revert_arranque_checks.txt`, `keepalive_sin_prueba.txt` | snapshot v2 + 6 comprobaciones |
| `cierre_verificacion_t4b.txt` | cierre comprobado: 0 VMs, 0 tareas, 0 reglas TFG, 0 procesos, variables borradas |
| `verificacion_correccion_t4b.txt` | `RESULT=PASS` de las correcciones (WE0-2, W-07 bruto/filtrado, sink, drytest, pytest, 193, cierre) |
| `MANIFEST.tsv`, `MANIFEST.sha256` | sello de todo el directorio |
| `pytest_t4b_fix.log` | `487 passed` |
| `pytest_defectos_t4b.log` | `487 passed` (verificación de los defectos T4b) |
| `verificacion_defectos_t4b.txt` | W-07 cuatro cifras, `.gitignore`, sello 195, pytest, cierre y copia limpia |

## Evidencia primaria de 2 h

`D:\TFG-VMs\legitimo-windows-2026-11-12\keepalive_2h\` (fuera de la VM) y copia sellada
en `Soporte/Laboratorio/windows/legit/evidencia/keepalive_2h/`
(`MANIFEST.tsv` sha256 `562580c03faf50523c2b44ce61f85faded4c9e70608dcf63be7df945a8f8b74b`).

## Nota de honestidad

- `crudo.done` declara `sums=0`: el día 12 no tenía todavía `.gz`/`.sum`; se copiaron los
  planos vivos. **El primer intento (13:02:42Z) falló** por permisos de `/var/ossec/logs`
  (el listado como `angel` volvía vacío); el **segundo (13:03:33Z)** funcionó con el fix
  `sudo -S -p ''` que está en el diff de `windows_legit_host_control.ps1` (sin commit).
- **W-07 canónico = bruto `6/90/NO` (nivel 15).** El `NO` lo provoca el `92213` de
  **10:06:02.285Z**, un **`artefacto_ataque`** de la acción 3 (policy test de PowerShell;
  precedente ATA073/ATA097), **no una detección**. **1 de las 70 exclusiones está dentro
  de `[t0,t1]`** (esa fila) y **no** se puede decir que las 70 estén en 10:07. Cifras:
  `sin_ajenas` (67) **23/15/NO**; `sin_artefactos_ps` (3) **87/6/SI**; `sin_ambas`
  **20/4/SI**. El `SI` se sostiene al excluir el artefacto; el canónico literal sigue
  `NO`. Todo está en `w07_exclusiones.csv`, `w07_variantes.csv` y `w07_clasificacion.log`.
- El log sellado `t4b/heartbeat_sink_ctl.log` termina en 11:47:12Z; los `stop` de
  13:10:13Z y 13:12:54Z están en `t4b/heartbeat_sink_ctl_cierre.log` (copia completa y
  sellada).
- `t4b/drytest.log` era un drytest del **2026-11-10** (tanda 3); se retiró/marcó como
  `drytest_2026-11-10_fuera_tanda4.log`.
- `cleanup` necesitó un arranque intermedio tras `stop` para desregistrar las tareas del
  invitado; es fuera de la ventana (t1=13:00Z) y no se mide.
- Ficheros no listados en la primera versión de este README: `sha256sums.txt` (**195**
  entradas, con `clasificar_w07_windows.py` y su test) y el **anexo T4** de
  `_fases/windows-legit-prep/auditoria_espejo_linux_windows.md`.
- **WE0-2 — TSV anterior sobrescrito:** el primer `we02_history_timeline.txt` (3 filas) se
  **sobrescribió**; **no se conserva copia**. El actual (5 filas, `0616320f…`) es la salida
  literal de la BD (`we02_reexport.log`), sin edición manual.
