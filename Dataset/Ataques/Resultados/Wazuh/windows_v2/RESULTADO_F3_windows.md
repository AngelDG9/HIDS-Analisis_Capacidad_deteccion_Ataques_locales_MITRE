# F3 — ataques Windows, VERSION 2 (lanzador local + `logall_json=yes`)

> Ejecutado el 2026-11-20/21. La ronda original (por SSH) queda como **«versión 1 (por SSH)»** en `../windows/` y no se ha tocado.
> `windows_index.csv` es el índice de esta campaña (última fila por `tag` manda; las filas `t0 corregido…` sustituyen a las originales).

## Qué cambia respecto a la versión 1
| | Versión 1 (por SSH) | **Versión 2** |
|---|---|---|
| Lanzamiento | `ssh … cmd /c run.cmd` (padre `sshd.exe`) | SSH **solo crea y dispara** una tarea programada `TFG-Attack-<ATA>` (usuario `angel`, interactiva, nivel alto): el padre de `cmd.exe` es `svchost.exe` (Programador de tareas) |
| Snapshot | `…-ataques-ssh` (49 casos) y `…-ataques-gui` (5) | **`lab-listo-windows-ataques-gui` para los 54** (sesión 1 con autologon) |
| Manager | `logall_json=no` | **`logall_json=yes`** (se guardan todos los eventos) |
| Datos por ventana | Detalle/Audited/Logs | **además** `alerts` y `archives` crudos del agente 002 en `[t0−60 s, t1+120 s]` y copia cruda diaria del manager con sha256 |

## Resultado de la campaña
- **108 ventanas (54 casos × 2): 108 OK**, 0 pendientes. ATA067 (reinicia la VM): la ventana espera al nuevo arranque y a la reconexión del agente 002; `t1` = reconexión + 20 s.
- Verificación de completitud (`verificar_completitud_ataques_v2.py`, recalcula sha256 y cruza alertas crudas vs Detalle): **0 fallos**.
- Tabla T2 v2 (`Hojas/T2_ataques_windows_v2.csv`): **TPR 54/54 en N=0 y N=3** (igual que la v1) y **0/54 en N≥7** (la v1 daba 2/54).
  Los 2 casos de la v1 en N≥7 (ATA073, ATA097) eran la regla `92213` (nivel 15, «ejecutable soltado»), que el catálogo **M1b-W** ya trata como *doble uso/artefacto* (su origen es la actividad legítima de GHOSTS); no es un efecto del cambio de lanzador. *(No se pudo reproducir un M1b-W de la v1 con la herramienta estándar: algunas ventanas S1 de la v1, p. ej. ATA104, no llevan cabecera de procedencia en su `-Audited.csv`.)*

## Problemas encontrados y cómo se resolvieron (hay que declararlos)
1. **`rs_origen=UNKNOWN`** en el Detalle: la extracción corrió en el host sin el ruleset del manager y ninguna fila contaba para C0/C1 (TPR 0). Se re-extrajo todo desde las alertas crudas con una **copia del ruleset del manager** (`D:\TFG-VMs\ataques-windows-v2-2026-11-20\ruleset_manager\rules.tgz`, sha256 `40303cf9…83c5`). → `reextraer_detalle_windows_v2.py`.
2. **`t0` mal sellado**: se tomó de la marca que escribe el propio script al arrancar (1–3 s después de lanzarlo): los procesos del ataque (`cmd.exe /c run.cmd`, `powershell -File ATA…ps1`) quedaban **antes** de `t0` y fuera de la ventana (ATA060 salía con 0 detecciones). En la v1 `t0` se sellaba antes de lanzar. **Corregido: `t0` = reloj del manager justo antes de `schtasks /run`** (`corregir_t0_windows_v2.py`; el `t0` original se conserva en la columna `error` del índice). Linux no se ve afectado (`bash` arranca en milisegundos y la ventana usa segundos enteros).
3. **Artefacto de medición del FIM**: el orquestador fuerza el escaneo FIM (`agent_control -r -u 002`) tras **cada** ataque (la v1 solo donde el caso lo exigía) y en el snapshot `-gui` eso genera cientos de alertas `752` (*Registry Value Entry Added*, p. ej. `AarSvc_*`) clasificadas como «novel/detección» (2 394 filas). Se declara la regla `752` como **artefacto de medición v2** en `catalogo_M1b_windows_v2.csv` (M1b-W + 752). Sin ese ajuste el número de «detecciones» se infla ×6.
4. **Dudosas**: 2 390 filas `dudosa` tras el filtro; **150 resueltas por precedente unánime de la v1** (no es revisión humana) y **2 240 siguen `dudosa`** (sobre todo `554` *FIM ambigua* por técnica, sin precedente en la v1). No afectan a los conteos de detección (solo se cuenta `categoria=deteccion`).
5. Diferencia de entorno: la v2 usa sesión interactiva (autologon) para todos los casos; hay más ruido de fondo por ventana que en la v1 (SSH, sin sesión 1). Es un cambio buscado (igual que el legítimo) pero debe declararse al comparar con la v1.

## Tablas Windows con la ventana legítima de 72 h (cierre de lo que quedaba con el baseline de 8 h)
`Hojas/T3_legitimo_windows.csv` (ahora con `doble_uso`), `T5_doble_uso_windows_v2.csv` (24 reglas, 3 de doble uso), `T4_rendimiento_windows_v2.csv`, `T5_pruning_windows_v2.csv`, `T5_steps_windows_v2.csv`.
Windows C1 N≥0: TPR 1,00; FPR 0,2939; Precisión 0,0624; F1 0,1174; GM 0,8403. En N≥7: TPR 0.

## Dónde está todo
- Repo: `Logs/<tag>/`, `CSV/`, `Auditado/` (filtrado base), `Auditado_precedente/`, `Revision_precedente/`, `M1b/`, `Bitacora/`, `windows_index.csv`, `filtrado_resumen.csv`, `VERIFICACION_COMPLETITUD.md`, `catalogo_M1b_windows_v2.csv`.
- Fuera del repo (`D:\TFG-VMs\ataques-windows-v2-2026-11-20\`): `raw/` (alerts + archives crudos por ventana), `crudo/` (copia diaria del manager con `MANIFEST.tsv` sha256), `ruleset_manager/`, `piloto_*`.
