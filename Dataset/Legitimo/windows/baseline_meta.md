# Baseline Windows — ficha (`fase-02b-baseline`)

> **Autor:** `tfg-executor`. **Plan:** `plan.md` (raíz, `status: approved_by_human`, 2026-10-07).
> **Naturaleza:** línea base de **Windows** = "ruido normal" del agente `victima-windows` (id
> `002`) **sin ataques**, con **actividad legítima programada**, en **2 ventanas × 4 h** (mismas
> franjas que Linux). **Sin secretos. Sin commit.**
> **Estado:** ✅ **COMPLETA** — **v1 (noche) + v2 (tarde) EXTRAÍDAS** · **catálogo unido** ·
> **estabilidad** medida. Todo bajo `Dataset/Legitimo/windows/`.

---

## 1. Ventanas (UTC / local Madrid CEST +02:00)

| Ventana | `t0` (UTC) | `t1` (UTC) | Duración | Local |
|---|---|---|---|---|
| **v1 — noche** | `2026-10-08 00:45:00Z` | `2026-10-08 04:45:00Z` | 240 min | 02:45 → 06:45 |
| **v2 — tarde** | `2026-10-08 12:00:00Z` | `2026-10-08 16:00:00Z` | 240 min | 14:00 → 18:00 |

- Mismas franjas que Linux y **el mismo día** (comparabilidad). Filtro de extracción en **UTC**
  (`timestamp ∈ [t0,t1]`); los `timestamp` de Wazuh ya vienen en UTC.
- **Fecha: 2026-10-08** (las del 07/10 quedaron inválidas/canceladas; ver
  `Soporte/Laboratorio/windows/baseline_resultado.md` §9-§10).
- Ninguna ventana cruza medianoche UTC (regla de medianoche no aplica).
- **Arranque ≥ 15 min antes de `t0`** (v1: `00:30Z` → `t0`=02:45 local; v2: `11:45Z` → `t0`=14:00
  local). El ruido de arranque cae **fuera** de `[t0,t1]` (criterio v2 de los ataques; **diferencia
  declarada con Linux**, §13).

> **Nota de fronteras (v2).** Las ventanas se toman **tal como las fija el plan §1.1**
> (`12:00:00Z`–`16:00:00Z`). La **tarea del host** `TFG-Baseline-Afternoon-Start` encendió la
> víctima a las **`11:45:00Z`** (15 min de asentamiento *antes* de `t0`) y la tarea del invitado
> `TFG-Baseline-Legit` disparó a las **`11:55:00Z`** (= `t0 − 5 min`). Por eso `START ≤ t0` y
> `END ≥ t1` se cumplen (§4). Un filtro alternativo `11:45–15:45Z` (la víctima completa "a pelo",
> sin asentamiento) **incluiría el arranque** del invitado (pico de registro/servicios y la alerta
> `503  Wazuh agent started`) y **rompería** la comparabilidad con v1 → **descartado**.

---

## 2. RuleSets activos

- **RS1** (ruleset por defecto de Windows) — **todas** las alertas de ambas ventanas.
  - v1: `67027` (`0955-WEF-baseline_rules.xml`), `60642`/`60702`
    (`0585-win-application_rules.xml`), `92201` (`0830-sysmon_id_11.xml`).
  - v2: los anteriores + `594`/`598`/`750` (`syscheck`, FIM de registro).
- **RS2 VACÍA** en Windows (no hay `auditd`; espejo del RS2 de Linux). **RS3 y RS4 vacías**
  (aún). **Diferencia declarada con Linux** (allí RS1+RS2).

---

## 3. Snapshot y arranque

- **Snapshot de la víctima:** **`lab-listo-windows-baseline`** (hijo de `lab-listo-windows`;
  incluye `C:\lab-legit\` + tarea `TFG-Baseline-Legit` + suspensión desactivada). Los snapshots
  `base-limpia` y `lab-listo-windows` quedan **intactos**.
- La víctima se **revierte** al snapshot al arrancar cada ventana; el **manager `wazuh-server`
  NO se revierte** (conserva las alertas; sigue encendido entre las dos ventanas).
- **Evidencia host** (log `%TEMP%\opencode\baseline_host_control.log`):
  - **v1:** `night-start` **2026-10-08T00:30:00Z** (rc=0) · `night-stop` **2026-10-08T04:50:00Z**
    (rc=0). Arranque `< t0−15min` ✔ · apagado `> t1` ✔.
  - **v2:** `afternoon-start` **2026-10-08T11:45:00Z** (rc=0; revert+start víctima y manager) ·
    `afternoon-stop` **2026-10-08T16:05:39Z** (víctima, `soft`, rc=0) y **16:06:55Z** (manager,
    `soft`, rc=0). Arranque `= t0−15min` ✔ · apagado `> t1` ✔. **Apagado limpio** confirmado.
- **Chequeo de suspensión (`SLEEPCHECK`) OMITIDO en los arranques de ambas ventanas** por **falta de
  la variable `TFG_GUEST_PW`** en el entorno de la tarea del host. **No bloqueó:** las ventanas se
  cubrieron **completas** (`baseline_resultado.md` §11.1/§12.1).

---

## 4. Actividad legítima programada (§1.5 del plan)

- **Script:** `Soporte/Wazuh/Scripts/baseline_actividad_windows.ps1` (sha256 repo =
  `EB60DF9D6213E483CCD57DF7DDD5F51AE3D56307AEB98E6C48CE6F8DC667263E`).
- **Tarea del invitado:** `TFG-Baseline-Legit` (`SYSTEM`, Highest, `StartWhenAvailable=False`,
  límite 5 h), disparos `2026-10-08T02:40:00+02:00` y `2026-10-08T13:55:00+02:00` (= `t0−5min` de
  cada ventana), `-DurationMin 248`.
  - **Desviación declarada:** `-DurationMin 248` ≠ **`260 min`** del `plan.md`. Se usa **248** para
    que el script escriba `END` **antes** del apagado del host (`t1+5`: 06:50 / 18:05) y así cubrir
    `[t0−5min, t1+…]` con `END ≥ t1` (con 260 el `END` caería tras el apagado y no se escribiría).
    Ya declarado en `baseline_resultado.md` §3.

| Ventana | `START` | nº ciclos | `CYCLE 1` | último `CYCLE` | `END` | cubre `[t0,t1]` |
|---|---|---|---|---|---|---|
| **v1** | `00:40:01Z` | **50** | `00:40:02Z` | `CYCLE 50 04:45:15Z` | `04:48:01Z` | ✔ (`START≤t0`, `END≥t1`) |
| **v2** | `11:55:01Z` | **50** | `11:55:06Z` | `CYCLE 50 16:00:34Z` | `16:03:02Z` | ✔ (`START≤t0`, `END≥t1`) |

- **Logs copiados** al repo: `baseline_log_ventana1.txt` / `baseline_log_ventana2.txt`.
- **Estado de la tarea (v2, `Get-ScheduledTaskInfo`):** `LastRunTime = 10/8/2026 1:55:55 PM`
  (local) · **`LastTaskResult = 0`** · `NumberOfMissedRuns = 0` · `NextRunTime` vacío (sin más
  disparos). (v1: `LastRunTime = 08/10/2026 02:40:40`, `LastTaskResult = 0`, `missed = 0`.)
- Ciclos esperados ≈ 50 (248 min ÷ ~5 min) → **50 reales** en ambas ventanas ✔.

---

## 5. Extracción (plan §2)

- **Fuente:** fichero **diario** del manager
  `/var/ossec/logs/alerts/2026/Oct/ossec-alerts-08.json` (**NO** `alerts.json`; regla operativa
  `state.md:83`). Es **más estricto** que el baseline Linux de Fase 2 (que usó `alerts.json`).
- **Herramienta:** `/home/angel/extraer_alertas.py` — **sin modificar**.
  **`sha256` repo == manager verificado:**
  `4019fda84a59f4079529f7f95cc6fe9d250b46fb447b235b3c9a90ba64569c44` (coincide con la huella
  congelada citada en `Bitacora/ATA024.json`).
- **Comandos (manager, root solo-lectura de `/var/ossec`):**
  ```bash
  # 1) detalle crudo (todos los agentes) de la ventana
  sudo python3 /home/angel/extraer_alertas.py \
    --alerts /var/ossec/logs/alerts/2026/Oct/ossec-alerts-08.json \
    --desde <t0> --hasta <t1> \
    --detail /tmp/baseline_win_vN_raw.csv
  # 2) aislar agent.id==002 ∧ agent.name==victima-windows ∧ ventana -> JSONL
  #    (helper temporal /tmp/filtrar_agente_win.py, NO versionado)
  sudo python3 /tmp/filtrar_agente_win.py <DIARIO> /tmp/baseline_win_vN_agent002.jsonl \
    victima-windows 002 <t0> <t1>
  # 3) agregado por rule.id reutilizando la lógica congelada sobre el JSONL aislado
  sudo python3 /home/angel/extraer_alertas.py \
    --alerts /tmp/baseline_win_vN_agent002.jsonl --desde <t0> --hasta <t1> \
    --out /tmp/ruleids_legitimos_vN.csv
  ```
- **Aislamiento por agente:**

  | Ventana | n_raw (todos) | n_filtrado (ag. 002) | otros agentes | 0 agentes ajenos en el catálogo |
  |---|---|---|---|---|
  | **v1** | 72 | **72** | 0 | ✔ |
  | **v2** | 158 | **87** | **71** (manager `000`) | ✔ (71 excluidas) |

  Cruce `agent.id`: `id==002 con nombre ≠ victima-windows = 0` y `nombre == victima-windows con
  id ≠ 002 = 0`. Detalle `agent_name` = {`victima-windows`}.
- **Esquema detalle:** `DETAIL_HEADER` **actual** del extractor: 17 columnas. Las 3 últimas
  (`srcip,srcuser,dstuser`) son adiciones de **H3** (`fase-03-afinado`); el fichero Linux
  `baseline_detalle_v1.csv` (14 col.) es **previo a H3**. **Diferencia declarada** (no se puede
  recortar sin alterar la salida del extractor congelado).

---

## 6. Resumen por ventana

| Métrica | v1 (noche) | v2 (tarde) |
|---|---|---|
| **Alertas (agent 002, `[t0,t1]`)** | **72** | **87** |
| **`rule.id` distintos** | **4** | **7** |
| **`UNKNOWN`** | **0** | **0** |
| **RS** | RS1 100 % | RS1 100 % |
| **Primera alerta** | `00:45:15.681Z` — `67027` | `12:00:32.134Z` — `67027` |
| **Última alerta** | `04:39:46.048Z` — `67027` | `15:59:46.160Z` — `67027` |
| **Cobertura** | continua (horas 00–04) | continua (horas 12–15) |
| **Hueco máximo entre alertas** | 40.8 min | 35.9 min |

**Catálogos por `rule.id` (`ruleids_legitimos_v1.csv` / `_v2.csv`):**

| `rule.id` | nivel | descripción | grupo(s) | v1 | v2 | RS |
|---|---|---|---|---|---|---|
| `594` | 5 | Registry Key Integrity Checksum Changed | ossec\|syscheck\|…registry | 0 | 6 | RS1 |
| `598` | 5 | Registry Key Entry Added to the System | ossec\|syscheck\|…registry | 0 | 4 | RS1 |
| `750` | 5 | Registry Value Integrity Checksum Changed | ossec\|syscheck\|…registry | 0 | 10 | RS1 |
| `60642` | 3 | Software protection service scheduled successfully. | windows\|windows_application | 2 | 1 | RS1 |
| `60702` | 5 | The VSS service is shutting down due to idle timeout. | windows\|windows_application | 1 | 1 | RS1 |
| `67027` | 3 | A process was created. | windows\| WEF | 68 | 64 | RS1 |
| `92201` | 9 | powershell.exe created a new scripting file under Temp/User data | sysmon\|sysmon_eid11_detections\|windows | 1 | 1 | RS1 |

**Resumen por origen** (`resumen_por_origen_v1.csv` / `_v2.csv` / unión `resumen_por_origen.csv`):

| origen | v1 rule_ids | v1 alertas | v2 rule_ids | v2 alertas | unión rule_ids | unión alertas |
|---|---|---|---|---|---|---|
| Seguridad (Windows) | 3 | 71 | 3 | 66 | 3 | 137 (86.16 %) |
| Sysmon | 1 | 1 | 1 | 1 | 1 | 2 (1.26 %) |
| FIM/syscheck | 0 | 0 | 3 | 20 | 3 | 20 (12.58 %) |
| PowerShell | 0 | 0 | 0 | 0 | 0 | 0 |
| Otros | 0 | 0 | 0 | 0 | 0 | 0 |

> **Nota de volumen (honestidad).** El ruido de Windows con esta actividad benigna y la
> telemetría **curada** de la construcción es **muy inferior** al de Linux. La actividad PowerShell
> rica (`92021/92066/91816/92031`) se observa en el **arranque del invitado** (fuera de `[t0,t1]`
> en **ambas** ventanas; en v2 cae en `11:45:3x–11:45:49Z`, antes de `t0`=12:00Z) pero **no** en
> régimen: el `powershell.exe` del script corre desde la ruta **estándar**
> (`…\System32\WindowsPowerShell\v1.0\`), que no dispara las detecciones de ruta sospechosa. La
> única `92201` de cada ventana es del arranque del propio script (creación de un fichero de
> scripting en Temp). Se **mide y se declara**; no se fuerza.

---

## 7. Validez

**Resultado: ambas ventanas VÁLIDAS** (con las salvedades de §8 y §13). Comprobaciones
(plan §4.3 / §6.1):

| Comprobación | v1 | v2 |
|---|---|---|
| **Cobertura de `[t0,t1]`** | horas 00–04 con telemetría; hueco máx. 40.8 min | horas 12–15 con telemetría; hueco máx. 35.9 min |
| **Pérdida del agente (`503`/`504`)** | **0** | **0** (el único `503` cae en `11:45:32Z`, **fuera** de la ventana del plan) |
| **Anti-contaminación (operador `192.168.65.1`)** | **0** eventos | **0** eventos (`srcip` exacto y logon/sesión `4624/4625/4672`/`wsmprovhost` = 0) |
| **Actividad legítima** | 50 ciclos, cubre `[t0,t1]` | 50 ciclos, cubre `[t0,t1]` |

- La **validez definitiva** del bloque se apoya en las **dos** ventanas válidas y en el análisis
  de **estabilidad** (§10-§11).
- **Cobertura v2 (matiz honesto):** el grueso de las alertas `67027` (proceso creado) se concentra
  en la **hora `12`** (64 de 87) tras el arranque, y luego hay actividad intermitente en `13`
  (8), `14` (9) y `15` (6); el **hueco máximo de 35.9 min** es propio de la actividad intermitente
  (no de un corte: la tarea legítima corrió **50 ciclos** sin interrupción). Idéntico patrón al de v1.

---

## 8. Desviaciones declaradas (específicas del bloque)

1. **🔴 FIM forzado solo en la ventana 2.** El plan (§1.6 fila 3, Q5) contempla
   `agent_control -r -u 002` **desde el manager** dentro de cada ventana (mismo método que Linux,
   sin tocar la VM). **En la noche NO se ejecutó**; **sí en la tarde**: `agent_control -r -u 002`
   a las **`2026-10-08T12:11:00Z`** (salida `Restarting Syscheck/Rootcheck on agent: 002`).
   **Resultado real: 20 alertas FIM** del agente `002` en `12:11:09–12:11:11Z`, reglas **`594`**
   (×6), **`750`** (×10) y **`598`** (×4). **NO fueron 0 como se esperaba:** el FIM de Windows
   **también vigila claves de registro** (`rdyboost`, `SharedAccess`, `VSS\Diag`, `WmiApRpl`) y el
   rescan forzado afloró cambios de registro acumulados. **Es la única diferencia de contenido
   entre v1 y v2** y **marca la estabilidad** (§11). Se declara.
2. **Esquema del detalle (17 vs 14 columnas).** Ver §5 (H3 posterior al fichero Linux).
3. **Diferencia con Linux — arranque fuera de ventana** (§1; mejora declarada sobre Linux, donde
   el churn de arranque cayó dentro).
4. **Fuente diaria** (más estricta), **aislamiento por agente** (Linux no filtró), **RS2 vacía**,
   **ubicación `Dataset/Legitimo/windows/`** (`plan.md` §1.6).
5. **`resumen_por_origen*`.** El plan §3.1 nombra `resumen_por_origen.csv` como vista de la
   **unión** v1+v2; aquí se ofrecen las **tres**: `_v1`, `_v2` y la **unión** (`resumen_por_origen.csv`).

---

## 9. Catálogo unido (v1+v2)

- **Herramienta:** `_artefactos/scripts/unir_catalogo_ruido.py` (**sin modificar**; tests en
  `_artefactos/scripts/tests/test_unir_catalogo_ruido.py`, **14/14 en verde**). Salida
  determinista (mismos bytes en 2 pasadas verificadas).
- **Salida:** `Dataset/Legitimo/windows/ruleids_legitimos.csv`
  (esquema `…,count_v1,count_v2,count_total,ventanas`, idéntico al catálogo Linux; línea `#`).
- **Cifras:** **7 `rule.id`** = **4 en ambas** (`v1+v2`) + **0 solo v1** + **3 solo v2**
  (`594`, `598`, `750`). **Alertas: 72 (v1) + 87 (v2) = 159**.

| `rule_id` | `count_v1` | `count_v2` | `count_total` | `ventanas` |
|---|---|---|---|---|
| `594` | 0 | 6 | 6 | v2 |
| `598` | 0 | 4 | 4 | v2 |
| `750` | 0 | 10 | 10 | v2 |
| `60642` | 2 | 1 | 3 | v1+v2 |
| `60702` | 1 | 1 | 2 | v1+v2 |
| `67027` | 68 | 64 | 132 | v1+v2 |
| `92201` | 1 | 1 | 2 | v1+v2 |

---

## 10. Estabilidad v1 ↔ v2 (plan §3.3)

- **Fichero:** `Dataset/Legitimo/windows/estabilidad_windows.csv`
  (`rule_id`,…,`count_v1`,`count_v2`,`delta`,`delta_pct`,`ventanas`,`tipo`).
- **Tipos de alerta:** **4 `rule.id` estables** (en **ambas** ventanas) · **0 solo v1** ·
  **3 variables (solo v2)**: **`594`, `598`, `750`** — las **tres de FIM/syscheck**.
- **Frecuencia:** Δ (`count_v2 − count_v1`): `67027` **−4** (−5.88 %), `60642` **−1** (−50 %),
  `60702` **0**, `92201` **0**; `594`/`598`/`750` **+6/+4/+10** (ausentes en v1).
- **Ritmo (régimen):** v1 72 alertas/240 min = **0.30/min**; v2 87/240 = **0.36/min**
  (0.28/min **excluyendo** las 20 de FIM forzado, que no son ruido de régimen).
- **Reparto por capa:** v1 = Seguridad (Windows) 98.61 % + Sysmon 1.39 %. v2 = Seguridad 75.86 %
  + FIM/syscheck 22.99 % + Sysmon 1.15 %. **Sin FIM forzado**, v2 sería Seguridad 98.5 % + Sysmon
  1.5 % → mismo reparto que v1.
- **Auto-ruido:** **ninguna** alerta de estado del agente (`503/506`) ni `stats` (`rule_id 11`) ni
  `wazuh-agent.exe` dentro de `[t0,t1]` en **ninguna** de las dos ventanas.
- **Veredicto: PARCIALMENTE ESTABLE (sin cambios estructurales salvo la desviación declarada).**
  - **Sin** el origen **FIM/syscheck** (aparece **solo** en v2 por el **scan FIM forzado**,
    desviación declarada §8.1), el **conjunto de orígenes es idéntico** (Seguridad + Sysmon) y
    **Δ total = (87−20−72)/72 = −6.9 %** → **estable en régimen** (dentro del umbral ~10 %).
  - El único `rule.id` con variación en régimen es `67027` (−5.88 %), coherente con actividad
    intermitente; `60642` (2→1) y el resto, idénticos.
  - **Con** el FIM forzado incluido, aparece/desaparece un **origen entero** y Δ total = +20.8 % →
    **no** es "estable" en sentido estricto. Se **declara sin maquillar**: la varianza es
    **artefacto de una acción nuestra (declarada)**, no del régimen.

---

## 11. Ficheros y huellas

| Fichero | `sha256` | bytes | EOL |
|---|---|---|---|
| `ruleids_legitimos_v1.csv` | `0c3e27b4318333cd94c845cc9203e0d9e51ebd82cdc201ca10eb65f6dc5a8ce4` | 678 | CRLF |
| `baseline_detalle_v1.csv` | `4f722e84a55a93b5cd698fc21fa9f9f30ccf22fd2c9b1436fff25c2ff26c5e87` | 8064 | LF |
| `resumen_por_origen_v1.csv` | `21550f7b395b27ab4ef72fd28fe49fe82563d7bf330a11f82cb7457b1462edca` | 203 | LF |
| `baseline_log_ventana1.txt` | `bd32092b2270da7d5bab3567f4f6ccad726eeb1325d0185668ce173895d63066` | 1615 | CRLF |
| **`ruleids_legitimos_v2.csv`** | `3bf4bbab0da63596f3653aee62478ce56f7b56408057648258ffe6bde639f4a2` | 1133 | CRLF |
| **`baseline_detalle_v2.csv`** | `de53c833065eb44c48494bb884632254d93d0fea3bcc8598ed6f1442093e6650` | 12144 | LF |
| **`resumen_por_origen_v2.csv`** | `c46d099944a5b528974715f4575efc45fd7201f8543b5c3ba1844edf6c5334ad` | 226 | LF |
| **`baseline_log_ventana2.txt`** | `ff980844f44818d3d9f7ce68e96bc479e7da3cbb6e5002720576e9d50cc2f7ed` | 1615 | CRLF |
| **`ruleids_legitimos.csv`** (unión) | `e726711f5acdfe4bf8fcb436ff629c904213bcda85d90e621b50cef72e77e96b` | 1332 | LF |
| **`resumen_por_origen.csv`** (unión) | `015793bb284de28653290c8658d7fe161ffa14b495d445c36f71231ba13f6f83` | 228 | LF |
| **`estabilidad_windows.csv`** | `ac5b39335a851dc8502a05dc771001c602b2eaba04d3d57c4bff1f4dd7bb7b0d` | 1061 | LF |

- Los ficheros **v2** replican el **esquema y EOL** de los **v1** (detalle LF; catálogo agregado CRLF;
  log CRLF). `ruleids_legitimos.csv` (unión) sale **LF** por el helper (igual que el catálogo Linux
  de unión).
- **Nota cosmética:** los `baseline_detalle_v1.csv` / `_v2.csv` incluyen un **comentario de cabecera
  `#` añadido a mano** (documentación de la ventana); las **filas de datos son el output *verbatim***
  del extractor. Por eso ese comentario difiere del que emitiría el script. La huella de la tabla es
  la del fichero tal cual está versionado.

**Pendiente (no en este paso):** nada del baseline Windows. Cierra el orquestador (`change-doc.md`,
`state.md`, `roadmap.md`).

---

## 12. Referencias

- `plan.md` §1.1-§1.6, §2, §3, §4.3, §6.
- `Soporte/Laboratorio/windows/baseline_resultado.md` §2-§12 (tareas host, snapshot, corrección
  de suspensión, re-armado 08/10, ventanas v1 y v2).
- Espejo Linux: `Dataset/Legitimo/baseline_meta.md`, `Dataset/Legitimo/ruleids_legitimos_v1.csv`.
- Regla operativa del fichero diario: `state.md:83`.
