# `legitimo_72h` (L1-fix, v3) — captura de 72 h de actividad legítima

> **Qué es.** Utilidades de **preparación, arranque, keepalive, vigilancia y extracción** de la
> captura de **72 h de actividad legítima** (GHOSTS + "internet local") sobre `victima-linux`
> con Wazuh virgen (`RS1..RS4`) y `logall_json` **ON solo en la ventana**.
> Plan de referencia: **`plan.md`** (raíz; `status: approved_by_human`, bloque `legitimo-fix` v3).
>
> **Ventana:** la ejecutará el bloque **`legitimo-72h-v2`** con su propio gate.
> **Propuesta (abierta):** `t0 = 2026-10-26T00:00:00Z` → `t1 = 2026-10-29T00:00:00Z`.
> **Este bloque NO ejecuta las 72 h**: deja el laboratorio **arreglado, probado, vigilado y
> snapshoteado** (`lab-listo-legit-v2`).

---

## 1. Qué cambió respecto de L1 (el fallo y su causa)

| # | Antes (L1) | Ahora (L1-fix) |
|---|---|---|
| 1 | `nlog.config` mandaba **todo** a la consola (`Trace`) y el lanzador redirigía a `ghasts.out` **sin tope** → **4,78 GB** → disco 100 % | **Consola a `Warn`** + **tope duro 20 MB × 2** (`client.out` + `client.out.1`) con `copytruncate` acotado en `client_ctl.sh` |
| 2 | Actividad: 4 handlers en bucle, 209 acciones/180 s, día y noche | **Receta determinista**: jornada 09:00–18:00 local, café/comida, **3 días distintos**, **111/117/105 acciones** |
| 3 | `df` propuesto a la timeline (v1) | **Retirado** (era telemetría): el disco lo reporta **el propio agente** (`df -P` cada 360 s); la vigilancia lo **lee**. **Sí** se conservan los **4 `df -h /` de usuario** de la receta (D1/D2 en B5; D3 en B3 y B5): acción legítima, **declarada** |
| 4 | Keepalive: `pgrep` (mide «estar») | Keepalive v3: **heartbeat = última acción REPORTADA** (`lastReportedUtc` de la API de GHOSTS), calendario, **2 confirmaciones ≥5 min**, **2 recuperaciones**, cooldown 30 min, **≥1000 MB libres**, **rotación diaria**, `recovery.log` |
| 5 | Vigilancia cada 3 h, sin umbrales | **9 señales cada 30 min** (**7 en vivo + 2 post-hoc**: RAM y `recovery.log`), niveles OK/AVISO/ALARMA, calendario (no juzga la noche), alarma visible |
| 6 | Extracción: un `archives.json` | **`.gz` por día + vivo**, **dedupe `sha256`**, `--estricto`, manifiesto |
| 7 | Navegador headless: sin evaluar | **Evaluado y descartado** con DT-B (`browser_eval.md`); en su lugar, **sesión web *browser-like* con `curl`** |

**Causa raíz (una sola):** stdout sin tope → disco lleno → orquestación muerta → agente muerto.
**Por qué no se vio:** la vigilancia medía *«el proceso está»* y no *«el proceso está haciendo»*.

---

## 2. Ficheros

| Fichero | Qué es |
|---|---|
| `legitimo_host_control.ps1` | Control **del HOST**: `prep` · `arm` · `watch` · `stop` · `drytest` · `cleanup` · `status` |
| `armar_legitimo.ps1` / `vigilancia_legitimo.ps1` | Atajos de `-Phase arm` / `-Phase watch` |
| `registrar_tareas.ps1` | Tareas del host con **`-T0`** (sin fechas duras), watch **cada 30 min**, `NextRun` en **UTC** |
| `recetas/` | **Receta v1**: `d1.json` (111), `d2.json` (117), `d3.json` (105), `calendario.json`, `bloques.env`, `receta_resumen.md`, `LEEME.md` |
| `recetas/superseded/` | Las timelines de L1 (`timeline_72h*.json`) **archivadas**, no borradas |
| `guest/tfg_keepalive.sh` | **Keepalive v3** (heartbeat + bloques + confirmación + topes + rotación + RAM post-hoc) |
| `guest/tfg-ghosts-legit.{timer,service}` | Tarea del invitado (fecha parametrizada, `Persistent=false`) |
| `guest/instalar_tarea_invitado.sh` | Instala la tarea con `T0` (rechaza fechas pasadas y verifica huellas) |
| `guest/verificar_arreglos.sh` | Comprueba **de verdad** los arreglos en el invitado (`RESULT=PASS/FAIL`, exit 40) |
| `watch_manager.py` | Señales de vigilancia **leídas del manager** (solo lectura): agente, daemons, crecimiento y **`df -P` incremental** |
| `exportar_denominador.sh` | **`copiar-ventana t0 t1`**: `.gz` por día + vivo + **manifiesto** + **dedupe sha256** |
| `prueba_en_seco.ps1` | Suite **DT0–DT13** (ver `prueba_en_seco.md`) |
| `browser_eval.md` | Evaluación del navegador (**DT-B0…DT-B5**) y decisión |
| `fallo_2026-10-19/` | **Evidencia** del fallo (`MANIFEST.md` + `evidencia/`) |
| `b10_sellado.md` · `sha256sums.txt` · `snapshot_v2.md` | Sellado B10, huellas y contenido de `v2` |
| `_artefactos/scripts/construir_receta_legitima.py` | **Generador + validador** de la receta (`--check`, `--dry`) |
| `_artefactos/scripts/contar_denominador.py` | Contador de `M` (+ dedupe, rangos, `--estricto`, `--manifest`) |

---

## 3. La receta (`recetas/`)

**Jornada 09:00–18:00 local** = **08:00–17:00 UTC** (CET = UTC+1 tras el DST del 25/10).

| Bloque | UTC | Local | Tipo | D1 | D2 | D3 |
|---|---|---|---|---|---|---|
| B1 Llegada | 08:00–08:12 | 09:00–09:12 | trabajo | 9 | 9 | 9 |
| B2 Correo y mañana | 08:12–10:00 | 09:12–11:00 | trabajo | 26 | 32 | 22 |
| P1 Café | 10:00–10:20 | 11:00–11:20 | **pausa** | 0 | 0 | 0 |
| B3 Documentos | 10:20–13:00 | 11:20–14:00 | trabajo | 42 | 34 | 46 |
| P2 Comida | 13:00–14:00 | 14:00–15:00 | **pausa** | 0 | 0 | 0 |
| B4 Reuniones/tarde | 14:00–16:15 | 15:00–17:15 | trabajo | 22 | 30 | 16 |
| B5 Cierre | 16:15–17:00 | 17:15–18:00 | trabajo | 12 | 12 | 12 |
| **Total** | | | | **111** | **117** | **105** |

- **Total ventana: 333 acciones** (frente a ~5,9 k del intento fallido).
- **Ráfagas y pausas**: 40–60 s dentro de la ráfaga; **hueco máximo intra-bloque ≤ 12 min**.
- **Determinismo**: solo handler `Command`; **cero** `random`, **cero** `delay-jitter`, **cero**
  handler `Curl`, **cero** `Browser*` y **cero pipes** de shell (`|`). JSON estático, bloques disjuntos.
  *Hallazgo*: GHOSTS v8.3.1 **pierde el reporte** de los comandos con `pipe` (no llegan a
  `history_timeline`), así que la receta usa redirecciones (`find … > fichero`, `wc -l fichero`).
- **Sesión web *browser-like* con `curl`** (8 posiciones que **ya existían**): UA fija y honesta
  (`TFG-Legit/1.0`), cookie jar, `Referer`, `Accept`/`Accept-Encoding`, **3 requisitos**
  (CSS+JS+SVG) y **descarga real del PDF**.
- **Guardián de fin de bloque**: el último evento duerme hasta pasar `UtcTimeOff` ⇒ el bloque
  termina limpio y **no se repite** dentro del día.

Generar/validar:

```powershell
python _artefactos\scripts\construir_receta_legitima.py           # genera recetas/
python _artefactos\scripts\construir_receta_legitima.py --check    # valida (RESULT=PASS)
python _artefactos\scripts\construir_receta_legitima.py --dry --base 10:00Z --out %TEMP%\d1.dry.json
```

---

## 4. Secuencia operativa (todo por tareas; **nada en segundo plano**)

| Tarea | Ámbito | Cuándo | Qué hace |
|---|---|---|---|
| **`TFG-Legit-Prep`** | host | `t0−45 min` | **G-1…G-12** → revert a **`lab-listo-legit-v2`** → start víctima+manager → deploy del cliente arreglado → `logall_json` ON → internet local + GHOSTS → `verificar_arreglos` → receta **d1** (cliente **parado**) + `rotacion.estado` = fecha de `t0` |
| **`TFG-Legit-Arm`** | host | `t0−20 min` | instala la **tarea del invitado** con `T0` (timer `t0−5 min`) → arranca el cliente → checklist |
| **`TFG-Ghosts-Legit`** | **invitado** | `t0−5 min` | systemd timer → keepalive v3 (heartbeat, rotación diaria, ≤2 recuperaciones) |
| **`TFG-Legit-Watch`** | host | cada **30 min** | vigilancia de 9 señales (**7 en vivo + 2 post-hoc**) (host + manager), **sin tocar la víctima** |
| **`TFG-Legit-Stop`** | host | `t1+5 min` | `stop` víctima (soft); el manager **sigue** para la extracción |

```powershell
powershell -File registrar_tareas.ps1 -T0 2026-10-26T00:00:00Z
powershell -File registrar_tareas.ps1 -T0 2026-10-26T00:00:00Z -Verificar
powershell -File registrar_tareas.ps1 -Eliminar
```

> **Secreto.** `prep`/`arm` necesitan `TFG_GUEST_PW` (variable de entorno de usuario; nunca en
> fichero). `-SetSecret` la pide por teclado; `-ClearSecret` la borra.

---

## 5. Guardarraíles de `prep` (aborta antes de `t0`)

| # | Comprobación | Código |
|---|---|---|
| G-1 | snapshot **`lab-listo-legit-v2`** existe | 41 |
| G-2 | disco libre **≥ 4 GB** e inodos libres ≥ 20 % | 42 |
| G-3 | `verificar_arreglos.sh` = **PASS** | 40 |
| G-4 | receta `--check` PASS + `sha256` == repo + mapeo 26/27/28 → d1/d2/d3 | 20 |
| G-5 | agente `active` y `agent_control -i 001` = **Active** | 43 |
| G-6 | **`df -P` del agente llega** en ≤ 7 min | 46 |
| G-7 | `logall_json=yes` + manager + daemons | 44 |
| G-8 | **NAT desconectado** + internet local responde | 45 |
| G-9 | sonda de rotación (aviso) | — |
| G-10 | host: `D:` ≥ 60 GB, Windows Update pausado, sesión iniciada | 47 |
| G-11 | `machineid`s de `victima-linux` registrados | — |
| G-12 | RAM libre **≥ 1500 MB** (swap se **declara**: la VM tiene swap) | 48 |

---

## 6. Vigilancia (9 señales = **7 en vivo + 2 post-hoc**, cada 30 min, **sin tocar la víctima**)

| # | Señal | Fuente | Umbral |
|---|---|---|---|
| 1 | ¿está **haciendo**? | `max(createdutc)` de `history_timeline` (host) + **calendario** | bloque: ≤15 OK · 15–30 AVISO · >30 **ALARMA**; pausa/noche: no se juzga |
| 2 | ¿agente dentro? | `agent_control -i 001` → `Last keep alive` (epoch) | ≤60 s OK · ≤10 min AVISO · >10 min **ALARMA** |
| 3 | daemons | `is-active` + `pgrep remoted/analysisd` | unit active y ≥1 de cada |
| 4 | ¿entran eventos? | Δ`archives.json` + Δ diario de alertas | 0 en 2 chequeos ⇒ **ALARMA** |
| 5 | **disco de la víctima** | `df -P` del agente, **offset incremental** | ≥3 GB OK · 2–3 AVISO · <2 **ALARMA**; tasa < −1 GB/h **ALARMA** |
| 6 | disco del host | `Get-PSDrive D` | ≥60 GB OK · 20–60 AVISO · <20 **ALARMA** |
| 7 | BD de GHOSTS | `pg_database_size('ghosts')` | <4 GB OK · 4–10 AVISO · >10 **ALARMA** |
| 8 | recuperaciones/rotaciones | `recovery.log` (se lee **al cerrar**) | informativo (§6.3.4 del plan) |
| 9 | **RAM** | **post-hoc** (`ram_free_mb` del keepalive) | mín. ≥512 MB; <256 MB ⇒ revisión |

- **Formato**: `... [watch] estado=OK doing_age=3m bloque=si hb=8s ag=Active mgr=active/2 arch=+2MB dia=+1MB df=5.2G tasa=-40MB/h db=68MB host=180G ram=post-hoc rec=0 rot=0 notas=`
- **Alarma visible**: `[ALARMA]` + `ALARMA_<UTC>.txt` + `msg.exe` (mejor esfuerzo); 2 seguidas
  de la misma señal ⇒ `PERSISTENTE`.
- **La vigilancia NUNCA actúa** (solo lectura): en `watch` no hay `192.168.65.129`, `$Vic`,
  `vmrun` ni `scp` (verificado con `grep`).

---

## 7. Extracción (después de `t1`, víctima parada, manager encendido)

> ⚠️ **ORDEN CRÍTICO.** `logall_json_ctl.sh off` **borra** `archives.json`: **1) COPIAR →
> 2) contar `M` → 3) apagar**.

```powershell
# 1) copia de la ventana (3 .gz + vivo + MANIFEST + dedupe)
<pw> | ssh ... manager "bash /tmp/exportar_denominador.sh copiar-ventana 2026-10-26T00:00:00Z 2026-10-29T00:00:00Z"
scp -r angel@192.168.65.128:/tmp/legit_denominador/*  <destino fuera del repo>
# 2) contar
python _artefactos\scripts\contar_denominador.py --desde 2026-10-26T00:00:00Z --hasta 2026-10-29T00:00:00Z `
    --estricto --manifest manifest.tsv --out denominador_M.csv <ficheros únicos>
# 3) apagar logall_json (restaura ossec.conf + reinicio robusto + diff)
<pw> | ssh ... manager "bash /tmp/logall_json_ctl.sh off"
```

- **Regla de borde**: `.gz` del día cubre `[t0, t1)`; el **vivo** solo puede aportar eventos con
  `timestamp` **exactamente `t1`**. `--estricto` **falla (exit 3)** si dos ficheros únicos solapan.
- **Dedupe `sha256`**: `archives.json` es un **hardlink** del día ⇒ se cuenta **una vez**.
- **`M` titular** = fila `endpoint` (agente `001`); `total` como complemento.

---

## 8. Prueba en seco y estado del laboratorio

- Suite: `prueba_en_seco.ps1` → `prueba_en_seco.md` (**DT0–DT13**). Navegador: `browser_eval.md`
  (**DT-B0…DT-B5**; **DT-B0 FAIL** ⇒ descartado).
- Snapshot nuevo: **`lab-listo-legit-v2`** (contenido y verificación en `snapshot_v2.md`).
- Snapshot de evidencia: **`fallo-2026-10-19-disco-lleno-NO-USAR`** (`fallo_2026-10-19/`).
- **El laboratorio queda CERRADO y NO armado**: 0 VMs, 0 tareas `TFG-Legit-*`, firewall
  retirado, `logall_json=no`, GHOSTS/internet local parados.

## 9. Disciplina en `[t0,t1]` (regla dura)

- **CERO** acceso a `victima-linux`: ni SSH, ni `vmrun runProgramInGuest`, ni consola, ni snapshots.
- El **manager** se consulta **por SSH de solo lectura**.
- **No** se cambia config (Wazuh/GHOSTS/internet local) dentro de la ventana.
- **PC encendido y sin suspensión** los 3 días.
- Lo único que **actúa** dentro es el **keepalive** (≤2 recuperaciones + ≤2 rotaciones + ≤3
  arranques), **declarado** y registrado en `recovery.log`.

## 10. Higiene

- La contraseña **nunca** en un fichero del repositorio (STDIN / variable de entorno).
- `_recursos/`, corpus, `Hojas/`, `Soporte/Metrica/` **sin tocar**; en `Dataset/` solo se
  **retiró la ficha inválida** (movida a `fallo_2026-10-19/` con verificación de huella).
- **Sin `git commit`/`push`** (los hace el orquestador/humano).
