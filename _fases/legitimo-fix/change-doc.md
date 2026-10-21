# change-doc — Bloque `legitimo-fix`: arreglo de la causa del fallo + actividad realista + repetición preparada

> Cierre. Fecha: **2026-10-21**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA** (2 salvedades a ratificar por el humano: D2/D3).
> Plan de referencia: `plan.md` (v3, 1409 líneas, `approved_by_human`, 2026-10-21).
> **Este bloque NO ha ejecutado la ventana de 72 h** (la fecha queda ABIERTA; la ejecutará `legitimo-72h-v2`).

---

## 1. Objetivo

Arreglar la **causa raíz** del fallo de L1 (log de GHOSTS sin tope → disco lleno → agente muerto), **rediseñar la actividad legítima** para que sea realista y determinista, **blindar la vigilancia**, corregir la **extracción** y dejar el laboratorio **listo y probado** para repetir.

---

## 2. Resultado

| Componente | Estado |
|---|---|
| **Causa raíz cortada** | ✅ NLog consola `Trace`→**`Warn`**; `client.out` con **tope 40 MB** (20×2, copytruncate) |
| **Receta realista** | ✅ Jornada 09–18 local, café 20 + comida 60, **111/117/105 acciones/día**, noche a 0; **secuencia idéntica** en dos ejecuciones (DT9: 111=111); 0 `random`, 0 `Browser*` |
| **Sesión web *browser-like*** | ✅ 8 acciones con `curl` (UA fija, cookies, `Referer`, `Accept-Encoding`, CSS/JS/SVG/PDF) |
| **Navegador headless** | ❌ **Descartado** con evidencia (DT-B0 falla: 12 librerías, 3,4 GB < 3,5 GB) — `browser_eval.md` |
| **Vigilancia** | ✅ **9 señales** (7 en vivo + 2 post-hoc), cada **30 min**, **sin tocar la víctima**; **`df` del agente** (no de la timeline) |
| **Keepalive v3** | ✅ 2 confirmaciones ≥5 min, 2 recuperaciones, 2 rotaciones, máx. 3 arranques, cooldown 30 min, ≥1 GB libre |
| **Extracción** | ✅ `.gz` por día + vivo, **dedupe `sha256`**, `--estricto` |
| **Manager** | ✅ Reinicio robusto (stop → pkill `wazuh_apid` → reset-failed → start) |
| **Snapshots** | ✅ **`lab-listo-legit-v2`** + **`fallo-2026-10-19-disco-lleno-NO-USAR`**; `lab-listo-legit` **conservado** |
| **Evidencia del fallo** | ✅ `fallo_2026-10-19/` (MANIFEST 16/16, serie `df -P` de 220 muestras con 100 % a las 14:03:39Z) |
| **Pruebas en seco** | ✅ **DT0–DT13 + DT-B** (todas documentadas; `prueba_en_seco.md`) |

---

## 3. Hallazgos

1. **El agente de Wazuh ya mandaba el disco** (`df -P` cada 360 s): el aviso del 100 % existía **8 h antes** de que muriera. Ahora lo lee la vigilancia. ✅
2. **Bug de GHOSTS v8.3.1**: pierde el reporte de comandos con **`|` (pipe)** → receta reescrita **sin pipes** (falso 108/111 → **111/111**). ✅
3. **El heartbeat del plan (`app.log`) era erróneo**: el hilo de updates mantiene fresco el fichero con el motor muerto → corregido a **`lastReportedUtc`**. ✅
4. **El cliente reescribe `timeline.json` al arrancar** → la rotación se decide por `rotacion.estado`. ✅

---

## 4. Verificación (`tfg-tester`) — **PASA**

- **5 puntos que bloqueaban** (CA-06 reanudación, CA-29/G-12, CA-14 `CONFIG_IDENTICA`, CA-11/documentación, DT13): **demostrados** ✅ (CA-06 y CA-14 re-verificados por el tester con recálculo independiente).
- **Regresiones**: `pytest` **189**, validador de la receta **PASS**, `sha256sums` 53/53, MANIFEST 16/16, rutas protegidas intactas, **0 secretos**, **0 VMs**, **0 `TFG-Legit-*`**, `logall_json=no` + `CONFIG_IDENTICA`, **Windows Update pausado**, `TFG_GUEST_PW` conservada.
- **Salvedades a ratificar por el humano**:
  - **D2 — swap**: el plan asumía `swap = 0`; la VM tiene **1915 MB** → G-12 avisa pero no bloquea. **Riesgo real menor, no mayor**. Se ratifica aquí.
  - **D3 — `plan.md` editado tras la aprobación** (redacción de CA-11/`df`): corrección factual, no de alcance. Se ratifica aquí.
- **Salvedades menores declaradas**: D1 (2 líneas históricas de mojibake en un log), D4 (CA-18 dice "borrada" y está conservada), D5/D6/D7/D8 (precisiones). Ninguna invalida.

---

## 5. Estado del laboratorio (listo, NO armado)

**0 VMs** · **0 tareas `TFG-Legit-*`** · **0 reglas firewall `TFG-*`** · GHOSTS/internet local parados · **`logall_json=no`** + `ossec.conf` **CONFIG_IDENTICA** · **Windows Update PAUSADO** (restaurar al cerrar la ventana) · **`TFG_GUEST_PW` conservada** (solo entorno) · sin commits/push en el bloque.

---

## 6. Siguiente

1. **`legitimo-72h-v2`** (bloque **nuevo**): la **ventana de 72 h** con la receta v2 y el snapshot `lab-listo-legit-v2`. **La fecha la fija el humano** (propuesta **26/10 00:00Z → 29/10 00:00Z**; nunca cruzando el DST del 25/10).
2. Antes de armar: **pausar Windows Update** (`pausar_windows_update.ps1 pausar`) y **no borrar `TFG_GUEST_PW`** hasta cerrar la ventana.
3. **`push`**: los commits son **locales**; publicar es del humano.
