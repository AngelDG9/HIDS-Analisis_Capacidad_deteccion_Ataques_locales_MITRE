---
fase: 3
bloque: fase-03-senales-ratificacion
nombre: Ratificación humana — las 4 escrituras de ATA007 pasan a `deteccion`
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-orchestrator
gate: aprobado por instrucción explícita del humano (2026-09-28) — «Hazlo»
---

# Micro-plan — Ratificación de los veredictos de ATA007

> **Micro-plan** (cambio de veredicto humano + re-plegado determinista). Corrige la **salvedad C11**
> del bloque `fase-03-senales` (`_fases/fase-03-senales/change-doc.md` §4).
> **No** entra: ningún otro cambio del filtro, ni escalar, ni Windows, ni la memoria.

## 0. Decisión del humano (2026-09-28)

De las **17** filas `dudosa` resueltas, se **ratifican como `ruido` las 13** que son **procesos ajenos**
(nuestro login: `systemctl --user`, `find` de `update-motd.d`, un `tar` watch, PAM).

**Las 4 escrituras del defacement (ATA007: `80790`/`80781`, 2 por iteración) pasan a `deteccion`:**
son **el ataque** (no ruido), y su **doble conteo se evita al contar** — la ficha reporta las **dos cifras**
(*alertas* y *acciones distintas*), así que el número de acciones sigue siendo el correcto.

## 1. Tareas

1. En los `-Revision.csv` de **ATA007 iter1/iter2** (`Dataset/Ataques/Resultados/Wazuh/linux/Auditado/`),
   cambia el `veredicto` de las **4** filas de escritura (`80790` y `80781`) de `ruido` a **`deteccion`**,
   con nota: *"es el ataque (la escritura del defacement); es el mismo evento ya contado por el `execve` del `cp` — se reporta con las dos cifras"*.
   Firma: `revisor="humano (ratificación 2026-09-28)"`.
   **No toques** las demás filas (13 → siguen `ruido`).
2. **Re-plega** con `filtrar_ruido.py --revision` (determinista) → regenera los audited **necesarios** (ATA007 iter1/2) y **comprueba que el resto de ventanas no cambia**.
3. **Actualiza** la ficha `ATA007_meta.md` y `Bitacora/ATA007.json` (conteos y hashes) y deja explícito el desglose
   **alertas vs `rule_id` distintos** (acciones).
4. **Verifica:** ATA007 pasa de **2 → 4** `deteccion` (con **2 acciones distintas**); las otras 5 ventanas **sin cambios**; **determinismo** (dos pasadas → mismo `sha256`); `pytest` **86**; la cadena de huellas coherente.
   ⚠️ **NO** `git checkout`/`stash`/`reset`.

## 2. Criterios de aceptación

| # | Criterio |
|---|---|
| **CA1** | Las 4 escrituras de ATA007: `categoria=deteccion`, `veredicto_humano=deteccion`, con la nota y la firma **del humano** |
| **CA2** | Las **13** de procesos ajenos **siguen `ruido`** |
| **CA3** | ATA007: `deteccion` = **4 alertas / 3 `rule_id` distintos** (`80781`,`80790`,`80792`) — **las 3 vistas son el MISMO evento** (el `cp` que sobrescribe la página, más sus dos escrituras vigiladas). El incremento de la ratificación es **+4 alertas / +2 `rule_id`**. *(Corregido el 2026-09-28: el plan decía "2 acciones"; la cifra medible es 3 `rule_id` = 1 acción.)* |
| **CA4** | Las **otras 5 ventanas** (ATA004, ATA012 y los 3 del piloto): **byte a byte idénticas** |
| **CA5** | `pytest` **86** · determinismo · hashes coherentes |
