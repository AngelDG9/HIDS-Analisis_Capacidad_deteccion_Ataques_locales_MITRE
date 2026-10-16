# reviews.md — Ataque del plan (bloque `reencuadre`)

> Revisión rigurosa del **orquestador** sobre `plan.md` (v1). Fecha: **2026-10-16**.
> **Veredicto: APROBABLE** — con 4 notas (ninguna bloquea el gate).

---

## 1. Lo que he verificado yo mismo (no me fío del plan)

| Comprobación | Resultado |
|---|---|
| **Premisa central**: los `-Audited.csv` traen `rule_level` + `rs_origen` | ✅ **160 ficheros**, **los 160** con ambos campos en cabecera → el **"recorte determinista"** (virgen × umbral × RS) es viable **sin re-atacar** |
| **RS3 = RS4 = 0** (Wazuh ya es "virgen") | ✅ `active_ruleset.txt` líneas 26-27 |
| **El corpus es 100 % P1** | ✅ `ATA_index.csv` (Impact / Exfiltration / Collection) |
| **`plan.md` sin secretos** | ✅ 0 apariciones reales (las 2 coincidencias son las propias reglas del plan) |
| **El planificador no tocó nada más** | ✅ `git status`: solo `plan.md` (untracked) |

---

## 2. Fortalezas

- **El hallazgo del "recorte"** cambia el coste del reencuadre de **semanas a días**.
- **Métrica definida con precisión**: unidades explícitas, reglas de conteo anti-sesgo, y **declara honestamente** que F1/GM mezclan planos (igual que el profesor).
- **Secuencia con camino crítico real**: identifica el **cuello de botella** (72 h de reloj) y lo arranca pronto.
- **Homogeneidad**: adopta T1–T5 + Requisitos + Leyenda del profesor y reutiliza el TFM hermano (Velociraptor).
- **Trazabilidad**: cada afirmación clave con cita verificable.

---

## 3. Notas (a resolver en el gate o en `reencuadre-metrica`)

1. **🔴 Unidad y comparación ENTRE HIDS (la más importante).** La "unidad legítima = evento" **no es comparable entre Wazuh y Velociraptor**: sus "eventos" son cosas distintas (registros de log vs filas de artifact) y los denominadores no son equivalentes. → Para la **comparativa VR↔Wazuh** hay que usar una **unidad común**: la **acción de GHOSTS** y/o la **hora**. El plan ya lo lista como decisión abierta (gate Q2) y tiene fallback; se propone dejarlo **explícito en la métrica congelada**.
2. **🟡 El denominador del legítimo NO existe en lo ya medido.** Los baselines actuales guardan **alertas**, no el total de eventos → la captura de **72 h con instrumentación del denominador es OBLIGATORIA** (no opcional) para T3/T4. *(El plan va en esa línea: L1 es el cuello de botella.)*
3. **🟢 El bloque `reencuadre` no ejecuta nada**: su producto es el propio plan + la aprobación. La reescritura de docs es **R1** y la métrica/tablas **R2**. Es correcto (ir "poquito a poco"), pero conviene que el gate lo sepa.
4. **🟢 GHOSTS podría necesitar menos "internet local"** si se usa el cliente **Lite** (genera tráfico sin apps reales) → lo decidirá el go/no-go de `L0`.

---

## 4. Recomendación

**Aprobar el marco** y **contestar el gate** (7 preguntas de `plan.md` §13). Con las respuestas, `reencuadre-metrica` congela la métrica incorporando la **nota 1**.

---

# Revisión v2 (2026-10-16, tras el material nuevo)

> El humano aportó **`Tabla 1 - Matriz MITRE Enterprise v17.xlsx`** (movida a `_recursos/reuniones/03/`),
> pidió **estudiar a fondo** y añadió su **duda del orden** (recorte vs legítimo). El planificador
> reescribió `plan.md` (**867 líneas**).

**Veredicto: APROBABLE** (sin notas bloqueantes).

## Lo que verifiqué
- **`plan.md` sin secretos** (0) y **git status** limpio (solo `plan.md`/`reviews.md`) ✅.
- **Tabla 1 (v17)**: Tactics **14/14/0** · Techniques **211** (red 77, **solo-red 17**) · Subtechniques **468** (red 91, **solo-red 34**) — coincide con lo que vi al volcarla ✅.
- La equivalencia **`host_eligible ≈ NOT(Only Network Detection)`** cuadra (padres P1: 38 vs 39) con **3 discrepancias trazadas**: `T1029`, `T1602`, `T1567.003` ✅.
  - **Nota**: `T1029` (ATA021) y `T1567.003` (ATA050) **los medimos y se detectaron** → la evidencia empírica respalda que **sí son observables por un HIDS** → es un **hallazgo**, no un error. `T1602` (Network Devices) queda fuera por no factible ✅.

## Lo que aporta el v2 (lo valoro muy positivamente)
- **§1.3** estudio **hoja a hoja** de la Tabla 1 + **desfase v17↔v19.1** y de **nombres de táctica** (*Defense Evasion*→*Stealth*) → **mapear por ID**, no por nombre ✅.
- **§1.4** el **repo hermano** (Ignacio Merchán, mismo tutor) a fondo: `TOTAL_LEG_FLOWS = 78.694.206`, `GM = √(TPR·TNR)`, **TPR por pcap / FPR por flujo**, doble métrica **Raw vs Diff-Alerts/Flow**, y su **pipeline de pruning** (500/1000 · Conservative · Generalized · Aggressive G-Mean) = **nuestra Tabla 5** ✅.
- **§1.5** lecciones de **Linares** (umbral↔FP: 85,5 % con 13,9 FP vs 51 % con 3,1 FP; **INetSim = internet simulado local** → refuerza §9) y de **Peña** (control benigno + aviso de **doble señal por acción**) ✅.
- **§4.6** resuelve **mi nota 1** (titular por evento; comparación VR↔Wazuh por **acción/hora** y **por técnica**) ✅.
- **§10.4** resuelve **la duda del humano**: `M1a` (histórico, en paralelo) + **`M1b` (re-ejecución tras el legítimo)**; baselines actuales → `histórico` ✅.
- **§16** declara **7 cosas que no cuadran** (guía desactualizada, desfase de versión, nombres de táctica, "4 niveles" reales, **ATA055/ATA035 no P1 puros**, **55 casos vs 128 ventanas**, "paquete pcap" disperso) ✅.

## Recomendación
**Aprobar** (`status: approved_by_human`) y contestar las **2 preguntas nuevas** del gate (Q8: Tabla 1 + discrepancias; Q9: orden legítimo→re-recorte). Las 7 anteriores ya están contestadas por el humano.
