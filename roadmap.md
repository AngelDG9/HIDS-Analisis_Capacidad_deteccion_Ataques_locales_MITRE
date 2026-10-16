# roadmap.md — Secuencia, hitos y riesgos del TFG

> **Versión:** v2 (reencuadre R1) · **Estado:** vigente · **Fecha:** 2026-10-16.
> Programa el trabajo en **bloques** (macro-fases **Clasificación → Ataques → Análisis**) con
> sus dependencias, hitos y riesgos. Sustituye a la secuenciación anterior por **"Fases 0–5"**,
> que se conserva marcada como **(histórico)**.
>
> **Anclas:** `(R0 §X.Y)` = `_fases/reencuadre/plan.md` (v2, 2026-10-16).

---

## 1. Cómo leer este roadmap (`R0 §10.1`, `§10.4`)

- **La unidad es el plan/bloque**: un `plan.md` por bloque; las **tandas** son tareas.
- Se separa **`histórico`** (lo ya hecho, que se reaprovecha) de **`nuevo`** (marco vigente).
- **Regla dura:** **nadie mide nada** hasta que la **métrica y las tablas estén congeladas**
  (bloque **R2**). Medir antes de congelar invalida el resultado.

---

## 2. Resumen ejecutivo (`R0 §3.2`, `§10`)

Programa en **3 macro-fases**:

```
Clasificación ──▶ Ataques ──▶ Análisis
  (R1 · R2)      (M1·L·V·B1)    (A1 · A2)
```

| Macro-fase | Bloques | Estado |
|---|---|---|
| **Clasificación** | R0 ✔ · **R1 (este)** · R2 | R0 cerrado; **R1 en curso** |
| **Ataques** | M1a/M1b · L0/L1/L2 · V0/V1 · B1 | histórico parcial (M1a) |
| **Análisis** | A1 · A2 | pendiente |

**Resultado del trabajo:** **5 tablas (T1–T5) + Requisitos + Leyenda** + **memoria**.

---

## 3. Trabajo hecho (`histórico`) (`state.md`, `R0 §1.2`)

| Fase (histórica) | Entregable | Estado | Se reaprovecha |
|---|---|---|---|
| **Fase 0** — Arranque | repo + agentes + docs slim | ✔ | Arquitectura de agentes |
| **Fase 1** — Corpus MITRE | `Hojas/corpus_host.csv` (697 → **625 host-eligible**) · `ATA_index.csv` | ✔ | RF-01, Tabla 1 |
| **Fase 2** — Laboratorio Wazuh | Wazuh **4.14.7** + agente · detección-only · **4 RS** (RS3/RS4 vacías) · baseline | ✔ | Lab, `active_ruleset.txt` |
| **Fase 2b** — Laboratorio Windows | VM `victima-windows` + Wazuh + Sysmon + baseline | ✔ | Segunda plataforma (B1) |
| **Fase 3** — Ataques y detección | **55 técnicas · 128 ventanas · 53 detectadas**; **P1-Linux cerrada** (`cobertura_p1_linux.csv`, 72 filas) | 🔶 P1-Linux cerrada | **El corpus YA es la medida "virgen"** |

> **Hallazgos que se conservan** (`R0 §1.2`): (1) el corpus actual **ya es virgen** (RS3 = RS4 =
> 0; `rule_level` + `rs_origen` en 160/160 `-Audited.csv`) ⇒ la rejilla *virgen × umbral × RS* es
> un **recorte determinista** (días, no semanas); (2) `rule_id 11` y `19010/19011` (SCA) son
> **FP del criterio congelado**, declarados; (3) el **baseline sintético** de pocas horas queda
> **(histórico)** — el **catálogo de ruido autoritativo** será el de las **72 h**.

---

## 4. Secuencia de bloques (marco nuevo) (`R0 §10.2`)

**Programa `reencuadre` (documentación, no toca el laboratorio):**

| # | Bloque | Qué hace | Depende de | Estado |
|---|---|---|---|---|
| R0 | `reencuadre` | Congela objetivo, alcance, métrica, tablas y secuencia. | — | ✔ |
| **R1** | **`reencuadre-docs`** | **Este bloque**: reescribe `context.md`/`requirements.md`/`roadmap.md`. | R0 | 🔶 |
| R2 | `reencuadre-metrica` | Congela métrica + plantillas T1–T5/Requisitos/Leyenda + scripts. | R0 | ⏳ |

**Medida VIRGEN de Wazuh (aprovecha lo hecho):**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| M1a | `virgen-wazuh-ataques` *(histórico)* | Recorte determinista de los 55 ATA por `rule_level`×`rs_origen` → T2/T4 (baseline **viejo**). | R2 |
| L0 | `legitimo-infra` | GHOSTS + "internet local"; **go/no-go**. | R2 |
| L1 | `legitimo-72h` | Captura legítima **72 h** + denominador. **Cuello de botella.** | L0 |
| M1b | `virgen-wazuh-ataques` *(re-ejecución)* | Re-corre el recorte con el **legítimo nuevo**. | L1, M1a |
| L2 | `legitimo-analisis` | T3/T4 (legítimo) → cierra T4 virgen. | L1, M1b |

**Velociraptor VIRGEN:** `V0 velociraptor-lab` · `V1 velociraptor-virgen`.

**Gate ¿reglas/artifacts propios? (contingente):** `W2 wazuh-propias` · `W3 wazuh-externas` ·
`V2 velociraptor-propias`.

**Windows (segunda plataforma):** `B1 fase-03b` (ataques Windows; continúa desde `ATA055`).

**Cierre:** `A1 analisis-final` (T5 + métricas + gráficas + comparativa VR↔Wazuh) · `A2 memoria`.

---

## 5. Camino crítico, paralelismo y cuello de botella (`R0 §10.3`, `§10.4`)

- **Camino crítico:** `R0 → R2 → L0 → L1 (72 h) → M1b → L2 → A1 → A2`.
- **Cuello de botella:** la **captura legítima de 72 h** (reloj de pared, **no acelerable**) ⇒
  **arrancarla cuanto antes** tras congelar (R2).
- **Paralelizable** (si el *tester* confirma que no se ensucia): M1a (recorte), V0/V1 y B1
  respecto a la captura.
- **Ventaja clave:** M1a/M1b son **recorte** (días → horas) porque el corpus ya está medido y
  etiquetado con `rule_level` + `rs_origen`.
- **Nota de orden (v2):** el recorte de ataques (M1a) **no depende** del legítimo, pero **el
  juicio del ruido y las métricas finales SÍ** ⇒ el recorte **se re-ejecuta** (M1b) con las 72 h,
  para que **todo se juzgue con el mismo legítimo**.

---

## 6. Orden de HIDS y plataformas (`R0 §10.3`, Q10/Q11)

**Orden fijado por el humano:** **Linux Wazuh → Windows Wazuh → Velociraptor (Linux y Windows)**.

- **No se mezclan HIDS**: un HIDS a la vez. Las **corridas de legítimo son POR SEPARADO** (un
  HIDS a la vez, **sin el otro instalado**), como en los TFGs hermanos.
- **Nunca** dos VMs pesadas encendidas a la vez (host de **16 GB**).

---

## 7. Hitos para el tutor (H0–H5) (`R0 §6`)

| Hito | Cuándo | Qué se le enseña |
|---|---|---|
| **H0** | Fase 0 ✔ | Planificación + arquitectura de agentes. |
| **H1** | Fase 1 ✔ | **Clasificación**: corpus P1 host-eligible + **Tabla 1** (equivalencia v17↔v19.1). |
| **H2** | Fase 2/2b ✔ | **Laboratorio** (Wazuh Linux **y** Windows) + **virgen** definido. |
| **H3** | nuevo | **Medida VIRGEN de Wazuh (Linux)**: ataques (**TPR**) + legítimo 72 h (**FPR**) → T2/T3/T4. |
| **H4** | nuevo | **Windows Wazuh** + **Velociraptor virgen** + **comparativa por técnica**. |
| **H5** | nuevo | **Memoria** y anexos. |

> El remapeo agrupa **H4** = Windows + Velociraptor (porque el orden es Linux Wazuh → Windows
> Wazuh → VR). Si el tutor prefiere separarlos → pasan a **H4/H5** y la memoria a **H6**
> *(se confirma con el profesor)*.

---

## 8. Riesgos y mitigaciones (`R0 §11.1`)

| Riesgo | Mitigación |
|---|---|
| **Unidad legítima mal definida** | Decidida (evento + complementos); validar con el tutor antes de congelar. |
| **Comparación entre HIDS** (unidades no homogéneas) | Unidad **común** (acción GHOSTS / hora) + **comparación por técnica**. |
| **GHOSTS no viable en el tiempo** | **Go/no-go** en L0; **plan B** (acciones reales por guion, declarado). |
| **72 h de reloj** | Arrancar pronto; paralelizar; **ampliable, no reducible**. |
| **`+propias`/`+custom` desboca el alcance** | **Contingente al gate**; acotado a P1. |
| **VR no es *rule-based*** | Unidad de VR definida; mapeo P1–P4↔nivel; comparación por técnica. |
| **Desfase v17↔v19.1** | Equivalencia + **3 discrepancias** declaradas. |
| **Congelar mal la config** | Bóveda de congelación + huella + repetición. |
| **Windows (2ª plataforma)** | Fase propia; nunca Linux y Windows a la vez (RAM). |
| **CRLF / cadena de huellas** | Deuda declarada; **no** `checkout`/`stash` sobre `esperado`/`Audited`. |
| **Fuga de secreto** | Regla dura: la contraseña del laboratorio **nunca** en ficheros del repo. |

---

## 9. Deuda y cabos pendientes (`state.md`, `R0 §11.1`)

- **Normalización de finales de línea + recálculo de huellas** (bloque futuro; un clon no
  reproduce las huellas por EOL mezclados).
- **Arreglo futuro del filtro**: `19010/19011` (SCA) y `rule_id 11` (mismo patrón; ya matizado).
- **Bloque de EVASIÓN** (versiones disfrazadas) — **trabajo futuro**, fuera de los bloques de
  cobertura.
- **Rotar la contraseña del laboratorio** (recomendado tras el incidente contenido de
  P1-cierre).
- **A confirmar con el tutor:** unidad legítima, hitos H3–H5, umbral de *pruning* (500/1000 vs
  escala propia) y el "tamaño/tiempos" (fleco 3).
