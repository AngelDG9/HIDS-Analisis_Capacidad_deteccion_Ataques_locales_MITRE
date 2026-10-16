# requirements.md — Requisitos y recursos del TFG

> **Versión:** v2 (reencuadre R1) · **Estado:** vigente · **Fecha:** 2026-10-16.
> Define **qué** hay que cumplir (**RF** funcional / **RNF** no funcional) y **con qué recursos**
> se cuenta. La **secuencia** (qué se hace y cuándo) vive en `roadmap.md` — **la unidad es el
> plan/bloque**, así que aquí **no** se duplican tareas ni flujos.
>
> **Anclas:** `(R0 §X.Y)` = `_fases/reencuadre/plan.md` (v2, 2026-10-16).

---

## 0. Convenciones

- **RF-NN** — requisito **funcional**. **RNF-NN** — requisito **no funcional**.
- **[AUTO]** lo hace el agente · **[HUMANO]** lo hace el alumno · **[MIXTO]** agente propone,
  alumno valida.
- **Gate:** ninguna tarea que edite/ejecute se hace sin el `plan.md` del bloque **aprobado por
  el humano**.
- *(histórico)* Los requisitos **R-01…R-14** del borrador quedan **subsumidos** aquí:
  R-02→RNF-01 · R-03/R-04→RF-01 · R-05→RF-03/RF-07 · R-06→(modo detección-only, ver §5) ·
  R-07→RF-02 · R-08/R-10→**(obsoleto**; sustituidos por RF-04/RF-05**) · R-11→RF-10 ·
  R-12/R-13→RF-02 · R-14→RNF-07. Las notaciones **R-/T-/F-** se conservan como referencia; las
  antiguas **tareas** (Bloque A–D) se han **plegado** a `roadmap.md`.

---

## 1. Recursos disponibles (estudio) (`R0 §1.1`, `§1.4`, `§1.5`)

| Fuente | Qué aporta | Qué se reaprovecha |
|---|---|---|
| **Guía y material del profesor** (`guia_profesor.txt`, `Detecciones Red (Ref).xlsx`, scripts de extracción MITRE) | Método de 4 pasos; filtro inverso; prioridad R/E/S; estructura de hojas | El **método** (vigente en lo esencial) y las **plantillas** de resultados |
| **Repo hermano NIDS** (Ignacio Merchán, **mismo tutor**, 2026) | Metodología de métricas y *pruning* | `GM = √(TPR·TNR)`; doble conteo *Raw* vs *Diff-Alerts/Flow*; **pipeline de *pruning*** = **nuestra T5**; `TOTAL_LEG_FLOWS = 78.694.206` |
| **Repo Snort-FG-PA** (estándar de facto) | Estructura de carpetas | `Hojas/` · `Dataset/{Ataques,Legitimo}` · `Soporte/` · `Estudio-<HIDS>/` · `BBDD/` |
| **TFMs hermanos** (Linares · Peña · Velociraptor) | Lecciones de FP/TP; perfiles de VR | Umbral↔FP (Linares); control benigno + doble conteo (Peña); **P1–P4, artifacts públicos vs custom, mapeo VR↔Wazuh** (VR) |
| **Lo nuestro** (repo) | Corpus, laboratorio y scripts ya construidos | Corpus P1-Linux (**55·128·53**), `Hojas/*.csv`, `Soporte/*`, `_artefactos/scripts/` |

---

## 2. Requisitos funcionales (RF) (`R0 §3.2`, `§4`, `§5`, `§7`, `§8`)

| ID | Requisito | Criterio de aceptación |
|---|---|---|
| **RF-01** | **Clasificar**: subconjunto **P1** host-eligible (filtro inverso v19.1) **espejado** con **Tabla 1 (v17)**, con equivalencia y **3 discrepancias** declaradas (`T1029`, `T1602.001/.002`, `T1567.003`). | Tabla 1 (diseño en `context.md`; **fichero en R2**) + `Hojas/corpus_host.csv`. |
| **RF-02** | **Ataques**: cada caso es un **"paquete equivalente a pcap"** (contexto + acciones + telemetría; **criterio ART**). | Carpeta por `ATA<NNN>` con guion + telemetría + `README`. |
| **RF-03** | **Detección Wazuh (virgen)**: medir por **caso** (TPR) y por **unidad legítima** (FPR). | T2/T4 virgen × umbral × RS. |
| **RF-04** | **Legítimo real**: **GHOSTS**, **72 h** (ampliable), **denominador instrumentado**. | T3 + `M` (nº de eventos legítimos). |
| **RF-05** | **Métricas**: TPR, FPR, TNR, Precisión, F1, GM, Usabilidad **por (HIDS × config × umbral)**. | T4 + bloque de fórmulas. |
| **RF-06** | ***Pruning* (T5)**: variantes 500/1000, Conservative, Generalized, Aggressive (G-Mean). | T5. |
| **RF-07** | **Velociraptor (virgen)** sobre el **mismo corpus** + **comparación con Wazuh por técnica**. | T2/T4 VR. |
| **RF-08** | **Windows** como **segunda plataforma** (misma técnica en otro SO = **otra fila / otro ATA**). | T2/T4 Windows. |
| **RF-09** | **Resultados** = **T1–T5 + Requisitos + Leyenda** (estructura del profesor). | Excels equivalentes. |
| **RF-10** | **Doble iteración** por ataque representativo; si difiere → `review`. | `ATA<NNN>_iter{1,2}` + aviso. |
| **RF-11** | **Memoria** siguiendo el esqueleto de los hermanos. | Memoria + anexos. |

---

## 3. Requisitos no funcionales (RNF) (`R0 §4.5`, `§6`, `§9`, `§10.1`)

| ID | Requisito |
|---|---|
| **RNF-01** | **Reproducibilidad determinista** + **huella `sha256`** por cifra. |
| **RNF-02** | **Métrica congelada antes de medir** (bóveda de congelación). |
| **RNF-03** | **"Virgen" definido y congelado** (versión de ruleset, telemetría, versión del HIDS, umbrales). |
| **RNF-04** | **Lab aislado + "internet local" declarada**; **sin secretos** en el repo. |
| **RNF-05** | **No mezclar HIDS ni plataformas**; corridas **por separado** (RAM 16 GB). |
| **RNF-06** | **Nada se descarta en silencio** (`dudosa`); cada desviación se **declara**. |
| **RNF-07** | **KISS + homogeneidad + reutilización** con los trabajos hermanos. |
| **RNF-08** | **Git local**; `push` = humano; `_recursos/` solo lectura. |

---

## 4. Matriz requisito ↔ bloque (`R0 §10.2`)

| Requisito | Bloque del `roadmap.md` |
|---|---|
| RF-01 / RNF-03 | R1 (diseño Tabla 1) → R2 (fichero) |
| RF-02 / RF-10 | M1a/M1b (ataques) · B1 (Windows) |
| RF-03 / RF-05 | M1a/M1b · L2 · A1 |
| RF-04 | L0 · L1 |
| RF-06 | A1 (T5) |
| RF-07 | V0 · V1 |
| RF-08 | B1 |
| RF-09 / RF-11 | R2 (plantillas) · A1 · A2 |
| RNF-01 / RNF-02 / RNF-06 | Transversal (todos los bloques) |
| RNF-04 / RNF-05 / RNF-08 | Transversal (laboratorio y repo) |

---

## 5. Fuera de alcance (`R0 §14`)

- **Tercer HIDS** (OSSEC/Sagan/Splunk/Samhain): fuera.
- **Snort / pcaps / análisis de red pura**: fuera (solo cita en el estado del arte).
- **Coste computacional**: fuera, salvo **experimento opcional declarado** (`R0 §14.1`).
- **InfoStealer** como exfiltración: fuera por ahora ("a decidir" a futuro).
- **Técnicas P2/P3**: fuera.
- **Modo bloqueo** del HIDS: fuera (**detección-only**).
- **Comparativa cuantitativa** con los TFGs hermanos: solo **cualitativa**.
- **`ait-aecid` / `kyoushi-environment` / FortiEDR**: fuera (solo cita / comercial).
