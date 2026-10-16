---
bloque: reencuadre-docs
nombre: Reescritura de los 3 documentos base del TFG (R1) con el marco nuevo aprobado
version: 1
status: approved_by_human
fecha: 2026-10-16
fecha_aprobacion: 2026-10-16
aprobado_por: humano
autor: tfg-planner
gate: |
  **APROBADO (2026-10-16).** Respuestas: Q1 reescribir conservando lo que vale → **SÍ** · Q2 glosario dentro de los docs → **SÍ** · Q3 Tabla 1 = diseño en R1, fichero en R2 → **SÍ** · Q4 roadmap = programa de bloques (híbrido) → **SÍ** · Q5 hitos H4 agrupa Windows+VR → **se confirma con el profesor** · Q6 README mínimo → **SÍ**.
---

# plan.md — Bloque `reencuadre-docs` (R1)

> **Qué es este documento.** El **plan** del bloque **R1**: **reescribir los 3 documentos base**
> (`context.md`, `requirements.md`, `roadmap.md`) para que reflejen el **marco nuevo aprobado** en
> `_fases/reencuadre/plan.md` (v2, `approved_by_human`, 2026-10-16).
>
> **Qué NO es.** No es la ejecución: **no se reescriben aún** los 3 documentos (eso es del bloque,
> una vez pasado el gate). Este plan **no toca** el laboratorio, ni el corpus, ni `_recursos/`, ni
> la métrica (eso es R2).
>
> **Fuente de verdad del marco:** `_fases/reencuadre/plan.md` (v2). Sus **§3** (objetivos), **§5**
> (tablas T1–T5), **§4** (métrica), **§10** (secuencia de bloques) y **§14** (fuera de alcance) son
> el texto de referencia. Este plan **no los reinterpreta: los traslada**.

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Contexto y anclaje](#1-contexto-y-anclaje)
2. [Objetivo y alcance del bloque](#2-objetivo-y-alcance-del-bloque)
3. [Estructura propuesta y contenido clave de cada documento](#3-estructura-propuesta-y-contenido-clave-de-cada-documento)
4. [Qué se conserva y qué cambia (antes → ahora)](#4-qué-se-conserva-y-qué-cambia-antes--ahora)
5. [Homogeneidad con los trabajos hermanos (y qué NO se copia)](#5-homogeneidad-con-los-trabajos-hermanos-y-qué-no-se-copia)
6. [Hitos del tutor (H0–H5) actualizados](#6-hitos-del-tutor-h0h5-actualizados)
7. [Trazabilidad](#7-trazabilidad)
8. [Riesgos y decisiones abiertas](#8-riesgos-y-decisiones-abiertas)
9. [Criterios de aceptación](#9-criterios-de-aceptación)
10. [Cómo se verifica](#10-cómo-se-verifica)
11. [Gate humano (lenguaje sencillo)](#11-gate-humano-lenguaje-sencillo)
12. [Qué NO entra (fuera de alcance)](#12-qué-no-entra-fuera-de-alcance)
13. [Ficheros que se tocarán](#13-ficheros-que-se-tocarán)
14. [Fuentes](#14-fuentes)

---

## 0. Resumen ejecutivo

El bloque `reencuadre` (R0) **congeló y aprobó el marco nuevo** del TFG. El bloque **R1** lo
**traslada a la documentación base**: reescribe **`context.md`** (de qué va el TFG), **`requirements.md`**
(requisitos y recursos) y **`roadmap.md`** (secuencia de bloques, hitos y riesgos).

**Cambio de fondo:** los 3 documentos actuales describen un trabajo **anterior** (Wazuh-only, "12-15
técnicas", métrica `η`, baseline de 2×4 h, tercer HIDS/Snort "si sobra tiempo"). El TFG vigente es
otro: **solo P1** (Impact/Exfiltration/Collection), **Wazuh + Velociraptor** en configuración
**"virgen"**, la parte legítima mide **FP**, y el resultado son **las 5 tablas del profesor (T1–T5) +
Requisitos + Leyenda**.

**Regla dura del marco (heredada de R0):** **nadie mide nada** hasta que la métrica y las tablas
estén **congeladas** (bloque `reencuadre-metrica`, R2). R1 **documenta**; R2 **congela**.

**Orden de trabajo que fija el humano (aprobado en R0, Q11):**
**Linux Wazuh → Windows Wazuh → Velociraptor (Linux y Windows)**; **sin mezclar HIDS**.

**Producto de R1:** los 3 documentos base reescritos (y, si se confirma, `README.md`). El ejecutor
**redacta**; el presente plan solo **define la estructura y los anclajes**.

---

## 1. Contexto y anclaje

### 1.1 Dónde estamos

- **`reencuadre` (R0): CERRADO** (2026-10-16). Plan v2, `reviews.md` y `change-doc.md` en
  **`_fases/reencuadre/`**. **11 decisiones del gate** aprobadas (`change-doc.md` §3).
- **`reencuadre-docs` (R1): este bloque.** Depende de R0. Antes de R2.
- **`reencuadre-metrica` (R2): después.** Congela métrica + `plantillas T1–T5 + Requisitos + Leyenda`
  + scripts deterministas.

### 1.2 Qué es "el marco nuevo" (en una tabla)

Tomado **literalmente** de `_fases/reencuadre/plan.md` §3.3 y §10:

| Tema | Marco VIGENTE (nuevo) | Ancla |
|---|---|---|
| Alcance | **Solo P1** (Impact / Exfiltration / Collection): **89 host-eligible** (72 Linux, 17 no-Linux) | §3.3, §3.2 O1 |
| HIDS | **Wazuh + Velociraptor**; fuera el tercer HIDS | §3.3 |
| Configuración | **Virgen primero** (sin reglas/artifacts propios); `+propias`/`+custom` = **gate posterior** | §3.3, §6 |
| Estructura | **Clasificación → Ataques → Análisis**, con **T1–T5 + Requisitos + Leyenda** | §3.2, §5 |
| Legítimo | **No es "línea base": es cuantificar el error** (FP/TN) con **acciones reales (GHOSTS)** y **72 h** | §3.2 O3, §7 |
| Métrica | **A dos planos** (ataque=caso→TPR; legítimo=unidad→FPR) + plano alerta (Precisión/F1/GM/Usabilidad) | §4 |
| Unidades | Titular = **evento**; comparación entre HIDS = **acción GHOSTS / hora** | §4.2, §4.6 |
| Internet | **Lab aislado + "internet local" simulada y declarada** (híbrida documentada) | §9 |
| Windows | **Segunda plataforma**, después de Linux | §3.3, §10.3 |
| Orden/HIDS | **Linux Wazuh → Windows Wazuh → Velociraptor**; **no mezclar HIDS** | §10.3 (Q10/Q11) |
| Fuera | Tercer HIDS · Snort/pcaps · coste CPU (opcional) · InfoStealer · P2/P3 | §14 |

> **Nota de orden (§10.4):** el **recorte de ataques** (`M1a`) se calcula pronto y **no depende del
> legítimo**; pero **el juicio del ruido y las métricas finales SÍ** dependen del **legítimo de 72 h**,
> así que los baselines actuales quedan **`histórico`** y el recorte **se re-ejecuta** (`M1b`).

---

## 2. Objetivo y alcance del bloque

### 2.1 Objetivo

**Reescribir `context.md`, `requirements.md` y `roadmap.md`** para que sean **fieles al marco
aprobado** en `_fases/reencuadre/plan.md` (v2), **homogéneos** con los trabajos hermanos y
**coherentes entre sí**. Deben quedar **congelables**: cualquier afirmación del marco viejo que ya
no vale, se **elimina** o se **declara obsoleta** (nunca se deja sin cualificar).

### 2.2 Alcance

**Entra:**
- Reescribir los **3 documentos base** con la estructura de §3 de este plan.
- **Limpiar las cifras y afirmaciones obsoletas** ("12-15 técnicas", "tercer HIDS", "Snort",
  "métrica η", baseline 2×4 h sin matiz) — el `state.md` ya lo dejó anotado como deuda.
- Incorporar el **glosario y la nomenclatura** nuevos (unidad legítima, "virgen", planos, GM/TPR/FPR,
  "paquete equivalente a pcap", GHOSTS, artifacts de VR…) **dentro de los documentos**.
- Dejar **referenciada** la **Tabla 1 (clasificación)** y la equivalencia v17↔v19.1 con sus 3
  discrepancias (el **fichero** de T1 se hará en R2; aquí solo se **documenta su diseño**, ver §8.1).
- Actualizar los **hitos H0–H5** al marco nuevo.

**No entra** (ver §12): reescribir la **métrica** (R2), crear los **excels T1–T5** (R2), tocar
laboratorio/corpus/`_recursos/`, medir, ni consolidar el "paquete pcap" (bloque posterior).

---

## 3. Estructura propuesta y contenido clave de cada documento

> **Contenido clave = el qué de cada sección; la redacción final la hace el ejecutor.** Cada
> sección lleva su **ancla** (fuente) entre paréntesis. Se marca **[CONSERVA]** lo que se mantiene
> del documento actual (aunque se edite), **[NUEVO]** lo que se añade y **[REESCRITO]** lo que cambia
> de fondo.

### 3.1 `context.md` — De qué va el TFG

| # | Sección | Contenido clave | Origen |
|---|---|---|---|
| 1 | **Qué es el TFG** | Título, tutor (D. F. J. Muñoz Calle, US/DIT), línea de investigación (red→host), **objetivo general nuevo (§3.1 del plan R0)** citado como redacción de referencia | §3.1 |
| 2 | **Objetivos específicos** | Tabla **O1–O8** (Clasificar · Ejecutar/caracterizar ataques · Medir el error en legítimo · Calcular métricas · Medir el pruning · Evaluar VR y comparar · Homogeneidad · Memoria) | §3.2 |
| 3 | **Alcance y marco** | Solo **P1**; **Wazuh + Velociraptor**; **virgen primero**; **Linux → Windows**; **qué NO entra** (tercer HIDS, Snort/pcaps, coste CPU opcional, InfoStealer, P2/P3, modo bloqueo) | §3.3, §14 |
| 4 | **Método (4 pasos del profesor, actualizados)** | 1º Clasificar (filtro inverso host ≡ NOT(Only Network Detection)); 2º Implementar ataques como **"paquete equivalente a pcap"** (contexto+acciones+telemetría; criterio ART); 3º Detectar con **Wazuh y VR** (virgen); 4º Analizar con **T1–T5** | §3.2, §5.2, §2.3 fleco 6 |
| 5 | **La métrica, en resumen** | A dos planos (ataque=caso→TPR; legítimo=unidad→FPR) + plano alerta; **remite a R2** para la congelación | §4 (resumen) |
| 6 | **Guía del profesor: vigente vs obsoleta** | Tabla "antes/ahora": vigentes el **filtro inverso host** y la **prioridad R/E/S**; obsoletos "12-15 técnicas", tercer HIDS, Snort/pcaps, `ait-aecid`, baseline corto | §3.4 |
| 7 | **Homogeneidad con los hermanos** | Reutilizar **T1–T5 + Requisitos + Leyenda**, nomenclatura y estructura de carpetas (ver §5 de este plan) | §3.2 O7, §1.4 |
| 8 | **Decisiones fijadas** | Tabla **actualizada** (ver §4): HIDS, alcance, config, legítimo, métrica, resultados, internet, orden, Git local | §3.3, change-doc §3 |
| 9 | **Glosario** | **[REESCRITO]** añade: *unidad de actividad legítima*, *plano ataque/legítimo/alerta*, *virgen*, *TPR/FPR/TNR/Precisión/F1/GM/Usabilidad*, *paquete equivalente a pcap*, *GHOSTS*, *artifact* (VR), *pruning*, *perfil P1–P4* | §4, §5, §7, §8 |
| 10 | **Recursos** | **[REESCRITO]** `_recursos/reuniones/03/` (material nuevo), `recursos_profesor/`, **repo hermano NIDS**, TFMs hermanos | §1.1, §1.4, §1.5 |
| 11 | **Referencias externas** | Matriz MITRE, STIX, docs de Velociraptor y Wazuh, ART, **GHOSTS**, repo NIDS hermano, repo Snort-FG-PA | §16 |

**Secciones del `context.md` actual:** 1 Qué es · 2 Método del profesor · 3 Decisiones fijadas ·
4 Glosario · 5 Recursos · 6 Referencias. **Se conserva** ese esqueleto y se **intercalan** las
secciones nuevas (objetivos específicos, alcance/marco, guía vigente/obsoleta, homogeneidad).

### 3.2 `requirements.md` — Requisitos y recursos

| # | Sección | Contenido clave | Origen |
|---|---|---|---|
| 0 | **Convenciones** | **[CONSERVA]** R-/T-/F-; se añaden **RF-** (funcional) y **RNF-** (no funcional) | — |
| 1 | **Recursos disponibles (estudio)** | Tabla por fuente: **(a)** guía y material del profesor (`guia_profesor.txt`, `Detecciones Red (Ref).xlsx`, scripts de extracción); **(b)** repo hermano **NIDS** (Ignacio Merchán, mismo tutor) — su *pruning* = nuestra T5; **(c)** repo **Snort-FG-PA** (estándar de facto: `BBDD/Dataset/Estudio/Soporte/Hojas`); **(d)** TFMs hermanos (**Linares**, **Peña**, **VR**); **(e)** **lo nuestro** (corpus, laboratorio, scripts, criterios). Para cada uno: **qué aporta** y **qué se reaprovecha** | §1.1, §1.4, §1.5 |
| 2 | **Requisitos funcionales (RF)** | Ver lista propuesta en §3.2.1 | §3.2, §4, §5, §7, §8 |
| 3 | **Requisitos no funcionales (RNF)** | Ver lista propuesta en §3.2.2 | §4.5, §6, §9, §10.1 |
| 4 | **Matriz requisito ↔ bloque** | Trazabilidad ligera RF/RNF → bloque del `roadmap.md` | §10.2 |
| 5 | **Fuera de alcance** | **[REESCRITO]** = §14 del plan R0 (tercer HIDS, Snort, coste CPU, InfoStealer, P2/P3, bloqueo, comparativa cuantitativa) | §14 |

> **Nota KISS:** las **tareas** (antiguo Bloque A–D de `requirements.md`) **se pliegan al
> `roadmap.md`** como **bloques** (la "unidad es el plan"). `requirements.md` se queda en
> **requisitos + recursos**; no duplica la secuencia. *(Decisión abierta D4, §8.)*

#### 3.2.1 Requisitos funcionales propuestos (RF)

| ID | Requisito | Ancla |
|---|---|---|
| RF-01 | **Clasificar**: subconjunto **P1** host-eligible (filtro inverso v19.1) **espejado** con **Tabla 1 (v17)**, con **equivalencia y 3 discrepancias declaradas** (`T1029`, `T1602.001/.002`, `T1567.003`) | §1.3, §3.2 O1, §5.1 |
| RF-02 | **Ataques**: cada caso es un **"paquete equivalente a pcap"** (contexto + acciones + telemetría; criterio ART) | §3.2 O2, §5.2 |
| RF-03 | **Detección Wazuh (virgen)**: medir por **caso** (TPR) y por **unidad legítima** (FPR) | §3.2 O3–O4, §4 |
| RF-04 | **Legítimo real**: **GHOSTS**, **72 h** (ampliable), **denominador instrumentado** | §3.2 O3, §7.2, §7.4 |
| RF-05 | **Métricas**: TPR, FPR, TNR, Precisión, F1, GM, Usabilidad **por (HIDS × config × umbral)** | §3.2 O4, §4.4 |
| RF-06 | **Pruning (T5)**: variantes 500/1000, Conservative, Generalized, Aggressive (G-Mean) | §3.2 O5, §5.5 |
| RF-07 | **Velociraptor (virgen)** sobre el **mismo corpus** + **comparación con Wazuh por técnica** | §3.2 O6, §8 |
| RF-08 | **Windows** como **segunda plataforma** (misma técnica en otro SO = **otra fila / otro ATA**) | §3.3, §10.2 (B1) |
| RF-09 | **Resultados** = **T1–T5 + Requisitos + Leyenda** (estructura del profesor) | §3.2 O7, §5 |
| RF-10 | **Doble iteración** por ataque representativo; si difiere → `review` | (métrica congelada existente) |
| RF-11 | **Memoria** siguiendo el esqueleto de los hermanos | §3.2 O8 |

#### 3.2.2 Requisitos no funcionales propuestos (RNF)

| ID | Requisito | Ancla |
|---|---|---|
| RNF-01 | **Reproducibilidad determinista** + **huella `sha256`** por cifra | §4.5.5, §10.1.6 |
| RNF-02 | **Métrica congelada antes de medir** (bóveda de congelación) | §6 |
| RNF-03 | **"Virgen" definido y congelado** (versión de ruleset, telemetría, versión de HIDS, umbrales) | §6 |
| RNF-04 | **Lab aislado + "internet local" declarada**; **sin secretos** en el repo | §9, regla dura |
| RNF-05 | **No mezclar HIDS ni plataformas**; corridas **por separado** (RAM 16 GB) | §10.3 (Q10/Q11) |
| RNF-06 | **Nada se descarta en silencio** (`dudosa`); cada desviación se **declara** | §4.5.4, §11.3 |
| RNF-07 | **KISS + homogeneidad + reutilización** con los hermanos | §3.2 O7, §1.4 |
| RNF-08 | **Git local**; `push` = humano; `_recursos/` solo lectura | regla vigente |

### 3.3 `roadmap.md` — Secuencia, hitos y riesgos

> El `roadmap.md` nuevo **no inventa**: traslada la secuencia aprobada de §10.2 del plan R0 y
> distingue **lo ya hecho (histórico)** de **lo nuevo**.

| # | Sección | Contenido clave | Origen |
|---|---|---|---|
| 1 | **Cómo leer este roadmap** | La **unidad es el plan/bloque**; se separa **`histórico`** (ya hecho) de **`nuevo`** (marco vigente) | §10.1, §10.4 |
| 2 | **Resumen ejecutivo** | Programa en 3 macro-fases (**Clasificación → Ataques → Análisis**) con estado por bloque | §3.2, §10 |
| 3 | **Trabajo hecho (histórico)** | Fases 0/1/2 ✔ · **corpus P1-Linux** (55 técnicas · 128 ventanas · 53 detectadas) ✔ · **lab Windows + baseline** ✔. Se marca qué se **reaprovecha** (corpus ya es la medida **virgen**; `rule_level`+`rs_origen`) | state.md, §1.2 |
| 4 | **Secuencia de bloques (marco nuevo)** | Tabla con **bloque · qué hace · depende de · estado** (ver §3.3.1) | §10.2 |
| 5 | **Camino crítico, paralelismo y cuello de botella** | Crítico: `R0→R2→L0→L1(72 h)→M1b→L2→A1→A2`; **cuello = legítimo 72 h** (reloj, no acelerable) | §10.3 |
| 6 | **Orden de HIDS y plataformas** | **Linux Wazuh → Windows Wazuh → Velociraptor**; **por separado**; nunca dos VMs pesadas a la vez | §10.3 (Q10/Q11) |
| 7 | **Hitos para el tutor (H0–H5)** | Ver §6 de este plan | §3.2, state.md |
| 8 | **Riesgos y mitigaciones** | Tabla de §11.1 (unidad legítima, comparación entre HIDS, GHOSTS go/no-go, 72 h, desbocarse con `+propias`, VR no-rule-based, desfase v17/v19.1, CRLF/huellas, fuga de secreto) | §11.1 |
| 9 | **Deuda y cabos pendientes** | Normalización de finales de línea + recálculo de huellas; arreglo futuro del filtro (`19010/19011`, SCA); bloque de **evasión** (futuro) | state.md, §11.1 |

**Secciones del `roadmap.md` actual:** Resumen ejecutivo · Fases 0–5 · Fases B (Windows) · Hitos ·
Riesgos. **Se conserva** el esqueleto de "resumen + hitos + riesgos", pero **la secuenciación pasa
de "6 fases" a "programa de bloques"** (decisión abierta D2, §8).

#### 3.3.1 Secuencia de bloques a trasladar (de §10.2)

**Programa `reencuadre` (documentación):**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| R0 | `reencuadre` ✔ | Congela el marco (hecho) | — |
| **R1** | **`reencuadre-docs`** | **Este bloque**: reescribe los 3 documentos | R0 |
| R2 | `reencuadre-metrica` | Congela métrica + plantillas T1–T5/Requisitos/Leyenda + scripts | R0 |

**Medida VIRGEN (aprovecha lo hecho):**

| # | Bloque | Qué hace | Depende de |
|---|---|---|---|
| M1a | `virgen-wazuh-ataques` (histórico) | Recorte determinista de los 55 ATA por `rule_level`×`rs_origen` → T2/T4 virgen (baseline **viejo**) | R2 |
| L0 | `legitimo-infra` | GHOSTS + "internet local"; go/no-go | R2 |
| L1 | `legitimo-72h` | Captura legítima **72 h** (Wazuh virgen) + denominador. **Cuello de botella** | L0 |
| M1b | `virgen-wazuh-ataques` (re-ejecución) | Re-corre el recorte con el **legítimo nuevo** | L1, M1a |
| L2 | `legitimo-analisis` | T3/T4 (legítimo) → cierra T4 virgen | L1, M1b |

**Velociraptor VIRGEN:** `V0 velociraptor-lab` · `V1 velociraptor-virgen`.

**Gate ¿propias?** (contingente): `W2 wazuh-propias` · `W3 wazuh-externas` · `V2 velociraptor-propias`.

**Windows:** `B1 fase-03b` (ataques Windows, continúa desde `ATA055`).

**Cierre:** `A1 analisis-final` (T5 + métricas + gráficas + comparativa VR↔Wazuh) · `A2 memoria`.

---

## 4. Qué se conserva y qué cambia (antes → ahora)

**Qué se CONSERVA** (sigue siendo válido y se reaprovecha):
- El **esqueleto** y el **tono** de los 3 documentos (contexto / requisitos / roadmap).
- La **nomenclatura base**: `ATA<NNN>`, `rule.id`, `RS1..RS4`, TP/FP, filtro inverso host, prioridad R/E/S.
- El **método del profesor** (4 pasos) — actualizado, no sustituido.
- La **arquitectura de agentes**, el **laboratorio** y el **corpus** ya medidos.
- El **principio "la unidad es el plan"** y los **gates humanos**.

**Qué CAMBIA** (tabla "antes → ahora"):

| Tema | Antes (docs actuales) | Ahora (marco nuevo) | Ancla |
|---|---|---|---|
| **Objetivo** | "capacidad de detección… mediante HIDS", Wazuh núcleo | Objetivo §3.1: **solo P1**, **Wazuh + VR virgen**, **TPR + FP**, Linux y Windows, tablas homogéneas | §3.1 |
| **Alcance de técnicas** | "**12-15 técnicas**", varias tácticas | **Solo P1**: 89 host-eligible (72 Linux, 17 no-Linux) | §3.3 |
| **HIDS** | Wazuh núcleo; VR y **un tercero** "si sobra" | **Wazuh + Velociraptor** (fuera el tercero) | §3.3 |
| **Velociraptor** | Extra | **Fase propia**; virgen primero; custom después (gate) | §8, §10.2 |
| **Reglas propias** | RS3 "crece en Fase 3" | **Eje de configuración** (virgen / +propias / +externas) | §3.3, §6 |
| **Legítimo** | "línea base", script sintético 2×4 h | **Medir FP**: GHOSTS + **72 h** + internet local; baseline actual = **`histórico`** | §7, §10.4 |
| **Métrica** | `η = √(CD·(1−FP))` | **Métrica del profesor a dos planos** (TPR/FPR/…/GM/Usabilidad) | §4 |
| **Resultados** | Tabla libre / `Detecciones.xlsx` | **T1–T5 + Requisitos + Leyenda** | §5 |
| **Clasificación** | `corpus_host.csv` (v19.1) | **+ Tabla 1 (v17)** como espejo; equivalencia y **3 discrepancias** | §1.3, §5.1 |
| **Umbral** | no explicitado | **`rule.level ≥ N` × RS × HIDS × SO** | §6 |
| **Snort / tercer HIDS** | extras / "si sobra" | **Fuera** (solo cita en el estado del arte) | §14 |
| **Coste computacional** | Fase 4 | **Fuera**, salvo **experimento opcional** declarado | §14 |
| **InfoStealer** | "¿exfiltración?" | **Fuera por ahora** ("a decidir") | §14 |
| **Internet** | no declarado | **Lab aislado + internet local declarada** | §9 |
| **Secuencia** | Fases 0–5 | **Programa de bloques** (R/M/L/V/B/A) | §10 |
| **Orden** | no definido | **Linux Wazuh → Windows Wazuh → VR**; no mezclar | §10.3 |
| **Corpus (cifra)** | 13 técnicas | **55 técnicas / 128 ventanas / 53 detectadas** | state.md |

> ⚠️ **Riesgo de "humo" (declarado):** en los documentos actuales hay **afirmaciones del marco
> viejo**. El ejecutor **no puede dejarlas sin cualificar**: o las **reescribe** al marco nuevo o las
> marca **`(histórico)`/`(obsoleto)`** explícitamente. CA5 (§9) lo verifica.

---

## 5. Homogeneidad con los trabajos hermanos (y qué NO se copia)

**Objetivo:** "si no se reaprovecha, dejar ficheros equivalentes en la misma línea" (nota del humano).
Lo que se **imita** (de `_recursos/reuniones/03/` y `recursos_profesor/`):

| Elemento | Se imita | Fuente |
|---|---|---|
| **Plantillas de resultados** | **T1–T5 + "Requisitos de estudios" + "Leyenda"** (misma cabecera y semántica; `SID`→`rule.id`, `pcapng`→`ATA<NNN>`) | Excel del profesor (§5) |
| **Estructura de carpetas** | `Hojas/` (BD) · `Dataset/{Ataques,Legitimo}` · `Soporte/` · `Estudio-<HIDS>/` · `BBDD/` | Repo Snort-FG-PA (§1.1) |
| **Nomenclatura** | `ATA<NNN>`, "paquete equivalente a pcap", TP/FP, "análisis manual" | notas del humano, §5.2 |
| **Método de métricas** | `GM = √(TPR·TNR)`, `Usabilidad = #Alertas_FP / #Alertas_TP`, doble conteo (*Raw* vs *Diff-Alerts/Flow*) | Repo NIDS hermano (§1.4) |
| **Referencias** | Citar **repo NIDS** (Ignacio Merchán, mismo tutor) y TFMs (**Linares**, **Peña**, **VR**) | §1.4, §1.5 |
| **Esqueleto de la memoria** | Introducción/Estado del arte → Base teórica → Ataques → Análisis → Resultados → Conclusiones → Anexos | §3.2 O8, roadmap actual |

**Qué NO se copia** (es del mundo NIDS o está superado):
- Columnas de **red**: flujos, pcaps, `SID`, `tranalyzer`, TCP_Replay/MTU, "Nº de mensajes de red".
- La clasificación **"solo-red"** se usa **como espejo** (es la vista del NIDS); la nuestra es **host**.
- El **tercer HIDS**, **Snort**, **FortiGate/PaloAlto**, `ait-aecid`/`kyoushi-environment` (solo cita).
- **Resultados ajenos**: se reutiliza la **metodología y las plantillas**, **nunca** los resultados.

---

## 6. Hitos del tutor (H0–H5) actualizados

> Propuesta de **remapeo** al marco nuevo (los hitos actuales son de las fases viejas). **[DECISIÓN
> ABIERTA D3, §8]** — se confirma con el tutor.

| Hito | Cuándo | Qué se le enseña |
|---|---|---|
| **H0** | Fase 0 ✔ | Planificación + arquitectura de agentes. |
| **H1** | Fase 1 ✔ | **Clasificación**: corpus P1 host-eligible + **Tabla 1** (equivalencia v17↔v19.1). |
| **H2** | Fase 2 / 2b ✔ | **Laboratorio** (Wazuh Linux **y** Windows) + **virgen** definido. |
| **H3** | nuevo | **Medida VIRGEN de Wazuh (Linux)**: ataques (**TPR**) + legítimo 72 h (**FPR**) → **T2/T3/T4**. |
| **H4** | nuevo | **Windows Wazuh** + **Velociraptor virgen** + **comparativa por técnica**. |
| **H5** | nuevo | **Memoria** y anexos (esqueleto de los hermanos). |

> **Relación con el orden aprobado:** H4 agrupa Windows y Velociraptor porque el humano fijó **Linux
> Wazuh → Windows Wazuh → Velociraptor**; si el tutor prefiere separarlos, se parte en H4/H5 y la
> memoria pasa a H6.

---

## 7. Trazabilidad

**Cada afirmación nueva de los 3 documentos se ancla** a una sección de `_fases/reencuadre/plan.md`
o a una fuente. Mapa documento → ancla:

| Documento · sección | Ancla principal |
|---|---|
| `context.md` §1 Objetivo general | §3.1 |
| `context.md` §2 Objetivos específicos | §3.2 |
| `context.md` §3 Alcance/fuera | §3.3, §14 |
| `context.md` §4 Método | §3.2, §5.2, §2.3 |
| `context.md` §5 Métrica (resumen) | §4 |
| `context.md` §6 Guía vigente/obsoleta | §3.4 |
| `context.md` §7 Homogeneidad | §1.4, §3.2 O7 |
| `context.md` §9 Glosario | §4.2, §5, §6, §7, §8 |
| `context.md` §10–11 Recursos/refs | §1.1, §1.4, §1.5, §16 |
| `requirements.md` §1 Recursos | §1.1, §1.4, §1.5 |
| `requirements.md` §2 RF | §3.2, §4, §5, §7, §8 |
| `requirements.md` §3 RNF | §4.5, §6, §9, §10.1 |
| `requirements.md` §5 Fuera de alcance | §14 |
| `roadmap.md` §3 Histórico | state.md, §1.2 |
| `roadmap.md` §4 Secuencia | §10.2 |
| `roadmap.md` §5 Camino crítico | §10.3 |
| `roadmap.md` §6 Orden | §10.3 (Q10/Q11) |
| `roadmap.md` §8 Riesgos | §11.1 |
| `roadmap.md` §9 Deuda | state.md, §11.1 |

**Regla de estilo:** donde el marco nuevo **hereda** una afirmación del plan R0, el documento puede
resumirla; donde la **cambia**, debe **decirlo** (no dejar la versión vieja implícita).

---

## 8. Riesgos y decisiones abiertas

### 8.1 Decisiones abiertas (para el orquestador / humano)

| # | Duda | Propuesta del planificador |
|---|---|---|
| **D1** | La línea de R1 en el plan R0 dice "…(+ glosario, nomenclatura, **Tabla 1**)". ¿R1 **produce** un glosario/nomenclatura aparte y el **fichero Tabla 1**, o solo los **referencia**? | **Glosario y nomenclatura DENTRO de los 3 documentos**; el **fichero Tabla 1 se hace en R2** (junto con T2–T5). R1 solo **documenta su diseño**. Confirmar. |
| **D2** | El `roadmap.md` nuevo, ¿mantiene la numeración "**Fase 0..5**" o pasa a "**programa de bloques**"? | **Híbrido**: conservar "Fase 0/1/2/2b" como **histórico** y usar **nombre de bloque** para lo nuevo (R1/R2/M…/L…/V…/B1/A…). |
| **D3** | ¿El remapeo de **hitos H0–H5** (§6) es el correcto, o se prefiere separar Windows y VR? | La §6 (H4 agrupa Windows+VR). Confirmar con el tutor. |
| **D4** | ¿Se **conserva la BBDD SQLite** (requisito antiguo R-T12) o se deja como **alternativa** a las hojas? | **Alternativa opcional** (como el `BBDD/` del hermano, "alternativo a Hojas"), no requisito del núcleo. |
| **D5** | ¿Se actualiza también **`README.md`**? | **Sí, mínimo** (objetivo y punteros a los 3 docs). Se lista en §13 como "candidato". |
| **D6** | Las **tareas** (antiguo Bloque A–D), ¿se mantienen en `requirements.md`? | **No**: se pliegan al `roadmap.md` como bloques (KISS, "la unidad es el plan"). |

### 8.2 Riesgos del bloque

| Riesgo | Mitigación |
|---|---|
| Dejar afirmaciones del marco viejo sin cualificar | CA5: búsqueda dirigida de términos prohibidos ("12-15", "tercer HIDS", "Snort", "η = √") |
| Incoherencia entre los 3 documentos | Revisión cruzada (context ↔ requirements ↔ roadmap); CA3 |
| Colar secretos | Auditoría de texto (CA8); la contraseña del lab **nunca** en ficheros |
| "Humo" al prometer lo que no depende de R1 | Trazabilidad (§7) + declarar lo que se difiere a R2 |
| Confundir R1 con R2 (reescribir la métrica) | §12 lo prohíbe explícitamente |

---

## 9. Criterios de aceptación

| # | Criterio | Cómo se comprueba |
|---|---|---|
| **CA1** | Los 3 documentos están **reescritos** con las secciones de §3, `status`/versión/fecha y son **coherentes con §3 del plan R0** | Revisión del fichero + coherencia cruzada |
| **CA2** | `context.md` declara el **objetivo nuevo** (solo P1 · Wazuh + VR · virgen · TPR + FP · Linux y Windows · tablas homogéneas) | Cita a §3.1 + lectura |
| **CA3** | `requirements.md` incluye **RF** y **RNF** + el **estudio de recursos** (hermanos, repos, guía) | §3.2 + listas RF/RNF |
| **CA4** | `roadmap.md` contiene la **secuencia de bloques aprobada** (§10.2) con **dependencias**, **cuello de botella** (L1 72 h) y el **orden del humano** (Linux Wazuh → Windows Wazuh → VR) | §3.3.1 + §10.3 |
| **CA5** | **No queda** ninguna afirmación del marco viejo sin cualificar ("12-15 técnicas", "tercer HIDS", "Snort", "η = √(CD·(1−FP))", "baseline 2×4 h" sin matiz) | `grep` dirigido sobre los 3 docs |
| **CA6** | **Homogeneidad**: se referencian **T1–T5 + Requisitos + Leyenda** y la nomenclatura; se declara **qué NO se copia** | §5 |
| **CA7** | **Trazabilidad**: cada afirmación nueva tiene ancla (§ del plan R0 o fuente) | §7 + muestreo |
| **CA8** | **Sin secretos** (contraseña del lab, claves) en los 3 documentos | Auditoría de texto |
| **CA9** | Los **hitos H0–H5** están actualizados al marco nuevo | §6 |
| **CA10** | **No** se toca `_recursos/`; **no** hay commit/push | `git status` + inspección |
| **CA11** | **`tfg-tester` = PASA** (o FALLA resuelta) | Informe del tester |
| **CA12** | La cifra **55 técnicas / 128 ventanas / 53 detectadas** sustituye a "12-15" donde proceda | state.md (nota "cifras desfasadas") |

---

## 10. Cómo se verifica

1. **Auto-revisión cruzada** de los 3 documentos (coherencia interna y entre sí) por el ejecutor.
2. **Chequeo determinista** (CA5, CA12): `grep`/búsqueda de términos prohibidos
   (`12-15`, `12–15`, `tercer HIDS`, `Snort`, `η`, `√(CD`, `2 ventanas`) sobre los 3 documentos;
   se espera **0** sin cualificar.
3. **Auditoría de secretos** (CA8): búsqueda de patrones de credenciales → **0**.
4. **`git status`** (CA10): solo los ficheros de §13 modificados; `_recursos/` intacto.
5. **Verificación `tfg-tester`** contra los **CA1–CA12** → **PASA** o **FALLA** (máx. 3 ciclos).

---

## 11. Gate humano (lenguaje sencillo)

> Preguntas para aprobar **este plan** antes de reescribir los documentos.

1. **¿Te vale que los 3 documentos se reescriban "de cero" con el marco nuevo** (solo P1, Wazuh +
   Velociraptor, virgen primero, legítimo = FP con GHOSTS 72 h, T1–T5), **sin dejarme nada del marco
   viejo sin marcar como obsoleto**?
2. **El glosario y la nomenclatura**, ¿los meto **dentro** de los 3 documentos (mi propuesta) o
   quieres un **fichero aparte**?
3. **La Tabla 1 (clasificación)**: ¿te vale que en **R1 solo documente su diseño** y que el **fichero
   de la tabla se haga en R2** junto con T2–T5 (mi propuesta), o la quieres ya en R1?
4. **El `roadmap.md`**: ¿te vale pasar de "Fase 0..5" a un **programa de bloques** (R/M/L/V/B/A),
   conservando las fases viejas como **histórico**?
5. **Los hitos H0–H5**: ¿te vale la propuesta de §6 (H4 agrupa Windows + Velociraptor), o prefieres
   separarlos?
6. **¿Actualizo también el `README.md`** (mínimo) o lo dejo fuera de este bloque?

---

## 12. Qué NO entra (fuera de alcance)

- **Reescribir la métrica** y **congelarla**: es **R2** (`reencuadre-metrica`). R1 solo la **resume**.
- **Crear los excels T1–T5 + Requisitos + Leyenda**: es **R2**.
- **Consolidar el "paquete equivalente a pcap"** por ataque: bloque posterior.
- **Tocar** el laboratorio, el corpus, los scripts o **`_recursos/`** (solo lectura).
- **Medir nada** (ni ataques, ni legítimo).
- **InfoStealer**, **P2/P3**, **tercer HIDS**, **Snort**, **coste computacional** (opcional declarado).
- **Commit / push** (el `push` es del humano).

---

## 13. Ficheros que se tocarán

**Se reescriben (núcleo de R1):**
- `context.md`
- `requirements.md`
- `roadmap.md`

**Candidato (decisión D5):**
- `README.md` (objetivo y punteros; cambio mínimo).

**Producto de este bloque (R1):**
- `plan.md` (este fichero, en la raíz durante el bloque; se archiva al cerrar en `_fases/reencuadre-docs/`).

**No se toca:**
- `_recursos/` (solo lectura), `state.md` (lo mantiene el orquestador),
  `_fases/reencuadre/plan.md` (ya archivado como fuente de verdad).

---

## 14. Fuentes

- **Marco aprobado:** `_fases/reencuadre/plan.md` (v2, `approved_by_human`) §1.2, §3, §4, §5, §7,
  §8, §9, §10, §11, §14, §16. · `_fases/reencuadre/change-doc.md` §3 (11 decisiones del gate).
  · `_fases/reencuadre/reviews.md` (v1 + v2).
- **Estado vivo:** `state.md` (nota "cifras desfasadas", resumen del reencuadre).
- **Documentos a reescribir:** `context.md`, `requirements.md`, `roadmap.md` (versión actual).
- **Guía y material del profesor:** `_recursos/reuniones/02/guia_profesor.txt`;
  `_recursos/reuniones/03/` (`notas reunion TFG.txt`, `ghost.txt`, `Tabla 1 …v17.xlsx`,
  `Tablas 2, 3, 4, 5 (con FG-PA).xlsx`, TFMs).
- **Hermanos:** `recursos_profesor/repos-similares/Snort-FG-PA-…/README.md` (+ `Hojas/`, `Dataset/`,
  `Soporte/`, `BBDD/`); repo NIDS `ignmercam/mitre-attack-ids-detection-optimization`.

> **Regla dura recordada:** la **contraseña del laboratorio nunca** en ficheros del repo (público).
