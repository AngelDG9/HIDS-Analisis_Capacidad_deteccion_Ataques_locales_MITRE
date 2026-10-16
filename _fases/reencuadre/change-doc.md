# change-doc — Bloque `reencuadre`: redefinición del TFG tras la 2ª reunión

> Cierre. Fecha: **2026-10-16**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA**
> (4 salvedades de redacción: **2 corregidas** en el plan, **2 declaradas**).
> Plan de referencia: `plan.md` (v2, `status: approved_by_human`; aprobado por el humano el 2026-10-16).
> **Bloque de DISEÑO**: su producto es el plan. **No** toca el laboratorio, ni el corpus, ni `_recursos/`.

---

## 1. Objetivo

**Reencuadrar el TFG** tras la 2ª reunión con el profesor (2026-10-16): fijar el **nuevo marco**
(objetivo, alcance, métrica, estructura de tablas, dimensiones de medida, plan del legítimo, plan de
Velociraptor y **secuencia de bloques**) de forma **congelable y defendible**.

---

## 2. Qué se ha producido

| Fichero | Qué |
|---|---|
| **`plan.md`** (v2, 1071 líneas, **aprobado**) | El marco completo: §3 objetivos, §4 métrica, §5 tablas T1–T5, §6 dimensiones, §7 legítimo, §8 Velociraptor, §9 internet, §10 secuencia, §11 riesgos, §12 CA, §13 gate |
| **`reviews.md`** | Revisión del orquestador (v1 + v2) + "ataque del plan" |

---

## 3. Decisiones del gate (aprobadas por el humano, 2026-10-16)

| # | Decisión |
|---|---|
| Q1 | **Marco**: solo P1 · Wazuh + Velociraptor · virgen primero · T1–T5 → **SÍ** |
| Q2 | **Unidad**: **evento** (titular) + **acción/hora** (comparación entre HIDS) → **SÍ** |
| Q3 | **Reglas/artifacts propios**: virgen completo primero; **decidir después** → **SÍ** |
| Q4 | **GHOSTS + 72 h** (+ plan B si GHOSTS no sale) → **SÍ** |
| Q5 | **Internet**: laboratorio aislado + internet local (alternativa híbrida documentada) → **SÍ** |
| Q6 | **Windows**: **después de Linux**, paso a paso |
| Q7 | **InfoStealer**: fuera por ahora ("a decidir") |
| Q8 | **Tabla 1 (v17)** como clasificación oficial + declarar las 3 diferencias → **SÍ** |
| Q9 | **Orden**: legítimo 72 h primero; recorte re-ejecutado (M1b) antes de las métricas → **SÍ** |
| **Q10** | **Corridas de legítimo POR SEPARADO** (un HIDS a la vez, sin el otro instalado) — como los TFGs hermanos |
| **Q11** | **Orden de bloques**: **Linux Wazuh → Windows Wazuh → Velociraptor (Linux y Windows)**; no mezclar HIDS |

---

## 4. El nuevo marco (resumen)

1. **Solo P1** (Impact / Exfiltration / Collection).
2. **Wazuh + Velociraptor**, **"de fábrica" (virgen)** primero; `+propias`/`+custom` después (gate).
3. **Estructura del profesor**: Clasificación → Ataques → Análisis, con **T1–T5 + Requisitos + Leyenda**.
4. **La parte legítima cambia de objetivo**: no es "línea base" → **cuantificar el error** (FP/TN) con
   **acciones reales (GHOSTS)** y **72 h**.
5. **Métrica a dos planos** (ataque = caso → TPR; legítimo = unidad → FPR) + plano alerta
   (Precisión, F1, GM, Usabilidad) — **la del profesor**, adoptada por comparabilidad.
6. **Dimensiones**: HIDS × configuración (virgen/+propias) × umbral (`rule.level ≥ N` / perfiles VR) × plataforma.
7. **Internet**: aislado + simulado + declarado.

---

## 5. Verificación (`tfg-tester`) — **PASA**

| CA | Resultado |
|---|---|
| CA-R1 (secciones + `approved_by_human`) | ✅ |
| CA-R2 (55 ATA tocan P1) | ✅ *(con matiz: ATA055 y ATA035 incluyen Credential Access — declarado)* |
| CA-R3 (RS3=RS4=0; `-Audited.csv` con `rule_level`+`rs_origen`) | ✅ **160/160** |
| CA-R9 (equivalencia Tabla 1 v17 ↔ corpus v19.1 + 3 discrepancias) | ✅ **38 vs 39 = T1029**; hallazgo sostenido: **T1029 y T1567.003 medidos y detectados** |
| CA-R10 (repo hermano) | ✅ `TOTAL_LEG_FLOWS=78.694.206`, `GM=√(TPR·TNR)`, variantes de pruning |
| CA-R8 (sin secretos) | ✅ 0 credenciales |
| Coherencia interna + higiene | ✅ citas resuelven; `git status` solo `plan.md`/`reviews.md` |

**Salvedades (ninguna bloquea):**
- **D1** (corregida): CA-R2 decía que `ATA035 = Collection; Credential Access`; el CSV trae `Collection` (el hecho subyacente sí es cierto: T1056.004 ∈ Collection + Credential Access).
- **D2** (corregida): el padre `T1602` es `solo_red` **también** en v19.1 ⇒ **sin discrepancia** (solo `.001`/`.002`).
- **D3** (declarada): el etiquetado "discrepancia" de `T1602.001/.002` vs "coherente" de `T1557.004` (mismo patrón) es discutible, no un error de datos.
- **D4** (declarada): §1.1 situaba `rulesets_diseno.md`/`politica_filtrado_ruido.md` en `Soporte/Wazuh/`; la ruta real es `Soporte/Wazuh/Configuracion/` (correcta en §16).

---

## 6. Hallazgos clave del bloque (los que cambian el TFG)

1. **El corpus actual YA es la medida "virgen" de Wazuh**: RS3 = RS4 = 0 y **160/160** `-Audited.csv`
   traen `rule_level` + `rs_origen` ⇒ toda la rejilla *virgen × umbral × RS* es un **recorte
   determinista** (días, no semanas).
2. **Tabla 1 (v17) ↔ corpus (v19.1)**: equivalencia buena (**38 vs 39**, única diferencia `T1029`);
   **`T1029` (ATA021) y `T1567.003` (ATA050) se midieron y se detectaron** ⇒ la tabla antigua se
   quedaba corta → **hallazgo a favor**, declarado (no oculto).
3. **Repo hermano** (Ignacio Merchán Cámara, **mismo tutor**, US/ETSI 2026): confirma el método
   (`TOTAL_LEG_FLOWS = 78.694.206`; `GM = √(TPR·TNR)`; TPR por pcap / TNR por flujo; doble métrica
   *Raw vs Diff-Alerts/Flow*) y su **pipeline de pruning** = **nuestra Tabla 5**.
4. **TFM de Linares**: también simulaba **internet en local** (INetSim) ⇒ **valida** nuestra decisión
   del laboratorio aislado.
5. **Guía del profesor desactualizada** en 5 puntos (tercer HIDS, Snort/pcaps, `ait-aecid`, nº de
   técnicas, baseline corto) ⇒ reflejado con tabla "antes/ahora".

---

## 7. Siguiente

1. **`reencuadre-docs` (R1)**: reescribir `context.md` / `requirements.md` / `roadmap.md` con los
   objetivos nuevos (§3 del plan) y la **secuencia de bloques aprobada**.
2. Después **`reencuadre-metrica` (R2)** → congelar métrica + plantillas de tablas + scripts.
3. Después las **mediciones** (recorte de ataques + 72 h de legítimo por separado) y **Velociraptor**.
4. **`push`**: los commits son **locales**; publicar es del humano.
