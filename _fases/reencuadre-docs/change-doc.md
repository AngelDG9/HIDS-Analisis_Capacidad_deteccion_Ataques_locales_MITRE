# change-doc — Bloque `reencuadre-docs` (R1): reescritura de los 3 documentos base

> Cierre. Fecha: **2026-10-16**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA**
> (4 salvedades de forma: **2 corregidas**, **2 declaradas**).
> Plan de referencia: `plan.md` (raíz, `status: approved_by_human`, aprobado por el humano el 2026-10-16).
> **Bloque de DOCUMENTACIÓN**: reescribe los documentos base. **No** toca laboratorio, corpus, scripts ni `_recursos/`.

---

## 1. Objetivo

**Reescribir los 3 documentos base** (`context.md`, `requirements.md`, `roadmap.md`) — y una edición
**mínima** del `README.md` — para que reflejen el **marco nuevo aprobado** en `_fases/reencuadre/plan.md` (v2).

---

## 2. Resultado

| Fichero | Líneas | Qué contiene ahora |
|---|---|---|
| **`context.md`** | 267 | De qué va el TFG: objetivo nuevo (§3.1 del plan R0), **O1–O8**, alcance y marco (solo P1 · Wazuh+VR · virgen · Linux→Windows), método 4 pasos, métrica resumida, **guía vigente vs obsoleta**, homogeneidad, decisiones fijadas, **glosario ampliado**, recursos, referencias |
| **`requirements.md`** | 98 | Convenciones; **estudio de recursos** (guía, repo NIDS hermano, repo Snort-FG-PA, TFMs, lo nuestro); **RF-01…RF-11**; **RNF-01…RNF-08**; matriz requisito↔bloque; fuera de alcance |
| **`roadmap.md`** | 159 | Programa de **bloques** (R/M/L/V/B/A) con dependencias; **trabajo hecho `(histórico)`**; camino crítico y **cuello de botella L1 (72 h)**; **orden Linux Wazuh → Windows Wazuh → Velociraptor**; hitos **H0–H5**; riesgos; deuda |
| **`README.md`** | 89 | Edición mínima: objetivo nuevo + punteros a los 3 documentos |

Los 3 documentos llevan cabecera `Versión: v2 (reencuadre R1) · Estado: vigente · Fecha: 2026-10-16`.

---

## 3. Qué se conservó / qué cambió

- **Se conserva**: esqueleto, tono, nomenclatura base (`ATA<NNN>`, `rule.id`, RS1..RS4, filtro inverso
  host, prioridad R/E/S), el **método del profesor** (4 pasos, actualizado) y el principio "la unidad es el plan".
- **Cambia**: objetivo y alcance (**solo P1**, **Wazuh + VR virgen**), **métrica** (η → métrica del
  profesor a dos planos), **legítimo** (baseline 2×4 h → **FP con GHOSTS + 72 h**; el baseline pasa a
  `histórico`), **resultados** (tabla libre → **T1–T5 + Requisitos + Leyenda**), **secuenciación**
  (Fases 0–5 → **programa de bloques**), **orden de HIDS** y **cifras** (13 → **55 técnicas / 128 ventanas / 53 detectadas**).
- **Lo viejo** (tercer HIDS, Snort/pcaps, `ait-aecid`, baseline sintético, "12-15") queda
  **`(histórico)`/`(obsoleto)`** o **fuera de alcance** — nunca suelto.

---

## 4. Verificación (`tfg-tester`) — **PASA**

| CA | Resultado |
|---|---|
| CA1 (reescritos + secciones + coherencia con R0) | ✅ |
| CA2 (objetivo nuevo en `context.md`) | ✅ |
| CA3 (RF + RNF + estudio de recursos) | ✅ |
| CA4 (secuencia + cuello de botella + orden) | ✅ |
| **CA5** (0 afirmaciones del marco viejo **sin cualificar**) | ✅ *(los `Snort`/`tercer HIDS` que aparecen están cualificados: fuera de alcance, tabla de obsoletos, nombre del repo hermano)* |
| CA6 (homogeneidad + qué NO se copia) | ✅ |
| CA7 (trazabilidad) | ✅ *(anclas a nivel de sección)* |
| CA8 (sin secretos) | ✅ 0 reales |
| CA9 (hitos H0–H5; H4 = Windows+VR, a confirmar con el profesor) | ✅ |
| CA10 (`_recursos/` intacto; sin commit) | ✅ |
| CA11 (informe del tester) | ✅ |
| CA12 (cifras 55/128/53) | ✅ |

**Coherencia cruzada** entre los 3 documentos: verificada, sin contradicciones.

---

## 5. Salvedades

- **D2 (corregida)**: el `README.md` citaba "en Fase 3" (nomenclatura antigua) → sustituido.
- **D3 (corregida)**: `context.md` atribuía a la guía la cita "unas pocas técnicas, 1-2 por táctica" (no literal) → reformulado como "la guía no fija cifra".
- **D1 (resuelta en el cierre)**: `plan.md` y `reviews.md` vivían en la raíz (artefactos del bloque) → **archivados** en `_fases/reencuadre-docs/`.
- **D4 (declarada)**: las anclas de RF/RNF y de la secuencia son **a nivel de sección** (no columna por fila); CA7 satisfecho.

---

## 6. Siguiente

1. **`reencuadre-metrica` (R2)**: **congelar** la métrica + crear las **plantillas T1–T5 + Requisitos + Leyenda** (excels equivalentes) + los **scripts de conteo deterministas**. *(Nadie mide nada hasta que R2 cierre.)*
2. Después: **`legitimo-infra` (L0)** → **`legitimo-72h` (L1, el cuello de botella)** → … y el recorte de ataques en paralelo.
3. **`push`**: los commits son **locales**; publicar es del humano.
