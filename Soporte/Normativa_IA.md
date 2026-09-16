# Normativa sobre el uso de IA en el TFG

> Nota de apoyo (no forma parte de la memoria). Recoge el marco vigente sobre el uso de
> herramientas de IA en Trabajos Fin de Estudios en la Universidad de Sevilla y cómo
> encaja la arquitectura de agentes de este TFG. **Fecha de la consulta: 2026-09.** Antes
> de entregar, re-verificar y consultar al tutor.

---

## 1. Resumen

Usar IA **no está prohibido**, pero **sí está regulado**. Lo esencial:

1. **El TFG es tuyo.** La IA es una herramienta, no un autor. Debes entender, revisar
   críticamente y asumir la responsabilidad de todo lo que produzca.
2. **Hay que declararlo** de forma explícita en la memoria (qué herramienta, para qué
   tareas y en qué medida contribuyó).
3. **No se pueden delegar los apartados sustantivos** (marco teórico, metodología,
   resultados, conclusiones) presentándolos como propios.
4. **Nunca generar citas/fuentes que no existan o no se hayan consultado.**
5. El uso deshonesto **se equipara al plagio** (falta grave o muy grave).

---

## 2. ETSI (tu centro)

- **Normativa de TFG de la ETSI (2022)**: no incluye una cláusula específica de IA. Se
  rige por la normativa general de la US. Exige TFG **original e individual**, con
  declaración firmada de originalidad, y evaluación por comisión (contenido técnico,
  presentación, discusión, otros méritos).
  - Fuente: `https://etsi.us.es/sites/default/files/2022-11/Normativa%20TFG%202022.pdf`
- **Acción**: conviene **preguntar al tutor / coordinación TFG** si existe criterio
  interno del centro/departamento (puede no estar publicado).

## 3. Universidad de Sevilla (marco general)

- **Normativa sobre TFE (BOUS 5/2017, art. 8.1)**: declaración explícita de originalidad;
  no usar fuentes sin citarlas. *"Presentar como propios resultados obtenidos con IA
  puede considerarse fraude académico."*
- **Reglamento de Régimen Disciplinario de los Estudiantes (BOUS 10/2022)**: el uso
  deshonesto de IA se equipara al plagio; sanciones que pueden llegar a expulsión
  temporal.
- **Decálogo de IA generativa de la US** y web `https://ia.us.es` (2026): uso ético
  (pensamiento crítico, protección de datos, conocer los riesgos) y **transparencia**.

## 4. Centros de la US con cláusula explícita (modelo a seguir)

La **Facultad de Comunicación (2025), art. 13** es el modelo más claro y se puede tomar
como referencia de lo que se admite y lo que no:

**Usos permitidos** — búsqueda preliminar de ideas; mejora de redacción/ortografía/estilo;
traducción de textos propios; **apoyo técnico en software, lenguajes de programación o
herramientas de análisis de datos, siempre que el estudiante comprenda, revise críticamente
y asuma la responsabilidad metodológica del procedimiento**.

**Usos prohibidos** — generar automáticamente apartados sustantivos (marco teórico,
metodología, resultados, conclusiones) y presentarlos como propios; fabricar o manipular
datos; parafrasear para evadir el antiplagio; **generar citas/referencias/fuentes
inexistentes o no consultadas**.

**Transparencia** — indicar en la memoria: qué herramientas, para qué tareas y en qué
medida contribuyeron.

## 5. Cómo encaja nuestra arquitectura de agentes

| Uso en el TFG | Encuadre |
|---|---|
| Scripts (corpus MITRE, análisis de alertas, tablas) | **Apoyo técnico en análisis de datos/programación** → permitido, si se comprende y valida |
| Orquestación de ataques y capturas repetitivas | Automatización de proceso experimental → permitido y declarable |
| `citation-protocol` (N1/N2, "nunca inventar una cita") | Protege justo contra la prohibición de citas falsas |
| Selección de técnicas, interpretación de resultados, conclusiones | **Decisión del alumno** (no delegable) |
| Redacción de la memoria | Borradores como apoyo; revisión, asunción y estilo propios |

## 6. Compromisos para este TFG

1. **Declaración de uso de IA** en el capítulo de Metodología (esquema del art. 13):
   herramientas, tareas, alcance y qué validó el alumno.
2. **Trazabilidad**: commits, `Bitacora/ATA<NNN>.json` y diffs como evidencia del proceso.
3. **Autoría de las decisiones**: selección de técnicas, análisis y conclusiones son del
   alumno.
4. **Citas verificadas**: toda afirmación crítica con fuente real y fragmento (N1/N2).
5. **Consultar al tutor** antes de dar por bueno el encuadre.

---

## 7. Fuentes consultadas

- Normativa TFG ETSI (2022): https://etsi.us.es/sites/default/files/2022-11/Normativa%20TFG%202022.pdf
- Normativa reguladora de los TFE US (BOUS 5/2017): https://www.etsii.us.es/docs/secretaria/normativa_trabajos_fin_estudios_2017.pdf
- Declaración de autoría/originalidad ETSII: https://www.dte.us.es/docencia/etsii/trabajo-fin-de-estudios/trabajo-fin-de-estudios
- Normativa TFG Facultad de Comunicación (2025, art. 13 - IA): https://fcom.us.es/sites/fcom/files/users/user-OrdenacionAcademica/NORMATIVA%20TFG%202025.pdf
- Guía de uso de IA en TFE, Filosofía US (2025): https://filosofia.us.es/sites/filosofia/files/contenido/estudiantes/TFE/Guia_Uso_IA_TFG_Filosofia%202025.pdf
- Web de IA de la Universidad de Sevilla: https://ia.us.es
