# reviews.md — Ataque del plan (bloque `reencuadre-docs`, R1)

> Revisión del **orquestador** sobre `plan.md` (v1, 483 líneas). Fecha: **2026-10-16**.
> **Veredicto: APROBABLE** — con 1 matiz de redacción y 6 decisiones abiertas (D1–D6) con propuesta.

---

## 1. Comprobaciones
- **Sin secretos** en `plan.md` (0 apariciones) ✅ · **`git status`**: solo `plan.md` (untracked) ✅ · `_recursos/` intacto ✅.
- **Anclaje correcto** al marco aprobado: cita `_fases/reencuadre/plan.md` §3/§4/§5/§10/§14 y las **11 decisiones** del `change-doc` ✅.
- **Coherencia con el orden del humano** (Q11): *Linux Wazuh → Windows Wazuh → Velociraptor* y **corridas por separado** ✅ (aparece en §1.2, §3.3, §6, §11).

## 2. Fortalezas
- **Estructura clara** de los 3 documentos, con **contenido clave + ancla** por sección, marcando **[CONSERVA]/[NUEVO]/[REESCRITO]**.
- **Tabla "antes → ahora"** muy completa (18 puntos) → evita el "humo" del marco viejo.
- **RF-01…RF-11** y **RNF-01…RNF-08** propuestos, con matriz requisito↔bloque.
- **Homogeneidad** explícita con los hermanos **y qué NO se copia** (resultados ajenos, columnas de red).
- **CA1–CA12** verificables + **verificación determinista** (grep de términos prohibidos: `12-15`, `tercer HIDS`, `Snort`, `η`, …).
- **Trazabilidad** documento→ancla.

## 3. Notas
1. **Redacción del gate Q1**: el plan dice reescribir "de cero", pero en §4 deja claro que **se conserva el esqueleto y el tono**. → Al presentarlo, aclarar: **"reescribir conservando lo que vale"** (no borrar y empezar).
2. **D1–D6**: las propuestas del planificador son sensatas (glosario dentro de los docs; Tabla 1 = diseño en R1 y fichero en R2; roadmap híbrido; hitos H4=Windows+VR **a confirmar con el tutor**; SQLite opcional; README mínimo; tareas plegadas al roadmap).
3. **Pendiente externo**: la confirmación del **remapeo de hitos** (D3) es del **tutor**, no bloquea el bloque.

## 4. Recomendación
**Aprobar** y contestar el gate (§11, 6 preguntas). El ejecutor reescribirá los 3 documentos; después, verificación del *tester* (CA1–CA12) y cierre.
