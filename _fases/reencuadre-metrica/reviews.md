# reviews.md — Ataque del plan (bloque `reencuadre-metrica`, R2)

> Revisión del **orquestador** sobre `plan.md` (v1, 913 líneas). Fecha: **2026-10-16**.
> El humano pidió **máximo rigor** (es el bloque que fija la regla de medición de TODO el TFG).
> **Veredicto: APROBABLE** — sin notas bloqueantes.

---

## 1. Comprobaciones
- **Sin secretos** (0) ✅ · **`git status`**: solo `plan.md` (untracked) ✅ · `_recursos/` y material protegido intactos ✅.
- **Las 7 fórmulas** coinciden con lo que verifiqué yo mismo en el Excel del profesor (`T4 (Rend)`): `TPR = TP/N`, `FPR = FP/M`, `TNR = 1−FPR`, `GM = √(TPR·(1−FPR))`, `Usabilidad = A_FP/A_TP` ✅. Y el plan **cita la celda** (`B14`, `B15`, `B16`, `B17`…) y **copia literal** el código del repo hermano (`gm = math.sqrt(tpr*tnr)`, `usab = a_fp/a_tp`) ✅.
- **Coherencia con R0** (§4 métrica, §5 tablas, §6 dimensiones, §10.4 orden) ✅.

## 2. Fortalezas (rigor)
- **Las 3 unidades y sus denominadores** fijados; el **denominador del legítimo (`M`)** queda **instrumentado** (`logall_json`) con **fallback declarado** y **disparador explícito** (si `archives.json` > ~5 GB en L1).
- **Honestidad metodológica**: declara que **FPR-por-evento NO es comparable entre HIDS** y fija la **unidad común** (acción GHOSTS / hora) + comparación **por técnica**.
- **Doble conteo** (D2) definido **uniformemente** (`#Alertas` vs `#rule.id` distintos; versión correlacionada `^c`).
- **Ventana canónica** (D3) resuelta (`_rev1` si está en `repeticiones.csv`, si no `iter1`) → cierra la ambigüedad "55 casos vs 128 ventanas".
- **11 casos límite congelados** (L1–L11): nivel 0, auto-ruido, doble uso, `dudosa`, ataque sin alerta, `RS2`, `C2/C3` vacías, `logall_json` no instrumentado…
- **Qué invalida una medida** (5 disparadores) + cabecera obligatoria con `metrica_version`/`boveda_version`/`sha256` de entradas.
- **Prueba de humo potente**: `C1 × N=0` debe reproducir **53/55** — ata la métrica nueva al resultado ya conocido.
- **Scripts**: módulo congelado de fórmulas + uno por tabla; **CSV = fuente de verdad**, `.xlsx` = export reproducible; `pytest` + determinismo.

## 3. Notas
1. **Tamaño**: 913 líneas es grande, pero es **proporcional** a lo que se juega este bloque (la regla de todo el TFG). **No se recorta.**
2. **Lo que R2 NO puede cerrar** (y lo declara): el **número `M`** (llega en L1), la **unidad de VR** (llega en V0) y **`C2/C3`** (contingentes al gate). Correcto.
3. **Decisiones que van al tutor** (§9.2): confirmar la unidad; el umbral del pruning; el fleco "tamaño/tiempos"; la rejilla de umbrales. No bloquean.

## 4. Recomendación
**Aprobar** y contestar el gate (§11, 7 preguntas). El ejecutor creará: `Soporte/Metrica/metrica_hids.md` (+ `boveda_congelacion.md`), las **plantillas** (CSV + Excel), los **scripts** y sus **tests**; después, verificación del *tester* (CA-R2-01…14) y cierre.
