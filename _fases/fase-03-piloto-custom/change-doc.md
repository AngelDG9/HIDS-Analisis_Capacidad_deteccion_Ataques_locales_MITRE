# change-doc — Bloque `fase-03-piloto-custom`: segundo piloto (camino "ataque escrito por nosotros")

> Cierre del bloque. Fecha: **2026-09-26**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**, con **2
> no-conformidades de DISEÑO** documentadas: `CA13` y el **ancla de H4**).
> Plan de referencia: `plan.md` (v1, `status: approved_by_human`; los 3 `esperado` validados por el humano).

---

## 1. Qué se ha hecho

1. **Los 2 arreglos previos** (cabos del afinado): el **default de `--out`/`--rev-out`** de `filtrar_ruido.py`
   ya usa la convención por SO (`…/Wazuh/linux/Auditado`) — con **2 tests nuevos** — y el **puntero** en el
   runbook §6.
2. **Las capturas C0 por técnica** (paso nuevo): las 3 dan **`80792` (level 3) → NO avisan** (ninguna detección
   silenciada por el ruleset base).
3. **Los 3 ataques × 2 iteraciones (6 ventanas)** — el **camino "ataque escrito por nosotros"** por primera vez:
   **ATA007/T1491** (manual), **ATA012/T1119** (manual) y **ATA004/T1489** (control de ART).

---

## 2. 🎯 Resultados (los 3 ataques **se detectan**)

| ATA | Técnica | Detecciones (alertas) | `rule_id` distintos | Genuinas / Ajenas | Veredicto v2 |
|---|---|---|---|---|---|
| **ATA007** | T1491 Defacement (manual) | 4 · 4 | **3** `{80781,80790,80792}` | **4 / 0** | `iguales` |
| **ATA012** | T1119 Automated Collection (manual) | 11 · 11 | **2** `{80790,80792}` | **7 / 4** · **8 / 3** | `iguales` |
| **ATA004** | T1489 Service Stop (ART) | 5 · 5 | **1** `{80792}` | **3 / 2** | `iguales` |

- **Conclusión sólida: el camino manual es detectable.** Los 3 se detectan por **`execve` genuino** con el
  ruleset **de fábrica**.
- **Cifra limpia por ataque = 1 evento** (`80792`, el `execve`). El resto es **redundancia** (el mismo evento
  visto por varias reglas) o **ruido ajeno**.
- **Desglose esperadas/sorpresas: `esperadas N` · `sorpresas 0`** (ninguna `novel`) en las 6 ventanas.

---

## 3. ⭐ Los 3 hallazgos (y son importantes para el escalado)

### H-A. **El ancla de H4 NO funciona** (fallo de diseño, no un bug del patrón)
- El patrón `…/lab-attack/ATA<NNN>/*` **no casa** el `audit_cwd` real (que va **sin barra final**) → **0
  coincidencias** en las 6 ventanas.
- **Más grave (verificado por el tester):** **aunque se corrija el patrón, H4 no puede anclar**, porque el filtro
  evalúa las señales como **OR independientes**, no como `exe AND cwd`. *(Contrafactual con el patrón corregido:
  ATA004 pasó de 5 a 11 detecciones — excluyó las 2 ajenas pero **promovió todo el churn de la carpeta**.)*
- **Consecuencia:** la convención de `plantilla_esperado.md` es **aspiracional**, no un mecanismo. **Hay que
  rediseñarla** (o dar al filtro señales **ancladas** con semántica AND).

### H-B. **Las señales por proceso (`audit_exe`) son anchas y cuentan alertas AJENAS**
- La señal `audit_exe=cp/find/systemctl` captura **todo** lo que ese proceso haga:
  - **ATA012:** 3-4 `find` de **`update-motd.d`** (`cwd=/`) disparados por **el login del operador** → contados
    como detección. *(Genuinas: 7-8.)*
  - **ATA004:** 2 `systemctl --user` del **cierre de sesión** del operador. *(Genuinas: 3.)*
  - **ATA007:** las **escrituras** (`80781/80790`) del `cp` se **promovieron a `deteccion`** cuando el plan las
    quería `ambigua` (**`CA13` no se cumple**).

### H-C. **Gap de despliegue (arreglado):** el `extraer_alertas.py` **desplegado en el manager estaba obsoleto**
(sin `srcip/srcuser/dstuser`) → **el predicado `OPERADOR` de H3 no funcionaba**. Se **desplegó** el del repo
(`sha256` idéntico), se **re-extrajeron** las ventanas afectadas y se registró la **lección** en el runbook:
*"repositorio y manager deben ir en sincronía: hay que **desplegar** antes de medir."*

---

## 4. Verificación (`tfg-tester`) — **PASA** con 2 no-conformidades de diseño

Reprodujo **6/6** filtrados **byte a byte**, cuadró **todas las cifras**, verificó el **aislamiento por agente**,
`dudosa=0`, el **determinismo**, `pytest` **77 en verde**, **solo 3 filas** de `ATA_index.csv`, sin secretos, sin
commit y los artefactos cerrados (piloto/afinado) **intactos**. Confirmó y **agravó** el diagnóstico de H4
(señal OR, no AND) y midió las alertas ajenas. *(El tester causó una escritura accidental con el default de
`--rev-out` y la **restauró byte a byte**.)*

**No-conformidades:** **`CA13`** (las escrituras debían ser `ambigua`) y **H4** (el ancla no ancla).

## 5. Cabos menores (del tester)

1. Las **fichas citan `sha256_artefacto.txt`** pero ese fichero **falta** en los 6 `Logs/`.
2. Las **cabeceras de los 3 `esperado`** dicen *"gate humano: PENDIENTE"* → **CA5 incompleto en el artefacto**
   (la validación sí consta en `plan.md`/fichas/bitácoras). *(Se repite el fallo del bloque anterior.)*
3. **Inconsistencia del README de H3:** en ATA004/ATA007 las PAM salieron `ruido_conocido` (`baseline`), no
   `dudosa`, porque sus `esperado` llevan señales `rule_id` (siempre evaluables). El resultado es el deseado,
   pero **el texto debe corregirse**.
4. **C0 de ATA004** solo capturó la línea de `systemctl`, no de journald → la hipótesis de `40700` quedó **sin
   probar** (0 detecciones de journald en las 2 ventanas).

---

## 6. Valoración honesta

- **Los resultados SE SOSTIENEN cualitativamente:** los **3 ataques se detectan** de verdad (por `execve` con
  reglas de fábrica) y el camino manual **funciona**.
- **NO usar el recuento bruto de alertas como "nº de detecciones":** está **inflado** por **redundancia** (un
  evento → varias reglas) y por **procesos ajenos**. La cifra defendible es **`rule_id` distintos** (+ el
  reparto genuinas/ajenas).

---

## 7. Siguiente (recomendación)

- **Antes de escalar hay que arreglar el DISEÑO de las señales** (H-A y H-B): o el filtro admite señales
  **ancladas** (semántica AND: `exe` **y** `cwd de la carpeta del ataque`), o la convención cambia a **declarar
  la detección por el `rule_id` del `execve`** (`80792`) en lugar de por `audit_exe` genérico. **Decisión de
  diseño** → va en el plan del escalado (o en un bloque corto previo).
- **Corregir los cabos §5** (ficheros ausentes, cabeceras de los `esperado`, el texto del README de H3).
- **Tutoría (H1/H2):** pendiente, no bloquea.
- **`push`:** los commits son locales; publicar es del humano.
