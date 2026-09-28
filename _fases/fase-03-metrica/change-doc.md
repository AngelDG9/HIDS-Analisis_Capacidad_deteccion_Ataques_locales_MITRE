# change-doc — Bloque `fase-03-metrica`: métrica de detección y "pertenencia al ataque"

> Cierre. Fecha: **2026-09-28**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**, tras **2 FALLA** corregidos).
> Plan de referencia: `plan.md` (v1, `approved_by_human`; decisiones D1–D5).
> Verificaciones: 3 vueltas de tester (1ª **FALLA**, 2ª **FALLA acotado**, 3ª **PASA**).

---

## 1. Objetivo y por qué

Dos problemas detectados al escalar la Fase 3:

1. **El "nº de alertas" no es una métrica válida**: una sola acción del ataque produce 2–7 alertas según
   cuántas reglas vigilan lo mismo. No es comparable entre técnicas.
2. **La huella del propio ataque caía en "ruido"**: todo lo que no estaba declarado como señal acababa en
   `ruido_conocido/baseline`, **aunque fuera del ataque** (el propio `collected.tar.gz` que creó el ataque,
   sus procesos). Eso **violaba la condición dura** del humano: *"nada que pueda ser del ataque se descarta;
   si no se demuestra ajeno, va a revisión"*.

**Alcance medido (verificado por el orquestador y por el tester):** **84 filas** del ataque estaban mal
etiquetadas (**82 detectadas por la regla de carpeta + 2 `mkdir` atribuidas por veredicto humano**).

---

## 2. Qué se ha hecho

### 2.1 La métrica (D1) — quedó fijada

> **O1 (la cifra que decide):** `detectado = SÍ/NO` — existe ≥1 fila `deteccion` **anclada** en **ambas**
> iteraciones, **+ con qué `rule_id`** **+ la primera evidencia**.
> **O2 (granularidad):** **acciones cubiertas `k/m`** (m = señales `deteccion` declaradas en el `esperado`).
> **Anexo (transparencia, nunca resultado):** nº bruto de alertas y `rule_id` distintos.

### 2.2 El arreglo (D2/D5) — categoría nueva `artefacto_ataque`

> **`artefacto_ataque` = "es del ataque, pero no es la detección de la técnica"** (pista floja).
> Se asigna **de forma automática y determinista**: la fila está en la carpeta del ataque
> (`ATTACK_ROOT = /home/angel/lab-attack/<ATA_id>`) y no casó una señal declarada.
> **NUNCA** cae en `ruido_conocido`. **No cuenta como detección.**

- **Ancla por ruta** (`audit_file`/`audit_dir`/`syscheck_path`, resueltas contra el `cwd`) además del `cwd`.
- **Guardarraíl de plegado:** `--revision` con `veredicto=ruido` sobre una fila del ataque → **falla con `exit 4` y no escribe**.
- **Tercer veredicto humano `artefacto`** → `artefacto_ataque` + `revision=resuelta`.
- **`AVISO` por execve no declarado** (a `stderr`; aporta las 6 filas de ATA013).

### 2.3 Regeneración (D3) y pilotos (D4)

- **Las 12 ventanas regeneradas** (`Audited` + `Revision`), más **6 fichas** y **6 bitácoras**.
- **Los 3 del piloto cubiertos sin editar su `esperado`** (la carpeta se deriva del `ata_id`).
- **`-Detalle.csv`, los `esperado` y `Hojas/ATA_index.csv`: intactos.**

---

## 3. Resultado (medido y reproducido)

| | Antes | **Después** |
|---|---:|---:|
| **`deteccion`** | 39 | **39 (sin cambios)** |
| `auto_ruido` | 7.653 | 7.653 |
| **`ruido_conocido`** | 1.836 | **1.752 (−84)** |
| **`artefacto_ataque`** | — | **84** |
| `dudosa` | 0 | 0 |
| **Veredicto** | **5 detectados / ATA013 NO** | **5 / 1 (idéntico)** |

**Desglose de los 84:** **78 automáticos** (carpeta del ataque) + **6 por veredicto humano** (2 `sudo`,
2 `collected.tar.gz`, 2 `mkdir public_site`).

**Por ventana (`artefacto_ataque`, it1/it2):** ATA002 9/9 · ATA004 6/6 · ATA007 8/6 · ATA008 4/4 ·
ATA012 10/10 · ATA013 6/6.

> **ATA013 (el no detectado) gana el matiz que importa:** el ataque **sí corrió y dejó 6 filas** en su
> carpeta; lo que no alerta es su señal declarada (`python3`, suprimida por la regla **`92600`** del propio
> Wazuh). Historia defendible: *"el ataque se ve; Wazuh no tiene regla para esa técnica"*.

---

## 4. Verificación (3 vueltas de `tfg-tester`)

| # | Comprobación | Resultado |
|---|---|---|
| **P1** | Veredicto intacto; `deteccion`=39; los 12 conjuntos de `rule_id` **idénticos** | ✅ |
| **P2** | **0** filas del ataque en `ruido_conocido`/`auto_ruido` (12 ventanas) | ✅ |
| **P3** | Precisión (no cepo): las ajenas (11 `sin_ancla`, PAM, churn `lab-legit`) **siguen `ruido_conocido`** | ✅ |
| **P4** | Determinismo 12/12 (2 pasadas → mismo `sha256`; cuerpo byte a byte) | ✅ |
| **P5** | `pytest` → **93** (86 + 7) | ✅ |
| **P6** | Golden del falso negativo + guardarraíl (`exit 4`) | ✅ |
| **P7** | Criterio único, **sin rama especial por ataque** | ✅ |
| **P8** | `veredicto=artefacto` → `artefacto_ataque`, sin inflar `deteccion` | ✅ |
| **P9** | Cadena de huellas coherente en las 12 | ✅ |

### Las 2 FALLA y sus correcciones (transparencia)

1. **1ª FALLA:** el `mkdir public_site` de **ATA007** (en `lab-legit`, fuera de `ATTACK_ROOT`) seguía en
   `ruido` pese a ser demostrablemente del ataque (consta en el guion y en la ficha §8.1) → **corregido**:
   veredicto **`artefacto`** (regla D2/D5).
2. **2ª FALLA (solo metadatos):** **8 de 12** cabeceras `-Revision.csv` eran del **código anterior** (sin el
   campo `artefacto_ataque`, con el artefacto contado como `ruido`), y **ATA008** autocitaba un `sha256`
   falso. El ejecutor lo dio por "no corregible"; **el tester demostró que sí** → **corregido**
   (regeneración de los 8 `-Revision` con los mismos veredictos; autocita eliminada; runbook alineado a 84).

---

## 5. ⚠️ Limitaciones declaradas (para la memoria)

1. **La pertenencia es mecánica y cubre la carpeta del ataque.** Una fila del ataque **fuera** de ella
   (el `mkdir public_site` en `lab-legit`) **se atribuye por veredicto humano** y **nunca** puede quedar en `ruido`.
2. **La "checklist" (`esperado`) sigue siendo el punto débil**: decide qué cuenta como detección. Mitigación:
   se escribe **antes** del ataque y la **valida el humano**. *(Ya constaba en `state.md`.)*
3. **La "pertenencia al ataque" NO es una detección del HIDS**: es nuestro instrumento **post-hoc de
   atribución** (usa la carpeta que creamos para el experimento). Debe quedar claro en la memoria.
4. **Los `-Revision.csv` son la foto de la 1ª pasada (pre-plegado)**, por diseño; el `-Audited.csv` es el
   resultado plegado. Por eso sus conteos difieren (no es un error).
5. **Clave de plegado no única** (timestamp+rule_id+evidencia colisiona en algunas filas) — **pre-existente**.

---

## 6. Anomalía de proceso (declarada)

El bloque se ejecutó en **dos tandas**: la **primera llamada al ejecutor falló con un error del proveedor
(HTTP 400) sin reportar**, pero **dejó trabajo hecho en el árbol**. La segunda completó el resto. **No hubo
daño** (el tester auditó el alcance: nada prohibido tocado, sin restos ni duplicados, 33 ficheros coherentes),
pero conviene saberlo: **un fallo de reporte no implica que no se haya actuado**.

---

## 7. Ficheros

| Fichero | Cambio |
|---|---|
| `_artefactos/scripts/filtrar_ruido.py` | `artefacto_ataque`, `ATTACK_ROOT`, `es_del_ataque()`, ancla por ruta, guardarraíl, veredicto `artefacto`, `AVISO` |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | **+7 tests** (→ 93) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | **v6** (orden de decisión, pertenencia, límite declarado) |
| `Soporte/Ataques/plantilla_esperado.md` | **v4** (pertenencia + veredicto `artefacto`) |
| `Soporte/Ataques/piloto_procedimiento.md` | §9 (métrica O1+O2, 84 filas, veredictos permitidos) |
| `…/linux/Auditado/ATA*_iter*-{Audited,Revision}.csv` | **24 regenerados** (12 ventanas) |
| `…/linux/ATA*_meta.md` (6) | métrica + conteos + `version`++ |
| `Bitacora/ATA*.json` (6) | conteos/hashes + evento `correccion` |

---

## 8. Siguiente

- **Escalar las 7 técnicas que faltan** — ya con la **métrica congelada** y el **recuento limpio**.
- **Tutoría (H1/H2):** pendiente; no bloquea.
- **`push`:** commits locales; publicar es del humano.
