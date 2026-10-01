# change-doc — Bloque `fase-03-repeticiones`: las 9 repeticiones auditadas

> Cierre. Fecha: **2026-10-02**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA**.
> Plan de referencia: `plan.md` (v1, `approved_by_human`). **Métrica y filtro CONGELADOS.**

---

## 1. Objetivo

Repetir los **9 ataques** que la **auditoría metodológica** marcó, para que **todo el corpus** cumpla las
**normas nuevas** (`Soporte/Ataques/criterio_ataques.md`):
- **Por ART** (había prueba usable y no se usó / no constaba): **ATA024, ATA029, ATA030, ATA038**
- **Por pre-staging** (preparaban su material **dentro** de la ventana): **ATA014, ATA016, ATA029, ATA035,
 ATA036, ATA037, ATA038**
👉 **Unión = 9 ataques** (dos de ellos —**ATA029 y ATA038**— arrastraban **los dos motivos**).

---

## 2. 🎯 Resultado: **9/9 DETECTADAS** (18 ventanas nuevas)

| ATA | Técnica | Motivo | ¿Det.? | `rule_id` | `k/m` | Cómo se cumplió el motivo |
|---|---|---|---|---|---|---|
| ATA030 | T1560.001 | ART | **SÍ** | `80792` | 2/2 | atómica `7af2b51e…` (`tar`) ejecutada tal cual |
| ATA029 | T1005 | **ART+PRE** | **SÍ** | `80792` | 3/3 | atómica `00cbb875…` + **`src/` y `.deb` fijados antes de `t0`** (factible offline) |
| ATA024 | T1531 | ART | **SÍ** | `550,5555,80792` | 1/1 | atómica `3c717bf3…` **adaptada** (solo cambia contraseña) |
| ATA014 | T1114 | PRE | **SÍ** | `80792` | 2/2 | buzón sembrado **antes de `t0`** (0 señales de siembra en ventana) |
| ATA016 | T1213.006 | PRE | **SÍ** | `80792` | 2/2 | BD sembrada antes → **`python3` = 0 en la ventana** (mata el `92600`) |
| ATA035 | T1056.004 | PRE | **SÍ** | `80792` | 1/1 | payload materializado antes; ventana = solo `LD_PRELOAD` |
| ATA036 | T1565.003 | PRE | **SÍ** | `80792` | 1/1 | `memedit`/`target` antes; ventana = solo `ptrace` |
| ATA037 | T1561.001 | PRE | **SÍ** | `80792` | 4/4 | imagen **creada antes de `t0`**; ventana = solo wipe |
| ATA038 | T1529 | **ART+PRE** | **SÍ** | `80792`,`506`,`503` (+SCA) | 3/3 | atómica `6326dbc4…` (reinicio) + material antes |

**C0 de las 9: PASA** (ganadora `80792` nivel 3, **sin silenciadores**).
**v2 `iguales`** · **`dudosa=0`** · **0 filas del ataque en `ruido`**.

**Cifras clave (verificadas):** `Hojas/repeticiones.csv` **9 filas** · `Hojas/ATA_index.csv` **43 filas intacto**
· **86 ventanas base intactas** (los originales no se tocan) · `pytest` **97** · cadena de huellas **1.582 citas / 0 desincronías**.

---

## 3. Contabilidad — cómo conviven original y repetición

- **El original NO se toca** (el registro histórico se conserva).
- La repetición se **añade** con sufijo **`_rev`**: `ATA<NNN>_esperado_rev.csv` (firmado) · `ataque_rev.sh` ·
 `-rev1/rev2` en `-Detalle`/`-Audited`/`-Revision` · `Logs/ATA<NNN>_revN/`.
- **Ficha:** una sola (`ATA<NNN>_meta.md`) con **§Repetición auditada**. **Bitácora:** bloque **`"repeticion"`**
 con `motivo_repeticion` ∈ {`art`, `prestaging`, `art+prestaging`}.
- **`Hojas/repeticiones.csv`**: la **tabla de repeticiones** (ataque, motivo, prueba ART citada, material, resultado).
- **La repetición es la medición canónica** para esas 9; el original queda como **antecedente declarado**
 (y **se pueden comparar**: ese es un valor añadido del bloque).

**Ventanas del corpus:** 86 base + **18 de repetición** = **104**.

---

## 4. ⚠️ Anomalía declarada (nueva): el re-escaneo SCA tras el reinicio

El reinicio de la víctima (ATA038) dispara el **re-escaneo CIS** del agente → **18 filas** (`19010`/`19011`,
grupo `sca`) que caen a **`novel` → `deteccion`** (**9 por iteración**).
- **No compromete ningún veredicto**: ATA038 se detecta por sus señales reales (`80792` + `506` + `503`).
- **Es el mismo patrón que `rule_id 11`**: **artefacto del criterio congelado** (el filtro solo reconoce
 `19004`+`sca` y `11`+`stats`; `19010/19011` se le escapan).
- **Decisión:** **documentarlo y NO tocar el filtro** (congelado). Candidato a un **arreglo futuro** junto con el
 `rule_id 11` (o a declararlo como limitación).

---

## 5. Verificación (`tfg-tester`) — **PASA**

| # | Comprobación | Resultado |
|---|---|---|
| V1–V3 | 18 ventanas detectadas; `dudosa=0`; **0 filas del ataque en `ruido`** | ✅ |
| V4–V6 | Hashes cuadran; **determinismo**; el filtro **reproduce** los `-Audited` | ✅ |
| **V7–V8** | **Cumplimiento del motivo**: ART real (los 4 `guid` existen en el clon, commit `388942a…`) y **pre-staging genuino** (material **fuera** de `[t0,t1]`; `python3`/`dpkg`/`useradd`/`mkfs.ext4` = **0** dentro) | ✅ |
| V9–V12 | Contabilidad completa (9 filas, §Repetición, bloque `repeticion`, `esperado_rev` firmados) | ✅ |
| V10 | **Original intacto**; `ATA_index` **43 filas** | ✅ |
| V13–V14 | `pytest` **97**; cadena **1.582/0** | ✅ |
| V15 | Alcance limpio (solo 9 bitácoras + 9 fichas + 1 test) | ✅ |

---

## 6. Incidencias de proceso (declaradas)

1. **El PC se reinició** a mitad del bloque: **R1+R2** quedaron completas; **R3** quedó **sin la contabilidad**
 (ventanas hechas, faltaban fichas/bitácoras/filas) → **completada**; **R4** sin empezar → **hecha**.
 *Lección ya conocida: un corte no implica que no se haya trabajado → **comprobar el disco antes de reintentar**.*
2. **HTTP 400** del proveedor en dos llamadas (una dejó trabajo hecho, otra no).
3. Ajustes operativos declarados: **test** adaptado para reconocer ventanas `_rev` (`.split("_rev")[0]`, sin
 debilitar el invariante) · **scan FIM forzado** tras el pre-staging y **antes de `t0`** (para que el prestage
 no ensucie la ventana) · CRLF de un script del clon de ART normalizado · `strings` es symlink
 (`x86_64-linux-gnu-strings`).

---

## 7. Entregables

| Fichero | Qué |
|---|---|
| `Dataset/Ataques/Comandos/*/ATA<NNN>_{esperado_rev.csv,ataque_rev.sh}` | **9 repeticiones** (checklists firmadas) |
| `Dataset/…/Auditado/ATA<NNN>_rev{1,2}-{Audited,Revision}.csv` + `CSV/*_revN-*` + `Logs/ATA<NNN>_revN/` | **18 ventanas** |
| `Hojas/repeticiones.csv` | **la tabla de repeticiones** (9 filas) |
| `Bitacora/ATA*.json` (9) + `Dataset/…/ATA*_meta.md` (9) | bloque `repeticion` y §Repetición |
| `Soporte/Ataques/c0/ATA<NNN>_rev_*` | C0 de las repeticiones |

**Intactos:** los **9 originales**, las **86 ventanas base**, `Hojas/ATA_index.csv`, `filtrar_ruido.py`, la
política, `_recursos/`, `Reglas/**`.

---

## 8. Siguiente

- **El corpus queda homogéneo**: **43 técnicas**, todas con **fuente+motivo** y **material externo declarados**, y
 las 9 que lo necesitaban **repetidas bajo las normas nuevas**. *(Lo que seguirá siendo mixto es la **fuente**
 —ART vs propio— pero **justificado en cada caso**: eso es la realidad, no una incoherencia.)*
- **Pendiente acordado:** ① **las ~29 técnicas restantes de Linux, sin evasión** (con las normas ya escritas)
 · ② **bloque futuro**: normalización de finales de línea + recálculo de huellas · ③ **evasión** · ④ **Windows**.
- **`push`:** los commits son locales; publicar es del humano.
