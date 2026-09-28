---
fase: 3
bloque: fase-03-senales
tarea: A3.0 (H-A/H-B/CA13) + nota de huellas (fase-03-gitattributes §5.1) · R-09/R-13
nombre: Señales ancladas (recuento limpio de detecciones) + nota de finales de línea
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-planner
gate: humano — **APROBADO ✔ (2026-09-28)**: (a) mecanismo = **ancla implícita + evento de ejecución** (§2); (b) lo que **no** ancla → **`dudosa` (revisión)**, **nunca** descartado (§2.3); (c) **regenerar solo los 3 ataques afectados** (ATA004/007/012) y **dejar intactos los 3 del piloto** (§4); (d) la **nota de 2 líneas** (§1). La **prueba de regresión P1–P6 (§5)** es **condición de aceptación**.
---

# Plan — Bloque `fase-03-senales`: arreglar **cómo contamos** las detecciones + 1 nota

> **Objetivo del bloque:** que el **recuento de detecciones sea limpio** (cuente el ataque y
> **no lo ajeno**) **sin** cambiar el resultado cualitativo (**los 3 siguen detectados**) y **sin
> esconder nada** (lo que no se pueda demostrar como propio → **`dudosa`/revisión**, nunca
> `ruido_conocido`). Se **cierra el diseño de las señales** (hallazgos **H-A** y **H-B** del
> `fase-03-piloto-custom` y la no-conformidad **`CA13`**) **antes de escalar**. Incluye **1 nota de
> 2 líneas** (punto trivial).
>
> **Banco de pruebas = los 6 ataques ya hechos** (los **CSV del repo**: `-Detalle.csv`); el bloque es
> **offline** (filtrar es local y determinista). **No se lanan ataques, no se encienden VMs, no se
> pide root.**
>
> **Fichero único de retorno: este `plan.md`.** Nada más se escribe hasta el gate.

---

## 0. Objetivo y alcance

- **Entra:**
  1. **Nota de 2 líneas** sobre huellas/finales de línea en `README.md` y `Soporte/Ataques/piloto_procedimiento.md` (§1).
  2. El **mecanismo de señales ancladas** en `filtrar_ruido.py` (+ tests) y la **política**/convención
     documentadas en paralelo (§2–§3).
  3. La **prueba obligatoria** sobre los **6 ataques** (§5): re-ejecutar el filtro y demostrar que
     **ninguna detección genuina se pierde**, que las **ajenas** caen en **`dudosa`**, que **el resto
     de filas no cambia** y que hay **determinismo byte a byte**.
  4. La **decisión sobre los artefactos cerrados** (§4).
- **NO entra:** escalar las **7 técnicas restantes**, **Windows**, **η/Fase 4**, la **memoria**,
  escribir reglas **RS3/RS4**, re-baselinar, `Hojas/Detecciones.xlsx`, `BBDD/` (§9).

---

## 1. Punto 1 (trivial) — Completar la nota de la limitación de huellas

**Hecho real:** la nota *"⚠️ Huellas y finales de línea"* existe en `README.md` (§ *Huellas y finales
de línea*, líneas ~40–46) y en `Soporte/Ataques/piloto_procedimiento.md` (§ *Nota — limitación del
repo*, líneas 12–18), con el **texto literal** que fijó `fase-03-gitattributes` (§5.1 del change-doc
lo deja como **riesgo residual**). **Lo que falta** (los 2 puntos del change-doc §5.1/§5.2):

1. **El disparador completo:** la nota cita `checkout`/`stash`/`reset`/clonar, pero **no**
   `git add`/commit **ni** `core.autocrlf=true` (que es lo que **reescribe los finales de línea en
   Windows** — hoy **activo** en este repo, `git config core.autocrlf` → `true`; `.gitattributes`
   **no existe**, revertido en `19afafb`).
2. **La cadena y el recálculo:** qué ficheros forman la cadena de huellas y **cómo recalcularlas**.

**Texto a añadir (2 líneas, en AMBOS sitios):**

> - **El riesgo no es solo al clonar:** también salta con **`git add`/commit** y por tener
>   **`core.autocrlf=true`** (reescribe LF→CRLF en Windows) — **cualquier** operación de git que
>   toque los finales de línea cambia los **bytes** y por tanto el `sha256`.
> - **Cadena de huellas:** `ATA<NNN>_esperado.csv` ↔ `ATA<NNN>_ataque.sh` ↔ `-Audited.csv` /
>   `-Revision.csv` ↔ `Bitacora/ATA<NNN>.json` ↔ `ATA<NNN>_meta.md`. Los scripts calculan el
>   `sha256` **de los bytes en disco** → hay que **re-pasarlos** (regenerar y actualizar las citas)
>   tras **cualquier** operación de git que toque los finales de línea.

- **Coste:** ~4 líneas de documentación. **Riesgo:** nulo. **Sin ficheros de datos.**

---

## 2. Punto 2 (el de verdad) — Afinar **cómo contamos**

### 2.1 Diagnóstico medido (datos reales, verificados en este plan)

El problema **no** es el operador ni el ruleset: es **cómo el filtro interpreta las señales**.

| Hallazgo | Hecho real (verificado en los CSV del repo) |
|---|---|
| **H-B** (señal ancha) | `audit_exe=find` captura los `find` de **`update-motd.d`** con `cwd=/` (login del operador) → **cuenta ajeno**. ATA012 i1: 11 `deteccion`, de los que **3** son `find` ajenos (`cwd=/`) + **1** `find` con `cwd` vacío. `audit_exe=systemctl` captura los `systemctl --user` de **cierre de sesión** (`cwd=/home/angel`). ATA004 i1: 5 `deteccion`, **3 genuinas** (i1) — **2 ajenas** (12:35:03, `cwd=/home/angel`). |
| **H-A** (ancla inerte) | El ancla del `esperado` (`audit_cwd=/home/angel/lab-attack/ATA<NNN>/*`) **no casa** el `cwd` real (`/home/angel/lab-attack/ATA<NNN>`, **sin barra final**) → 0 coincidencias. **Y aunque casara**, el filtro evalúa las señales como **OR** (gana la primera): el `audit_exe` **solo** ya promueve a `deteccion`, sin exigir el `cwd`. |
| **`CA13`** | ATA007: el `cp` produce, **con el mismo `cwd` del ataque**, dos tipos de evento — **execve** `80792` (`rule_groups=audit\|audit_command`, `audit_key=audit-wazuh-c`) **y watch** `80790`/`80781` (`audit\|audit_watch_*`, `audit-wazuh-w`). La señal `audit_exe=cp` promueve **también las escrituras** a `deteccion` (4 detecciones/iter) cuando el plan las quería **`ambigua`** → **`CA13` no se cumple**. |

> **Consecuencia:** el **`audit_exe` solo no ancla**; y el **`audit_cwd` solo tampoco** (las
> escrituras de ATA007 llevan el `cwd` del ataque). Para fijar `CA13` hace falta, además, distinguir
> el **evento de ejecución** del **evento watch**.

### 2.2 Decisión — Mecanismo elegido: **ancla implícita + evento de ejecución** (opción 2, KISS)

**Elegido:** **dar al filtro señales AND reutilizando el ancla que el `esperado` YA declara**
(el `audit_cwd`), **sin cambiar el esquema ni editar los `esperado` congelados**, y exigir que la
señal de proceso sea un **evento de ejecución**. Formalmente:

> **Ancla de un `esperado`** = el conjunto de señales `tipo=deteccion, campo=audit_cwd` que declara.
>
> **Si el `esperado` declara ≥1 ancla**, una señal `deteccion` con `campo=audit_exe` casa una fila
> **solo si** se cumplen **las tres**:
> 1. `audit_exe` casa el patrón (`full` o `basename`), **y**
> 2. el `audit_cwd` de la fila casa el ancla, **y**
> 3. la fila es un **evento de ejecución** (`rule_groups` contiene **`audit_command`**).
>
> **Si el `esperado` NO declara ancla** → comportamiento **legado** (el `audit_exe` casa solo), con un
> **`AVISO` por `stderr`** que anima a declarar el ancla. *(Retrocompatibilidad: los 3 `esperado` del
> piloto —ATA002/008/013— **no** declaran ancla → **no cambian**; ATA001 es un ejemplo.)*

**Corrección de H-A(i) sin editar el `esperado`:** el match del ancla se prueba contra el `cwd` **y**
contra `cwd + "/"`, de modo que el patrón existente `…/ATA<NNN>/*` **casa** el `cwd` real
`…/ATA<NNN>` (el `*` casa la cadena vacía). La convención **nueva** (`plantilla_esperado.md`) usa el
`cwd` **sin `/*`** (o `…/ATA<NNN>*`); **no se editan** los `esperado` congelados.

### 2.3 Destino de lo que **no** ancla (condición del humano — **obligatoria**)

> **"Si no puedes demostrar que es tuyo, no lo descartes: mándalo a revisión."**

- Una fila que **casa una señal `audit_exe` `deteccion`** pero **falla el ancla o el evento de
  ejecución** → **`dudosa`** (motivo **`sin_ancla:<senal_id>`**, `revision=pendiente`), **nunca**
  `deteccion` **ni** `ruido_conocido`. → Es lo que ocurre con los `find` ajenos (`cwd=/`), el `find`
  con `cwd` vacío, los `systemctl` de cierre de sesión y las **escrituras** de ATA007.
- Si esa fila **además** casa una señal `ambigua` declarada → gana el motivo **`ambigua:<senal_id>`**
  (sigue siendo `dudosa`). → Es el caso de ATA007 (`80790`→`T1491-A1`, `80781`→`T1491-A2`): **`CA13`
  se cumple** sin reclasificar nada a `ruido`.
- **Ninguna** fila se promueve ni se descarta en silencio: queda `dudosa` y la resuelve el humano.

### 2.4 Coste/beneficio de las alternativas (declarado para el gate)

| Opción | Cambio | Coste | Beneficio | ¿Se elige? |
|---|---|---|---|---|
| **1. Ancla explícita (extensión del esquema)** — nuevo `tipo=ancla` o campo, y **editar** los 3 `esperado` (añadir `audit_key=audit-wazuh-c` como contexto) | filtro + **esquema** + **editar `esperado` congelados** + regenerar todo | **alto** (rompe la regla "el `esperado` se escribe antes y no se ajusta después", cadena de huellas del `esperado`) | explícito y general | **No** (la "extensión" es cosmética: el `audit_cwd` ya *es* el ancla) |
| **2. Ancla implícita + evento de ejecución (ELEGIDA)** | solo **filtro** + docs + tests | **medio-bajo** | arregla H-A/H-B/**`CA13`**; **no toca** los `esperado` congelados | **Sí** |
| **2b. Ancla implícita + "gana `ambigua`"** (sin exigir `audit_command`) | solo filtro | **menor** | arregla H-A/H-B y ATA007, pero deja las escrituras de ATA012 (no declaradas `ambigua`) como `deteccion` | No (menos general; depende de que el autor declare `ambigua`) |
| **3. Declarar la detección por `rule_id=80792`** | filtro/esperados | **alto y peor**: `80792` es **genérico** (cualquier comando) y está en el catálogo | ninguna | **No** |

> **Honestidad:** el **único** añadido conceptual de la opción elegida es exigir que la señal
> `audit_exe` sea un **evento de ejecución** (`audit_command`). Es correcto: el `dato_componente`
> de esas señales es literalmente *"Process Creation"*; en un evento **watch**, `audit_exe` es el
> **causante de la escritura**, no "el proceso del ataque". Sin esta condición, **`CA13` no se arregla**.

---

## 3. Precisión del mecanismo (para el ejecutor)

- **Orden de decisión (se mantiene; cambia solo el contenido del paso 2 y se añade el fallback):**
  1. `auto_ruido` (§3), **2.** `deteccion` (**ahora anclada**, §2.2), **1.5.** `operador` (H3),
  **3.** `dudosa` (`ambigua` → `sin_ancla` → `sin_campos`), **4.** `deteccion`/`novel`, **5.** `ruido_conocido`/`baseline`.
- **Motivo nuevo:** `sin_ancla:<senal_id>`; `evidencia` = el campo del ancla que falló
  (p. ej. `audit_cwd=/` / `audit_exe=/usr/bin/find`).
- **Constante nueva:** `AUDIT_CMD_GROUP = "audit_command"` (junto a las ya existentes
  `WAZUH_PROCESOS`, `OPERADOR_SRCIPS`…). Documentada en la política.
- **`AVISO` (no bloqueante) por `stderr`:** señal `audit_exe` `deteccion` **sin** ancla `audit_cwd`
  → *"señal de proceso sin ancla; el recuento puede ser ancho (convención H4)"*.
- **Determinismo (R-13):** intacto (misma entrada → salida byte a byte). El `AVISO` va a `stderr`,
  **no** a la salida.
- **No regresión:** `auto_ruido`, el predicado `OPERADOR` (paso 1.5), la revisión humana, el
  `--modo baseline` y las columnas de salida **no** cambian.

---

## 4. Decisión — ¿Qué pasa con los **artefactos cerrados**?

Los 6 ataques del banco ya están **cerrados y verificados**; sus `-Audited.csv` citan el `sha256`
del esperado y están enlazados con fichas y bitácoras (cadena de 36 huellas, §1).

### ✅ Recomendación: **regenerar SOLO los 3 del piloto-custom afectados** (ATA007/012/004)

- **Qué se regenera:** los **6 `-Audited.csv`** + **6 `-Revision.csv`** de ATA007/012/004 (nuevas
  `dudosa`) y se actualizan **ficha §2/§8/§8.1/§9/§10** + **`Bitacora/ATA00{4,7,12}.json`** (conteos,
  genuinas/ajenas, hashes, **evento `correccion`**). Las nuevas `dudosa` las **resuelve el humano**
  (mismo flujo del paso 11: `veredicto`/`nota`/`revisor`/`fecha`), fold con `--revision`.
- **Qué NO se toca:** los **3 del piloto** (ATA002/008/013) — **no declaran ancla** → re-ejecución
  **byte a byte idéntica** (prueba de **retrocompatibilidad**); ni ATA001 (ejemplo).
- **`Hojas/ATA_index.csv`:** **intacto** (el resultado cualitativo no cambia → siguen `cerrado`/`review`).

**Por qué (justificación):**
1. **Es el objetivo del bloque:** el recuento del repo queda **limpio** (la categoría `deteccion`
   pasa a ser *"lo anclado"* = lo genuino) y **`CA13` se cierra en el artefacto**, no solo en el papel.
2. **Precedente:** `fase-03-piloto` y `fase-03-cabos` **regeneraron** los `-Audited.csv` y
   actualizaron hashes/fichas/bitácoras (aquí los **datos** cambian, así que también los **conteos**).
3. **No se re-mide:** se **re-filtran** los **mismos** `-Detalle.csv` (offline, determinista).
4. Coste acotado y **offline**.

**Alternativa (si el humano prefiere no tocar cerrados):** *no regenerar* y **aplicar el mecanismo
solo al escalado**, dejando la prueba en un **informe** (`Soporte/Ataques/anclaje_prueba.md`) con los
conteos corregidos y el `-Audited.csv` intacto (como se hizo con el criterio v2: "no se recalculan los
cerrados; la diferencia se documenta").
- **A favor:** KISS, **cero** riesgo sobre lo verificado, cero re-revisión humana.
- **En contra:** el recuento de los 3 ataques en el repo sigue siendo el **anterior** (ya documentado
  con las "dos cifras" y genuinas/ajenas) → **la no-conformidad `CA13` queda "resuelta por mecanismo",
  no en el artefacto**.

> **⚠️ Este es el punto (c) del gate.** La recomendación es **regenerar los 3 afectados**; el humano
> puede elegir la alternativa.

---

## 5. Prueba obligatoria (banco = los 6 ataques ya hechos)

Se **re-ejecuta** `filtrar_ruido.py` sobre los **`-Detalle.csv` reales** de los **6** ataques
(12 ventanas) — a **temporal** para comparar y, si se aprueba §4-regenerar, **en su sitio** para los 3
afectados. Se demuestra, ventana a ventana:

| # | Qué se demuestra | Cómo |
|---|---|---|
| **P1** | **Ninguna detección GENUINA se pierde** | los `rule_id` del **`execve` del ataque** (`80792` en `audit_command`, `cwd` del ataque) siguen **`deteccion`**; ningún `rule_id` de detección genuina desaparece del conjunto |
| **P2** | **Las ajenas dejan de contar** | los `find` `cwd=/`, el `find` `cwd` vacío, los `systemctl` `cwd=/home/angel` y las **escrituras** de ATA007 pasan de `deteccion` a **`dudosa`** (motivo `sin_ancla:*` / `ambigua:*`), **nunca** `ruido_conocido` |
| **P3** | **El resto de filas no cambia** | `git diff` fila a fila: solo cambian las filas-candidato (las que casan `audit_exe`); el resto (`auto_ruido`, `baseline`, PAM, `novel`) **idénticas** |
| **P4** | **Retrocompatibilidad** | los `-Audited.csv` de **ATA002/008/013** re-generados son **byte a byte idénticos** a los del repo (esperado de `python3`/`dd`/`wget` **sin** ancla) |
| **P5** | **Determinismo** | 2 pasadas del filtro por ventana → `sha256` **idéntico** |
| **P6** | **`CA13`** | ATA007: `80790`/`80781` → **`dudosa`** (`ambigua:T1491-A1/A2`); `80792` (execve) → `deteccion` |

**Rejilla esperada (a confirmar por el executor, sin fijar cifras aquí):**

| ATA | antes `deteccion` | después `deteccion` (anclado) | a `dudosa` (ajenas/escrituras) |
|---|---|---|---|
| ATA007 i1/i2 | 4 / 4 | **2 / 2** (los `cp` execve) | 2 / 2 (`80790`,`80781`) |
| ATA012 i1/i2 | 11 / 11 | **6 / 7** (`find`×4/5, `cp`, `tar` execve) | ~5 / ~4 (3 `find` ajenos + `cwd` vacío + `tar` write) |
| ATA004 i1/i2 | 5 / 5 | **3 / 3** (`systemctl` genuino) | 2 / 2 (`systemctl` de cierre) |
| ATA002/008/013 | s/c | **idéntico** | 0 |

---

## 6. Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `README.md` | § *Huellas y finales de línea*: **+2 líneas** (§1) |
| `Soporte/Ataques/piloto_procedimiento.md` | nota § *limitación del repo* **+2 líneas**; §5/§8.2: **resolución** de H-A/H-B (ancla implementada) |
| `_artefactos/scripts/filtrar_ruido.py` | **mecanismo anclado** + `AUDIT_CMD_GROUP` + motivo `sin_ancla` + `AVISO`; **docstring actualizado** (coincidencia literal con la política) |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | **+4–6 tests** (§7): ancla exe∧cwd, **golden falso negativo**, evento watch → `dudosa` (`CA13`), retrocompatibilidad sin ancla, patrón sin barra final, determinismo |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | §2 (orden/fallback `sin_ancla`), §4 (ancla + evento de ejecución), constantes; **`version`++** |
| `Soporte/Ataques/plantilla_esperado.md` | convención H4 **v2**: ancla obligatoria para señales de proceso; patrón **sin `/*`**; evento de ejecución |
| **§4-regenerar:** `…/linux/Auditado/ATA00{4,7,12}_iter{1,2}-Audited.csv` (6) + `…-Revision.csv` (6) | **regenerados** (nuevas `dudosa` resueltas por el humano) |
| **§4-regenerar:** `…/linux/ATA00{4,7,12}_meta.md` | §2 hashes, §8/§8.1 conteos, §9 v2, §10 hallazgos; **`version`++** |
| **§4-regenerar:** `Bitacora/ATA004.json`, `ATA007.json`, `ATA012.json` | conteos/hashes + **evento `correccion`** (append-only) |
| `Soporte/Ataques/anclaje_prueba.md` | **nuevo** (solo si §4=alternativa) — informe de la prueba P1–P6 |

**No se toca:** los artefactos del **piloto** (ATA002/008/013: `esperado`, `-Audited`, `-Revision`,
fichas, bitácoras), `ATA001_esperado.csv`, los `-Detalle.csv` y `-Detalle_raw.csv` de los 6,
`extraer_alertas.py`, `preflight_enmascaramiento.py`, `Soporte/Wazuh/Reglas/**`, `Hojas/ATA_index.csv`,
`Hojas/Detecciones.xlsx`, `BBDD/`, `_recursos/`, `Estudio-Wazuh/`.

---

## 7. Criterios de aceptación y casos de prueba

| # | Criterio (verificable) | Caso de prueba |
|---|---|---|
| **CA1** | **Nota (punto 1):** `README.md` **y** el runbook mencionan el **disparador completo** (`git add`/commit, `core.autocrlf=true`) **y** la **cadena** + **cómo recalcular**. | Leer ambos: contienen las 2 líneas; `git config core.autocrlf` = `true`; no existe `.gitattributes`. |
| **CA2** | **Mecanismo:** una señal `audit_exe` `deteccion` casa **solo** con **(exe ∧ cwd-ancla ∧ `audit_command`)**; sin ancla → legado + `AVISO`. | Código + política (§2/§4) + docstring **coincidentes**. |
| **CA3** | **⭐ Golden del falso negativo:** un proceso del ataque **desde otra carpeta / fuera del ancla** → **`dudosa`** (motivo `sin_ancla:*`), **no** `deteccion`, **no** `ruido_conocido`. | Test nuevo: fila `audit_exe=find`, `cwd=/tmp`, grupo `audit_command`, esperado con ancla → `dudosa`/`sin_ancla`. |
| **CA4** | **`CA13`:** un evento **watch** (`audit_watch_*`) del mismo proceso/ancla **no** es `deteccion`; cae a su `ambigua` → `dudosa`. | Test nuevo: `audit_exe=cp`, `cwd=…/ATA007`, grupo `audit_watch_write` + esperado con `ambigua rule_id` → `dudosa`. |
| **CA5** | **Retrocompatibilidad:** un esperado **sin** ancla mantiene el comportamiento legado (exe → `deteccion`) y los 3 del piloto re-generan **byte a byte**. | Test nuevo + re-ejecución de ATA002/008/013 (P4). |
| **CA6** | **Patrón sin barra final:** `…/ATA<NNN>/*` casa el `cwd` real `…/ATA<NNN>`. | Test nuevo de `glob`/ancla. |
| **CA7** | **Prueba P1–P3 (6 ataques):** genuinas intactas; ajenas → `dudosa`; resto sin cambios. | Diff de los 12 `-Audited` (a temporal) vs repo; tabla §5. |
| **CA8** | **Determinismo (R-13):** 2 pasadas → `sha256` idéntico. | Re-ejecutar a temporal ×2; `sha256` igual. |
| **CA9** | **No regresión:** `pytest` verde (**77 + nuevos**); `auto_ruido`/`OPERADOR`/`--modo baseline`/columnas intactos. | `pytest _artefactos/scripts/tests/`. |
| **CA10** | **`§4-regenerar` (si se aprueba):** hashes coherentes en **todos** los sitios (audited cabecera ↔ bitácora ↔ ficha §2); **cifras actualizadas**; `ATA_index.csv` **intacto**; los 3 siguen **detectados**. | Recorrer la cadena de huellas; `git status`. |
| **CA11** | **Higiene:** sin secretos; piloto/`ATA001`/`extraer_alertas`/`preflight`/RS3-RS4/`_recursos`/`BBDD`/`xlsx` **intactos**. | `grep` de la contraseña; `git status`; `git diff` acotado. |

---

## 8. Cómo se verifica (`tfg-tester`) — **sin lanzar ataques, sin VMs**

1. **Nota (CA1):** leer `README.md` + runbook; confirmar las 2 líneas y `core.autocrlf=true`.
2. **Código/docs (CA2/CA6):** leer `filtrar_ruido.py` (docstring) ↔ `politica_filtrado_ruido.md`
   (coincidencia literal); revisar las pruebas nuevas.
3. **Suites (CA9):** `pytest _artefactos/scripts/tests/` → verde (77 + nuevas).
4. **Prueba (CA7/CA8):** re-ejecutar el filtro sobre los 12 `-Detalle.csv` a un **temporal**:
   - **P1/P2/P3:** comparar con los `-Audited` del repo; contar genuinas/ajenas; comprobar que **solo**
     cambian filas-candidato y que las ajenas son `dudosa` (nunca `ruido_conocido`);
   - **P4:** ATA002/008/013 **byte a byte**;
   - **P5:** 2 pasadas → `sha256` idéntico.
5. **Golden (CA3/CA4/CA5):** ejecutar los tests nuevos (incluido el falso negativo).
6. **`§4-regenerar` (CA10):** si se aprueba, comprobar la cadena de huellas completa, los conteos
   actualizados en fichas/bitácoras, `ATA_index.csv` intacto y que los 3 siguen detectados.
7. **Higiene (CA11):** sin secretos; sin commit; `_recursos/`/`BBDD/`/xlsx intactos.
   **Veredicto PASA/FALLA con evidencia.**

---

## 9. Qué NO entra (fuera de alcance)

- **Escalar** las **7 técnicas restantes** del corpus (ni sus filas de `ATA_index.csv`:
  ATA001, ATA003, ATA005, ATA006, ATA009, ATA010, ATA011).
- **Windows** y el *split* del baseline por SO.
- **η / precio de la detección** (Fase 4) y las gráficas.
- **Escribir** reglas **RS3/RS4** y su pre-flight.
- `Hojas/Detecciones.xlsx`, `BBDD/wazuh.db`, `Estudio-Wazuh/`.
- **Instalar** dependencias / **re-baselinar** / **reconectar NAT** / **encender VMs** / pedir root.
- **Redactar la memoria** / tocar `_recursos/`.
- **Re-medir** los ataques o tocar sus `-Detalle.csv`; tocar los artefactos del **piloto** (ATA002/008/013).

---

## 10. Qué tiene que aprobar el humano (gate)

1. **Punto 1 — la nota de 2 líneas** (§1) en `README.md` + runbook.
2. **El mecanismo (a):** **ancla implícita** (`audit_exe` ∧ `audit_cwd` ∧ evento `audit_command`) sobre
   el ancla que el `esperado` **ya** declara, **sin** cambiar el esquema ni editar los `esperado`
   congelados (§2.2). *(Alternativas 1/2b/3 descartadas y justificadas en §2.4.)*
3. **El destino de lo que no ancla (b):** **`dudosa`** (`sin_ancla:*` / `ambigua:*`), **nunca**
   `ruido_conocido` (§2.3) — cumple la condición *"si no puedes demostrarlo, a revisión"*.
4. **El trato a los artefactos cerrados (c):** **regenerar los 3 piloto-custom** (ATA007/012/004) +
   actualizar ficha/bitácora, **dejando intactos los 3 del piloto**, *o* la **alternativa** de no
   tocarlos y aplicar solo al escalado (§4).
5. **La prueba obligatoria** P1–P6 (§5) y los **criterios/casos** (§7), incluido el **golden del
   falso negativo**.
6. Que este bloque **no escala**, **no toca** el piloto/`ATA001`/`extraer_alertas`/`preflight`/RS3-RS4
   y **no mide η**.

---

## 11. Notas de ejecución (orden y cuidados)

1. **Orden:** (i) **nota** (§1) → (ii) **mecanismo** + tests (§2/§3) → (iii) **prueba** a temporal
   (§5) → (iv) si se aprueba, **regenerar** los 3 afectados + actualizar fichas/bitácoras (§4).
2. **Encoding/integridad:** los CSV son **UTF-8 sin BOM** con **LF**; **no** hacer
   `checkout`/`stash`/`reset` sobre `esperado`/`Audited` (ver §1); hashes en **minúsculas**.
3. **`--rev-out`**: al regenerar, escribir en su sitio **solo** tras resolver el humano; nunca sobre
   ficheros no previstos.
4. **Bitácoras = append-only:** actualizar campos de hash **y** añadir un **evento `correccion`**.
5. **Meseta:** si un dato no cuadra (p. ej. un `rule_id` genuino desaparece de `deteccion`), **parar**
   y reportar (**no** "forzar" el mecanismo).
6. **Contraseña del laboratorio:** no se necesita en este bloque (offline); si en algún momento se
   usara root, **solo en memoria** y jamás en el repo.
