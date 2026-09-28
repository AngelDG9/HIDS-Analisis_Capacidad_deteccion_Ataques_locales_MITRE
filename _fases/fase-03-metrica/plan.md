---
fase: 3
bloque: fase-03-metrica
tarea: A3.0 (métrica de detección + integridad del recuento) · R-09/R-13
nombre: Métrica de detección y "pertenencia al ataque" (que nada del ataque caiga en "ruido")
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-planner
gate: humano — **APROBADO ✔ (2026-09-28)**: **D1** = métrica **O1+O2** (Sí/No + con qué `rule_id` + acciones cubiertas `k/m`); **D2** = **opción B completa** (categoría **`artefacto_ataque`** + ancla por ruta + **prohibido** `veredicto=ruido` sobre una fila del ataque); **D3** = **SÍ, regenerar las 6 ventanas cerradas**; **D4** = cubrir los 3 del piloto derivando la carpeta del `ata_id` (**sin** editar sus `esperado`); **D5** = **SÍ**, tercer veredicto humano **`artefacto`**. La prueba **P1–P9** es condición de aceptación.
---

# Plan — Bloque `fase-03-metrica`: cómo contamos una detección y qué hacemos con la huella del ataque

> **Objetivo del bloque:** (1) fijar **una métrica única y defendible** de "detección" para las 13
> técnicas; (2) corregir un defecto **sistemático** del filtro: hoy la **huella del propio ataque**
> (los procesos de su árbol, sus ficheros) cae en `ruido_conocido` — lo que **viola la condición
> dura** *"nada que pueda ser del ataque se descarta; si no se demuestra ajeno, va a revisión"*.
>
> **Banco = los CSV del repo (12 ventanas).** Bloque **offline**: no se encienden VMs, no se pide
> root, no se lanzan ataques. **Fichero único de retorno: este `plan.md`.**

---

## 0. Alcance

- **Entra:**
  1. **Métrica** de detección (comparación de ≥4 opciones y elección) — §2.
  2. **Arreglo** del falso negativo y del defecto sistemático asociado — §3.
  3. **Decisión sobre la retrocompatibilidad** de las 6 ventanas cerradas (qué se regenera) — §3.5.
  4. **Qué hacemos con los 3 del piloto** (sin ancla) y con `ATA_index`/fichas — §4.
  5. **Prueba de regresión + golden + determinismo** — §5.
  6. **Criterios de aceptación, riesgos y lo que NO entra** — §6.
- **NO entra:** escalar las 7 técnicas pendientes; Windows; η/Fase 4; reglas RS3/RS4; memoria;
  `Hojas/Detecciones.xlsx`; `BBDD/`; tocar `_recursos/`; commits/push (los hace el orquestador).

---

## 1. Diagnóstico medido (verificado sobre los datos reales)

Reproduje la clasificación actual importando `filtrar_ruido.py` sobre los **12 `-Detalle.csv`** y
su plegado con los `-Revision.csv` vigentes (solo lectura). Los 5 hallazgos que me pasó el
orquestador **se confirman**, con una **corrección de alcance importante**: el fallo del punto 2
**no es de 2 filas, es de 82**.

### 1.1 Verificación de los hallazgos

| # | Hallazgo del orquestador | Veredicto del planificador |
|---|---|---|
| 1 | El nº de alertas no es métrica válida | ✅ **Confirmado**. Redundancia (1 acción → N reglas) + procesos ajenos. Ej.: ATA007 = 4 alertas / **3 `rule_id` = 1 sola acción**; ATA004 = 3 alertas = 1 acción. |
| 2 | Falso negativo: `ATA012` `80790` "Created: …/ATA012/collected.tar.gz" en `ruido_conocido` | ✅ **Confirmado** (1 fila/iter). Es un **artefacto del ataque dentro de su propia carpeta**, rotulado `ruido`. |
| 3 | Posibles fallos del mismo tipo en otras ventanas | ✅ **Confirmado y agravado**: hay **82 filas** de huella del ataque en `ruido_conocido` (no 2). Detalle en §1.2. |
| 4 | El ancla mira el `cwd` pero no la ruta del fichero | ✅ **Confirmado en el código**: `evaluar_senales()`/`_casa_ancla()` solo usan `audit_cwd`; `audit_file`/`audit_dir`/`syscheck_path` se leen **solo** para `auto_ruido`. |
| 5 | Los 3 del piloto (sin ancla) corren en modo legado (OR) | ✅ **Confirmado**: `ATA002/008/013_esperado.csv` **no** declaran `audit_cwd` → el `audit_exe` casa solo. Consecuencia: ATA002 cuenta **escrituras watch** como `deteccion` (4/iter: 2 execve + 2 watch). |
| 6 | ¿Incoherencia doc↔código con `sin_ancla` + `ruido_conocido`? | ⚠️ **Matizado**: **no** es un bug del código. El código produce `dudosa`; es el **plegado humano** (`--revision`, `veredicto=ruido`) el que la convierte en `ruido_conocido` **conservando** el motivo `sin_ancla:*`. El fallo es de **criterio** (tratar "fuera del ancla" como "ajeno") + **ambigüedad de la política** (dice "nunca `ruido_conocido`" sin aclarar "salvo veredicto humano"). Ver §1.3. |

### 1.2 La cifra que decide: huella del ataque en `ruido_conocido`

Definición adoptada: **"fila del ataque"** = fila cuyo `audit_cwd` **o** cuya ruta
(`audit_file`/`audit_dir`/`syscheck_path`, resuelta contra el `cwd`) cae bajo
`/home/angel/lab-attack/<ATA_id>`. (Es una prueba **demostrable**: esa carpeta la crea y usa
solo el ataque.)

| Ventana | filas | `deteccion` | huella del ataque **hoy en `ruido_conocido`** | huella del ataque en `dudosa` (tras plegar) |
|---|---:|---:|---:|---:|
| ATA002_iter1 / iter2 | 1014 / 770 | 4 / 4 | **9 / 9** | 0 / 0 |
| ATA004_iter1 / iter2 | 751 / 738 | 3 / 3 | **6 / 6** | 0 / 0 |
| ATA007_iter1 / iter2 | 737 / 748 | 4 / 4 | **7 / 5** | 0 / 0 |
| ATA008_iter1 / iter2 | 666 / 724 | 2 / 2 | **4 / 4** | 0 / 0 |
| ATA012_iter1 / iter2 | 751 / 756 | 6 / 7 | **10 / 10** | 0 / 0 |
| ATA013_iter1 / iter2 | 841 / 1032 | 0 / 0 | **6 / 6** | 0 / 0 |
| **TOTAL** | **9.528** | **39** | **82** | **0** |

**Qué son esas 82 filas** (todas `rule_id=80792`, grupo `audit_command`):
- **78** son el **árbol de procesos del propio ataque** ejecutado con `cwd` en su carpeta:
  `bash`, `date`, `ls`, `dirname`, `gawk`, `ps`, `mkdir`, `tee`, `id`, `cat`, `wc`, `gzip`, `dash`.
  Ej. ATA012: `mkdir`/`gzip`/`dash`/`ls`/`date`/`wc` — **el staging del ataque**.
- **4** son **efectos del ataque** que pasaron por `dudosa` y el humano/ejecutor plegó a `ruido`:
  los **2** `Created: …/ATA012/collected.tar.gz` (el fichero que **creó el ataque**) y los **2**
  `sudo` (elevación del ataque, `cwd` de su carpeta).
- **Ninguna** de las 82 se puede demostrar ajena: **todas** están en la carpeta del ataque.

> **Conclusión:** el defecto no es anecdótico (2 filas) sino **sistemático**: la regla actual manda
> a `ruido_conocido/baseline` **todo** lo que no está declarado como señal, aunque sea el propio
> ataque. El caso del `.tar.gz` solo es el más visible (lleva la ruta completa en la descripción).

### 1.3 Por qué pasa (causa raíz) y el caso ATA013

El orden de decisión (§2 de la política) acaba en:
`si rule_id ∈ catálogo → ruido_conocido/baseline`. `80792` **está** en el catálogo (es genérico), así
que **cualquier** `execve` no declarado cae en "ruido". El filtro **no tiene en cuenta la ubicación**
(`cwd`/ruta) para decidir pertenencia al ataque: solo el `cwd` **al anclar señales declaradas**.

- **ATA013 (punto ciego de fábrica):** su `esperado` declara `python3` (suprimido por `92600`), pero
  el ataque deja **6 filas `80792` en su carpeta** (`bash`, `date`, `dirname`, `ls`, `cat`) que hoy
  son "ruido". Con el arreglo (§3) esas 6 filas pasan a ser **evidencia de que el ataque corrió** —
  aunque su señal declarada no alerte. Refuerza el hallazgo con datos.

---

## 2. Métrica de detección: opciones y recomendación

### 2.1 Opciones comparadas

| Opción | Qué mide | Pros | Contras | Coste |
|---|---|---|---|---|
| **O1. Binaria + evidencia** — "detectado sí/no", con **qué `rule_id`** y **primera evidencia** | ¿lo vio Wazuh? | Simple, comparable en 13 técnicas, robusta a redundancia y a ajenos, fácil de defender | Poca granularidad (1 alerta = detectado) | bajo |
| **O2. Cobertura de acciones** `k/m` — m = señales `deteccion` del `esperado` (cada una ≈ una acción), k = cuántas se anclaron ≥1 vez | ¿cuánto del ataque se vio? | Robusta (una acción → N reglas = 1), granular, mapea al guion del ataque | Depende de cómo se redactó el `esperado` (pero se escribe **antes** y lo **valida el humano**) | bajo |
| **O3. Nº de `rule_id` distintos anclados** (la "cifra limpia" actual) | vistas distintas de lo anclado | Ya existe | **Infla**: ATA007 = 3 `rule_id` para **1** acción | nulo |
| **O4. Detección por el `rule_id` del `execve` (`80792`)** | ¿hubo `execve` del ataque? | Uniforme | Atada a **auditd**; no cubre FIM/SCA/journald; `80792` es genérico y está en el catálogo; **rompería** los pilotos | medio |
| **O5. Nº bruto de alertas** | — | — | **Inválida** (redundancia + ajenos) | — |

### 2.2 Recomendación

> **O1 como cifra que decide + O2 como cifra de granularidad. O5/O3 quedan como anexo
> (transparencia), nunca como resultado.**

- **Resultado por técnica (la tabla del TFG):** `detectado = sí/no` (existe ≥1 fila `deteccion`
  anclada en **ambas** iteraciones), **+** los `rule_id` que la originan **+** la primera evidencia.
- **Granularidad:** `acciones cubiertas k/m` (p. ej. ATA012 `3/3`; ATA004 `1/1`).
- **Por qué:** es la única que es **comparable entre las 13 técnicas**, **inmune a la redundancia**
  (O3/O5 no lo son) y **no ata el TFG a auditd** (O4). Reutiliza el `esperado` ya validado por el
  humano. Es la que un tribunal sigue sin explicación adicional.

> La **cifra "82 en ruido"** (§1.2) **no** cambia el veredicto, pero **sí** la defensa: mientras el
> "ruido" contenga ataque, el recuento **no** es limpio. Por eso el §3 es inseparable del §2.

---

## 3. Arreglo del falso negativo (y del defecto sistemático)

### 3.1 Opciones de arreglo

| Opción | Qué hace | Arregla | Coste / riesgo |
|---|---|---|---|
| **A. Mínima (guardarraíl en el plegado)** | En `--revision`, **prohibir** `veredicto=ruido` cuando la fila es "del ataque" (cwd/ruta en su carpeta) | Las 4 filas plegadas (tar.gz + sudo) | Bajo. **Deja las 78 filas de árbol de procesos en `ruido_conocido`** |
| **B. Completa — "pertenencia al ataque" (RECOMENDADA)** | A + nueva regla de decisión: si la fila es "del ataque" y no casó una señal declarada → **categoría nueva `artefacto_ataque`** (nunca `ruido_conocido`) | **Las 82** | Medio. **Cambia las 12 ventanas** → regenerar (ver §3.5) |
| **C. Ancla por ruta en las señales declaradas** | Extender el ancla a `audit_file`/`audit_dir`/`syscheck_path`: un `watch` cuya **ruta** está en la carpeta del ataque se considera "del ataque" | El `.tar.gz` de ATA012 pasa de `sin_ancla` a **anclado** | Bajo, pero **solo** afecta a señales ya declaradas; no arregla las 78 |
| **D. Aplicar solo al escalado** | No tocar los cerrados; documentar la limitación | Nada en el repo | Nulo, pero **el recuento del repo sigue sucio** (viola la condición dura) |

### 3.2 Decisión recomendada (B + C + guardarraíl + test)

> **`artefacto_ataque` = "es del ataque, pero no es la detección de la técnica".**
> Se asigna **de forma determinista** (demostrable por la carpeta), **no** requiere revisión humana
> (fila mecánica y reproducible), y **nunca** cae en `ruido_conocido`.

**Orden de decisión propuesto (mínima modificación):**

```
1.   auto_ruido
2.   deteccion        (señal declarada ANCLADA: exe ∧ cwd/ruta-ancla ∧ audit_command)
1.5  operador
3.   dudosa           (ambigua / sin_ancla / sin_campos)
3.5  artefacto_ataque (NUEVO: fila "del ataque" que no casó detección → nunca ruido_conocido)
4.   deteccion        (novel)
5.   ruido_conocido   (baseline)  ← ahora SOLO contiene filas que NO son del ataque
```

- **"Del ataque"** = `audit_cwd` o ruta resuelta bajo `/home/angel/lab-attack/<ATA_id>`
  (constante `ATTACK_ROOT = "/home/angel/lab-attack/"`; el `<ATA_id>` se deriva del `--ata`, **así
  cubre también a los 3 del piloto sin editar su `esperado`** — punto 5 del orquestador).
- **Mejora C:** el match de ancla prueba también la **ruta** (`audit_file`/`audit_dir`/`syscheck_path`)
  resueltas contra el `cwd`. Así el `.tar.gz` (watch en la carpeta del ataque) queda **anclado**:
  con la lógica de la **ratificación de ATA007** ("la escritura es el ataque") → **`deteccion`**; si el
  humano prefiere no contarla como detección, → **`artefacto_ataque`**. **Nunca `ruido`.**
- **Guardarraíl de plegado:** si una fila "del ataque" recibe `veredicto=ruido` en `--revision`, la
  herramienta **falla ruidosamente** (`exit ≠ 0`) indicando la fila; se admite `deteccion` **o** el
  veredicto nuevo **`artefacto`**.
- **Aviso nuevo:** una fila `artefacto_ataque` con grupo `audit_command` (execve de un binario **no
  declarado**) emite **`AVISO`** *"posible señal de detección no declarada"* (aportará las 6 de ATA013).
- **Evidencia auditable:** en `artefacto_ataque`, `evidencia` debe llevar la **ruta/campo** que
  demostró la pertenencia (`audit_cwd=…` o `audit_file=…`), para que un revisor lo compruebe desde el
  propio `-Audited.csv` (que hoy **no** vuelca `audit_file`).

### 3.3 El tercer veredicto humano `artefacto` (opcional pero recomendado)

Hoy el humano solo puede elegir `deteccion`/`ruido`; eso **forzó** la mala etiqueta del `.tar.gz`. Con
el veredicto **`artefacto`** ("es el ataque, pero no cuenta como detección de la técnica") el problema
desaparece de raíz: mapea a `artefacto_ataque`, `revision=resuelta`, `veredicto_humano=artefacto`.

### 3.4 Coherencia documental (punto 6)

Aclarar en `politica_filtrado_ruido.md`: (i) el `sin_ancla` es `dudosa` **en la clasificación
automática**; (ii) si el humano pliega a `ruido`, la fila pasa a `ruido_conocido` **conservando el
motivo** — y eso **solo** es legítimo si la fila **no** es del ataque; (iii) nueva regla de
pertenencia. La política y el código deben volver a decir **lo mismo, literalmente**.

### 3.5 Retrocompatibilidad y qué se regenera

**Hecho medido: el arreglo B cambia las 12 ventanas** (82 filas salen de `ruido_conocido`). Por
tanto **no** habrá salida byte a byte para ningún ataque.

| Qué | Decisión recomendada |
|---|---|
| `…/linux/Auditado/ATA*_iter*-{Audited,Revision}.csv` | **Regenerar los 12** (6 ataques × 2 iter) |
| `…/linux/ATA*_meta.md` | Actualizar §8/§8.1/§9/§10 + `version`++ (6 fichas) |
| `Bitacora/ATA*.json` | Actualizar conteos/hashes + evento `correccion` (append-only) |
| `-Detalle.csv` / `-Detalle_raw.csv` | **No se tocan** (son la entrada; se re-filtra offline) |
| `esperado` congelados (incl. pilotos) | **No se tocan** (la carpeta se deriva del `ata_id`) |
| `Hojas/ATA_index.csv` | **Intacto** (el veredicto no cambia) |
| `Soporte/…/filtrar_ruido.py` + tests + política + plantilla | Modificar (§6) |

- **Alternativa "no tocar cerrados" (opción D):** aplicar B **solo al escalado** y dejar constancia
  de las 82 filas como **limitación declarada** de las 6 ventanas (que siguen `cerrado`/`review`). Es
  más barato y de riesgo cero, pero **el recuento del repo queda con ataque en "ruido"** → la
  condición dura **no** se cumple en el artefacto.
- **Recomendación:** **regenerar los 6**. Es el mismo patrón que ya se hizo en `fase-03-senales`
  (regenerar ATA004/007/012) y en `fase-03-cabos`: se re-filtran los **mismos** `-Detalle.csv`
  (offline, determinista) y se actualiza la **cadena de huellas**.

---

## 4. Los 3 del piloto, `ATA_index.csv` y las fichas

- **Los 3 del piloto (ATA002/008/013)** quedan **cubiertos por el arreglo B sin editar su `esperado`**
  (la carpeta del ataque se deriva del `ata_id`). Su anomalía de fondo (señal sin ancla / modo
  legado) **se documenta**; **no** se re-escriben sus `esperado` (regla: se escriben antes).
  - **ATA002:** su `deteccion` actual incluye **watch** (2 execve + 2 watch). Con la métrica O1 se
    reportan **2 acciones** (los execve de `dd`) y las escrituras se ven como huella; **la decisión
    se delega al humano** (ver gate 3).
- **`Hojas/ATA_index.csv`:** **sin cambios** (5 detectados / 1 no). El escalado podrá añadir una
  columna de métrica (`acciones k/m`).
- **Fichas:** actualizar las 6 existentes con la **tabla de métrica** (O1 + O2 + anexo) y el desglose
  `deteccion` / `artefacto_ataque` / `ruido_conocido`.

---

## 5. Diseño de verificación (regex de regresión + golden)

| # | Qué se demuestra | Cómo |
|---|---|---|
| **P1** | **Veredicto intacto**: los 6 ataques mantienen su resultado (**5 detectados / ATA013 no**) | mismo conjunto de `rule_id` con `deteccion` genuina (anclada) por ventana |
| **P2** | **Nada del ataque en "ruido"** | invariante: **0** filas con `cwd`/ruta en `/home/angel/lab-attack/<ATA>` en `ruido_conocido` **ni** `auto_ruido` (en las 12 ventanas) |
| **P3** | **Precisión (no un cepo):** las filas **ajenas** siguen siendo `ruido_conocido` | las **13** `sin_ancla` ajenas (los `systemctl --user` del cierre, los `find` de `update-motd.d`, el `find` sin `cwd`) **siguen `ruido_conocido`** (no están en la carpeta del ataque) |
| **P4** | **Determinismo (R-13)** | 2 pasadas por ventana → `sha256` idéntico |
| **P5** | **`pytest` verde** | suite actual (**86**) + tests nuevos |
| **P6** | **Golden del falso negativo** | (a) fila `watch` sobre un fichero **dentro** de la carpeta del ataque → **no** `ruido_conocido` (→ `deteccion` o `artefacto_ataque`); (b) `--revision` con `veredicto=ruido` sobre una fila del ataque → **la herramienta falla** (`exit≠0`) |
| **P7** | **Criterio único y aplicado a todos** | el invariante P2 se comprueba con **un solo** código sobre las **12** ventanas (6+3 pilotos incluidos); no hay rama especial por ataque |
| **P8** | **Guardarraíl `artefacto`** | plegar `veredicto=artefacto` → `categoria=artefacto_ataque`, `revision=resuelta`; no infla `deteccion` ni cae en `ruido` |
| **P9** | **Cadena de huellas** | `sha256` coherentes en cabecera ↔ bitácora ↔ ficha; `-Revision.csv` editables; sin secretos |

**Cifras esperadas (a confirmar por el executor, no se fijan aquí):** `ruido_conocido` **baja**
en 82 (reparto §1.2) y aparece `artefacto_ataque` ≈ 82 (+/- las que el humano reclasifique);
`deteccion` **no** baja en ninguna ventana.

---

## 6. Criterios de aceptación, riesgos y ficheros

### 6.1 Criterios de aceptación

| # | Criterio |
|---|---|
| **CA1** | Existe **definición de métrica** (O1+O2) escrita y aplicada de forma uniforme a las 6 fichas. |
| **CA2** | **0** filas de la carpeta del ataque en `ruido_conocido`/`auto_ruido` en las 12 ventanas (P2/P7). |
| **CA3** | Los **6 veredictos no cambian** (5/1) y **ninguna detección genuina se pierde** (P1). |
| **CA4** | Las **13** filas ajenas siguen `ruido_conocido` (P3) — el arreglo es **preciso**, no un cepo. |
| **CA5** | Golden del falso negativo + guardarraíl de plegado en verde (P6/P8). |
| **CA6** | Determinismo (P4), `pytest` verde (P5), sin secretos, sin commit (P9). |
| **CA7** | Cadena de huellas coherente; `-Detalle.csv` y `esperado` **intactos**; `ATA_index.csv` intacto. |
| **CA8** | Política/código/docstring **coincidentes literalmente** (incl. la aclaración de §3.4). |

### 6.2 Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `_artefactos/scripts/filtrar_ruido.py` | categoría `artefacto_ataque`, constante `ATTACK_ROOT`, ancla por ruta, guardarraíl de plegado, veredicto `artefacto`, `AVISO`; docstring |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | +tests P2/P3/P6/P7/P8 |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | §2/§3.5/§4/§5 + aclaración §3.4; `version`++ |
| `Soporte/Ataques/plantilla_esperado.md` | pertenencia por carpeta + veredicto `artefacto` |
| `Soporte/Ataques/piloto_procedimiento.md` | paso 11: veredictos permitidos; paso 12: tabla de métrica |
| `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA*_iter*-{Audited,Revision}.csv` | **12 regenerados** (si gate 2 = regenerar) |
| `Dataset/Ataques/Resultados/Wazuh/linux/ATA*_meta.md` (6) | métrica + conteos + `version`++ |
| `Bitacora/ATA*.json` (6) | conteos/hashes + evento `correccion` |

**No se toca:** `-Detalle*.csv`, `esperado` (incl. pilotos), `Hojas/ATA_index.csv`,
`extraer_alertas.py`, `preflight_enmascaramiento.py`, `Soporte/Wazuh/Reglas/**`, `_recursos/`,
`BBDD/`, `Hojas/Detecciones.xlsx`, `Estudio-Wazuh/`.

### 6.3 Riesgos

| Riesgo | Mitigación |
|---|---|
| Meter en `artefacto_ataque` una fila que **sí** es ajena | La pertenencia se basa en la **carpeta que solo crea el ataque** (demostrable). P3 lo verifica. |
| Ocultar una **detección no declarada** al mandarla a `artefacto_ataque` | `AVISO` por execve no declarado; la ficha reporta el conteo de `artefacto_ataque` (transparencia). |
| `autocrlf` rompe hashes al regenerar | No hacer `checkout/stash/reset`; regenerar por script; verificar `sha256` (P9). |
| Sobrecoste de revisión humana | La nueva categoría es **determinista** (no va a revisión); solo son dudosas las filas que casan señales declaradas y fallan ancla (las 13 actuales). |
| Que el arreglo sea un "cepo" (todo a artefacto) | P3 exige que las ajenas sigan en `ruido_conocido`. |

### 6.4 Qué NO entra

Escalar técnicas; Windows; η; RS3/RS4; memoria; `BBDD`; `xlsx`; re-medir / re-extraer; editar
`esperado`; tocar `_recursos/`; commits/push.

---

## 7. Gate humano (decisiones, en lenguaje sencillo)

> **Contexto en una frase:** Wazuh **sí** detecta los 5 ataques; el problema es que hoy **la huella
> del propio ataque** (los comandos que ejecutó él mismo, y el fichero que creó) aparece contada como
> "ruido", y eso **no** es defendible ante un tribunal. Son **82 filas** (≈4,5 % de las 1.836 filas
> de `ruido_conocido`, pero **100 % evitables**: todas están dentro de la carpeta del ataque).

**D1 — La métrica (mi recomendación: opción A).**
¿Cómo contamos "detectado"?
- **A (recomendada):** **Sí/No** + **qué regla** lo vio + **cuántas acciones** del ataque se
  cubrieron (`k/m`). Simple y comparable.
- B: solo `rule_id` distintos (lo actual). Infla (una acción = hasta 3 reglas).
- C: solo por el `rule_id` del `execve`. Ata el TFG a auditd.

**D2 — El arreglo (mi recomendación: opción B).**
¿Qué hacemos con la huella del ataque que hoy cae en "ruido"?
- **B (recomendada):** nueva etiqueta **`artefacto_ataque`** ("es del ataque, pero no es la detección
  de la técnica"), automática. Y **prohibir** que algo del ataque se llame "ruido".
- A: solo impedir el mal plegado (arregla 4 filas, deja 78).
- D: no tocar nada ahora y aplicarlo solo a las 7 técnicas que faltan (el repo queda "sucio").

**D3 — ¿Regeneramos las 6 ventanas ya cerradas? (mi recomendación: SÍ).**
- **Sí:** volver a pasar el filtro sobre los mismos CSV (offline, ~minutos) y actualizar fichas,
  bitácoras y huellas. El resultado (5 detectados / 1 no) **no cambia**.
- No: dejarlas como están y aplicar el arreglo solo al escalado (más barato, pero el "ruido" del
  repo seguiría conteniendo ataque).

**D4 — Los 3 del piloto (ATA002/008/013), sin ancla.**
- **Recomendada:** cubrirlos con la misma regla (derivando la carpeta del `ata_id`), **sin** editar su
  `esperado`; documentar que su señal es "de nombre" (legado).
- Alternativa: dejarlos como están.

**D5 — El tercer veredicto humano `artefacto` (mi recomendación: SÍ).**
Además de `deteccion`/`ruido`, permitir **`artefacto`** ("es el ataque, no cuenta como detección").
Evita que vuelva a pasar lo del `.tar.gz`.

---

## 8. Notas de ejecución

1. **Orden:** (i) política/docstring + tests (contrato) → (ii) mecanismo en `filtrar_ruido.py` →
   (iii) prueba a **temporal** sobre las 12 ventanas (P1–P3, P7) → (iv) si el gate D3 = sí,
   **regenerar** en su sitio + actualizar fichas/bitácoras (P9).
2. **Encoding/integridad:** CSV **UTF-8 sin BOM** con **LF**; **no** `checkout/stash/reset` sobre
   `esperado`/`Audited`; hashes en minúsculas.
3. **Determinismo:** el `AVISO`/`CONFLICTO` va a `stderr`, **nunca** a la salida.
4. **Meseta:** si un `rule_id` genuino desaparece de `deteccion`, **parar** y reportar.
5. **Sin secretos, sin commit/push** (los hace el orquestador).

---

## 9. Referencias

- Diagnóstico y resultados previos: `_fases/fase-03-senales/change-doc.md` (§2/§4/§5),
  `_fases/fase-03-senales-ratificacion/change-doc.md` (§4).
- Política y convención: `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`,
  `Soporte/Ataques/plantilla_esperado.md`, `Soporte/Ataques/criterio_doble_iteracion.md`.
- Herramientas: `_artefactos/scripts/filtrar_ruido.py`, `_artefactos/scripts/extraer_alertas.py`.
- Datos: `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/*`, `Dataset/Legitimo/ruleids_legitimos.csv`.
