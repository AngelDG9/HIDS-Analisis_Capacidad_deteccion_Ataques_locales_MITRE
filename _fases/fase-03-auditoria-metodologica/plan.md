---
fase: 3
bloque: fase-03-auditoria-metodologica
nombre: Auditoría metodológica de los 43 (ART vs propio · criterios escritos · pre-staging · rule_id 11 · .gitattributes · cobertura ART)
version: 3
status: approved_by_human
fecha: 2026-10-01
fecha_aprobacion: 2026-10-01
aprobado_por: humano
autor: tfg-planner
gate: **APROBADO (2026-10-01)** con las 4 confirmaciones del humano: **(a) lista de motivos** neutra (6 códigos); **(b) "cuándo" del pre-staging** + **1 solo documento** con las 3 normas; **(c) `.gitattributes` de 3 líneas, SIN `.csv`** (los CSV quedan **declarados sin protección**); **(d) ATA035 pasa de `review` → `cerrado`**.
---

# Plan — Auditoría metodológica de los 43 ataques y criterios de la Fase 3

> **Bloque de ANÁLISIS.** No se ataca ninguna técnica. Se audita **cómo se construyó** el
> corpus (con **citas del repo**), se dejan **criterios escritos**, se **rellena el "por qué"**,
> y se hacen **tres arreglos mínimos y reversibles**: el falso positivo `rule_id 11`, un
> `.gitattributes` mínimo y la regeneración del mapa de cobertura de ART.
>
> La **repetición** de ataques (por ART o por pre-staging) **no entra aquí**: la lista se
> decide por el humano **después** de esta auditoría y se ejecuta en un **bloque posterior**.

> **Cambios de esta versión (v3)** respecto a v2: (1) lista de motivos **neutra de plataforma y
> fusionada**; (2) **pre-staging define el CUÁNDO** (los CÓMO ya estaban); (3) las **3 normas se
> funden en 1 documento con 3 apartados** (recomendación KISS); (4) se **corrige el contenido
> del `.gitattributes`** por un riesgo real detectado (ver §A y §5-T7); (5) se **arregla el
> orden** de tareas; (6) se añaden verificaciones de consistencia y la nota de Windows.

---

## A. Evaluación fría (crítica honesta, sin adornos)

1. **`.gitattributes` con `*.csv text eol=lf` ROMPE las 1.411 huellas.** Evidencia medida
   (2026-10-01): `DataSet/.../ATA001_iter1-Detalle.csv` está en **CRLF** en el working tree
   (`sha256=3f3c115b…`, que es el **citado** en `Bitacora/ATA001.json`), pero el **blob** de
   git es **LF** (`sha256=3c3344ff…`). Hay **97 ficheros citados** en `w/crlf` (todos
   `*-Detalle.csv` y `*-Revision.csv`). Forzar `eol=lf` haría que un clon materializara LF →
   **97 desincronías**. La prueba de clon lo cazaría, pero entonces el objetivo del fichero
   (proteger `.csv` del CRLF) es **inalcanzable sin re-basar hashes** (prohibido). **Recorte:**
   `.b64 binary` + `.png binary` (+ `*.sh text eol=lf`, que es seguro: ningún `.sh` citado está
   en CRLF) y **no tocar `.csv`**. Dato de fondo: la cadena ya es frágil — depende de
   `core.autocrlf=true` local; hay que **declararlo**, no ocultarlo.
2. **Orden circular T1↔mapa.** En v2 la auditoría (T1) usaba la columna `art_disponible` "del
   mapa regenerado (T7)" pero declaraba depender de `—`. Corregido: **regenerar el mapa primero**.
3. **`no_se_comprobo` = "no debe quedar ninguno" vs "no re-atacar".** Contradicción. Se resuelve
   definiéndolo como *"no se comprobó ART al diseñar **y** no hay evidencia en el repo"*; con el
   **cruce mecánico** contra el mapa regenerado (T1) los 43 deberían poder clasificarse como
   `art_*`/`propio_*`. Si aun así queda algún `no_se_comprobo`, es un hallazgo **legítimo**, no
   se maquilla.
4. **Colapsar los 3 `propio_por_*` en `propio_por_diseno` pierde el "por qué"** — que es
   justamente el objetivo del bloque. Compensación obligatoria: `motivo_detalle` **obligatorio**
   para `propio_por_diseno` y `otro` ("seguridad", "medir otra variante", "medir otra capa"…).
5. **Sobreingeniería a recortar:** (a) 3 normas → **1 documento**; (b) el "test opcional" del
   helper de auditoría **sobra** (con 43 filas basta el script de extracción factual); (c)
   `material_externo` y `se_sustituyo` se **solapan** con `motivo_detalle`: dejar `se_sustituyo`
   que sea la cita y `material_externo` que liste artefactos, sin duplicar prosa.
6. **La prueba de clon exige commit local.** Un `git clone` materializa **commits**, no el
   *working tree*: si T5/T6 no están commiteados, el clon prueba un estado viejo. Hay que
   **commit local antes del clon** (nunca `push`). v2 lo mencionaba de pasada; aquí es explícito.
7. **`rule_id 11` como `auto_ruido`** es discutible: la firma es "alerta interna de Wazuh", no
   "proceso de Wazuh". Es aceptable, pero debe quedar **declarado como decisión de clasificación**.
   Verificado: **ningún** `*_esperado.csv` declara `rule_id 11`, así que no silencia detecciones.
8. **Falta:** verificación de **consistencia** E1↔cobertura y E1↔casillas; y **constancia** de que
   `cobertura_atomic.csv` (`nota`) es **Linux-céntrica** (para Windows habrá que revisarla + línea
   base + adaptar el filtro → **otro bloque**, aquí solo se deja escrito).

---

## 1. Decisiones ya fijadas por el humano (este plan diseña el CÓMO, no las rediscute)

| # | Decisión | Diseño de este plan |
|---|---|---|
| **D1** | **Auditoría de los 43**, ataque por ataque, **con citas del fichero**: ¿ART o propio? ¿por qué? ¿cómo se construyó? ¿se sustituyó algo? ¿se trajo material de fuera? → **tabla de 43 filas** + **las 2 listas**. | Tareas **T2** (tabla) y **T3** (listas). |
| **D2** | **Normas** de método (elección/grado de ART · ataque manual · pre-staging), **un solo documento con 3 apartados**, **neutro de plataforma**. | Tarea **T4** (recomendación KISS: 1 doc). |
| **D3** | **Rellenar el "por qué" de los 43**: campo **estructurado** aditivo (**fuente** + **motivo** de lista cerrada). No se reescribe la historia. | Tarea **T5**. |
| **D4** | **Arreglar el FP `rule_id 11`** con los requisitos dictados (cambio **mínimo y estrecho**; prueba sobre las **86 ventanas**; test nuevo; reversible; actualizar política, fichas y `review` de ATA035; `deteccion` **449 → 448**; **ATA035 sale de `review`**). | Tarea **T6**. |
| **D5** | **`.gitattributes` mínimo** + verificar que **las 1.411 huellas** siguen cuadrando (con **clon real** en temporal). | Tarea **T7** (contenido corregido, §A.1). |
| **D6** | **Regenerar el mapa de cobertura de ART** (hoy 13 de 43; caducado y mal formado). | Tarea **T1** (va **primero**: alimenta la auditoría). |
| **D7** | **Los 43 antiguos NO se re-atacan**: solo se **rellena la casilla**. La norma de **pre-staging es para los ataques nuevos**. | §5-T5 y §8. |

---

## 2. Alcance y principios

- **Solo lectura sobre los datos** (alertas, CSV, `esperado` firmados). Las **únicas
  escrituras** son las explícitas de D2–D6, todas **mínimas, justificadas y reversibles** (git).
- **Toda conclusión cita un fichero real del repo** (fichero + ruta + campo/línea). Nada se
  afirma "de memoria".
- **NO se ataca**, no se tocan VMs, no se repiten ataques, no se toca la métrica salvo el fallo
  puntual de D4 (con su prueba).
- **Redacción neutra y profesional.**
- **Nunca `push`**; los commits son locales. `_recursos/` no se toca. Sin secretos.

---

## 3. Entregables (rutas concretas)

| # | Entregable | Ruta | Tipo |
|---|---|---|---|
| **E1** | Mapa de cobertura ART regenerado (43 filas) + §6 de la ficha | `Hojas/cobertura_atomic.csv` + `Soporte/Ataques/atomic_red_team.md` §6 | regeneración |
| **E2** | Tabla de auditoría de los **43** | `Hojas/auditoria_origen.csv` | nuevo (derivado) |
| **E3** | Las **2 listas** (repetir por ART / por pre-staging) + narrativa | `_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` | nuevo (bloque) |
| **E4** | **Norma única** con 3 apartados (ART · ataque manual · pre-staging) | `Soporte/Ataques/criterio_ataques.md` | nuevo (vivo) |
| **E5** | Campo aditivo **fuente + motivo** en las **43** bitácoras | `Bitacora/ATA<NNN>.json` (bloque `atomic`) | edición mínima |
| **E6** | Arreglo FP `rule_id 11` | código + política + tests + salidas ATA035 | edición mínima |
| **E7** | `.gitattributes` mínimo | `.gitattributes` (raíz) | nuevo |

> E4 **sustituye** a los antiguos E3/E4/E5 de v2 (3 ficheros → 1). Razón en §5-T4.

---

## 4. Tareas y orden

Orden: **primero** la evidencia (T1 mapa → T2 ), luego la redacción (T3–T4), luego los cambios
físicos (T5–T7) para que la verificación de huellas (T7) sea sobre el **estado final**.

| Tarea | Qué hace | Depende de | Modo |
|---|---|---|---|
| **T1** | Regenerar `Hojas/cobertura_atomic.csv` (43) + actualizar `atomic_red_team.md` §6. | — | regeneración |
| **T2** | Auditoría ataque por ataque → `Hojas/auditoria_origen.csv` (43 filas, con citas). Usa T1. | T1 | lectura + redacción |
| **T3** | Las **2 listas** (criterio + candidatos) → `auditoria_decisiones.md`. | T2 | redacción |
| **T4** | Escribir la **norma única** E4 (3 apartados). | T2 | redacción |
| **T5** | Añadir **fuente + motivo** aditivo a las 43 bitácoras. | T2 (códigos) | edición mínima |
| **T6** | Arreglar FP `rule_id 11` (código + política + tests + salidas ATA035). | T2 | edición mínima |
| **T7** | Aplicar `.gitattributes` mínimo + **commit local** + verificar huellas con **clon**. | T5, T6 (estado final) | edición mínima |

---

## 5. Detalle por tarea

### T1 — Regenerar el mapa de cobertura de ART (E1) — **va primero**

- Ejecutar `_artefactos/scripts/cobertura_atomic.py` → `Hojas/cobertura_atomic.csv` con **43
  filas** (hoy 13), ordenado y **bien formado** (cabecera + una fila por ATA; sin filas
  vacías/duplicadas). Comprobar determinismo (segunda ejecución **byte a byte** idéntica).
- Actualizar `Soporte/Ataques/atomic_red_team.md` **§6** para que **no contradiga** el CSV
  (sustituir la tabla de 13 filas por el resumen + puntero al CSV regenerado).
- **Contingencia:** el clon de ART está **ignorado por git**. Si no estuviera presente en el
  host, **no se fabrica** el mapa: se declara **"no factible"** y la tarea queda pendiente.
  (Verificado 2026-10-01: el clon **sí** está presente → ejecutable.)
- **Nota de plataforma (solo constancia):** la columna `nota` del CSV (`cubierta` /
  `solo_linux` / `solo_windows`) está pensada con **víctima Linux**. Para una auditoría Windows
  habrá que revisarla + línea base Windows + adaptar el filtro → **otro bloque**.

### T2 — Auditoría de los 43 (solo lectura) → `Hojas/auditoria_origen.csv` (E2)

**Una fila por ATA (43).** Columnas:

```
ata_id, tecnica, tactica,
via,                 # ART_tal_cual | ART_adaptado | propio
fuente_bitacora,     # valor literal del bloque atomic.fuente
art_disponible,      # prueba_art (sí/no) del mapa regenerado (T1)
tests_plataforma,    # nº de pruebas de ART para la técnica en ESTA plataforma (mapa T1)
art_usado,           # sí/no ejecutó una atómica
motivo_codigo,       # lista cerrada (ver abajo)
motivo_detalle,      # frase; OBLIGATORIA si motivo_code ∈ {propio_por_diseno, otro, art_no_prueba_plataforma}
como_se_construyo,   # método real, con cita
se_sustituyo,        # qué se cambió respecto al enfoque de ART (o "—"), con cita
material_externo,    # artefactos traídos de fuera (ART, payload precompilado, receptor…)
cita_bitacora,       # ruta del JSON (y campo)
cita_readme,         # ruta del README (y apartado)
candidato_repetir_art,
candidato_repetir_prestaging
```

**Fuentes de evidencia** (todas del repo, sin recordar): `Bitacora/ATA<NNN>.json` (bloque
`atomic`, `prueba_de_efecto`, `hallazgos`), `Dataset/Ataques/Comandos/*/README.md` (fila `Vía` y
§2), `Hojas/cobertura_atomic.csv` (T1), `Soporte/Ataques/piloto_procedimiento.md` §12–§13 y
`Soporte/Ataques/receiver/README.md`.

**Método:** helper **read-only** `_artefactos/scripts/auditar_origen_ataques.py` extrae las
columnas **factuales** (fuente literal, técnica, artefacto, cruce con la cobertura). Las
columnas de **juicio** (`como_se_construyo`, `se_sustituyo`, `material_externo`, `motivo_detalle`)
las redacta el ejecutor **con cita**. Reproducible para las columnas factuales. **Sin test
automático propio** (43 filas; recorte de sobreingeniería, §A.5).

**Lista cerrada de `motivo_codigo`** (neutral de plataforma, fusionada — **a confirmar en gate**):

| Código | Significado | `motivo_detalle` |
|---|---|---|
| `art_no_prueba_plataforma` | ART no tiene prueba para **esta** plataforma. El detalle aclara **"ninguna"** (no hay prueba en ninguna) o **"solo la otra"**. | **Sí** (obligatorio) |
| `art_requiere_red_nube` | La prueba de ART pide internet / nube / SaaS. | No |
| `art_mecanismo_no_coincide` | Existe prueba para la plataforma, pero **no coincide con el mecanismo** del corpus. | No |
| `propio_por_diseno` | Se diseñó a mano **a propósito** (motivo en detalle: factibilidad offline, otra capa del HIDS, seguridad, medir otra variante, control del efecto…). | **Sí** (obligatorio) |
| `no_se_comprobo` ⚠️ | **No se comprobó** ART al diseñar **y** no hay evidencia en el repo. Es el **hueco a tapar**: con el cruce mecánico de T1 el objetivo es **0**. | No |
| `otro` | Cualquiera no clasificable arriba. | **Sí** (obligatorio) |

> **Fusiones respecto a v2:** `art_sin_prueba_linux` + `art_solo_windows` → `art_no_prueba_plataforma`
> (con detalle "ninguna"/"solo la otra"); `propio_por_factibilidad` + `propio_por_diversidad_capas`
> + `propio_por_control_del_efecto` → `propio_por_diseno` (el matiz va en `motivo_detalle`, §A.4).

> **Dato de partida (verificado 2026-10-01):** el campo `atomic.fuente` **no está normalizado**
> (`"ART"` en ATA001; `"atomic-red-team"` en ATA002/004/008/013; `"custom"` en los 38 restantes).
> La auditoría deja constancia de esa deuda histórica (no la oculta).

### T3 — Las 2 listas → `auditoria_decisiones.md` (E3)

> **Entregable para el humano.** No se repite nada aquí; se proponen candidatos con criterio.
> La lista final la fija el humano **después** de leer la auditoría.

- **Lista A — repetir por ART.** Criterio (todas): el ataque es **propio**; el mapa T1 le da
  **≥1 prueba de esta plataforma**; esa prueba es **ejecutable offline sin NAT** y del **mismo
  mecanismo**. Se marca `candidato_repetir_art=1` en E2 y se lista con coste (2 ventanas por ataque).
- **Lista B — repetir por pre-staging.** Criterio: el ataque **siembra el activo legítimo dentro
  de `[t0,t1]`** y esa semilla genera señales `ambigua`/`artefacto` que **ensucian** la lectura,
  **siempre que la creación de la semilla NO sea la técnica**. Se marca
  `candidato_repetir_prestaging=1`.
- **Regla de oro:** una repetición **no borra** el resultado anterior (se **añade** ventana y se
  declara el cambio de método). Incluir **coste** (2 ventanas: revert + ataque + extracción +
  filtrado + ficha + bitácora, con C0 y validación humana del `esperado`) y **prioridad**.

### T4 — Norma única con 3 apartados (E4) — **recomendación KISS: 1 documento**

**Decisión:** **un solo documento** `Soporte/Ataques/criterio_ataques.md` con **3 apartados**,
en vez de 3 ficheros. Razón: son **tres decisiones del mismo acto de diseño** (diseñar un
ataque); se enlazan entre sí; 3 ficheros cortos casi vacíos es peor para el lector y para el
mantenimiento. Se mantiene el estilo "documento vivo" (como `criterio_doble_iteracion.md`) con
enlaces cruzados a `plantilla_esperado.md` y `politica_filtrado_ruido.md`.

- **§A — Elección y grado de ART:** **tal cual · adaptado · propio**, con **motivo obligatorio**
  (`motivo_codigo`) cuando es propio. Condiciones para usar ART: (1) prueba de **esta
  plataforma**; (2) ejecutable **offline sin NAT** (o pre-staging declarado, §C); (3) **mismo
  mecanismo**. Si falta alguna → propio **con `motivo_codigo`**. Encaja con E5.
- **§B — Cómo se diseña un ataque manual:** paso a paso de la técnica → **mecanismo → capa del
  HIDS** → comando; **guardarraíl** obligatorio; **prueba de efecto independiente de la alerta**;
  `esperado` redactado **antes** y **validado por el humano**; declarar **realismo acotado**.
- **§C — Pre-staging: el CUÁNDO (§C.1) y el CÓMO (§C.2).**
  - **§C.1 — CUÁNDO se usa pre-staging:**
    1. **Solo** cuando el ataque necesita algo que **NO está en el laboratorio** (herramienta /
       fichero / servicio) para ser **fiel** al mecanismo.
    2. Si ese algo es **pequeño y fijable** (**URL + `sha256`**) → **se trae antes de `t0`**.
    3. Si es un **servicio real externo** (nube / AWS / web real) → se declara **"no factible"**.
    4. La decisión se toma **al diseñar el ataque** (en `c0/ATA<NNN>_c0_plan.md`), **no** durante
       la ventana.
  - **§C.2 — CÓMO (las 3 reglas ya fijadas):** (1) el material entra **ANTES de `t0`** (fuera de
    `[t0,t1]`); (2) **pequeño y fijado** (URL + `sha256`) — reproducible; (3) **nada de
    nubes/emuladores**; lo que no se resuelva así se declara **"no factible"**.

> **Neutro de plataforma (constancia):** el documento debe ser válido también para Windows. Allí
> el reparto cambia (ART tiene muchas pruebas, habrá que levantar su **línea base Windows** y
> **adaptar el filtro**) → **otro bloque**; aquí solo se deja escrito.

### T5 — Campo aditivo en las 43 bitácoras (E5)

- **Añadir** dentro del bloque `atomic` de cada `Bitacora/ATA<NNN>.json`:
  - `"fuente_norm"`: `art_tal_cual` | `art_adaptado` | `propio`
  - `"motivo_codigo"`: un código de la **lista cerrada** de T2
  - `"motivo_detalle"`: frase; **obligatoria** para `propio_por_diseno`, `otro` y
    `art_no_prueba_plataforma`.
- **No se modifica** ningún campo existente (`fuente`, `nota`, hashes, conteos): solo se
  **añaden** claves. El `"fuente"` literal se conserva como **provenance histórica**.
- **Los 43 antiguos NO se re-atacan** en este bloque: solo se **rellena la casilla**. La norma de
  pre-staging (§C) aplica a **ataques nuevos**, no a estos.
- Al ser un cambio **aditivo**, la cadena de huellas no se ve afectada (las bitácoras **no** son
  objeto de hash en `auditar_cadena_huellas.py`; verificado: ningún fichero cita el sha de una
  bitácora). Se verifica que los 43 JSON siguen **parseando** y que el recuento de códigos es 43.

### T6 — Arreglo del FP `rule_id 11` (E6)

**Diagnóstico (evidencia, verificado 2026-10-01):** `rule_id 11` (grupo `stats`, alerta
**interna** de Wazuh) cae en `novel → deteccion` en `ATA035_iter2-Audited.csv` (línea 265). En
`ATA011_iter1` la **misma** regla 11 ya cae en `auto_ruido` **por traer `audit_cwd=/var/ossec`**.
Cambia `deteccion` **449 → 448**. **ATA035 sale de `review`**.

**Cambio (mínimo y estrecho):**
1. En `_artefactos/scripts/filtrar_ruido.py`, dentro de `detectar_auto_ruido`, **tras** los pasos
   actuales (nombre de proceso / `cwd == /var/ossec` / glob `/var/ossec/var/run/*`), añadir un
   paso **al final** que reconozca la firma **interna** de Wazuh: **`rule_id == "11"` ∧ grupo
   `stats`** → `auto_ruido` (`motivo=auto_ruido:stats`, `evidencia=rule_id=11`). Clave: **al ir al
   final**, `ATA011_iter1` conserva su `motivo`/`evidencia` actuales **byte a byte**.
   - **Nunca** se discrimina por `agent_name` (todas las filas son `victima-linux`): la condición
     es la **firma de la propia regla interna**, no la víctima.
   - Decisión declarada (§A.7): se clasifica como `auto_ruido` ("interno Wazuh") aunque no sea un
     proceso de Wazuh. Verificado que **ningún** `*_esperado.csv` declara `rule_id 11`.
2. **Test automático nuevo** en `test_filtrar_ruido.py`:
   - una alerta con **firma de ataque** (agente víctima; p. ej. `80792` en `audit_command`,
     declarada como detección) **no** puede clasificarse como ruido interno;
   - una fila `rule_id=11` **sin** grupo `stats` **no** entra en el predicado interno;
   - una fila `rule_id=11` **con** `stats` sí → `auto_ruido`.
3. Actualizar `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` (§3, versión 7) con la
   regla y su motivo; mantener **literalmente** alineados doc y código.
4. Regenerar `ATA035_iter2-Audited.csv` (mismos inputs; solo cambia la fila 11) y actualizar
   `Bitacora/ATA035.json` (nuevo `audited_sha256` de iter2; `rule_id_distintos=["80792"]`;
   `doble_iteracion: "iguales"`; retirar la sorpresa 11) y `ATA035_meta.md` (§8/§8.1/§9).
5. **Prueba obligatoria sobre las 86 ventanas:** re-clasificar las 86 con el código nuevo y
   confirmar que **la única** diferencia respecto a `HEAD` es la línea `rule_id 11` de
   `ATA035_iter2`. **Si cambia cualquier otra cosa → ⛔ se revierte.**

**Consecuencia de registro:** al quedar `doble_iteracion=iguales`, **ATA035 sale de `review`** →
se propone pasar su `estado` a `cerrado` en `Hojas/ATA_index.csv` y en su bitácora/ficha. Es el
único cambio de `estado`; **no** se tocan los `review` históricos del piloto (ATA002/008/013).

### T7 — `.gitattributes` mínimo (E7) + verificación de huellas

> **Contenido corregido tras la evaluación fría (§A.1).**

```gitattributes
*.b64 binary
*.png binary
*.sh  text eol=lf
```

- **Objetivo real:** que un clon **no** corrompa los **binarios/base64** (`.b64` → `binary`, sin
  conversión de EOL) ni el `.png`; y que los `.sh` sean **LF** en cualquier clon (hoy ya lo son;
  seguro).
- **PROHIBIDO tocar `.csv` en este fichero.** Evidencia: 97 CSV citadas están en **CRLF** en el
  working tree y su `sha256` **citado** es el de CRLF, mientras el **blob** de git es LF. Añadir
  `*.csv text eol=lf` (o `-text`) cambiaría los bytes materializados → **rompería las 1.411
  huellas**. Si el humano insistiera en tocar `.csv`, sería **incompatible** con la cadena de
  huellas actual y quedaría **fuera de alcance**.
- **Plan B:** si al aplicar este fichero **cualquier** huella deja de cuadrar → **revertir**
  `.gitattributes` y documentar la limitación (la fragilidad de la cadena por `core.autocrlf`
  queda **declarada**, no oculta).

**Verificación (prueba fuerte, pedida por el humano):**
1. `git add -A` + **commit local** (nunca `push`) para que el clon materialice el estado final.
2. `git clone` del repo local a un **directorio temporal**.
3. En el clon: `python _artefactos/scripts/auditar_cadena_huellas.py --repo <tmp>` → **0
   desincronías** (1.411 citas verificadas).
4. En el clon: los 4 `.b64` decodifican (`base64 -d`) y `git hash-object` del `.png` coincide con
   el blob de `HEAD`.
5. Local: `git check-attr -a -- <rutas>` muestra las reglas esperadas.

---

## 6. Ficheros que se tocarán

| Fichero | Tarea | Naturaleza |
|---|---|---|
| `Hojas/cobertura_atomic.csv` | T1 | regenerado |
| `Soporte/Ataques/atomic_red_team.md` (§6) | T1 | edición mínima |
| `Hojas/auditoria_origen.csv` | T2 | nuevo |
| `_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` | T3 | nuevo |
| `Soporte/Ataques/criterio_ataques.md` | T4 | nuevo (vivo) |
| `Bitacora/ATA001..ATA043.json` | T5 | **aditivo** (solo claves nuevas) |
| `Bitacora/ATA035.json` | T6 | edición mínima |
| `Hojas/ATA_index.csv` | T6 (solo `estado` de ATA035) | edición mínima |
| `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA035_iter2-Audited.csv` | T6 | regenerado |
| `Dataset/Ataques/Resultados/Wazuh/linux/ATA035_meta.md` | T6 | edición mínima |
| `_artefactos/scripts/filtrar_ruido.py` | T6 | edición mínima |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | T6 | test nuevo |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | T6 | edición mínima (v7) |
| `_artefactos/scripts/auditar_origen_ataques.py` | T2 | nuevo (solo lectura) |
| `.gitattributes` | T7 | nuevo |

**No se tocan:** `esperado` firmados, el resto de `-Audited.csv`, `Hojas/Detecciones.xlsx`,
`_recursos/`, `BBDD/`, `Reglas/**`, y **ningún `.csv` vía `.gitattributes`** (§A.1).

> `state.md`, `roadmap.md` y el `change-doc` los actualiza el **orquestador** al cierre.

---

## 7. Verificación (`tfg-tester`) y criterios de aceptación

| # | Criterio de aceptación | Cómo se verifica |
|---|---|---|
| **CA1** | `Hojas/cobertura_atomic.csv` tiene **43 filas**, bien formado y **determinista** (re-ejecución byte a byte idéntica); `atomic_red_team.md` §6 coherente | re-ejecución + diff |
| **CA2** | `Hojas/auditoria_origen.csv` tiene **43 filas** (una por ATA) y **cada celda de dato cita un fichero real** | recuento + **muestreo de 5 filas al azar**: cada una se contrasta contra su `Bitacora/ATA<NNN>.json` / README citados (0 campos inventados) |
| **CA3** | **Consistencia** entre E2 y E1: `art_disponible`/`tests_plataforma` de la tabla coinciden con el CSV de cobertura | cruce programático de las 43 filas |
| **CA4** | Existen **las 2 listas** con **criterio, candidatos, coste y prioridad** | lectura de `auditoria_decisiones.md` |
| **CA5** | Existe la **norma única** con los 3 apartados (§A/§B/§C) y el **CUÁNDO** de pre-staging (§C.1) + las 3 reglas (§C.2) | `ls` + lectura de `criterio_ataques.md` |
| **CA6** | Las **43 bitácoras** tienen `fuente_norm` + `motivo_codigo` válidos (`motivo_detalle` donde es obligatorio); JSON válido; **nada más cambió** | parseo JSON + recuento 43 + `git diff` aditivo + `auditar_cadena_huellas.py` → 0 desincronías |
| **CA7** | **FP `rule_id 11`:** re-clasificar las **86 ventanas** → **solo** cambia la línea `rule_id 11` de `ATA035_iter2`; `deteccion` **449 → 448**; **ATA035 sale de `review`** | re-ejecución de `filtrar_ruido.py` sobre las 86 ventanas + `git diff`; **si cambia otra línea → ⛔ revertir** |
| **CA8** | **Test nuevo** de firma de ataque pasa; suite completa en verde | `pytest` (93 + nuevos) |
| **CA9** | Política actualizada y **coincidente** con el código; ficha y bitácora de ATA035 coherentes | lectura + `git diff` |
| **CA10** | **`.gitattributes`:** tras **commit local + clon a temporal**, **las 1.411 huellas cuadran** (0 desincronías); `*.png` intacto; los **4 `.b64`** decodifican; **ningún `.csv`** cambia de bytes | `auditar_cadena_huellas.py --repo <clon>`; `git hash-object`; `base64 -d`; `git check-attr` |
| **CA11** | Nada medible ajeno cambió: `git status` solo con los ficheros del bloque; sin secretos; `_recursos/` intacto; **sin `push`** | `git status`, revisión |

**Plan B (contingencias):**
- Si T6 cambia **cualquier** línea distinta de `ATA035_iter2` → **revertir** el cambio de código.
- Si `.gitattributes` altera bytes al clonar → **revertir** `.gitattributes` y documentar.
- Si falta el clon de ART → no regenerar el mapa; declarar **"no factible"**.
- Si algún `no_se_comprobo` no puede resolverse con evidencia → **se deja declarado** como hueco
  (no se fabrica un motivo).

---

## 8. Qué NO entra (fuera de alcance)

- **Repetir ataques** (ni por ART ni por pre-staging): es un **bloque posterior**; aquí solo la
  **lista**. **Los 43 antiguos NO se re-atacan**; la norma de pre-staging (§C) es para **ataques
  nuevos**.
- **Las ~29 técnicas restantes** de P1-Linux, **la evasión**, **Windows** (solo se deja
  constancia de la neutralidad de la lista/normas), **Fase 4** y **la memoria**.
- **Tocar la métrica** salvo el **fallo puntual** de T6, con su prueba. **No** se reescriben
  `esperado` firmados ni datos; no se recalcula nada más.
- **Tocar `.csv` vía `.gitattributes`** (rompería las huellas, §A.1).
- Tocar `_recursos/`, `BBDD/`, `Detecciones.xlsx`, `Reglas/**`; `push` (solo se admite el
  **commit local** que exige la prueba de clon de CA10).

---

## 9. Gate humano (lenguaje sencillo)

> **En una frase:** hemos medido 43 ataques; ahora **auditamos cómo** los hicimos, dejamos
> **una norma con 3 apartados**, **rellenamos el "por qué"**, **arreglamos un falso positivo**
> con una prueba estricta, **blindamos los binarios** con un `.gitattributes` mínimo (sin tocar
> los CSV, que romperían las huellas) y **regeneramos el mapa de ART** — sin atacar nada.

**Se pide aprobación para:**
1. **T1–T4.** Regenerar la cobertura ART (13 → 43), auditar los 43 (con citas) y publicar la
   tabla + las 2 listas + la norma única.
2. **T5.** Añadir `fuente`+`motivo` a las 43 bitácoras (**solo rellenar**, sin re-atacar).
3. **T6.** Arreglar `rule_id 11` (**449 → 448**; ATA035 de `review` a `cerrado`; la prueba de las
   86 ventanas lo protege).
4. **T7.** Aplicar el `.gitattributes` mínimo (`.b64`/`.png`/`.sh`, **sin `.csv`**) y verificar
   las 1.411 huellas con un clon real.

**Pendiente de tu decisión (posterior a la auditoría, no se ejecuta aquí):** leer las **2 listas**
y elegir qué ataques repetir en el **bloque siguiente**.

**A confirmar en el gate:**
- (a) la **lista cerrada de motivos** de T2 (6 códigos, neutral de plataforma);
- (b) el **CUÁNDO** de pre-staging (§C.1) y la **norma única** con 3 apartados (vs 3 ficheros);
- (c) el contenido exacto del `.gitattributes` (**3 líneas, sin `.csv`** — por el riesgo de las
  97 CSV citadas en CRLF);
- (d) si ATA035 pasa a `cerrado` al desaparecer su `review`.
