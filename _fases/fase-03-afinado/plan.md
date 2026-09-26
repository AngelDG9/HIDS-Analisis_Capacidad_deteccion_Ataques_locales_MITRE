---
fase: 3
bloque: fase-03-afinado
tarea: A3.0 (afinado H1–H4) · prepara el escalado (F-03 · R-09/R-11/R-13)
nombre: Afinado de las 4 mejoras del piloto (H1–H4) antes de escalar
version: 1
status: approved_by_human
fecha: 2026-09-26
fecha_aprobacion: 2026-09-26
aprobado_por: humano
autor: tfg-planner
gate: humano — **APROBADO ✔ (2026-09-26)**: (a) este plan; (b) **H2** (la detección decide, sanidades a aviso, **ventana completa sin recortes**, `t0` tras el asentamiento, **NO** se recalcula el piloto, con nota de coherencia v1/v2); (c) **H3** (solo se auto-excluye lo **demostrable**: `5715` con `srcip` del operador; **`5501`/`5502` → `dudosa`**; `19004` por grupo `sca`); (d) **H1** (chequeo **C0 aviso, no bloqueo**, con paso 0 y root autorizados).
---

# Plan — Bloque `fase-03-afinado`: las 4 mejoras del piloto (H1–H4)

> El **piloto está CERRADO y verificado** (`_fases/fase-03-piloto/`, 15/16 PASA). Antes de **escalar**
> a las 10 técnicas restantes hay que **quitar los 4 enganchones** que el piloto reveló (H1–H4),
> porque cada uno **se multiplicaría** en el escalado (más dudosas, más `review`, más puntos ciegos).
> **KISS:** se afina **lo mínimo** para que el escalado nazca limpio. **No** se re-hace la maquinaria.
>
> **Fichero único de retorno: este `plan.md`.** Nada más se escribe en este bloque hasta el gate.

---

## 0. Objetivo y alcance

**Objetivo:** refinar **4 artefactos ya existentes** (pre-flight, criterio de doble iteración, filtro de ruido, convención de señales) para corregir los hallazgos H1–H4 del piloto, **sin romper el determinismo** (R-13) ni los artefactos cerrados del piloto.

- **Entra:** los 4 afinados (H1–H4), sus tests offline, la documentación de las políticas afectadas, y la **verificación del piloto como banco de pruebas** (en copia, sin sobrescribir sus artefactos).
- **NO entra (fuera de alcance):**
  - **Escalar** a las 10 técnicas restantes del corpus (bloque siguiente: `fase-03-escalado`).
  - **Windows** y el *split* del baseline por SO (se hará cuando toque).
  - **η / precio de la detección** (Fase 4) y gráficas.
  - **Re-diseñar C1/C2** del pre-flight (H1 **añade** un chequeo, no toca los existentes).
  - **Escribir reglas RS3/RS4** y su pre-flight de despliegue.
  - **Redactar la memoria** / tocar `_recursos/`.
  - **Cambiar los artefactos cerrados del piloto** (los 3 `_esperado.csv`, los `-Audited.csv`, las bitácoras, `ATA_index.csv`): **salvo** que el humano apruebe expresamente **recalcular veredictos** (ver §4, decisión H2). Por defecto: **NO se tocan**.
  - Instalar dependencias / re-baselinar.

---

## 1. Diagnóstico de partida (datos reales del piloto, inspeccionados)

| # | Hallazgo | Evidencia medida en el piloto | Mejora |
|---|---|---|---|
| **H1** | **Enmascaramiento base-contra-base**: `92600` (level 0, `0850-audit_rules.xml`, **RS1**) es **hermana** de `80792` (`0365-auditd_rules.xml`, **RS2**), mismo grupo `audit`; suprime el `execve` de `python3` → ATA013 = **0 detecciones**. | `92600` ∈ RS1 (`active_ruleset.txt` l.179); `80792` ∈ RS2 (l.198); en `ATA013_iter1-Detalle.csv` **no hay ninguna fila `audit_exe=python3`** (el `execve` no generó alerta). | Chequeo **C0 base-contra-base** en el pre-flight. |
| **H2** | **El ruido de arranque dispara las sanidades** de la doble iteración. | Conteos: ATA002 iter1 vs iter2 → `auto_ruido 606→641`, `ruido_conocido 404→125`; los **3 criterios formales PASAN** (detección idéntica), pero las **2 sanidades fallan** → `review` en los 3. | Criterio nuevo: **la detección decide**; las sanidades de ruido dejan de bloquear. El arranque se aparta **sellando `t0` tras el asentamiento** (no recortando la ventana). |
| **H3** | **`sin_campos` → dudosas sistemáticas** por sesiones del operador y SCA. | **185 filas** dudosas: ATA002 **177** (`ambigua:T1485-A2`), ATA008 **7**, ATA013 **1** (`19004`); las `sin_campos` son `rule_id ∈ {5501,5502,5715,19004}` (**19** en total). **Origen en el JSON (verificado):** `5715` trae `data.srcip=192.168.65.1`; `5501/5502` **no** traen IP ni id. de sesión (solo usuario); `19004` no tiene origen. | **Regla ∧ contexto**: auto-excluir **solo lo demostrable** (`5715` con `srcip` del operador; `19004` por grupo `sca`). **`5501/5502` → no auto-excluir** (`dudosa`). |
| **H4** | **Señales genéricas** (`audit_exe` solo). | Las filas de **detección** de ATA002/008 **sí** traen `audit_cwd=/home/angel/lab-attack/ATA<NNN>`; en ATA013 hay **6 filas** con `cwd=…/ATA013` (pero no `python3`, por H1). | Añadir **`audit_cwd` = carpeta del ataque** como señal. |

> ⚠️ **Dato de la inspección que condiciona H1:** en ATA013 **no** hay filas `python3` en el detalle → H1 **no** se puede resolver con los CSV del piloto; hay que **demostrarlo con `wazuh-logtest`** (paso 0, root) y versionar la captura.

---

## 2. H1 — Pre-flight **base-contra-base** (chequeo C0)

**Objetivo:** que el examen **avise cuando la detección esperada de una técnica pueda quedar silenciada por una regla de fábrica**, para que un "0 detecciones" quede **explicado automáticamente**.

**Decisión de diseño (KISS, determinista):** **añadir un tercer chequeo C0** al pre-flight existente. **No se toca C1 ni C2.**

- **C0 · base-contra-base (empírico, `wazuh-logtest` diferencial NULO).** Para una **lista corta de eventos sintéticos** derivados de las **señales esperadas** de la técnica (p. ej. una línea `audit` de `execve` del `audit_exe` esperado), se captura `wazuh-logtest -v` **con el ruleset base desplegado** (0 reglas propias) y se parsea la **regla ganadora por evento**. Si la ganadora tiene **`level=0`** (no emite alerta) → **AVISO: "detección esperada silenciada por regla de fábrica `<id>`"**. Es determinista (mismo evento → misma ganadora) y reutiliza el parser de logtest que ya existe (`parse_logtest`, `resolver_ancestro`).
- **Por qué así y no 100 % estático:** decidir si un `<match>`/`<if_group>` de un silenciador cubre el predicado de otra regla **no es decidible en general** (misma conclusión que llevó a C2). `wazuh-logtest` da la verdad del motor.
- **Cómo se hace determinista y verificable:**
  1. **Paso 0 (con root, una vez):** capturar `wazuh-logtest -v` de los **eventos sintéticos** (golden de H1: uno `python3`, uno `ls`) → `fixtures/c0_logtest_base.txt`. Versionado.
  2. El chequeo **C0 offline** consume esa captura (o una nueva): no necesita root al re-ejecutarse.
  3. **Sin captura C0 → `INCOMPLETO`** (nunca PASA en silencio) — coherente con el contrato actual.
- **Golden GOLDEN obligatorio de H1** (debe quedar como **test offline** en `test_preflight_enmascaramiento.py`):
  - **python3** (evento `execve` con `comm="python3"`, `key="audit-wazuh-c"`) → ganadora **`92600`** (`level=0`) → **AVISA**.
  - **ls** (mismo `key="audit-wazuh-c"`, `comm="ls"`) → ganadora **`80792`** (`level=3`) → **NO avisa**.
- **Contrato de C0:** **aviso** (no bloquea el despliegue, porque el silenciador es de fábrica y **no** lo controlamos); **se integra en el informe** y, si `--out`, queda versionado. Código de salida: un **AVISO de C0 no cambia `PASA/FALLA`**; añade una sección `## C0` y aparece en la línea final como `RESULTADO: PASA (AVISOS: C0=1)`. *(Decisión a aprobar en el gate: ¿aviso o bloqueo? Se propone **aviso**.)*
- **Uso en el escalado:** el ejecutor ejecuta C0 **para cada técnica antes de medir**; si avisa, el "0 detecciones" de esa técnica queda **explicado**, no como sorpresa.

**Ficheros H1:** `_artefactos/scripts/preflight_enmascaramiento.py` (añadir C0; C1/C2 intactos) · `_artefactos/scripts/tests/test_preflight_enmascaramiento.py` (+ fixtures `c0_*`) · `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md` (§C0) · `preflight_informe.md` (ejemplo con C0) · fixture de captura logtest del golden.

---

## 3. H2 — Criterio de doble iteración nuevo

**Objetivo:** que el criterio **mida lo que importa (la detección)** y que `review` **informe de algo**.

**Regla nueva (propuesta, a aprobar):**

1. **Criterio que DECIDE (bloqueante):**
   - **C1′ ·** **mismo conjunto de `rule_id`** con `categoria=deteccion` en iter1 e iter2; **y**
   - **C2′ ·** recuento de `deteccion`: `|n2 − n1| ≤ max(2, 10 % · n1)`; **y**
   - **C3′ ·** **ninguna fila `dudosa` sin resolver** (se mantiene).
2. **Sanidades (pasan a NO bloqueantes):** los totales de `auto_ruido` y `ruido_conocido` **se siguen calculando y registrando**, pero su desviación **solo se reporta como aviso** (`review_motivo`), **no** fuerza `review`. **Justificación:** esas dos categorías dependen del **churn de arranque** (y del régimen), no del ataque; en el piloto la detección fue **idéntica** y aun así 3 ataques quedaron en `review`. El criterio actual **medía el ruido del arranque, no la detección**.
3. **Ventana de cálculo: la ventana COMPLETA `[t0,t1]`. Sin exclusiones por tiempo.** Las sanidades se calculan sobre **todas** las filas de la ventana `[t0,t1]` (que ya está **en régimen**, ver punto 4). **No** se excluye ningún tramo por tiempo (en particular, **no** existe una "ventana de asentamiento" dentro de `[t0,t1]`). **Por qué es justo y comparable:** las **dos iteraciones parten del mismo estado limpio** (`lab-revert` a `lab-listo` + asentamiento antes de `t0`) → la diferencia que quede entre iteraciones es **ruido real de régimen**, no churn de arranque. Determinista (solo depende de los timestamps reales de la ventana).
4. **Paso operativo (mecanismo PRINCIPAL para el arranque): sellar `t0` ≥ 60–90 s DESPUÉS de confirmar el agente `Active`.** Así el **ruido de arranque se queda FUERA de la ventana** (ocurre **antes** de `t0`) y el ataque empieza ya en régimen. Es la vía para que `[t0,t1]` sea comparable entre iteraciones **sin** recortar la ventana a posteriori. Se documenta en el runbook (`Soporte/Ataques/piloto_procedimiento.md` §2, paso 2/4: esperar al asentamiento antes de sellar `t0`).
   > ⚠️ **Restricción de coherencia (corregida):** **NO** se define ninguna exclusión `[t0, t0+90 s]` de las sanidades. Con ventanas reales de **30–45 s** (piloto: ATA002 44/31 s, ATA008 39/41 s, ATA013 40/41 s), tal exclusión cubriría **la ventana entera** y dejaría la sanidad **sin datos**. El arranque se aparta **moviendo `t0`** (punto 4), no recortando la ventana.

**Prueba (recalcular los 3 ataques del piloto):** con la regla nueva, sobre los `-Audited.csv` ya cerrados:

| ATA | detección i1/i2 | conjunto rule_id | C1′/C2′/C3′ | veredicto **nuevo** |
|---|---|---|---|---|
| ATA002 | 4 / 4 | `{80781,80790,80792}` | ✅/✅/✅ | **`iguales`** |
| ATA008 | 2 / 2 | `{80791,80792}` | ✅/✅/✅ | **`iguales`** |
| ATA013 | 0 / 0 | `{}` | ✅/✅/✅ | **`iguales`** |

> ⚠️ **IMPACTO DECLARADO (decisión de gate):** el piloto está **cerrado y verificado**; sus
> `doble_iteracion: "review"` viven en `Bitacora/ATA002|008|013.json` y `ATA_index.csv`
> (`estado=review`). **DECISIÓN CERRADA (aprobada por el humano): NO se recalculan.** Se **aplica la
> regla nueva solo al escalado**; los 3 ataques del piloto conservan su `review`.

**📌 Coherencia para la memoria (decisión del humano — dejar por escrito, sin tocar el bloque cerrado):**
en `Soporte/Ataques/criterio_doble_iteracion.md` quedará una **nota de trazabilidad** que diga, literalmente:
> *Los 3 ataques del piloto (ATA002, ATA008, ATA013) se **evaluaron con el criterio v1** (3 criterios
> formales + 2 sanidades bloqueantes) y quedaron `review` por el **ruido de arranque**. Con el
> **criterio v2** (la detección decide; las sanidades pasan a aviso) **darían `iguales`**. No se
> recalcularon porque el piloto está **cerrado y verificado**; su `review` es **histórico del criterio
> v1**, no una discrepancia de detección.*

Esto da **coherencia** a la memoria (el lector ve ambos criterios y por qué difieren) **sin reescribir**
bitácoras, fichas ni `ATA_index.csv` (append-only y cerrado). Los `doble_iteracion: "review"` del
piloto **no** se tocan.

**Ficheros H2:** `_fases/fase-03-piloto/plan.md` §6 (referencia, `status` cerrado → **no se edita**; se anota el cambio en el runbook) · `Soporte/Ataques/piloto_procedimiento.md` (§2 cierre y §6) · **nuevo** `Soporte/Ataques/criterio_doble_iteracion.md` (la regla vigente, versionada **con la nota de coherencia v1/v2**). *No se tocan* bitácoras ni `ATA_index.csv`.

> Nota KISS: hoy el criterio **se aplica a mano** (no hay script). Este bloque **no** crea herramienta nueva; solo **fija la regla** por escrito, deja la **nota de coherencia v1/v2** y la prueba sobre los CSV existentes. Un script de doble iteración es **opcional** y se puede añadir al escalar (§9).

---

## 4. H3 — Excluir sesiones del operador y SCA (LO MÁS DELICADO)

### 4.0 Evaluación de las propuestas del humano (regla **+ origen**) — **incorporada, con matices**

**La preocupación es legítima y la propuesta va en la dirección correcta.** Un `5715` *"sshd: authentication success"* puede ser **nuestra** sesión o la de **un atacante**; excluirlo solo por regla sería un **falso negativo silencioso**. Verificado con datos reales (`Dataset/Muestras/baseline_muestra.jsonl`):

| `rule_id` | ¿Trae **origen** en el JSON? | Qué campo | ¿Discrimina operador vs atacante? |
|---|---|---|---|
| **5715** | **Sí** | `data.srcip = 192.168.65.1`, `srcport`, `dstuser=angel` | **Sí**: la IP del **host/sobremesa** (operador). Otra IP → atacante. |
| **5501** | **No** | `data.srcuser=angel`, `dstuser=angel`, `uid=0` | **No** por IP: solo el **usuario**. |
| **5502** | **No** | `data.dstuser` (`angel`/`root`) | **No** por IP: solo el usuario. |
| **19004** | **No** | (SCA, sin campos de origen) | **No aplica**: es el HIDS, no un login. |

> ⚠️ **Hallazgo que matiza la propuesta:** "de dónde viene la conexión" **solo es discriminable en `5715`** (tiene `srcip`). En **`5501`/`5502`** el `full_log` **no trae IP** (solo PAM con usuario) y **`19004`** no tiene origen alguno.

### 4.0.bis Segunda duda del humano (la que cierra el agujero) — **tiene razón: `dstuser==angel` no demuestra nada**

Mi primera redacción excluía `5501`/`5502` si `dstuser == angel`. **Es un falso negativo silencioso del mismo tipo que corregimos en `5715`:** `angel` es el usuario **de la víctima**, así que el predicado **no distingue** *"ha entrado el operador"* de *"ha entrado un atacante **con ese mismo usuario**"* (credenciales válidas / cuentas válidas, T1078). Y como PAM **no lleva `srcip` ni id. de sesión**, **no existe forma local de demostrar la atribución**.

- **Aclaración pedida por el humano (confirmada):** da **igual** que su usuario de **Windows** se llame `angel`. El predicado mira `data.srcuser`/`data.dstuser`, que son los usuarios **de dentro de la víctima** (Linux `angel`), **no** el nombre de la cuenta de Windows del operador. No es un dato relevante para la decisión.

**Opciones evaluadas:**

| Opción | Qué hace | Veredicto |
|---|---|---|
| **(A) Segura** | **No auto-excluir** `5501`/`5502` → quedan `dudosa` (revisión humana). | ✅ **ELEGIDA.** Coste bajo (13 filas en el total del piloto; ~2–8 por ventana) y respeta el principio **"si no puedes demostrarlo, no lo ignores"**. |
| **(B) Intermedia (nivel de ventana)** | Excluir `5501`/`5502` si en la **misma ventana** hay un `5715` con `srcip` del operador. | ❌ **Descartada.** Si en la ventana entra **también** un atacante desde otra IP, **no se puede atribuir cada PAM a una sesión concreta** (no hay id. de sesión en el evento PAM) → **podrías descartar algo ajeno**. Es *"demostrar por proximidad"*, no por evidencia: **viola el principio acordado**. Un **aviso** no lo salva: el dato se perdería igual. |
| **(C) Correlación por id. de sesión/tty o `audit` `ses=`** | Atribuir el PAM a la sesión SSH concreta. | ❌ **Descartada por coste y por falta de dato:** el evento PAM (`full_log` sshd/pam) **no** trae `ses=` ni tty del login; requeriría cruzar con `audit.log` (`ses=`) y aun así no resuelve el caso de dos sesiones simultáneas. **Sobreingeniería** para ~13 filas. |

### 4.1 Decisión final: identificación **regla ∧ contexto**, con el origen como condición **demostrable** y **nada** auto-excluido sin prueba

Predicado de exclusión explícito por regla:

| `rule_id` | Grupo requerido | **Condición de exclusión (estrecha)** | Fundamento |
|---|---|---|---|
| **5715** | `sshd`/`syslog`/`authentication_success` | **`srcip ∈ OPERADOR_SRCIPS`** = `{192.168.65.1}` | Es **nuestra** sesión (host del operador). **Demostrable** por la IP. **SSH del atacante desde otra IP → NO se excluye → dudosa/detección.** |
| **5501** | `pam`/`sshd`/`syslog` | **NINGUNA → no se auto-excluye** (queda `dudosa`) | Sin IP ni id. de sesión **no hay prueba**. Se revisa a mano. |
| **5502** | `pam`/`sshd`/`syslog` | **NINGUNA → no se auto-excluye** (queda `dudosa`) | Ídem. |
| **19004** | `sca` | **sin condición de origen** (no existe): basta regla + grupo `sca` | Autoevaluación del HIDS, **inequívoca**; `19004` **no es un login** y **no se ve afectado** por la duda de PAM. |

- `OPERADOR_SRCIPS = {192.168.65.1}` (IP del **host en VMnet1**; a confirmar en el **paso 0** con `ipconfig`).
- **Principio rector declarado (explícito en la política):** *solo se auto-excluye lo que se puede **demostrar** como propio; lo que no, se **revisa** (`dudosa`).* `5501`/`5502` **no cumplen** → no se excluyen.
- **Regla general:** *nunca* se excluye una alerta de estas reglas si **no se cumple su condición**; si falta el campo de origen (`srcip`), la condición **no** se satisface → `dudosa` (**lado seguro**).
- **Dónde entra (cambio MÍNIMO):** **PASO 1.5**, **después** de `auto_ruido` (1) y de las señales de **detección** (2), **antes** de `dudosa`/`sin_campos` (3). Si una **señal de detección** casa la alerta → **gana `deteccion`** (garantía dura); si no y se cumple el predicado → `ruido_conocido`, `motivo=operador:<rule_id>`, `revision=""`.
- **Garantía estructural anti-frágil (nueva, por la preocupación del humano):** si el `esperado` del ataque **declara una señal** cuyo `campo=rule_id` (o `rule_group`) **casara una regla del predicado H3**, la herramienta emite **`CONFLICTO` por `stderr`** y **prevalece la detección** — así una señal declarada **nunca** se excluye en silencio y queda aviso trazable. Esto convierte el "depende de acordarse" en "si te olvidas, la detección declarada sigue ganando; si no la declaras, el riesgo es el de un `sin_campos` normal (queda dudosa, no ruido)".

### 4.2 Cambio de esquema declarado: campos de origen en el detalle

**Decisión:** **añadir `srcip,srcuser,dstuser` al `DETAIL_HEADER` de `extraer_alertas.py`** (hoy **no** expone el origen; verificado: `DETAIL_HEADER` acaba en `syscheck_path`). Sin este campo, la condición `srcip` de `5715` no es evaluable.

- **Coste:** bajo. `DETAIL_HEADER` es una **lista**; los tests construyen las alertas con esa constante (`ea.DETAIL_HEADER`) → **se adaptan solos**; el filtro lee **por nombre de columna** (`row.get(...)`) → tolerante.
- **Compatibilidad con el piloto (CERRADO):**
  - Los `-Audited.csv` del piloto **no cambian de esquema**: su `OUT_HEADER` (15 columnas) **no** incluye campos de origen y **no se toca** (el filtro puede leer el campo sin volcarlo).
  - Los `-Detalle.csv` del piloto **no se regeneran** (cerrados). Al ejecutar el filtro nuevo sobre ellos, `srcip` vendrá **vacío** → la condición de `5715` **no** se cumple → **no** se excluiría por la vía nueva. **Por eso la prueba de seguridad (§4.4) re-extrae** el detalle del **manager** (que **conserva** las alertas del 25-sep) con el extractor nuevo, a un **directorio temporal**, **sin** tocar los CSV versionados.
  - El `sha256` del detalle del piloto **no** se altera; la cabecera de los `-Audited.csv` sigue apuntando al detalle original (trazabilidad intacta).
- **Alternativa refutada:** re-extraer y **reescribir** los `-Detalle.csv` del piloto para meter el origen → **rompería** los `sha256` de los audited (están en su cabecera) y la verificación cerrada. **Descartada.**

### 4.3 Impacto en volumen (decisión A) y limitación declarada

**Cuántas filas del piloto quedan en `dudosa` con la decisión (A)** (datos reales de los `-Revision.csv`):

| Ventana | `5715` (se excluye si `srcip`=operador) | `5501`+`5502` (**quedan `dudosa`**) | `19004` (se excluye) |
|---|---|---|---|
| ATA008 iter1 | 1 | 1 + 1 = **2** | 0 |
| ATA008 iter2 | 1 | 1 + 2 = **3** | 0 |
| ATA013 iter1 | 2 | 3 + 3 = **6** | 0 |
| ATA013 iter2 | 1 | 1 + 1 = **2** | 1 |
| **Total piloto** | **5** | **13** | **1** |

- **`sin_campos` totales = 19** (`5501`=6, `5502`=7, `5715`=5, `19004`=1). Con (A): **13 filas** (PAM) quedan `dudosa`; `5715`(5) y `19004`(1) se auto-excluyen. **≈2–6 por ventana → volumen asumible** (la revisión es trivial: son "sesión del operador, ajena al ataque", como ya hicimos a mano).
- Las **177 de ATA002** son de otra naturaleza (`ambigua:T1485-A2`, no `sin_campos`) y **no** las toca esta decisión (se abordan con la señal específica de **H4**).
- **Limitación declarada (residual):** `5501`/`5502` **permanecen en revisión humana** por diseño (no se pueden demostrar). No es un defecto: es el **lado seguro**. Se documenta en la política.
- La lista **no** es extensible por grupo genérico: son **`rule_id` concretos** con predicado propio.

### 4.4 ⚠️ PRUEBA DE SEGURIDAD (banco = el piloto; **re-extraído en copia**) — debe **recalcularse con la decisión nueva**

> ⚠️ **La prueba al 100 % cambia respecto a la versión anterior del plan.** En el piloto, el humano marcó **a mano** las **185** filas (177 `ambigua` de ATA002 + 7 `sin_campos` de ATA008 + 1 de ATA013) como `ruido`. **Con (A), las 13 filas de `5501`/`5502` NO se auto-excluyen** → en la re-ejecución aparecerán como **`dudosa`**, no como `ruido`. La prueba **debe reflejar y explicar esa diferencia**, sin tocar el piloto.

En el **manager** (conserva los diarios del 25-sep), **re-extraer** las **6 ventanas** con el `extraer_alertas.py` nuevo (con `srcip/srcuser/dstuser`) a un **directorio temporal** y aplicar el filtro nuevo. Comprobar:

1. **`deteccion` no cambia**: ATA002 **4/4**, ATA008 **2/2**, ATA013 **0/0** en **cada** iteración (mismo conjunto de `rule_id`). **[al 100 %]**
2. **Ninguna otra fila cambia** de categoría (fuera de las `sin_campos` afectadas). **[al 100 %]**
3. **`5715` (5 filas) y `19004` (1)** → `ruido_conocido`, `motivo=operador:<rule_id>`, `revision=""` (auto-excluidas, con condición cumplida: `5715` con `srcip=192.168.65.1`). **[al 100 %]**
4. **`5501`/`5502` (13 filas)** → **`dudosa`** (`motivo=sin_campos`), `revision=pendiente` (decisión A). **Esta es la diferencia esperada respecto al piloto** (allí se marcaron a mano como `ruido`): se documenta, **no** es un fallo.
5. **Golden de seguridad del falso negativo (obligatorio, offline):**
   - **`5715` sintético con `srcip` ≠ `192.168.65.1`** (atacante) → **NO** se excluye → **`dudosa`** (no `ruido`).
   - **`5501`/`5502` con `dstuser=angel`** → **NO** se auto-excluyen → **`dudosa`** (decisión A).
   - Si una señal `deteccion` declara `rule_id=5715` (o `5501/5502`), la fila **sigue siendo `deteccion`** (paso 1.5 va después) y se emite `CONFLICTO`.

> **Interpretación de la prueba:** el éxito **no** es "reproduce al 100 % los 185 veredictos a mano", sino **"no cambia ninguna `deteccion` ni ninguna fila ajena, y las diferencias están exactamente en las 13 PAM, que quedan `dudosa`"** (lado seguro). Si alguna `deteccion` cambia o alguna fila ajena se mueve → **FALLA** y se rediseña.
> **Sin romper el piloto:** todo a `_artefactos/tmp/afinado/…`; **nunca** `--out` sobre `…/linux/Auditado/`. Los `sha256` del piloto **no se alteran**.

**Ficheros H3:** `_artefactos/scripts/filtrar_ruido.py` (**predicado `OPERADOR`** = solo `5715` con `srcip ∈ OPERADOR_SRCIPS` y `19004` con grupo `sca`; `5501/5502` **fuera** del predicado; paso 1.5 + motivo `operador:` + conflicto de señal) · `_artefactos/scripts/extraer_alertas.py` (**+ `srcip,srcuser,dstuser` en `DETAIL_HEADER`**; `--detail`/`--muestra`/agregado intactos) · `_artefactos/scripts/tests/test_filtrar_ruido.py` (+ golden §4.4.5) · `_artefactos/scripts/tests/fixtures/filtro_alerta_ejemplo.csv` (regenerar con columnas nuevas) · `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` (§2 orden paso 1.5, §5, motivo `operador:`, **principio "solo lo demostrable"** y limitación §4.3).

---

## 5. H4 — Señales "esperadas" más específicas (convención)

**Objetivo:** dejar **escrita la convención** y actualizar **runbook + plantilla/ejemplo**, para que los **10 ataques nuevos nazcan específicos**. **NO se tocan** los artefactos del piloto.

**Convención (decisión):** toda señal del tipo `audit_exe` de una **técnica que escribe en la carpeta del ataque** se **acompaña** de una señal de **contexto de directorio**:

```csv
T<id>-S1,deteccion,audit_exe,<herramienta>,Process Creation,T<id>,ejecucion de la herramienta (ver nota H4)
T<id>-S2,deteccion,audit_cwd,/home/angel/lab-attack/ATA<NNN>/*,Process Creation,T<id>,la señal de exe queda anclada al cwd del ataque
```

- **Regla de redacción:** `audit_exe` (proceso) **más** `audit_cwd` (carpeta del ataque) cuando el artefacto copia a `/home/angel/lab-attack/ATA<NNN>/`; el `audit_cwd` **ancla** el proceso al ataque y discrimina el churn (`/`, `var/ossec`…).
- **Ejemplo documentado (prueba, sin ejecutar ataques):** actualizar el **ejemplo** `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/ATA001_esperado.csv` (que **es un EJEMPLO de formato**, no un ataque ejecutado) para reflejar la convención `audit_exe` + `audit_cwd`; y documentar que la señal `audit_cwd` **ya casaba** en los datos reales del piloto (`audit_cwd=/home/angel/lab-attack/ATA002` en las 4 detecciones de ATA002; `/…/ATA008` en las 2 de ATA008) → la convención es **retrocompatible y verificada con datos**.
- **⚠️ NO se modifica** ningún `_esperado.csv` del piloto (ATA002/008/013): cambiar un `esperado` invalida el `sha256` de los `-Audited.csv` (están en la cabecera) y rompe la trazabilidad. Si el humano quisiera re-escribirlos, sería **otro bloque** con su impacto declarado.

**Ficheros H4:** `Soporte/Ataques/piloto_procedimiento.md` (§2.5/§5, convención de señales) · **nuevo** `Soporte/Ataques/plantilla_esperado.md` (o nota en el runbook) · `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/ATA001_esperado.csv` (ejemplo) · `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §4 (nota de convención, sin cambiar el esquema).

---

## 6. Ficheros que se tocarán (resumen)

| Fichero | Mejora | Cambio |
|---|---|---|
| `_artefactos/scripts/preflight_enmascaramiento.py` | H1 | **añadir** chequeo C0; C1/C2 intactos |
| `_artefactos/scripts/tests/test_preflight_enmascaramiento.py` + `fixtures/c0_*` | H1 | **nuevos** tests + golden python3/ls |
| `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md` | H1 | **sección C0** (contrato, aviso) |
| `Soporte/Wazuh/Configuracion/preflight_informe.md` | H1 | ejemplo con sección C0 |
| `_artefactos/scripts/filtrar_ruido.py` | H3 | predicado `OPERADOR` + `OPERADOR_SRCIPS` + paso 1.5 + `motivo=operador:` + conflicto de señal detectable |
| `_artefactos/scripts/extraer_alertas.py` | H3 | **+ `srcip,srcuser,dstuser` en `DETAIL_HEADER`** (solo `--detail`; agregado/`--test` intactos) |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | H3 | golden H3 + **golden del falso negativo (srcip ajeno → dudosa)** |
| `_artefactos/scripts/tests/fixtures/filtro_alerta_ejemplo.csv` | H3 | regenerar con las columnas nuevas |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | H3/H4 | orden (paso 1.5), dudosas, motivo `operador:`, **limitación §4.3**, nota de convención de señales |
| **nuevo** `Soporte/Ataques/criterio_doble_iteracion.md` | H2 | regla vigente, versionada |
| `Soporte/Ataques/piloto_procedimiento.md` | H2/H4 | t0 asentado; §2/§5/§6; convención de señales |
| **nuevo** `Soporte/Ataques/plantilla_esperado.md` | H4 | convención + ejemplo |
| `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/ATA001_esperado.csv` | H4 | ejemplo (formato) |
| *(solo si el humano recalcula)* `Bitacora/ATA00{2,8}.json`,`ATA013.json`,`Hojas/ATA_index.csv` | H2 | evento append + `estado` |

**No se toca:** los `-Detalle.csv`/`-Audited.csv`/`-Revision.csv` **versionados** del piloto, sus 3 `_esperado.csv`, sus fichas, `C1`/`C2` del pre-flight, `_recursos/`, `Hojas/Detecciones.xlsx`, `BBDD/`. *(El **esquema** de `OUT_HEADER` de los audited —15 columnas— **no** cambia; solo el **detalle** gana las 3 columnas de origen, y el piloto no se regenera.)*

---

## 7. Criterios de aceptación y casos de prueba

| # | Criterio verificable | Caso de prueba (sin ejecutar ataques) |
|---|---|---|
| **CA-H1-a** | C0 detecta el silenciamiento de fábrica. | **GOLDEN python3**: captura logtest con `python3` → ganadora `92600` (level 0) → **AVISA**. |
| **CA-H1-b** | C0 **no** da falso positivo. | **GOLDEN ls**: mismo `key` con `ls` → ganadora `80792` (level 3) → **NO avisa**. |
| **CA-H1-c** | C0 no rompe C1/C2 ni el contrato. | `pytest` en verde; repo con 0 reglas propias → **PASA**; sin captura C0 → `INCOMPLETO`; informe byte a byte idéntico (R-13). |
| **CA-H2-a** | La regla nueva clasifica la detección. | Recalcular los 3 del piloto → **`iguales`** (tabla §3); C1′/C2′/C3′ ✅. |
| **CA-H2-b** | Las sanidades dejan de bloquear y se reportan. | El informe/bitácora muestra el delta de `auto_ruido`/`ruido_conocido` **como aviso**, no como `review`. |
| **CA-H2-c** | Nada del piloto cambia por defecto. | `git status` no muestra cambios en los artefactos del piloto (salvo decisión expresa de recalcular). |
| **CA-H2-d** | Las sanidades se calculan sobre la **ventana completa `[t0,t1]`**, sin exclusiones por tiempo. | El cálculo usa **todas** las filas de la ventana; **no** existe recorte `[t0, t0+90 s]`; el runbook indica **sellar `t0` tras el asentamiento** (fuera de la ventana). |
| **CA-H3-a** ⭐ | **No cambia ninguna `deteccion` ni fila ajena**; las diferencias están solo donde toca. | Re-extraer las **6 ventanas** del manager (copia) + filtro nuevo: ATA002 4/4 · ATA008 2/2 · ATA013 0/0; **`5715`(5)+`19004`(1)** → `ruido_conocido` (`operador:*`); **`5501/5502`(13) → `dudosa`** (decisión A); ninguna otra fila cambia. |
| **CA-H3-b** | No descarta detecciones reales. | (i) fila que casa una señal `deteccion` → **`deteccion`** (paso 1.5 va después); (ii) señal declarada sobre regla del predicado → **`CONFLICTO`** por stderr y **gana detección**. |
| **CA-H3-c** | **Solo se auto-excluye lo demostrable.** | **`5715` con `srcip ≠ 192.168.65.1` → NO se excluye → `dudosa`**; `5715` con `192.168.65.1` → excluido. **`5501`/`5502` con `dstuser=angel` → NO se auto-excluyen → `dudosa`** (aunque el usuario coincida). Si falta `srcip` → condición **no** satisfecha → `dudosa`. |
| **CA-H3-d** | Estrecha y explícita. | Solo `rule_id` concretos con su predicado; un `5501` con grupo distinto → no excluido; `19004` requiere grupo `sca`. **Nada de exclusión por usuario/genérico.** |
| **CA-H3-e** | Esquema del detalle ampliado sin romper nada. | `extraer_alertas.py --detail` emite `srcip,srcuser,dstuser`; `--detail`/`--muestra`/agregado y `--test` siguen OK; los `-Audited.csv` del piloto (15 columnas) **intactos**. |
| **CA-H3-f** | El usuario de **Windows** del operador es irrelevante. | El predicado lee `data.srcuser`/`data.dstuser` (usuarios **dentro de la víctima**), no el nombre de la cuenta de Windows. |
| **CA-H4-a** | Convención escrita y ejemplo coherente. | La plantilla/ejemplo muestra `audit_exe` + `audit_cwd`; el runbook la describe; el esquema del esperado **no cambia**. |
| **CA-H4-b** | Retrocompatible con datos reales. | El ejemplo cita `audit_cwd=/home/angel/lab-attack/ATA<NNN>` (existe en ATA002/ATA008 del piloto). |
| **CA-det** | Determinismo (R-13) en todo. | Dos ejecuciones de C0 y del filtro con la misma entrada → salida byte a byte idéntica. |
| **CA-sec** | Sin secretos. | `grep` de la contraseña real → no aparece; "la contraseña del laboratorio" en docs. |
| **CA-nor** | No regresión. | `pytest _artefactos/scripts/tests/` en verde (todas las suites). |

## 8. Cómo se verifica (`tfg-tester`) — **sin lanzar ataques**

El tester **no ataca, no enciende VMs y no despliega reglas**:
1. **Suite:** `pytest _artefactos/scripts/tests/` en verde (H1/H3 añaden casos; no regresión de C1/C2 ni del filtro).
2. **H1:** reproduce los dos **golden** (python3 → avisa; ls → no) desde las **fixtures versionadas**; comprueba que C0 no rompe C1/C2, que sin captura C0 es `INCOMPLETO` y que el informe es determinista.
3. **H2:** recalcula la tabla §3 **desde los `-Audited.csv`** y comprueba que la regla nueva da `iguales`; verifica que la regla escrita en `criterio_doble_iteracion.md` coincide con el §3; confirma que **no** se han tocado los artefactos del piloto (salvo decisión expresa).
4. **H3 (prueba de seguridad):** **re-extrae** las **6 ventanas** del manager (a temporal) y aplica el filtro; comprueba CA-H3-a..f: `deteccion` intacta (4/4·2/2·0/0), `5715`(5)+`19004`(1) auto-excluidas, **`5501/5502`(13) → `dudosa`** (diferencia esperada vs. el piloto, explicada en §4.4), ninguna fila ajena cambia, y los **golden del falso negativo** (srcip ajeno → dudosa; PAM → dudosa; señal declarada → deteccion). Confirma que los `sha256` y el esquema de los artefactos del piloto **no** cambiaron.
5. **H4:** comprueba que la plantilla/ejemplo y el runbook describen la convención, que el esquema del esperado no cambió y que los 3 `_esperado.csv` del piloto están intactos.
6. **Determinismo y no-regresión** (CA-det, CA-nor) y **sin secretos** (CA-sec). **Veredicto PASA/FALLA con evidencia.**

## 9. Orden de las tareas y partición

1. **T1 — H3 (filtro):** primero, porque **desbloquea el volumen** del escalado y su prueba de seguridad es autocontenida. Incluye **ampliar `extraer_alertas.py`** (campos de origen) y **re-extraer las 6 ventanas del manager** (paso 0, root) para la prueba al 100 %. *(Trabajo acotado pero crítico.)*
2. **T2 — H2 (criterio):** trivial en código (no hay script); **decisión ya cerrada** (no recalcular + nota de coherencia). *(Trivial.)*
3. **T3 — H1 (pre-flight C0):** **el trabajo real** (paso 0 con root + capturas logtest + chequeo + golden). *(≈60 % del esfuerzo del bloque.)*
4. **T4 — H4 (convención):** documental + ejemplo. *(Trivial.)*

> **¿Partir?** Si al aprobar el humano H1 se quiere con más profundidad (p. ej. C0 sobre un catálogo completo de silenciadores), **H1 merece su propio bloque** (`fase-03-afinado-preflight`) por tamaño. Con el alcance mínimo de arriba, **cabe junto al resto**. **H2 y H4 son triviales**; **H3 es acotado pero delicado** (su valor está en la prueba al 100 % y en la **condición de origen**).

## 10. Paso 0 (requiere root en el manager/víctima; solo lectura + captura logtest)

1. **Confirmar la IP del operador (H3):** `ipconfig` en el **sobremesa** → fijar `OPERADOR_SRCIPS` = **IP del host en VMnet1** (esperado `192.168.65.1`). Debe **coincidir** con el `data.srcip` de los `5715` de las ventanas del piloto (se comprueba en la re-extracción del punto 4).
2. **Capturar las líneas `audit` de H1:** obtener de `audit.log` (víctima) o construir sintéticas las dos líneas `execve` del **mismo `key="audit-wazuh-c"`**: una con `comm="python3"` / `exe="/usr/bin/python3.12"` y otra con `comm="ls"` / `exe="/usr/bin/ls"`.
3. **`wazuh-logtest -v` con el ruleset base** (0 reglas propias) sobre esas 2 líneas → guardar captura `fixtures/c0_logtest_python3_ls.txt` y **confirmar** que ganan `92600` y `80792` respectivamente. **Evidencia para `preflight_demo`/`c0`.**
4. **Re-extraer las 6 ventanas (H3):** del **fichero diario del 25-sep** del manager (que **conserva** las alertas), con el `extraer_alertas.py` **nuevo** (con `srcip,srcuser,dstuser`) y las mismas ventanas `[t0,t1]` (de `times.log`/bitácoras), filtradas a `victima-linux`, a un **directorio temporal** (`_artefactos/tmp/afinado/`). **No** se sobrescriben los `-Detalle.csv` del piloto.
5. **Re-verificar el estado del manager** (0 reglas propias, servicios `active`) al terminar.
6. **No se toca nada del laboratorio** salvo la captura y la extracción a temporal (reversibles).
> La **contraseña del laboratorio** se usa **solo en memoria** (`sudo -S` por stdin); **jamás** se escribe en el repo.

## 11. Qué tiene que aprobar el humano (gate)

1. El **alcance** de las 4 mejoras tal como está (§2–§5) y que **el piloto no se toca por defecto**.
2. **H2 — regla nueva ya aprobada:** que **la detección decide** y las **sanidades de ruido pasan a aviso**; que las sanidades se calculan sobre la **ventana completa `[t0,t1]`** (sin exclusiones por tiempo) y que el arranque se aparta **sellando `t0` tras el asentamiento** (paso operativo); y **NO recalcular** el piloto, dejando la **nota de coherencia** v1/v2 (§3).
3. **H1 — que C0 sea AVISO, no bloqueo**, y que se autorice el **paso 0 con root** (captura `wazuh-logtest`, reversible) para el **golden python3/ls`.
4. **H3 — la identificación "regla ∧ contexto" con "solo se auto-excluye lo demostrable"**: `5715` **solo** si `srcip=IP del operador`; **`5501`/`5502` NO se auto-excluyen** → `dudosa` (opción A); `19004` por grupo `sca`. El **impacto declarado** (13 filas PAM en el piloto quedan `dudosa`, asumible), el **campo nuevo `srcip,srcuser,dstuser` en el detalle** (§4.2) y que **la prueba de seguridad (sin cambios en `deteccion`; diferencias solo en las 13 PAM; golden del falso negativo) es condición de aceptación**.
5. **H4 — la convención de señales** (`audit_exe` + `audit_cwd`) y que **NO** se modifican los 3 `_esperado.csv` del piloto.
6. Que **este bloque no escala** a las 10 técnicas y que **no se crea herramienta nueva salvo C0** (H2 no lleva script).

---

> **Resumen para el ejecutor — lo que necesito:** **VMs encendidas** para el **paso 0 de H1**
> (captura `wazuh-logtest`, con root) y la **contraseña del laboratorio** en el momento de ejecutar.
> Sin esa captura, el **golden de H1** no puede demostrarse y C0 quedaría `INCOMPLETO` (no se inventa).
