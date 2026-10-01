# change-doc — Bloque `fase-03-auditoria-metodologica`: auditoría de los 43 y criterios de la Fase 3

> Cierre. Fecha: **2026-10-01**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA** (tras **1 FALLA** corregida).
> Plan de referencia: `plan.md` (v3, `approved_by_human`). **Bloque de ANÁLISIS: no se atacó ninguna técnica.**

---

## 1. Objetivo

Cerrar **4 inquietudes metodológicas** levantadas por el humano, antes de seguir ampliando:
**(1) ART** (¿dónde se usó? ¿con qué criterio? ¿hay trazabilidad?) · **(2) ataques manuales** (¿cómo se hicieron? ¿son válidos?)
· **(3) `.gitattributes` + el falso positivo `rule_id 11`** · **(4) pre-staging** (¿conviene? ¿ensucia?). Y, con todo eso:
**¿hay ataques que deban repetirse?**

---

## 2. Resultado de la auditoría (los 43, con citas)

**`Hojas/auditoria_origen.csv`** — 43 filas, **100/100 citas resuelven** (verificador propio).

| `fuente` | Nº |
|---|---:|
| **ART tal cual** | **5** (ATA001, 002, 004, 008, 013) |
| **ART adaptado** | **1** (ATA018) |
| **Propio** | **37** |

| `motivo_codigo` (por qué no se usó ART) | Nº |
|---|---:|
| `propio_por_diseno` | 24 |
| `art_requiere_red_nube` | 8 |
| `na_art_usado` *(se usó ART; el motivo no aplica)* | 6 |
| `art_no_prueba_plataforma` | 2 |
| **`no_se_comprobo`** ⚠️ *(hueco declarado)* | **2** (ATA029, ATA030) |
| `art_mecanismo_no_coincide` | 1 |

> **Honestidad del método:** donde el repo **no permitía justificar** la elección, **no se inventó**: se marcó
> **`no_se_comprobo`** (hueco declarado). Son **2**, ambos con prueba de ART disponible y ejecutados a mano
> **sin dejar constancia del porqué**.

### Las 2 listas (candidatos a repetir — **decide el humano**)

| Motivo | Ataques | Coste |
|---|---|---|
| **Repetir por ART** (hay prueba usable y no se usó) | **ATA024, ATA029, ATA030, ATA038** | 2 ventanas c/u |
| **Repetir por pre-staging** (siembran el activo **dentro** de `[t0,t1]`) | **ATA014, ATA016, ATA029, ATA035, ATA036, ATA037, ATA038** | 2 ventanas c/u |

---

## 3. Los tres criterios escritos — `Soporte/Ataques/criterio_ataques.md` (1 documento, 3 apartados)

### §A — ART *(neutro de plataforma: sirve para Linux y para Windows)*
- **Si existe una prueba de ART que (a) corra en la plataforma del laboratorio, (b) sin internet y (c) haga el
 mismo mecanismo** → **se usa** y se **cita** (`guid` + fichero + `commit`).
- **Si hay que adaptarla** → se anota **qué se cambió**.
- **Si no se puede** → **propio + `motivo_codigo`** de la lista cerrada.
- **Se decide ANTES de atacar** (al diseñar, no después).
- En **Windows** cambia el **reparto** (ART tiene muchas más pruebas), **no la regla**; allí harán falta además
 su **línea base** y **adaptar el filtro** (otro bloque).

### §B — Ataque manual
El método paso a paso: técnica MITRE → *data components* → acciones → guardarraíles → **C0** → prueba del
efecto → validación humana.

### §C — Pre-staging
- **CUÁNDO:** cuando el ataque necesite **algo que no está en el laboratorio** (herramienta/fichero/servicio)
 para ser fiel. Se decide **al diseñar**.
- **Los 3 CÓMO:** ① el material se coloca **ANTES de `t0`**; ② solo material **pequeño y fijado** (URL + `sha256`);
 ③ **nada de nubes/emuladores**: lo que necesite un servicio real externo → **"no factible" declarado**.
- **Un solo modo por técnica** (no media con pre-staging y media sin él).

**Aplicación:** se **rellenaron** las casillas `fuente_norm` + `motivo_codigo` + `motivo_detalle` en **las 43
bitácoras** (aditivo: no se reescribió la historia). **La norma de pre-staging es para los ataques NUEVOS**:
**los 43 no se re-atacan** (solo se documentan).

---

## 4. El arreglo del falso positivo `rule_id 11` (con los requisitos del humano)

- **Qué era:** una alerta **interna del manager** (grupo `stats`) que, al no estar en el catálogo, caía en
 `novel` → **contada como "detección"**.
- **El cambio:** predicado **estrecho** y **al final** de la detección de ruido propio:
 *"grupo `stats` **y** origen manager (no de la víctima) → `auto_ruido:stats`"*. **Un ataque no puede producir
 una alerta así** (los ataques corren en la víctima).
- **La prueba (obligatoria):** re-pasado el filtro por **las 86 ventanas** → **85/86 byte a byte idénticas**;
 **solo cambia `ATA035_iter2`** (2 líneas). `ATA011_iter1` (misma regla 11 con `cwd=/var/ossec`) **intacta**
 (el predicado va al final). **Si hubiera cambiado algo más → se revertía.**
- **Resultados:** `deteccion` **449 → 448** · **ATA035 pasa de `review` → `cerrado`** (su `review` era falso)
 · **4 tests nuevos** (una firma de ataque **nunca** es ruido interno) · **política v7**.
- **Decisión declarada:** clasificar una alerta **interna** como `auto_ruido` es **discutible** (no es un proceso
 de Wazuh) → queda **declarado** como decisión consciente.

---

## 5. `.gitattributes` y la limitación del clon (excepción aceptada)

- **Creado:** `*.b64 binary` · `*.png binary` · `*.sh text eol=lf` — **SIN `*.csv`**.
 *(Poner `eol=lf` a los `.csv` habría roto **97 huellas**: los CSV están **CRLF en disco** y **LF en git**,
 y las huellas se calcularon sobre los bytes del disco.)*
- **Prueba real con clon:** **sin** el fichero → **420** ficheros desincronizados; **con** él → **376** (−44:
 arregla los `.sh` citados). **Mejora y no empeora.**
- **⚠️ Excepción aceptada por el humano:** el objetivo *"un clon reproduce las 1.411 huellas"* **NO es
 alcanzable** con el repo tal como está (**finales de línea mezclados** + `core.autocrlf=true`): **ninguna**
 configuración global lo consigue. → **Se mantiene** el `.gitattributes` (mejora parcial) y **se declara** la
 limitación. **Bloque futuro propuesto: normalizar finales de línea + recalcular huellas** (mecánico, grande;
 relevante para la defensa: *hoy un clon no verifica las huellas*).

---

## 6. Mapa de cobertura ART regenerado

`Hojas/cobertura_atomic.csv`: **13 → 43 filas** (determinista) + `Soporte/Ataques/atomic_red_team.md` §6.
**Para qué:** que al diseñar cada ataque nuevo lo **primero** sea mirar *"¿ART tiene algo usable aquí?"*.

---

## 7. Verificación (`tfg-tester`) — **PASA** (tras 1 FALLA)

| # | Comprobación | Resultado |
|---|---|---|
| Citas | `verificar_citas_auditoria.py` + **5 filas al azar** | **43/43** resuelven; 5/5 coherentes |
| Columnas | cruce con el mapa | 43/43 cuadran |
| Semántica | `fuente=ART_*` → `na_art_usado`; ATA029/030 → `no_se_comprobo` | ✅ |
| Bitácoras | 43 con las casillas nuevas, **aditivas** | ✅ |
| **T5** | 86 ventanas: **solo** `ATA035_iter2`; `ATA011_iter1` intacta | ✅ |
| Tests | 4 nuevos + `pytest` **97** | ✅ |
| **T6** | 3 líneas sin `.csv`; clon **420→376**; declarado | ✅ (excepción aceptada) |
| Regresión | 85 ventanas byte a byte; cadena de huellas **1.411/0** | ✅ |
| Alcance | sin commit, sin secretos, `_recursos/` y datos intactos | ✅ |

**La FALLA (1ª vuelta):** las **citas** apuntaban a líneas de un **fichero temporal** (offsets globales, no del
README) y faltaban columnas del plan → **corregido**: **citas 43/43** (con verificador propio) y columnas
restituidas. **Lección de método:** las citas deben **resolverse contra el fichero citado**, no contra un volcado.

---

## 8. Entregables

| Fichero | Qué |
|---|---|
| `Hojas/auditoria_origen.csv` | **43 filas** (fuente, motivo, cómo, sustituciones, material, **citas que resuelven**) |
| `_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` | las **2 listas** + hallazgos |
| `Soporte/Ataques/criterio_ataques.md` | **los 3 criterios** (ART · manual · pre-staging) |
| `Bitacora/ATA*.json` (43) | **+** `fuente_norm`, `motivo_codigo`, `motivo_detalle` (aditivo) |
| `Hojas/cobertura_atomic.csv` + `atomic_red_team.md` | mapa ART **13→43** |
| `.gitattributes` | 3 líneas (sin `.csv`) |
| `_artefactos/scripts/filtrar_ruido.py` + tests + `politica_filtrado_ruido.md` (v7) | **FP `rule_id 11`** corregido |
| `_artefactos/scripts/auditar_origen_ataques.py`, `anadir_fuente_motivo.py`, `verificar_citas_auditoria.py` | herramientas de la auditoría |

---

## 9. Siguiente

1. **Decide tú qué ataques se repiten** (las 2 listas del §2) → se repiten en un **bloque posterior** (2 ventanas c/u).
2. **Las ~29 técnicas restantes de Linux, sin evasión** — ya con **las normas escritas** (cada ataque nuevo nace
 con sus casillas: fuente+motivo y material externo).
3. **Bloque futuro anotado:** **normalización de finales de línea + recálculo de huellas** (para que un clon
 verifique). Y sigue pendiente **Windows** (su línea base + adaptar el filtro).
4. **`push`:** los commits son locales; publicar es del humano.
