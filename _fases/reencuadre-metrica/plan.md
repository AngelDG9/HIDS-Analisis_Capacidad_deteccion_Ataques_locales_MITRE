---
bloque: reencuadre-metrica
nombre: Congelar la métrica, las plantillas (T1–T5 + Requisitos + Leyenda) y los scripts de conteo deterministas
version: 1
status: approved_by_human
fecha: 2026-10-16
fecha_aprobacion: 2026-10-16
aprobado_por: humano
autor: tfg-planner
depende_de: reencuadre (R0, cerrado) · reencuadre-docs (R1, cerrado)
gate: |
  **APROBADO (2026-10-16).** Respuestas del humano al gate (§11): Q1 regla de medida (3 planos + fórmulas del profesor/hermano) → **SÍ** · Q2 unidad = evento + acción/hora; comparación entre HIDS por acción/hora y por técnica → **SÍ** · Q3 doble conteo (siempre 2 cifras) → **SÍ** · Q4 ventana canónica (una por caso) → **SÍ** · Q5 pruning (6 variantes + variante % si hace falta) → **SÍ** · Q6 plantillas (columnas del profesor, CSV+Excel) → **SÍ** · Q7 nada se mide hasta congelar → **SÍ**.
---

# plan.md — Bloque `reencuadre-metrica` (R2)

> **Qué es este documento.** El **plan** del bloque **más delicado** del programa: **fija la
> regla con la que se medirá TODO** (los 55 casos P1-Linux, las 72 h de legítimo, Velociraptor y
> la comparación). **Nadie mide nada hasta que R2 cierre** (`roadmap.md` §1, `R0 §9.1`).
>
> **Regla dura.** Un error aquí **contamina todos los resultados**. Por eso este bloque produce:
> (1) la **métrica congelada** (documento propio, versionado y con huella), (2) las **plantillas**
> de **T1–T5 + "Requisitos de estudios" + "Leyenda"** (excels equivalentes a los del profesor, con
> la **cabecera exacta** leída de su Excel), y (3) los **scripts de conteo deterministas**
> (misma entrada → mismos bytes) con **huella `sha256`** y **tests**.
>
> **Este bloque NO implementa** (eso es la ejecución, tras el gate): aquí se **especifica y decide**.

## Anclas

- `(R0 §X.Y)` = `_fases/reencuadre/plan.md` (v2, **aprobado**, 2026-10-16).
- `(R1)` = `context.md` / `requirements.md` / `roadmap.md` (v2, vigentes).
- `(F3 §X)` = `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` (v7) — **métrica congelada
  de Fase 3** (la *pertenencia*).
- `(P-Excel hoja X)` = `_recursos/reuniones/03/Tablas 2, 3, 4, 5 (con FG-PA).xlsx` (cabeceras y
  fórmulas leídas **celda a celda** con `openpyxl`, esta revisión).
- `(Hermano)` = `github.com/ignmercam/mitre-attack-ids-detection-optimization` (TFG NIDS de
  Ignacio Merchán, **mismo tutor**), scripts `optimo_Snort_GM_v4.py` y `procesa_prioridades_snort_v2.py`
  (leídos y citados literalmente en §2.5).

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [La métrica congelada, especificada al detalle](#2-la-métrica-congelada-especificada-al-detalle)
3. [Definición operativa de "virgen" y bóveda de congelación](#3-definición-operativa-de-virgen-y-bóveda-de-congelación)
4. [Estructura EXACTA de las plantillas (T1–T5 + Requisitos + Leyenda)](#4-estructura-exacta-de-las-plantillas-t1t5--requisitos--leyenda)
5. [Dónde vive cada cosa en el repo](#5-dónde-vive-cada-cosa-en-el-repo)
6. [Especificación de los scripts](#6-especificación-de-los-scripts)
7. [Relación con la métrica de Fase 3 (reutiliza vs nuevo)](#7-relación-con-la-métrica-de-fase-3-reutiliza-vs-nuevo)
8. [Comparabilidad ENTRE HIDS (unidad común)](#8-comparabilidad-entre-hids-unidad-común)
9. [Riesgos, decisiones abiertas y casos límite no resolubles](#9-riesgos-decisiones-abiertas-y-casos-límite-no-resolubles)
10. [Criterios de aceptación (verificables)](#10-criterios-de-aceptación-verificables)
11. [Gate humano (lenguaje sencillo)](#11-gate-humano-lenguaje-sencillo)
12. [Ficheros que se tocarán](#12-ficheros-que-se-tocarán)
13. [Trazabilidad (fuentes y afirmaciones verificadas)](#13-trazabilidad-fuentes-y-afirmaciones-verificadas)
14. [Lo que NO cuadra (declarado, para el revisor)](#14-lo-que-no-cuadra-declarado-para-el-revisor)

---

## 0. Resumen ejecutivo

R2 **congela la medida**. Produce **tres artefactos**:

1. **`Soporte/Metrica/metrica_hids.md`** — la **métrica congelada** (`version: 1`, `fecha`,
   `sha256`), que define **cada término, unidad, fórmula, regla de conteo y caso límite** (§2).
   Es la **fuente única de verdad**: ningún script puede contradecirla.
2. **Las plantillas** (CSV canónico + export `.xlsx` equivalente) de **T1–T5 + Requisitos +
   Leyenda**, con **la cabecera y la semántica leídas del Excel del profesor** (§4).
3. **Los scripts de conteo deterministas** (`_artefactos/scripts/`), con **`sha256`** y **tests**
   (§6). Misma entrada → **mismos bytes** (RNF-01).

**Tres decisiones centrales** que este plan fija (y que R0 dejaba abiertas o implícitas):

- **D1 — La unidad del legítimo y su denominador.** Titular = **evento/registro decodificado por
  el HIDS** (análogo al "flujo" del NIDS); denominador **instrumentado** (`<logall_json>` en Wazuh
  — **no** cambia el ruleset ⇒ virgen preservada). **Complementos**: **acción de GHOSTS** y
  **FP/hora**. **Fallback declarado** si el volumen lo hace inviable (§2.2).
- **D2 — El doble conteo.** Se separan **siempre** `#Alertas` (**bruto**) y `#rule.id` **distintos**
  (de-duplicado). La variante "**correlacionada por unidad**" (el `#Flow-correlated Alerts` del
  profesor) se define de forma **uniforme** (§2.4): en ataque = **`rule.id` distintos del caso**;
  en legítimo = **Σ sobre unidades de `rule.id` distintos**.
- **D3 — La ventana canónica por caso.** Para el plano ataque, **un solo caso = una ventana
  canónica**: **`_rev1`** si el ATA está en `Hojas/repeticiones.csv` (los **9**), si no **`iter1`**;
  la **2.ª ventana** (`iter2`/`rev2`) es la **prueba de reproducibilidad** (C1′/C2′ del criterio
  v2). Esto elimina la ambigüedad "55 casos vs 128 ventanas".

**Ventaja de coste** (heredada): los 55 ATA **ya traen** `rule_level` + `rs_origen` + `categoria`
en sus `-Audited.csv` (160 ficheros) ⇒ **T2 es un recorte determinista**, no una re-medición.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo del bloque

Dejar **congelado**, **definido sin ambigüedad** y **con herramientas**, todo lo necesario para
medir: la **métrica** (§2), las **plantillas** T1–T5/Requisitos/Leyenda (§4) y los **scripts de
conteo** deterministas (§6). Es un bloque **de diseño**: su producto primario es **el plan**; tras
el gate, produce **el documento congelado**, **las plantillas** y **los scripts + tests**.

### 1.2 Entra

- **La métrica congelada** (documento + decisión de cada caso límite).
- **La definición operativa de "virgen"** y **la bóveda de congelación** (§3).
- **Las plantillas** de las **5 tablas + Requisitos + Leyenda** (CSV canónico + `.xlsx`) — §4.
- **Los scripts** de recuento + **tests** + **huellas** — §6.
- **Los CA** (§10), el **gate** (§11) y la **trazabilidad** (§13).

### 1.3 NO entra (fuera de alcance)

- **Medir de verdad**: los números finales de T2/T4 (eso es `M1a`/`M1b`), T3 (eso es `L2`), T5
  (eso es `A1`), VR (eso es `V1`). **R2 solo deja la herramienta** (con una **prueba de humo**
  sobre el corpus ya medido, §6.7).
- **Construir GHOSTS / la "internet local"** (bloque `L0`), **desplegar Velociraptor** (`V0`),
  **atacar Windows** (`B1`).
- **Escribir reglas/artifacts propios** (`W2`/`W3`/`V2`, contingentes al gate).
- Tocar el **laboratorio**, el **corpus**, `Hojas/`, `Dataset/`, `_recursos/` ni
  **`_artefactos/scripts/extraer_alertas.py`** (sha congelado).

---

## 2. La métrica congelada, especificada al detalle

> **Este es el núcleo del bloque.** Todo lo demás son herramientas para calcular *esto*.

### 2.1 Los tres planos y sus unidades

Replica **exactamente** la estructura del trabajo de referencia (P-Excel hoja `T4 (Rend)`; §3.3):

| Plano | Unidad (HIDS) | Equivalente NIDS | Se usa para |
|---|---|---|---|
| **Ataque** | **caso** = ventana canónica `ATA<NNN>` (§2.7) | `pcap` | **TPR**, FN |
| **Legítimo** | **unidad de actividad legítima** = **evento/registro decodificado** | `flujo` | **FPR**, TN |
| **Alerta** | **`rule.id` que Wazuh emite** / **fila de artifact de VR** | `alerta` | **Precisión**, **Usabilidad**, F1 |

**Nomenclatura fija** (para todo el TFG y la memoria):

- `N` = nº de **casos** (plano ataque) = **55** (una ventana canónica por `ATA<NNN>`; §2.7).
- `M` = nº de **unidades legítimas** (plano legítimo) = nº de **eventos/registros decodificados**
  por el HIDS en la ventana (denominador **instrumentado**; §2.2).
- `A_TP`, `A_FP` = nº de **alertas** (planos de alerta).

### 2.2 La unidad del legítimo y su denominador (decisión D1 · la más delicada)

**Titular (congelado).**

- **Unidad** = **un evento/registro de telemetría legítimo**, entendido como **una entrada decodificada
  por el HIDS** (en Wazuh, una línea de `archives.json`; análoga al "flujo" del NIDS).
- **Denominador `M`** = nº de **eventos decodificados** en la ventana legítima, **instrumentado**
  con **`<logall_json>yes</logall_json>`** del manager (Wazuh escribe **todos** los eventos que
  decodifica en `archives.json`, **hayan disparado o no** una regla). **No cambia el ruleset** ⇒
  **virgen preservada** (`R0 §7.4`). Alternativa declarada: contar en el origen (auditd/Sysmon/FIM).
- **`FP_uni`** = nº de unidades con **≥1 alerta** en la ventana (config × umbral dados).
- **`TN_uni`** = `M − FP_uni`.

**Complementos declarados (se reportan siempre, no sustituyen al titular).**

1. **Acción de GHOSTS** (unidad discreta, contable): `FP/acción`, `nº de acciones`.
2. **Hora de actividad**: `FP/hora`.

**Fallback declarado (con disparador explícito).** Si al cerrar `L1` el fichero `archives.json`
de 72 h **no es manejable** (p. ej. > ~5 GB) **o** la decodificación no es fiable, el **titular
cae** a **`FP/acción` + `FP/hora`** y se **documenta como limitación** (`R0 §4.2`). **El disparador
y la decisión se registran** en `L1`; la métrica **no cambia**, solo qué columna es titular.

**Por qué es defendible (declarado, honesto):** el "evento" **depende de la telemetría** (que se
congela en la bóveda, §3) ⇒ **`FPR`-por-evento NO es comparable entre HIDS** (el evento de Wazuh
≠ la fila de VR). Para **comparar** se usa la **unidad común** (§8), no el evento.

> **Decisión humana aprobada** (`R0 §4.2`, gate Q2): unidad = **evento** (titular) + **acción/hora**
> (comparación). **Se confirma con el tutor antes de congelar** (§9.2, abierta 1).

### 2.3 Matriz de confusión (por plano)

**Plano ATAQUE (caso):**

```
                    | detectado | no detectado
  ataque real (P1)  |  TP_ata   |   FN_ata
```

- `TP_ata` = nº de casos con **≥1 alerta `categoria=deteccion`** (pertenencia congelada, §7) **y
  `rule_level ≥ N`** (config × umbral dados).
- `FN_ata = N − TP_ata`, con `N = 55` (casos medidos).
- **`TPR = TP_ata / N`** (§3.3 fórmula 1).

**Plano LEGÍTIMO (unidad):**

```
                     | con alerta | sin alerta
  actividad legítima |  FP_uni    |  TN_uni
```

- `FP_uni` = nº de unidades legítimas con **≥1 alerta** (config × umbral dados).
  **La auto-alerta del HIDS cuenta como FP** (`R0 §4.5.3`); la variante **sin `auto_ruido`** se
  reporta como **complemento** (§2.5, regla 3).
- `TN_uni = M − FP_uni`; **`FPR = FP_uni / M`**; **`TNR = 1 − FPR`** (§3.3).

**Plano ALERTA (conteo):**

- `A_TP` = nº de alertas de los ataques (`categoria=deteccion`).
- `A_FP` = nº de alertas sobre legítimo (**todas**, **auto-alerta incluida**).
- **Doble conteo (D2)**: se reportan **`#Alertas`** (bruto) **y** `#rule.id` **distintos**; la
  variante **correlacionada por unidad** (§2.4).
- **`Precisión = A_TP / (A_TP + A_FP)`**; **`Usabilidad (FTTAR) = A_FP / A_TP`** (§3.3).

### 2.4 Doble conteo y "alertas correlacionadas" (decisión D2)

**Problema** (`R0 §11.3`, lección de Peña): una misma acción puede generar **varias señales a la
vez** ⇒ contar alertas brutas **infla**. El profesor lo resuelve con **dos cifras** (P-Excel
`T2 (At)` y `(B) Legitimo`): `#Alerts` **y** `#Flow-correlated Alerts` (+ `#SID`).

**Definición congelada (uniforme):**

- **`#Alertas`** = nº **bruto** de alertas (filas).
- **`#rule.id` distintos** = cardinalidad del **conjunto** de `rule.id` con alerta.
- **`#Alertas correlacionadas`** = **Σ sobre unidades de (`rule.id` distintos en esa unidad)**:
  - **Plano ataque:** la unidad es **el caso** ⇒ `#Alertas correlacionadas = #rule.id distintos
    del caso` (que es **exactamente** el conjunto C1′ del criterio v2 y el O1 congelado de Fase 3,
    §7).
  - **Plano legítimo:** la unidad es el **evento** ⇒ `Σ_eventos (rule.id distintos del evento)`.
- **Regla de reporte:** **siempre** se publican **las dos cifras** (`#Alertas` y `#rule.id`), y las
  métricas de alerta se dan en **versión bruta** y en **versión correlacionada** (`^c`), igual que
  el profesor. Ninguna sustituye a la otra (§2.5, regla 4).

### 2.5 Fórmulas congeladas (con fuente literal)

> **Fuente primaria:** P-Excel hoja `T4 (Rend) S<=4, FG>=1`, bloque de fórmulas (celdas leídas
> celda a celda). **Fuente confirmada** en el repo hermano (`optimo_Snort_GM_v4.py`, `calc_metrics`).

| # | Métrica | Fórmula | Óptimo | Fuente literal |
|---|---|---|---|---|
| 1 | **TPR** (Recall/CD) | `TP_ata / N` | →1 | Excel `B14 = B6 / 'T2…'!$D$79` |
| 2 | **FPR** | `FP_uni / M` | →0 | Excel `B15 = B10 / $B$4` (`#Flows FP / #Clear flows`) |
| 3 | **TNR** (Especificidad) | `1 − FPR` | →1 | Excel `%Flows_TN = 1 − %Flows_FP` |
| 4 | **Precisión (P)** | `A_TP / (A_TP + A_FP)` | →1 | Excel bloque de fórmulas `P = TP/(TP+FP)` |
| 5 | **F1** | `2·P·R / (P + R)`, `R = TPR` | →1 | Excel bloque de fórmulas `F1 = 2PR/(P+R)` |
| 6 | **GM** | `√(TPR · (1 − FPR))` | →1 | Excel `B16 = SQRT(B14*(1-B15))`; hermano `gm = math.sqrt(tpr*tnr)` |
| 7 | **Usabilidad (FTTAR)** | `A_FP / A_TP` | →0 | Excel `B17 = B12 / B8`; hermano `usab = a_fp / a_tp` |
| 7c | **Usabilidad `^c`** | `A_FP^c / A_TP^c` | →0 | Excel `B18 = B13 / B9` (`correlated`) |

**Cita literal del repo hermano** (para que el revisor la vea, **no parafraseada**):

```python
tp = sum(1 for pcap_sids in atk_data_pcap.values() if not pcap_sids.isdisjoint(test_sids))
fn = total_atk_pcaps - tp
tpr = tp / total_atk_pcaps if total_atk_pcaps > 0 else 0.0
fp = sum(1 for flow_sids in leg_data_flow.values() if not flow_sids.isdisjoint(test_sids))
tn = total_leg_flows - fp
tnr = tn / total_leg_flows if total_leg_flows > 0 else 0.0
gm = math.sqrt(tpr * tnr)
...
usab = round(a_fp / a_tp, 4) if a_tp > 0 else 0.0
```

> **Nota metodológica honesta** (`R0 §4.4`, se **declara** en la memoria): `Precisión` vive en el
> plano **alerta** y `Recall/TPR` en el plano **caso**; `F1` y `GM` **mezclan** ambos. Es
> **exactamente** la convención del profesor (`GM = √(TPR·TNR)` con TPR por *pcap* y TNR por
> *flujo*). Se adopta **por comparabilidad** y se **declara la limitación**. Si el tutor lo pide,
> se añade la variante "todo a casos" y "todo a unidades" (declarada).

### 2.6 Reglas de conteo (anti-sesgo) — congeladas

1. **Config (Wazuh).** `C0 = {RS1}` · **`C1 = {RS1, RS2}` (virgen)** · `C2 = C1 ∪ {RS3}` ·
   `C3 = C2 ∪ {RS4}`. La **pertenencia de una alerta a un RS** se toma **tal cual** del campo
   `rs_origen` de la fila (el extractor lo asigna por fichero de origen; **no se recalcula**).
2. **Umbral (Wazuh).** `rule.level ≥ N`, con `N ∈ {0, 3, 7, 10, 12}`. **`N=0` ≡ "cualquier alerta
   emitida"** (las reglas de nivel 0 **no emiten** alerta — caso `92600`, `R0 §4/§11.3`). El
   **titular** es **`C1` (virgen) × `N=0`**, + la **rejilla** completa.
3. **Un umbral no borra un caso** (`R0 §4.5.2`): un caso pasa a `FN` **solo si ninguna** alerta del
   caso (`categoria=deteccion`) **supera** el umbral.
4. **Doble conteo (§2.4):** se publican **`#Alertas`** **y** `#rule.id` **distintos**; nunca uno solo.
5. **La auto-alerta cuenta como FP** (`R0 §4.5.3`); se **reporta aparte** la variante **excluyendo
   `auto_ruido`** (complemento, para que se vea cuánto del FP es el propio HIDS).
6. **Nada se descarta en silencio** (`RNF-06`): una fila no atribuible va a **`dudosa`** y **se
   declara**. `dudosa > 0` en un caso **bloquea** su incorporación al TPR hasta que el humano
   resuelva (es el C3′ del criterio v2).
7. **Reproducibilidad** (`RNF-01`): cada cifra se **regenera** con un script determinista y una
   **huella `sha256`**; la cabecera del CSV lleva la **versión de la métrica** + los **hashes de
   las entradas**.

### 2.7 La ventana canónica por caso (decisión D3)

- El **plano ataque** cuenta **casos** (`ATA<NNN>`), **no** ventanas. **`N = 55`.**
- **Ventana canónica** (regla congelada):
  - **`ATA<NNN>_rev1`** si el ATA **está** en `Hojas/repeticiones.csv` (**9 casos**); si no,
  - **`ATA<NNN>_iter1`**.
- La **segunda ventana** (`iter2`, o `rev2` en los 9) se usa **solo** para la **prueba de
  reproducibilidad** (C1′ = mismo conjunto de `rule.id`; C2′ = `|n2−n1| ≤ max(2, 10 %·n1)`;
  C3′ = ninguna `dudosa` sin resolver). Si falla → **`review`** y el caso se **marca** (su TPR se
  declara como "en revisión", no como TP ni FN silencioso).
- **Estado esperado** (verificado antes de medir): los 55 casos son **`iguales`** ⇒ TPR sin
  ambigüedad. **Prueba de humo** (§6.7): la rejilla **`C1 × N=0`** debe reproducir **53/55**.

### 2.8 Qué se congela y qué invalida una medida

**Se congela** (en `Soporte/Metrica/metrica_hids.md`, `version: 1`, `fecha`, huella):

- Las **3 unidades** y sus **denominadores** (§2.1–§2.2).
- Las **7 fórmulas** (§2.5) — **literales**.
- Las **reglas de conteo** (§2.6) y los **casos límite** (§2.9).
- La **regla de ventana canónica** (§2.7) y el **orden de decisión** heredado de Fase 3 (§7).
- El **glosario de equivalencias** (`pcap↔ATA`, `flujo↔unidad`, `SID↔rule.id`).

**Invalida una medida** (obliga a **recalcular** y **declarar**, `RNF-02`):

1. Cambiar **cualquiera** de los 7 puntos congelados (versión de métrica nueva).
2. Cambiar un elemento de la **bóveda de congelación** (§3): ruleset, telemetría, versión del HIDS,
   umbrales, definición de "virgen".
3. **Re-calibrar** el catálogo de ruido (los `baselines` **históricos** no sirven para el juicio
   final: el catálogo **autoritativo** son las **72 h**, `R0 §10.4` ⇒ **M1b**).
4. **Añadir/quitar** un caso, o cambiar la **ventana canónica** de un caso.
5. Cambiar el **denominador `M`** o su instrumentación (§2.2).

> Se registra en la cabecera de cada CSV: `metrica_version`, `boveda_version`, y los `sha256` de
> **todas** las entradas. Una cifra sin esa cabecera **no es válida**.

### 2.9 Casos límite (congelados)

| # | Caso | Decisión congelada |
|---|---|---|
| L1 | **Nivel 0 no emite alerta** (`92600`) | `N=0` ≡ "cualquier alerta emitida"; se documenta. |
| L2 | **Auto-ruido del HIDS** (≈54 % en Linux) | Cuenta como **FP** (regla 5); se reporta aparte la variante **sin `auto_ruido`**. |
| L3 | **Reglas de doble uso** (TP en ataque, FP en legítimo) | **No se borran a ciegas**; solo **T5** (variantes conservadoras) las evalúa. En T2/T4 permanecen. |
| L4 | **`dudosa` sin resolver** en un caso | El caso **no cuenta como TP** ni como FN silencioso: se **marca `review`** y se declara. |
| L5 | **Ataque sin alerta** (0 filas `deteccion`) | `FN_ata` (caso real: ATA013, ATA034). Contribuye a `FN`. |
| L6 | **`RS2` (auditd) es del paquete** | Parte de **`virgen` (`C1`)**; se ve su aporte comparando `C0` vs `C1` (recorte). |
| L7 | **Un evento con varias señales** | Doble conteo resuelto por §2.4 (`#Alertas` vs `#rule.id`). |
| L8 | **`C2`/`C3` (propias/externas)** | **No** se miden en virgen: **contingentes al gate** (`W2`/`W3`). El script las soporta pero **se quedan vacías** hasta que existan. |
| L9 | **`N=0` y todas las alertas nivel 0** | Un caso con solo reglas de nivel 0 ⇒ **no emite** ⇒ `FN`. |
| L10 | **Un caso sin segunda ventana válida** | `review` por reproducibilidad; declarado. |
| L11 | **`logall_json` no instrumentado** | `M` = `n/a`; FPR-por-evento **no** se publica; se usa el **fallback** (§2.2). |

---

## 3. Definición operativa de "virgen" y bóveda de congelación

### 3.1 "Virgen" (congelada)

> **"Virgen" = ruleset de detección de fábrica, sin reglas propias ni de terceros; la telemetría
> estándar SÍ se activa** (`R0 §6`, `context.md §9`). Para **Wazuh** = `RS1 + RS2` (`C1`), con
> **RS3 = RS4 = 0** (verificado: `active_ruleset.txt` → `RS3 propias 0`, `RS4 externas 0`). Para
> **Velociraptor** = **artifacts públicos/nativos**, sin artifacts propios.

- **auditd / Sysmon son FUENTE de telemetría, no "reglas"** ⇒ **sí** se activan en virgen.
- **Se declara** para que la comparación sea justa (`R0 §6`).

### 3.2 Bóveda de congelación (lo que se sella antes de medir)

Se materializa en **`Soporte/Metrica/boveda_congelacion.md`** + un fichero de **hashes**
(`Soporte/Metrica/boveda_congelacion.sha256`). **Antes de la primera medida** se sella:

| # | Elemento | Cómo se sella |
|---|---|---|
| B1 | **Versión del HIDS** | Wazuh **4.14.7** (`Soporte/Wazuh/Configuracion/version_wazuh.txt`); VR: versión al desplegar (`V0`). |
| B2 | **Ruleset por defecto** | `active_ruleset.txt` (**sha256**) + conteo por fichero (RS1 4.471 · RS2 44 · RS3 0 · RS4 0). |
| B3 | **Telemetría** | separadores de auditd (clave `audit-wazuh-c`), config SwiftOnSecurity de Sysmon v15.22, canales Windows (Security + Sysmon + PS 4104), FIM — por **sha256** de los ficheros de config. |
| B4 | **Imágenes / snapshots** | nombre y **id** de snapshot (`lab-listo`, `lab-listo-windows`, …). |
| B5 | **Umbrales** | `N ∈ {0,3,7,10,12}` (§2.6) y perfiles P1–P4 de VR. |
| B6 | **Definición de "virgen"** | §3.1. |
| B7 | **Constantes de la métrica congelada de Fase 3** | `politica_filtrado_ruido.md` **v7** (sha) + `filtrar_ruido.py` (sha): `ATTACK_ROOT`, `OPERADOR_SRCIPS`, `CATEGORIAS`, `OUT_HEADER`. |
| B8 | **Versión de la métrica** | `metrica_hids.md` **v1** (sha). |
| B9 | **Corpus congelado** | `Hojas/ATA_index.csv`, `Hojas/repeticiones.csv`, los `-Audited.csv` (cadena de huellas). |
| B10 | **Config del legítimo** | GHOSTS (versión) + "internet local" + fichero de instrumentación del denominador. |

> **Regla:** si **cualquiera** de B1–B10 cambia ⇒ **métrica/medida invalidada** (§2.8).

---

## 4. Estructura EXACTA de las plantillas (T1–T5 + Requisitos + Leyenda)

> **Fuente de verdad de las cabeceras:** las hojas del Excel del profesor, leídas **celda a celda**
> (esta revisión). Se **mantienen nombres/semántica** donde son homogéneos y se **cambia** lo que
> en un HIDS es distinto (**unidad**, **ejes**): `SID→rule.id`, `pcap→ATA<NNN>`,
> `flujo→unidad legítima`. Cada plantilla se entrega como **CSV canónico** (determinista, huella)
> **y** export **`.xlsx`** equivalente.

### 4.1 T1 — Clasificación (matriz MITRE, espejo red↔host) — `Hojas/T1_clasificacion.csv`

> Adapta la hoja **`Techniques`** de `Tabla 1 …v17.xlsx` + `Hojas/corpus_host.csv` (v19.1) +
> cobertura (`R0 §5.1`). Las **dos columnas de red (v17)** y la de **host (v19.1)** van **juntas**
> para que la equivalencia sea auditable y las **3 discrepancias** (`T1029`, `T1602.001/.002`,
> `T1567.003`) queden **visibles**.

**Columnas:**

1. `tactica` — táctica principal (nombre v19.1). *(P-Excel `TÁCTICA`)*
2. `otras_tacticas` — resto de tácticas (v19.1). *(P-Excel `OTRAS TÁCTICAS`)*
3. `id_tactica` — `TAxxxx`. *(P-Excel `ID TÁCTICA`)*
4. `tecnica` — nombre de la técnica. *(P-Excel `TÉCNICA`)*
5. `id_tecnica` — `Txxxx`. *(P-Excel `ID TÉCNICA`)*
6. `subtecnica` — nombre de la subtécnica (si la hay). *(P-Excel `SUBTÉCNICA`)*
7. `id_subtecnica` — `Txxxx.yyy` (si la hay). *(P-Excel `ID SUBTÉCNICA`)*
8. `plataformas` — plataformas MITRE. *(nuevo, de `corpus_host.csv`)*
9. `p1_res` — `P1` si toca Ransomware/Exfiltración/Sabotaje (`priority`). *(de `corpus_host.csv`)*
10. `only_network_detection_v17` — `YES/NO` (Tabla 1 v17). *(P-Excel `Only Network Detection`)*
11. `network_detection_v17` — `YES/NO` (Tabla 1 v17). *(P-Excel `Network Detection`)*
12. `host_eligible_v191` — `YES/NO` (filtro inverso v19.1). *(de `corpus_host.csv`)*
13. `dc_host` — nº de Data Components host. *(de `corpus_host.csv`)*
14. `dc_red` — nº de Data Components de red. *(de `corpus_host.csv`)*
15. `cubierta_en_corpus` — `ATA<NNN>` (o vacío). *(de `cobertura_p1_linux.csv`/`inventario_p1_windows.csv`)*
16. `estado_cobertura` — `medida | cubierta_madre | cubierta_por_ata | cubierta_parcial | no_factible | no_linux`. *(de `cobertura_p1_linux.csv`)*
17. `nota_desfase` — `—` o la discrepancia declarada (`T1029`/`T1602.*`/`T1567.003`). *(nuevo)*

### 4.2 T2 — Ataques y detecciones — `Hojas/T2_ataques.csv`

> Adapta **`Tabla 2 - Ataques detec (Imple)`** (cabecera real: `Nº | Nº Technique | pcapng
> (SubTechnique-Attack) | Technique | #Flows |` + por config `#Alerts | #Flow-correlated Alerts |
> #SID | #Attack_Flows | Detection`) y la vista **`T2 (At) …`** (`Nº | Technique | Description |
> #pcaps | #flows | #pcaps (#flows) |` + por config `#Alerts | #Flow-correlated Alerts |
> #Flow-correlated Alerts (total) | #SID | %Detection_pcaps | #Attack_Flows`).

**Bloque META (una fila por caso; independiente de config×umbral):**

1. `n` — `Nº` (1..55). *(P-Excel `Nº`)*
2. `ata_id` — `ATA<NNN>`.
3. `id_tecnica` — `Txxxx(.yyy)`. *(P-Excel `Nº Technique` / `Technique`)*
4. `subtecnica` — nombre (si la hay).
5. `tactica` — táctica. *(de `ATA_index.csv`)*
6. `plataforma` — `linux | windows`.
7. `paquete_pcap` — ruta de la carpeta-**paquete** (`contexto + acciones + telemetría`, criterio
   ART). *(P-Excel `pcapng (SubTechnique-Attack)`; `R0 §5.2`)*
8. `herramienta` — herramienta/s usadas. *(P-Excel `(A) Ataques` `HERRAMIENTA`; de la bitácora)*
9. `n_acciones_k` — acciones cubiertas `k`. *(P-Excel `#Attack_Flows`; de `metrico_o2` de la bitácora)*
10. `n_acciones_m` — acciones totales `m`. *(ídem)*
11. `t0_utc` / `t1_utc` — inicio/fin de la ventana canónica. *(de la bitácora)*
12. `duracion_s` — `t1 − t0`. *(nuevo, `R0 §5.2` fleco 3)*
13. `ventana_canonica` — `iter1 | rev1` (§2.7).
14. `doble_iteracion` — `iguales | review` (C1′/C2′/C3′). *(de `criterio_doble_iteracion.md`)*
15. `analisis_manual` — cómo se verificó el efecto (cita a la ficha `ATA<NNN>_meta.md`). *(P-Excel `ANÁLISIS…`)*

**Bloques por (config × umbral)** (`C0/`C1`/`C2`/`C3` × `N∈{0,3,7,10,12}`; en virgen, `C2`/`C3`
vacías, L8). Por cada bloque, **estas columnas** (nombre = P-Excel → adaptación):

| Columna plantilla | P-Excel (original) | Semántica |
|---|---|---|
| `#Alertas` | `#Alerts` | alertas brutas del caso |
| `#rule.id_distintos` | `#SID` | `rule.id` **distintos** del caso |
| `#Alertas_correlacionadas` | `#Flow-correlated Alerts` | `#rule.id` distintos del caso (D2) |
| `#Alertas_correlacionadas_total` | `#Flow-correlated Alerts (total)` | `H (G)` = `corr (raw)` |
| `#acciones_cubiertas` | `#Attack_Flows` | acciones del ataque cubiertas `k` |
| `t_hasta_1a_deteccion_s` | — *(nuevo, fleco 3)* | `t(1.ª alerta detección) − t0` |
| `primera_evidencia_rule_id` | — *(nuevo)* | `rule.id` de la 1.ª detección |
| `%Deteccion` | `%Detection_pcaps` | 100 % si `TP_ata`, si no 0 % |
| `Detection` | `Detection` | `SÍ / NO` |

### 4.3 T3 — Legítimo — `Hojas/T3_legitimo.csv`

> Adapta **`Tabla 3 (Legítimo)`** y **`(B) Legitimo`**. Cabecera real del profesor:
> `Metric |` + por config; filas `#Flows | #Alerts | #Flow-correlated Alerts | #SIDs, #AttackID o
> #ThreatID | #AppID | #Flows_FP | #Flows_TN | %Flows_FP | %Flows_TN`. Y `(B) Legitimo`:
> `pcap (Nombre) | Tipo de tráfico | Tamaño real del tráfico | #Flujos | #Intentos Flujo (SYN) |
> #IPs (sin repetición) |` + por RS `#Alertas | #Alertas/SID | #Alertas diferentes por flujo |
> SIDs (sin repetición) | #SID | #Flujos con Ataques detectados (con SID)`.

**Bloque META (una corrida por fila):**

1. `corrida` — id de la corrida (p. ej. `L1-linux-wazuh-72h`).
2. `hids` — `wazuh | velociraptor`.
3. `so` — `linux | windows`.
4. `tipo_trafico` — `(Legítimo) <descripción>` (GHOSTS / plan B declarado). *(P-Excel `Tipo de tráfico`)*
5. `fuente_generadora` — `GHOSTS | plan_B`.
6. `inicio_utc` / `fin_utc` / `duracion_h` — ventana. *(P-Excel `pcap (Nombre)` → aquí, la corrida)*
7. `tamano` — tamaño real (eventos / GB). *(P-Excel `Tamaño real del tráfico`)*
8. `n_acciones_ghosts` — nº de acciones GHOSTS. *(P-Excel `#Intentos Flujo (SYN)` → análogo)*
9. `n_ips_o_entidades` — nº de entidades distintas. *(P-Excel `#IPs (sin repetición)`)*

**Bloques por (config × umbral)** (por config; nombre = P-Excel → adaptación):

| Columna plantilla | P-Excel (original) | Semántica |
|---|---|---|
| `#Unidades` | `#Flows` | **`M`** = eventos decodificados (§2.2) |
| `#Alertas` | `#Alerts` | alertas brutas en legítimo |
| `#Alertas_correlacionadas` | `#Flow-correlated Alerts` | `Σ_unidades (rule.id distintos)` |
| `#rule.id_distintos` | `#SIDs, #AttackID o #ThreatID` | `rule.id` distintos |
| `#Unidades_FP` | `#Flows_FP` | unidades con ≥1 alerta |
| `#Unidades_TN` | `#Flows_TN` | `M − #Unidades_FP` |
| `%Unidades_FP` | `%Flows_FP` | `#Unidades_FP / #Unidades` |
| `%Unidades_TN` | `%Flows_TN` | `1 − %Unidades_FP` |
| `#Alertas_FP` | — | alertas brutas (FP) |
| `#Alertas_FP_sin_auto_ruido` | — *(complemento, L2)* | FP sin la auto-alerta del HIDS |
| `FP_por_accion` | — *(complemento D1)* | `FP / n_acciones_ghosts` |
| `FP_por_hora` | — *(complemento D1)* | `FP / duracion_h` |

**Bloque DETALLE por `rule.id`:** `rule.id | rule_level | groups | rs_origen | #alertas_legitimas |
#unidades_con_la_regla | #alertas_correlacionadas | ¿es_TP_en_algún_ataque? | veredicto`
(`solo_FP | mixta | auto_ruido | operador`).

### 4.4 T4 — Rendimiento (métricas) — `Hojas/T4_rendimiento.csv`

> Adapta **`T4 (Rend)`**. Filas del profesor (verbatim): `#Attack flows | #Clear flows | #Total
> Flows | #pcaps TP | #pcaps FN | #Alerts TP | #Flow-correlated Alerts TP | #Flows FP | #Flows TN |
> #Alerts FP | #Flow-correlated Alerts FP | TPR | FPR | GM | Operational Usability | Operational
> Usability (correlated alerts)` + bloque de **fórmulas**.

**Filas adaptadas (mismo orden lógico):**

| Fila plantilla | P-Excel | Fórmula/nota |
|---|---|---|
| `#Casos` | `#Attack flows` | `N = 55` |
| `#Unidades_legitimas (M)` | `#Clear flows` | denominador §2.2 |
| `#Total` | `#Total Flows` | `#Casos + M` (informativo) |
| `#Casos_TP` | `#pcaps TP` | §2.3 |
| `#Casos_FN` | `#pcaps FN` | `N − #Casos_TP` |
| `#Alertas_TP` | `#Alerts TP` | `A_TP` |
| `#Alertas_correlacionadas_TP` | `#Flow-correlated Alerts TP` | `A_TP^c` |
| `#Unidades_FP` | `#Flows FP` | `FP_uni` |
| `#Unidades_TN` | `#Flows TN` | `M − FP_uni` |
| `#Alertas_FP` | `#Alerts FP` | `A_FP` |
| `#Alertas_correlacionadas_FP` | `#Flow-correlated Alerts FP` | `A_FP^c` |
| **`TPR`** | `TPR` | `#Casos_TP / #Casos` |
| **`FPR`** | `FPR` | `#Unidades_FP / M` |
| **`TNR`** | *(añadido)* | `1 − FPR` |
| **`Precisión`** | *(bloque fórmulas)* | `A_TP/(A_TP+A_FP)` |
| **`F1`** | *(bloque fórmulas)* | `2PR/(P+R)`, `R=TPR` |
| **`GM`** | `GM` | `√(TPR·(1−FPR))` |
| **`Usabilidad`** | `Operational Usability` | `A_FP/A_TP` |
| **`Usabilidad (correlacionadas)`** | `Operational Usability (correlated alerts)` | `A_FP^c/A_TP^c` |

**Columnas = (HIDS × config × umbral).** Incluye un **bloque de fórmulas/leyenda** idéntico al
profesor (las 7 de §2.5, **literales**).

### 4.5 T5 — Pruning (mejora del rendimiento) — `Hojas/T5_pruning.csv`

> Adapta **`T5 (Pru)`** = **exactamente** el *pipeline* del repo hermano (`optimo_Snort_GM_v4.py`).
> Variantes del profesor: `No Pruning | Pruning 500 | Pruning 1000 | Conservative | Generalized
> Conservative | Aggressive (G-Mean)`. Con `rule.id` en lugar de `SID`.

**Definición congelada de cada variante** (cita literal del hermano):

1. **No Pruning** — todas las reglas.
2. **Pruning N (500 / 1000)** — quitar reglas con **`#alertas_correlacionadas` FP > N**
   (hermano: `sids = {s for s in sids_activos if leg_diff_counts[s] <= 500}`).
3. **Conservative** — quitar reglas que son **FP y nunca TP**
   (hermano: `ids_fp_exclusivos = sids_legitimo − sids_ataque`).
4. **Generalized Conservative** — quitar **todas** las FP **aunque sean TP**.
5. **Aggressive (G-Mean)** — **eliminación hacia atrás**: ordenar las reglas mixtas por impacto en
   legítimo (desc) y **quitar solo si el GM mejora** (hermano: `if m_gm > current_gm`).

**Columnas por variante:** `GM | %Deteccion_casos | #reglas_quitadas | lista_rule.id_quitados |
#Alertas_total | #Alertas_TP | #Alertas_FP | Usabilidad`.
**Tabla auxiliar** (variante agresiva): `paso | rule.id_quitado | TP_casos | FN_casos | TN_unidades |
FP_unidades | TPR | TNR | GM | Alertas_TP | Alertas_FP` (hermano: `2_GM_Optimization_Steps.csv`).

> **Decisión abierta de escala (§9.2, abierta 8).** `N ∈ {500, 1000}` es la **escala del NIDS**
> (78 M flujos). En nuestro legítimo (eventos), 500/1000 **siguen siendo válidos** (el auto-ruido
> `80791` solo ya produce miles), pero se **declara** un **umbral relativo** `N = p %·(máx FP)`
> como **variante adicional** si el volumen lo hace degenerado. **Parámetro congelable.**

### 4.6 "Requisitos de estudios" — `Hojas/requisitos_estudio.csv`

> Adapta **`Requisitos Estudios`** (cabecera real: `Requisito de pcaps | Columnas para Filtrar |
> <HIDS1> | <HIDS2> | Nº pcaps Tabla detecciones no lo cumplen`; 137 pcaps).

**Columnas:** `requisito | columna_para_filtrar | wazuh | velociraptor | n_casos_que_no_lo_cumplen | nota`.
**Filas** (6, `R0 §5.6`; analogía directa):

1. **Técnica detectable por host** (≡ "detectable por red").
2. **Marcado manual de ataques** (acciones/instancias) (≡ "marcado manual de flujos/instancias").
3. **Asociación manual TP/FP por `rule.id`** (en cada RS) (≡ "asociación manual de SIDs").
4. **Ataque detectable por patrones/reglas** (≡ "detectable por patrones").
5. **Cubren todas las técnicas P1** (≡ "cubran todas las técnicas de red").
6. **"Paquete pcap" completo (contexto + acciones + telemetría)** (≡ "ataques L3").

`¿cumple?` = `SI | NO | ?` por HIDS; `n_casos_que_no_lo_cumplen` = recuento **calculado** sobre
`Hojas/ATA_index.csv` + cobertura + bitácoras.

### 4.7 "Leyenda" — `Hojas/leyenda.csv`

> Adapta **`(E) Leyenda`**. Documenta **columna a columna** cada tabla, el **glosario de unidades**
> (§2.1) y **las equivalencias** (`pcap↔paquete`, `red↔host`, `SID↔rule.id`, `flujo↔unidad`,
> `pcap↔ATA`), más el **bloque de fórmulas** (§2.5) y la **definición de "virgen"** (§3.1).

**Columnas:** `tabla | columna | significado | equivalencia_nids | unidad | nota`.
Cubre **todas** las columnas de T1–T5 + Requisitos, de modo que un lector externo pueda auditar
cada cifra sin abrir los scripts.

---

## 5. Dónde vive cada cosa en el repo

```
Soporte/Metrica/                         (NUEVA carpeta)
  metrica_hids.md                        ← métrica congelada (v1) + sha256
  metrica_hids.sha256
  boveda_congelacion.md                  ← §3.2 (+ .sha256)
  formula_plantillas.md                  ← bloque de fórmulas literal (profesor + hermano)

Hojas/
  T1_clasificacion.csv                   ← T1 (canónico)
  T2_ataques.csv                         ← T2
  T3_legitimo.csv                        ← T3
  T4_rendimiento.csv                     ← T4
  T5_pruning.csv                         ← T5 (+ T5_steps.csv)
  requisitos_estudio.csv                 ← Requisitos
  leyenda.csv                            ← Leyenda

Estudio-Wazuh/                           (expone el estándar de carpetas del hermano)
  TFG_HIDS_Wazuh_linux.xlsx              ← export .xlsx (5 hojas + Requisitos + Leyenda)
  TFG_HIDS_Wazuh_windows.xlsx
Estudio-Velociraptor/                    (NUEVO; se puebla en V1)
  TFG_HIDS_Velociraptor_linux.xlsx
  ...

_artefactos/scripts/
  metrica_hids.py                        ← MÓDULO CONGELADO (formulas + unidades + constantes)
  tabla1_clasificacion.py
  tabla2_ataques.py
  tabla3_legitimo.py
  tabla4_rendimiento.py
  tabla5_pruning.py
  requisitos_leyenda.py
  exportar_excel.py
  tests/test_metrica_hids.py
  tests/test_tabla2_ataques.py
  tests/test_tabla3_legitimo.py
  tests/test_tabla4_rendimiento.py
  tests/test_tabla5_pruning.py
  tests/fixtures/tablas_*                ← fixtures sintéticos
```

> **Principio KISS/reproducibilidad:** el **CSV es la fuente de verdad** (determinista, `sha256`,
> diff-able); el **`.xlsx` es un export** generado por `exportar_excel.py` con **propiedades
> fijadas** (fechas internas constantes) para que sea reproducible byte a byte. El `sha256` de cada
> CSV **y** de cada `.xlsx` se registra en la cabecera del CSV / en el `change-doc`.

---

## 6. Especificación de los scripts

> **Decisión:** **un módulo común congelado** (`metrica_hids.py`) **+ un script por tabla**.
> Razón: las fórmulas deben vivir en **un solo sitio** (si no, divergen); cada tabla tiene una
> entrada distinta y se testea aparte. Todos: **Python 3 estándar** (sin dependencias salvo
> `openpyxl` para el export), **UTF-8 sin BOM**, fin de línea **LF**, **sin reloj** en la salida,
> orden estable, **misma entrada → mismos bytes** (`RNF-01`).

### 6.1 `metrica_hids.py` — módulo congelado (sin `main`)

- **Contiene:** `VERSION_METRICA`, las 3 unidades, las 7 fórmulas (funciones puras `tpr`, `fpr`,
  `tnr`, `precision`, `f1`, `gm`, `usabilidad`), los juegos de umbrales/config, la **regla de
  ventana canónica** (§2.7), las **variantes de pruning** (§4.5) y la **lectura del orden de
  decisión** de Fase 3 (`CATEGORIAS`).
- **No lee ficheros** (salvo tests). Es la **fuente única** de la métrica.
- **Test:** `test_metrica_hids.py` fija cada fórmula con vectores conocidos (p. ej. `gm(1,1)=1`,
  `gm(0.5,0.5)=0.5`, `f1(1,1)=1`, `fpr=M,FP` exacto) y **prohíbe** que otro script reimplemente.

### 6.2 `tabla2_ataques.py` — T2 (plano ataque)

- **Lee:** `--auditado DIR` (los `-Audited.csv` de una medición: `linux/Auditado/`),
  `Hojas/ATA_index.csv`, `Hojas/repeticiones.csv`, las bitácoras `Bitacora/ATA<NNN>.json`
  (`t0,t1,duracion_s,conteos,metrico_o2,doble_iteracion`), y `--config`/`--umbral`.
- **Escribe:** `Hojas/T2_ataques.csv` (cabecera `#` con `metrica_version` + `sha256` de entradas
  + `config/umbral`).
- **Determinismo:** orden por `(n, ata_id)`; sin reloj; redondeos **fijos** (ver §6.8).
- **Verificación interna:** aplica **C1′/C2′/C3′** entre ventana canónica y 2.ª ventana; si falla,
  marca `doble_iteracion=review` y **no cuenta** el caso como TP (L4).
- **Invoca:** solo lectura de ficheros; **no** toca el laboratorio.

### 6.3 `tabla3_legitimo.py` — T3 (plano legítimo)

- **Lee:** el **detalle por evento** de la corrida legítima (`Dataset/Legitimo/<so>/…`, formato de
  `extraer_alertas.py --detail` ampliado con el **contador del denominador**), el **nº de eventos
  decodificados** (`archives.json` ⇒ `M`), y el **fichero de acciones GHOSTS** (si existe).
- **Escribe:** `Hojas/T3_legitimo.csv` (meta + bloques config×umbral + detalle por `rule.id`).
- **Fallback (L11):** si no hay `M` instrumentado, `#Unidades = n/a` y **no** publica FPR-por-evento
  (usa `FP_por_accion` / `FP_por_hora`); lo **declara** en la cabecera.
- **Clasificación de la ventana legítima:** reutiliza `filtrar_ruido.py --modo baseline` para
  separar `auto_ruido` vs resto (regla 5, §2.6); **no** reimplementa el filtro.

### 6.4 `tabla4_rendimiento.py` — T4 (métricas)

- **Lee:** `Hojas/T2_ataques.csv` + `Hojas/T3_legitimo.csv` + `metrica_hids.py`.
- **Escribe:** `Hojas/T4_rendimiento.csv` (filas de §4.4; columnas config×umbral×HIDS + bloque de
  fórmulas).
- **No** recalcula la clasificación: **solo** agrega y aplica fórmulas.

### 6.5 `tabla5_pruning.py` — T5 (pruning)

- **Lee:** T2 + T3 + el **`#rule.id` FP/TP** por regla (derivado de T3/DETALLE y de los catálogos
  `Dataset/Legitimo/ruleids_legitimos*.csv`).
- **Escribe:** `Hojas/T5_pruning.csv` + `Hojas/T5_steps.csv` (variante agresiva).
- **Determinismo:** orden estable de reglas (numérico ascendente, como el hermano); la eliminación
  hacia atrás es **determinista** (mismo orden ⇒ mismo resultado).

### 6.6 `tabla1_clasificacion.py`, `requisitos_leyenda.py`, `exportar_excel.py`

- **`tabla1_clasificacion.py`:** lee `Tabla 1 …v17.xlsx` (hoja `Techniques`), `Hojas/corpus_host.csv`,
  `cobertura_p1_linux.csv`, `inventario_p1_windows.csv` → `Hojas/T1_clasificacion.csv`.
- **`requisitos_leyenda.py`:** calcula `n_casos_que_no_lo_cumplen` desde `ATA_index.csv` + cobertura
  → `Hojas/requisitos_estudio.csv`; emite `Hojas/leyenda.csv` (estática + recuentos).
- **`exportar_excel.py`:** `CSV → .xlsx` con `openpyxl`, **una hoja por tabla + Requisitos +
  Leyenda**, **propiedades fijadas** (`wb.properties.created/modified` = constante) ⇒ **reproducible**.

### 6.7 Cómo se invocan y cómo se testean

- **Invocación tipo** (Windows/PowerShell o Linux, **solo lectura del repo**):
  `python _artefactos/scripts/tabla2_ataques.py --auditado Dataset/Ataques/Resultados/Wazuh/linux/Auditado --config C1 --umbral 0`
- **Tests** (`pytest`, como en el resto del repo, sin VMs): **fixtures sintéticos**
  (`tests/fixtures/tablas_*`) que fijan la matriz de confusión, las 7 fórmulas, el doble conteo,
  los casos límite L1–L11 y el **determinismo byte a byte**.
- **Prueba de humo (CA fuerte):** `tabla2_ataques.py` sobre el **corpus congelado** (`C1 × N=0`)
  debe reproducir **53/55** (`TP=53, FN=2`, `rule.id` distintos por caso) ⇒ **sin re-medir**.
- **Regla dura:** los scripts **no** escriben fuera de `Hojas/` y `Estudio-*/`; **no** tocan
  `Dataset/`, `Soporte/Wazuh/`, ni `extraer_alertas.py`.

### 6.8 Redondeo y formato (congelados, anti-deriva)

- Porcentajes: **4 decimales** en T3/T4 (como el profesor: `4.3095 %`); ratios `GM/TPR/FPR`: **6
  decimales** (hermano: `:.6f`); `Usabilidad`: **4 decimales** (hermano: `round(...,4)`).
- `%Deteccion` en T2/T5: **2 decimales** (hermano: `55.45 %`).
- Separador decimal **punto**; `%` **literal** en la celda de T3/T5 solo en el export.

---

## 7. Relación con la métrica de Fase 3 (reutiliza vs nuevo)

**Son dos cosas distintas y NO deben confundirse** (`R0 §4.5.1`):

| | **Fase 3 (congelada, v7)** | **R2 (nueva)** |
|---|---|---|
| Qué es | **Pertenencia / atribución**: a qué categoría va cada fila | **Métrica de resultado**: TPR, FPR, …, a niveles |
| Salida | `categoria ∈ {deteccion, ruido_conocido, auto_ruido, dudosa, artefacto_ataque}` | T2/T3/T4/T5 |
| Dónde vive | `filtrar_ruido.py` + `politica_filtrado_ruido.md` v7 | `metrica_hids.py` + `metrica_hids.md` v1 |
| Unidad | la **alerta** | el **caso** / la **unidad legítima** / la **alerta** |

**Se REUTILIZA tal cual** (no se toca, `RNF-02`):

- El **orden de decisión** y las **categorías** (`deteccion` = la técnica; `artefacto_ataque`
  nunca `ruido`; `dudosa` nunca descartada).
- La **pertenencia** (`ATTACK_ROOT`, ancla `exe ∧ cwd ∧ audit_command`, predicado `OPERADOR`,
  `rule_id 11 stats`).
- Los **`-Audited.csv`** como **entrada directa** de T2 (no se re-clasifica).
- El **criterio de doble iteración v2** (C1′/C2′) y la **ventana canónica** (§2.7).

**Es NUEVO:**

- Las **fórmulas de resultado** (TPR/FPR/TNR/Precisión/F1/GM/Usabilidad) y su **agregación**.
- El **denominador del legítimo** (`M`) y su instrumentación.
- La **regla de la ventana canónica** y el **doble conteo** formalizado (§2.4).
- La **estructura de las 5 tablas + Requisitos + Leyenda**.

> **Aviso para el revisor:** la métrica de Fase 3 es **insumo**, no resultado. Confundir
> "`deteccion` = pertenencia" con "TPR = resultado" es el error que R2 evita.

---

## 8. Comparabilidad ENTRE HIDS (unidad común)

> La unidad legítima = **evento** **NO es comparable** entre Wazuh (registros de log) y
> Velociraptor (filas de artifact): sus "eventos" son **cosas distintas** (`R0 §4.6`).

**Queda fijado así** (congelado):

- **El titular de FPR de cada HIDS** es **por su propio evento** (**per-HIDS**, su denominador es
  **específico del HIDS** ⇒ **no** comparable en crudo).
- **La comparación VR↔Wazuh** usa **DOS ejes**:
  1. **Unidad COMÚN explícita**: la **acción de GHOSTS / la hora** (`FP/acción`, `FP/hora`) — la
     **misma** actividad real alimenta ambos HIDS (corridas **por separado**, Q10).
  2. **Comparación POR TÉCNICA** (como el TFM del mismo tutor): misma `ATA<NNN>`/`T<n>` ⇒ ¿detecta
     SÍ/NO?, con qué `rule.id`/artifact.
- **Se declara** que son **paradigmas distintos** (alarmas vs recolección) y **no se fuerza** una
  igualdad artificial.
- **Puente de severidad VR↔Wazuh:** perfiles **P4 ≤ P3 ≤ P2 ≤ P1** ↔ niveles Wazuh (Tabla 60 del
  TFM), **respetando el orden** (en Wazuh mayor = más severo; en Snort `N=1` = máximo).

---

## 9. Riesgos, decisiones abiertas y casos límite no resolubles

### 9.1 Riesgos (con mitigación)

| Riesgo | Impacto | Mitigación |
|---|---|---|
| **Congelar mal** la métrica | Contamina TODO | Documento versionado + huella + gate humano + **CA de humo** (53/55) |
| **Denominador `M` inviable** | FPR-por-evento no publicable | Fallback declarado (§2.2) + complementos acción/hora |
| **Doble conteo mal resuelto** | Precisión/GM sesgados | `#Alertas` **y** `#rule.id`, variante correlacionada (§2.4) |
| **Ventana canónica ambigua** | TPR no reproducible | Regla D3 (§2.7) + C1′/C2′ |
| **`logall_json` altera el ruleset** | Rompe "virgen" | Se **verifica** que solo toca `archives`; no cambia reglas (§2.2) |
| **Umbral de pruning degenerado** | T5 sin sentido | Parámetro + variante relativa declarada (§4.5) |
| **VR no-rule-based** | Comparación injusta | Unidad común + por técnica (§8); placeholder hasta `V0` |
| **`dudosa` sin resolver** | Caso no contabilizado | Marcado `review`, nunca TP/FN silencioso (L4) |
| **CRLF / cadena de huellas** | Reproducibilidad | Deuda declarada; **no** `checkout/stash` sobre `esperado`/`Audited` |
| **Fuga de secreto** | Seguridad | La contraseña del laboratorio **nunca** en ficheros del repo |

### 9.2 Decisiones abiertas (se llevan decididas al tutor; el humano confirma)

1. **Unidad legítima** (evento titular + acción/hora): **confirmar con el tutor antes de congelar**
   (`R0 §11.2.1`).
2. **FPR-por-evento vs fallback**: se decide en `L1` según el volumen de `logall_json` (§2.2).
3. **Umbral de "Pruning N"** (§4.5): ¿500/1000 o escala propia? — **parametrizado**; se confirma.
4. **Fleco 3** ("tamaño/tiempos"): confirmar que `nº acciones k/m` + `tiempo de ventana` + `t hasta
   1.ª detección` es el "algo equivalente" (`R0 §5.2`).
5. **Umbrales de la rejilla** `{0,3,7,10,12}`: confirmar (¿basta con 3–4?).
6. **¿`C2`/`C3` (propias/externas)?** → **contingente al gate**; las plantillas los soportan vacíos.
7. **VR**: la unidad ("fila de artifact") y el mapeo P1–P4 **se fijan en `V0`/`V1`** (placeholder
   aquí, declarado).
8. **Windows (`B1`)**: las tablas se reutilizan tal cual; los números llegan en `B1`.

### 9.3 Casos límite no resolubles ahora (declarados)

- **El denominador del legítimo** depende de `L0`/`L1` (GHOSTS + `logall_json`): **hoy no existe**;
  R2 deja la **especificación** y el **fallback**, no el número.
- **La unidad de VR** no se puede congelar hasta **desplegar VR** (`V0`).
- **`C2`/`C3`** no tienen datos (RS3=RS4=0) ⇒ sus columnas quedan **vacías** hasta el gate.

---

## 10. Criterios de aceptación (verificables)

| # | Criterio | Verificación |
|---|---|---|
| **CA-R2-01** | Existe **`Soporte/Metrica/metrica_hids.md`** con `version: 1`, `fecha`, `status: congelada` y **`sha256`**. | Fichero + sidecar |
| **CA-R2-02** | Las **3 unidades** y los **denominadores** están definidos sin ambigüedad (§2.1–§2.2). | Revisión + `metrica_hids.py` coincide |
| **CA-R2-03** | Las **7 fórmulas** son **literales** del Excel del profesor y del hermano (citadas). | Fichero vs `metrica_hids.py` |
| **CA-R2-04** | Las **reglas de conteo** (§2.6) y los **casos límite L1–L11** (§2.9) están **congelados**. | Revisión |
| **CA-R2-05** | Existen las **plantillas** de T1–T5 + Requisitos + Leyenda con la **cabecera exacta** del profesor (equivalencias declaradas). | §4 + CSV + `.xlsx` |
| **CA-R2-06** | Existe la **bóveda de congelación** (§3.2) con hashes B1–B10. | `boveda_congelacion.md` + `.sha256` |
| **CA-R2-07** | Los **scripts** existen, son **deterministas** (misma entrada → mismos bytes) y tienen **`sha256`**. | `pytest` + doble ejecución |
| **CA-R2-08** | `pytest` **en verde** (fixtures de tabla + fórmula + casos límite + determinismo). | Salida de `pytest` |
| **CA-R2-09** | **Prueba de humo:** `tabla2_ataques.py` sobre el corpus congelado (`C1 × N=0`) reproduce **53/55**. | Recuento exacto |
| **CA-R2-10** | El **`.xlsx` de export** es **reproducible** (propiedades fijadas). | Doble export → mismo `sha256` |
| **CA-R2-11** | **No** se ha tocado `extraer_alertas.py`, `Hojas/`, `Dataset/`, `_recursos/` ni el laboratorio. | `git status` + huellas |
| **CA-R2-12** | **Sin secretos** (contraseña del laboratorio **nunca** en ficheros). | Auditoría de texto |
| **CA-R2-13** | Reutiliza la **pertenencia de Fase 3** y **no** la reimplementa (§7). | Revisión de código |
| **CA-R2-14** | La **comparabilidad entre HIDS** queda **fijada** (§8). | Revisión |

---

## 11. Gate humano (lenguaje sencillo)

> Para aprobar R2 **antes** de escribir el documento congelado, las plantillas y los scripts.

1. **La regla de medida.** Voy a medir en **tres planos**: **ataques** (¿detecta el caso? → **TPR**),
   **legítimo** (¿cuánta actividad normal genera alerta? → **FPR**) y **alertas** (Precisión, GM,
   Usabilidad). **GM = √(TPR·(1−FPR))** y **Usabilidad = nº alertas falsas / nº alertas buenas** —
   **las fórmulas del profesor y del TFG hermano de Ignacio Merchán**, copiadas literalmente.
2. **La unidad del legítimo (lo delicado).** Cuento como unidad **cada evento que el HIDS
   decodifica** (como el NIDS contaba *flujos*), con `logall_json` para el denominador (no cambia
   las reglas ⇒ sigue "virgen"). **Además** doy **por acción de GHOSTS** y **por hora**.
   **En crudo, Wazuh y Velociraptor NO son comparables por evento** (sus "eventos" no son lo mismo):
   los comparo por **acción/hora** y **por técnica**. ¿De acuerdo?
3. **El doble conteo.** Reporto **siempre** dos cifras (alertas brutas **y** `rule.id` distintos),
   como el profesor; nunca una sola.
4. **La ventana canónica.** Cada ataque cuenta **una vez** (su ventana canónica: la repetición para
   los 9 repetidos, si no la iteración 1); la otra ventana es **control de reproducibilidad**.
5. **El "pruning" (T5).** Copio las **6 variantes** del profesor (500, 1000, Conservador,
   Conservador generalizado, Agresivo por GM). El umbral 500/1000 es la escala del NIDS; **si en
   nuestra escala no tiene sentido, añado la variante en %** (declarado).
6. **Las plantillas.** Son las **5 tablas del profesor + Requisitos + Leyenda**, con **sus mismas
   columnas**, cambiando `SID→rule.id`, `pcap→ATA`, `flujo→unidad`. Se entregan en **CSV (fuente
   de verdad)** y en **Excel (equivalente)**.
7. **Nada se mide hasta que esto esté congelado y tú lo apruebes.**

---

## 12. Ficheros que se tocarán

**Nuevos (creados en ejecución, tras el gate):**
- `Soporte/Metrica/metrica_hids.md` (+ `.sha256`), `boveda_congelacion.md` (+ `.sha256`),
  `formula_plantillas.md`.
- `Hojas/T1_clasificacion.csv`, `T2_ataques.csv`, `T3_legitimo.csv`, `T4_rendimiento.csv`,
  `T5_pruning.csv` (+ `T5_steps.csv`), `requisitos_estudio.csv`, `leyenda.csv`.
- `Estudio-Wazuh/TFG_HIDS_Wazuh_linux.xlsx` (+ `windows`), `Estudio-Velociraptor/…` (placeholder).
- `_artefactos/scripts/metrica_hids.py`, `tabla1..5_*.py`, `requisitos_leyenda.py`,
  `exportar_excel.py` (+ `tests/…`).

**Modificados (mínimo):**
- `state.md`, `roadmap.md` (marcar R2) y el `change-doc` del bloque (al cerrar).

**Prohibido tocar:**
- `_artefactos/scripts/extraer_alertas.py` (**sha congelado**), `filtrar_ruido.py` (solo se **usa**),
  `Hojas/*` **existentes**, `Dataset/**`, `Soporte/Wazuh/**`, `_recursos/**` (solo lectura), el
  laboratorio.

---

## 13. Trazabilidad (fuentes y afirmaciones verificadas)

| Afirmación | Cita verificable |
|---|---|
| **T4**: filas `#Attack flows … Operational Usability (correlated alerts)`; `TPR=B6/…D79`; `FPR=B10/$B$4`; `GM=SQRT(B14*(1-B15))`; `Usab=B12/B8`; `Usab corr=B13/B9` | P-Excel hoja `T4 (Rend) S<=4, FG>=1` (celdas leídas, esta revisión) |
| **T3**: filas `#Flows, #Alerts, #Flow-correlated Alerts, #SIDs/#AttackID/#ThreatID, #AppID, #Flows_FP, #Flows_TN, %Flows_FP, %Flows_TN` | P-Excel hoja `Tabla 3 (Legítimo)` R2–R11 |
| **T2 Imple**: `Nº | Nº Technique | pcapng (SubTechnique-Attack) | Technique | #Flows |` + `#Alerts | #Flow-correlated Alerts | #SID | #Attack_Flows | Detection` | P-Excel hoja `Tabla 2 - Ataques detec (Imple)` R1–R2 |
| **T2 pivot**: `Nº | Technique | Description | #pcaps | #flows | #pcaps (#flows) |` + 6 subcolumnas/config | P-Excel hoja `T2 (At) S<=4, FG>=1` R1–R2 |
| **T5**: variantes `No Pruning | Pruning 500 | Pruning 1000 | Conservative | Generalized Conservative | Aggressive` | P-Excel hoja `T5 (Pru) S<=4,FG>=1` A4–A39 |
| **Requisitos** (6 requisitos + cabecera `Requisito de pcaps | Columnas para Filtrar | …`) | P-Excel hoja `Requisitos Estudios` (ref_dump, 137 pcaps) |
| **`(B) Legitimo`**: `pcap (Nombre) | Tipo de tráfico | Tamaño real del tráfico | #Flujos | #Intentos Flujo (SYN) | #IPs |` + por RS 6 subcols | P-Excel hoja `(B) Legitimo` R1–R3; `#Flujos=78.694.206` |
| **`(A) Ataques`**: `TÁCTICA | OTRAS TÁCTICAS | … | HERRAMIENTA | pcap (Nombre TFGs) | … | NIVEL DE ATAQUE | PROCESO DE GENERACIÓN DEL PCAP | VALIDACIÓN DEL PCAP | ANÁLISIS DE DETECCIONES` | P-Excel hoja `(A) Ataques` R1–R2 |
| **Severidad invertida Snort vs FG/PA** | P-Excel hoja `RuleSets` A26 (nota) |
| **Fórmulas del hermano**: `gm=math.sqrt(tpr*tnr)`, `usab=a_fp/a_tp`, `tp`=pcaps, `fp`=flows; pruning 500/1000/Conservative/Agressive | `Scripts/optimo_Snort_GM_v4.py` (`calc_metrics`, `main`) |
| **RS3 = RS4 = 0**; RS1 4.471 · RS2 44 | `Soporte/Wazuh/Configuracion/active_ruleset.txt` |
| **`-Audited.csv`** con `rule_level` + `rs_origen` + `categoria` | `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA001_iter1-Audited.csv` (160 ficheros) |
| **Corpus**: 55 casos (ATA001..055) · 128 ventanas · 53 detectadas (2 no: ATA013, ATA034) | `Hojas/ATA_index.csv`, `state.md` |
| **9 repeticiones canónicas** (`_rev`) | `Hojas/repeticiones.csv` (9 filas) |
| **Pertenencia / orden de decisión** | `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` v7; `filtrar_ruido.py` |
| **Doble iteración v2** (C1′/C2′/C3′) | `Soporte/Ataques/criterio_doble_iteracion.md` |

---

## 14. Lo que NO cuadra (declarado, para el revisor)

1. **`FPR`-por-evento no es comparable entre HIDS** (evento de Wazuh ≠ fila de VR). Se **declara**
   y se resuelve con la **unidad común** (acción/hora + por técnica). `M` es **per-HIDS**.
2. **El denominador `M` aún no existe** (llega en `L0`/`L1`). R2 fija la **especificación** + el
   **fallback**; el **número** no puede congelarse aquí.
3. **La unidad de VR** no se congela hasta `V0`. Aquí queda el **placeholder** declarado.
4. **`C2`/`C3`** (RS3/RS4) están **vacíos**: sus columnas nacen **vacías** hasta el gate.
5. **`Pruning N` a escala del NIDS** (500/1000) puede ser **degenerado** en nuestra escala; se
   **parametriza** y se declara la variante relativa.
6. **El umbral de nivel** `{0,3,7,10,12}` es una **propuesta**; se confirma con el tutor (abierta 5).
7. **La ventana canónica** (`rev1`/`iter1`) es una **decisión de R2** para cerrar la ambigüedad
   "55 casos vs 128 ventanas"; el criterio v2 las declara `iguales`, así que es consistente.
8. **La auto-alerta cuenta como FP** (convención del profesor) aunque sea del propio HIDS; se
   reporta aparte la variante sin `auto_ruido` para no "esconder" ni "inflar".
