---
bloque: reencuadre-metrica
nombre: Métrica HIDS congelada (unidades, denominadores, fórmulas, reglas, ventana canónica)
version: 1
status: congelada
fecha: 2026-10-16
autor: tfg-executor
sha256: metrica_hids.sha256
depende_de: plan.md (bloque `reencuadre-metrica`, aprobado 2026-10-16) · Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md (v7)
---

# Métrica HIDS congelada — versión 1

> **Este documento es la FUENTE ÚNICA DE VERDAD de la medida.** Ningún script puede
> contradecirlo: las fórmulas viven en `_artefactos/scripts/metrica_hids.py` y **coinciden
> literalmente**. Cambiar cualquiera de los puntos congelados aquí **invalida las medidas**
> y exige una **versión nueva** (§9). La huella del fichero está en `metrica_hids.sha256`.

Se apoya en la **métrica de Fase 3** (`politica_filtrado_ruido.md` v7), que es **insumo**
(la *pertenencia*: `categoria` de cada fila), **no** resultado (§7).

---

## 1. Los tres planos y sus unidades

Réplica exacta de la estructura del trabajo de referencia (P-Excel hoja `T4 (Rend)`):

| Plano | Unidad (HIDS) | Equivalente NIDS | Se usa para |
|---|---|---|---|
| **Ataque** | **caso** = ventana canónica `ATA<NNN>` (§8) | `pcap` | **TPR**, FN |
| **Legítimo** | **unidad de actividad legítima** = **evento/registro decodificado** | `flujo` | **FPR**, TN |
| **Alerta** | **`rule.id` que Wazuh emite** / **fila de artifact de VR** | `alerta` | **Precisión**, **Usabilidad**, F1 |

**Nomenclatura fija:**

- `N` = nº de **casos** (plano ataque) = **55**.
- `M` = nº de **unidades legítimas** = nº de **eventos/registros decodificados** por el HIDS
  en la ventana (denominador **instrumentado**; §2).
- `A_TP`, `A_FP` = nº de **alertas** (planos de alerta).

---

## 2. La unidad del legítimo y su denominador (`M`)

**Titular (congelado).**

- **Unidad** = **un evento/registro de telemetría legítimo** = **una entrada decodificada por
  el HIDS** (en Wazuh, una línea de `archives.json`; análoga al "flujo" del NIDS).
- **Denominador `M`** = nº de **eventos decodificados** en la ventana legítima, **instrumentado**
  con **`<logall_json>yes</logall_json>`** del manager (Wazuh escribe **todos** los eventos que
  decodifica en `archives.json`, **hayan disparado o no** una regla). **No cambia el ruleset**
  ⇒ **virgen preservada** (`boveda_congelacion.md`, §3).
- **`FP_uni`** = nº de unidades con **≥1 alerta** en la ventana (config × umbral dados).
- **`TN_uni`** = `M − FP_uni`.

**Complementos declarados (se reportan siempre, no sustituyen al titular).**

1. **Acción de GHOSTS** (unidad discreta, contable): `FP/acción`, `nº de acciones`.
2. **Hora de actividad**: `FP/hora`.

**Fallback declarado (con disparador explícito).** Si al cerrar `L1` el fichero `archives.json`
de 72 h **no es manejable** (p. ej. > ~5 GB) **o** la decodificación no es fiable, el **titular
cae** a **`FP/acción` + `FP/hora`** y se **documenta como limitación**. **El disparador y la
decisión se registran en `L1`**; la métrica **no cambia**, solo qué columna es titular (caso L11).

**Limitación declarada (`FPR`-por-evento NO comparable entre HIDS).** El "evento" **depende de
la telemetría** (congelada en la bóveda) ⇒ el evento de Wazuh **≠** la fila de VR. Para
**comparar** se usa la **unidad común** (§10), no el evento. `M` es **per-HIDS**.

---

## 3. Matriz de confusión (por plano)

**Plano ATAQUE (caso):**

```
                    | detectado | no detectado
  ataque real (P1)  |  TP_ata   |   FN_ata
```

- `TP_ata` = nº de casos con **≥1 alerta `categoria=deteccion`** (pertenencia de Fase 3) **y**
  `rule_level ≥ N` **y** `rs_origen ∈ config` (config × umbral dados).
- `FN_ata = N − TP_ata`, con `N = 55`.
- **`TPR = TP_ata / N`** (§5, fórmula 1).

**Plano LEGÍTIMO (unidad):**

```
                     | con alerta | sin alerta
  actividad legítima |  FP_uni    |  TN_uni
```

- `FP_uni` = nº de unidades legítimas con **≥1 alerta** (config × umbral dados). **La
  auto-alerta del HIDS cuenta como FP** (regla de conteo 5); la variante **sin `auto_ruido`**
  se reporta como **complemento**.
- `TN_uni = M − FP_uni`; **`FPR = FP_uni / M`**; **`TNR = 1 − FPR`**.

**Plano ALERTA (conteo):**

- `A_TP` = nº de alertas de los ataques (`categoria=deteccion`).
- `A_FP` = nº de alertas sobre legítimo (**todas**, **auto-alerta incluida**).
- **Doble conteo**: se reportan **`#Alertas`** (bruto) **y** `#rule.id` **distintos**; la
  variante **correlacionada por unidad** (§4).
- **`Precisión = A_TP / (A_TP + A_FP)`**; **`Usabilidad (FTTAR) = A_FP / A_TP`**.

---

## 4. Doble conteo y "alertas correlacionadas"

Una misma acción puede generar **varias señales a la vez** ⇒ contar alertas brutas **infla**.
Se publican **siempre dos cifras** (como el profesor), y las métricas de alerta se dan en
**versión bruta** y en **versión correlacionada** (`^c`). Ninguna sustituye a la otra.

- **`#Alertas`** = nº **bruto** de alertas (filas).
- **`#rule.id` distintos** = cardinalidad del **conjunto** de `rule.id` con alerta.
- **`#Alertas correlacionadas`** = **Σ sobre unidades de (`rule.id` distintos en esa unidad)**:
  - **Plano ataque:** la unidad es **el caso** ⇒ `#Alertas correlacionadas = #rule.id
    distintos del caso` (que es el conjunto **C1′** del criterio v2 y el **O1** congelado de
    Fase 3).
  - **Plano legítimo:** la unidad es el **evento** ⇒ `Σ_eventos (rule.id distintos del evento)`.

---

## 5. Las 7 fórmulas congeladas (con fuente literal)

> **Fuente primaria:** P-Excel hoja `T4 (Rend) S<=4, FG>=1`, celdas leídas celda a celda.
> **Fuente confirmada** en el repo hermano (`optimo_Snort_GM_v4.py`, `calc_metrics`).

| # | Métrica | Fórmula | Óptimo | Fuente literal |
|---|---|---|---|---|
| 1 | **TPR** (Recall/CD) | `TP_ata / N` | →1 | Excel `B14 = B6 / 'T2…'!$D$79` |
| 2 | **FPR** | `FP_uni / M` | →0 | Excel `B15 = B10 / $B$4` |
| 3 | **TNR** (Especificidad) | `1 − FPR` | →1 | Excel `%Flows_TN = 1 − %Flows_FP` |
| 4 | **Precisión (P)** | `A_TP / (A_TP + A_FP)` | →1 | Excel bloque de fórmulas `P = TP/(TP+FP)` |
| 5 | **F1** | `2·P·R / (P + R)`, `R = TPR` | →1 | Excel bloque de fórmulas `F1 = 2PR/(P+R)` |
| 6 | **GM** | `√(TPR · (1 − FPR))` | →1 | Excel `B16 = SQRT(B14*(1-B15))`; hermano `gm = math.sqrt(tpr*tnr)` |
| 7 | **Usabilidad (FTTAR)** | `A_FP / A_TP` | →0 | Excel `B17 = B12 / B8`; hermano `usab = a_fp / a_tp` |
| 7c | **Usabilidad `^c`** | `A_FP^c / A_TP^c` | →0 | Excel `B18 = B13 / B9` |

**Cita literal del repo hermano** (no parafraseada):

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

> **Nota metodológica honesta (se declara en la memoria):** `Precisión` vive en el plano
> **alerta** y `Recall/TPR` en el plano **caso**; `F1` y `GM` **mezclan** ambos. Es
> **exactamente** la convención del profesor (`GM = √(TPR·TNR)` con TPR por *pcap* y TNR por
> *flujo*). Se adopta **por comparabilidad** y se **declara la limitación**.

**Redondeo (anti-deriva).** Porcentajes 4 decimales (T3/T4); ratios `GM/TPR/FPR` 6 decimales;
`Usabilidad` 4 decimales; `%Deteccion` 2 decimales; separador decimal **punto**; `%` **literal**
en la celda solo en el export `.xlsx` de T3/T5. Precisión y F1 (ratios) a 6 decimales.

---

## 6. Reglas de conteo (anti-sesgo) — congeladas

1. **Config (Wazuh).** `C0 = {RS1}` · **`C1 = {RS1, RS2}` (virgen)** · `C2 = C1 ∪ {RS3}` ·
   `C3 = C2 ∪ {RS4}`. La **pertenencia** de una alerta a un RS se toma **tal cual** del campo
   `rs_origen` de la fila (**no se recalcula**).
2. **Umbral (Wazuh).** `rule_level ≥ N`, con `N ∈ {0, 3, 7, 10, 12}`. **`N=0` ≡ "cualquier
   alerta emitida"** (las reglas de nivel 0 **no emiten** alerta). El **titular** es
   **`C1` (virgen) × `N=0`**; se publica además la **rejilla** completa.
3. **Un umbral no borra un caso:** un caso pasa a `FN` **solo si ninguna** alerta del caso
   (`categoria=deteccion`) **supera** el umbral.
4. **Doble conteo (§4):** se publican **`#Alertas`** **y** `#rule.id` **distintos**; nunca uno solo.
5. **La auto-alerta cuenta como FP**; se **reporta aparte** la variante **excluyendo
   `auto_ruido`** (complemento).
6. **Nada se descarta en silencio:** una fila no atribuible va a **`dudosa`** y **se declara**.
   `dudosa > 0` en un caso **bloquea** su incorporación al TPR hasta que el humano resuelva (C3′).
7. **Reproducibilidad:** cada cifra se **regenera** con un script determinista y una **huella
   `sha256`**; la cabecera del CSV lleva la **versión de la métrica** + los **hashes de las entradas**.

---

## 7. Relación con la métrica de Fase 3 (reutiliza vs nuevo)

| | **Fase 3 (congelada, v7)** | **R2 (esta métrica)** |
|---|---|---|
| Qué es | **Pertenencia / atribución**: a qué categoría va cada fila | **Métrica de resultado**: TPR, FPR, … |
| Salida | `categoria ∈ {deteccion, ruido_conocido, auto_ruido, dudosa, artefacto_ataque}` | T2/T3/T4/T5 |
| Dónde vive | `filtrar_ruido.py` + `politica_filtrado_ruido.md` v7 | `metrica_hids.py` + este documento |
| Unidad | la **alerta** | el **caso** / la **unidad legítima** / la **alerta** |

**Se REUTILIZA tal cual** (no se toca): el **orden de decisión** y las **categorías**; la
**pertenencia**; los **`-Audited.csv`** como entrada directa de T2; el **criterio de doble
iteración v2** (C1′/C2′/C3′) y la **ventana canónica**. **Es NUEVO:** las fórmulas de resultado
y su agregación; el denominador `M`; el doble conteo formalizado; la estructura de T1–T5.

> **Aviso al revisor:** la métrica de Fase 3 es **insumo**, no resultado. Confundir
> "`deteccion` = pertenencia" con "TPR = resultado" es el error que R2 evita.

---

## 8. La ventana canónica por caso (decisión D3)

- El **plano ataque** cuenta **casos** (`ATA<NNN>`), **no** ventanas. **`N = 55`.**
- **Ventana canónica (regla congelada):**
  - **`ATA<NNN>_rev1`** si el ATA **está** en `Hojas/repeticiones.csv` (**9 casos**); si no,
  - **`ATA<NNN>_iter1`**.
- La **segunda ventana** (`iter2`, o `rev2` en los 9) se usa **solo** para la **prueba de
  reproducibilidad** (C1′ = mismo conjunto de `rule.id`; C2′ = `|n2−n1| ≤ max(2, 10 %·n1)`;
  C3′ = ninguna `dudosa` sin resolver). Si falla → **`review`** y el caso se **marca** (no
  TP ni FN silencioso).

---

## 9. Qué se congela y qué invalida una medida

**Se congela (este documento):** las 3 unidades y sus denominadores (§1–§2); las 7 fórmulas
(§5, literales); las reglas de conteo (§6) y los casos límite L1–L11 (§9.2); la regla de ventana
canónica (§8); el orden de decisión de Fase 3 (§7); el glosario de equivalencias (§4, §10).

**Invalida una medida** (obliga a **recalcular** y **declarar**):

1. Cambiar **cualquiera** de los 7 puntos congelados (versión de métrica nueva).
2. Cambiar un elemento de la **bóveda de congelación** (`boveda_congelacion.md`): ruleset,
   telemetría, versión del HIDS, umbrales, definición de "virgen".
3. **Re-calibrar** el catálogo de ruido (los `baselines` **históricos** no sirven para el juicio
   final: el catálogo **autoritativo** son las **72 h**).
4. **Añadir/quitar** un caso, o cambiar la **ventana canónica** de un caso.
5. Cambiar el **denominador `M`** o su instrumentación (§2).

> Se registra en la cabecera de cada CSV: `metrica_version`, `boveda_version`, y los `sha256`
> de **todas** las entradas. Una cifra sin esa cabecera **no es válida**.

### 9.2 Casos límite (congelados)

| # | Caso | Decisión congelada |
|---|---|---|
| L1 | **Nivel 0 no emite alerta** (`92600`) | `N=0` ≡ "cualquier alerta emitida"; se documenta. |
| L2 | **Auto-ruido del HIDS** (≈54 % en Linux) | Cuenta como **FP** (regla 5); se reporta aparte la variante **sin `auto_ruido`**. |
| L3 | **Reglas de doble uso** (TP en ataque, FP en legítimo) | **No se borran a ciegas**; solo **T5** las evalúa. En T2/T4 permanecen. |
| L4 | **`dudosa` sin resolver** en un caso | El caso **no cuenta como TP** ni como FN silencioso: se **marca `review`** y se declara. |
| L5 | **Ataque sin alerta** (0 filas `deteccion`) | `FN_ata` (casos reales: **ATA013, ATA034**). Contribuye a `FN`. |
| L6 | **`RS2` (auditd) es del paquete** | Parte de **`virgen` (`C1`)**; se ve su aporte comparando `C0` vs `C1`. |
| L7 | **Un evento con varias señales** | Doble conteo resuelto por §4. |
| L8 | **`C2`/`C3` (propias/externas)** | **No** se miden en virgen: **contingentes al gate**. Sus bloques quedan **vacíos** hasta que existan. |
| L9 | **`N=0` y todas las alertas nivel 0** | Un caso con solo reglas de nivel 0 ⇒ **no emite** ⇒ `FN`. |
| L10 | **Un caso sin segunda ventana válida** | `review` por reproducibilidad; declarado. |
| L11 | **`logall_json` no instrumentado** | `M` = `n/a`; FPR-por-evento **no** se publica; se usa el **fallback** (§2). |

---

## 10. Comparabilidad ENTRE HIDS (unidad común)

La unidad legítima = **evento** **NO es comparable** entre Wazuh (registros de log) y
Velociraptor (filas de artifact): sus "eventos" son **cosas distintas**.

- **El titular de FPR de cada HIDS** es **por su propio evento** (**per-HIDS**, no comparable en crudo).
- **La comparación VR↔Wazuh** usa **dos ejes**:
  1. **Unidad COMÚN explícita**: la **acción de GHOSTS / la hora** (`FP/acción`, `FP/hora`) —
     la **misma** actividad real alimenta ambos HIDS (corridas **por separado**).
  2. **Comparación POR TÉCNICA**: misma `ATA<NNN>`/`T<n>` ⇒ ¿detecta SÍ/NO?, con qué
     `rule.id`/artifact.
- **Se declara** que son **paradigmas distintos** (alarmas vs recolección) y **no se fuerza**
  una igualdad artificial.
- **Puente de severidad VR↔Wazuh:** perfiles **P4 ≤ P3 ≤ P2 ≤ P1** ↔ niveles Wazuh, **respetando
  el orden** (en Wazuh mayor = más severo).

---

## 11. Glosario de equivalencias NIDS ↔ HIDS

| NIDS (profesor) | HIDS (este TFG) |
|---|---|
| `pcap` | `ATA<NNN>` (caso = ventana canónica) |
| `flujo` | **unidad** = evento/registro decodificado |
| `SID` | `rule.id` (o fila de artifact de VR) |
| alerta | `rule.id` emitido / fila de artifact |
| `#Attack flows` | `N` = 55 casos |
| `#Clear flows` | `M` = unidades legítimas |
| `#Flows FP / TN` | `FP_uni / TN_uni` |
| `%Detection_pcaps` | `%Deteccion` |
| `Operational Usability` | `Usabilidad (FTTAR)` |

---

## 12. Trazabilidad (fuentes verificadas)

| Afirmación | Cita verificable |
|---|---|
| Fórmulas T4 (`TPR=B6/…D79`; `FPR=B10/$B$4`; `GM=SQRT(B14*(1-B15))`; `Usab=B12/B8`; `Usab^c=B13/B9`) | P-Excel `T4 (Rend) S<=4, FG>=1` (celdas leídas) |
| `gm=math.sqrt(tpr*tnr)`, `usab=a_fp/a_tp`, `tp`=pcaps, `fp`=flows | `Scripts/optimo_Snort_GM_v4.py` (`calc_metrics`) |
| Categorías y orden de decisión de Fase 3 | `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` v7; `filtrar_ruido.py` |
| Doble iteración v2 (C1′/C2′/C3′) | `Soporte/Ataques/criterio_doble_iteracion.md` |
| Corpus: 55 casos · 128 ventanas · 53 detectadas / 2 no | `Hojas/ATA_index.csv`; `state.md` |
| 9 repeticiones canónicas (`_rev`) | `Hojas/repeticiones.csv` |
| `RS3 = RS4 = 0`; RS1 4.471 · RS2 44 | `Soporte/Wazuh/Configuracion/active_ruleset.txt` |

## 13. Lo que NO se puede congelar aquí (declarado)

1. El **número `M`** (denominador del legítimo): llega en `L0`/`L1`. R2 deja la especificación
   y el **fallback** (`FP/acción`, `FP/hora`).
2. La **unidad de VR**: se fija al desplegar (`V0`). Aquí queda el **placeholder** declarado.
3. **`C2`/`C3`** (RS3/RS4 = 0): sus bloques nacen **vacíos** hasta el gate.
4. **`Pruning N`** a escala del NIDS (500/1000) puede ser **degenerado** en nuestra escala; se
   **parametriza** y se declara la variante relativa en `formula_plantillas.md`.
