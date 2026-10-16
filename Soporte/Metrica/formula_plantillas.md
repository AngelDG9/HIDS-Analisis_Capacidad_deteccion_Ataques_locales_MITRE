---
bloque: reencuadre-metrica
nombre: Leyenda de fórmulas y plantillas (bloque de fórmulas literal del profesor + hermano)
version: 1
status: congelada
fecha: 2026-10-16
autor: tfg-executor
depende_de: Soporte/Metrica/metrica_hids.md (v1)
---

# Leyenda de fórmulas y plantillas

> Documento de apoyo de `metrica_hids.md` (v1). Reúne, **literalmente**, el **bloque de
> fórmulas** del Excel del profesor y del repo hermano, la **leyenda de columnas** de cada
> plantilla y las **6 variantes de pruning**. Las fórmulas **se implementan en un solo sitio**:
> `_artefactos/scripts/metrica_hids.py` (funciones puras `tpr`, `fpr`, `tnr`, `precision`,
> `f1`, `gm`, `usabilidad`). Ningún script las reimplementa.

## 1. Bloque de fórmulas (literal del P-Excel `T4 (Rend)`)

```
* Cálculo por flujos
Recall (Sensibilidad) o True Positive Rate (TPR) :  R = TPR = TP / (Total ataques) = TP / (TP + FN)   [Ataques]
FPR (False Positive Rate)                        :  FPR = FP / (Total legítimo) = FP / (TN + FP)      [Legítimo]
Precisión                                        :  P = TP / (Total alarmas)  = TP / (TP + FP)        [Tráfico total]
F1-Score (media armónica)                        :  F1 = 2 * (P * R) / (P + R)                        [Tráfico total]
GM (Geometric Mean)                              :  GM = √(TPR * (1 - FPR))                             [Tráfico total]
TNR (Especificidad)                              :  TNR = 1 - FPR = TN / (TN + FP)                      [Legítimo]
Operational Usability = FTTAR                    :  = #Alertas_FP / #Alertas_TP                         [Tráfico total]
Óptimo: Altos (salvo FPR y Usabilidad, que interesan próximos a 0)
```

Celdas del Excel usadas como **fuente** (verbatim): `B14 = B6/'T2…'!$D$79` (TPR);
`B15 = B10/$B$4` (FPR); `B16 = SQRT(B14*(1-B15))` (GM); `B17 = B12/B8` (Usabil.);
`B18 = B13/B9` (Usabil. correlacionadas).

## 2. Bloque de fórmulas del repo hermano (`optimo_Snort_GM_v4.py`)

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

Estas fórmulas están implementadas **idénticamente** en `metrica_hids.py` (mismo
comportamiento en el caso límite: denominador 0 → `0.0`).

## 3. Plantillas: columnas y equivalencias

| Plantilla | Fichero | Equivalencias NIDS→HIDS |
|---|---|---|
| **T1** Clasificación | `Hojas/T1_clasificacion.csv` | `Only Network Detection`→`host_eligible`; red↔host |
| **T2** Ataques | `Hojas/T2_ataques.csv` | `pcap`→`ATA<NNN>`; `SID`→`rule.id`; `#Flows`→acciones |
| **T3** Legítimo | `Hojas/T3_legitimo.csv` | `flujo`→unidad; `#Flows`→`#Unidades` |
| **T4** Rendimiento | `Hojas/T4_rendimiento.csv` | columnas = HIDS × config × umbral |
| **T5** Pruning | `Hojas/T5_pruning.csv` (+ `T5_steps.csv`) | `SID`→`rule.id`; 6 variantes |
| **Requisitos** | `Hojas/requisitos_estudio.csv` | `pcap`→caso/paquete |
| **Leyenda** | `Hojas/leyenda.csv` | columna a columna + glosario + fórmulas + virgen |

La **leyenda viva** columna a columna (con su significado y equivalencia) está en
`Hojas/leyenda.csv` (generada por `_artefactos/scripts/requisitos_leyenda.py`).

## 4. Variantes de pruning (literal del hermano)

| Variante | Definición congelada | Cita del hermano |
|---|---|---|
| **No Pruning** | todas las reglas | — |
| **Pruning 500** | quitar reglas con `#alertas_correlacionadas` FP > 500 (aunque sean TP) | `sids = {s for s in sids_activos if leg_diff_counts[s] <= 500}` |
| **Pruning 1000** | ídem con umbral 1000 | ídem |
| **Conservative** | quitar reglas **FP y nunca TP** | `ids_fp_exclusivos = sids_legitimo - sids_ataque` |
| **Generalized Conservative** | quitar **todas** las FP **aunque sean TP** | — |
| **Aggressive (G-Mean)** | eliminación **hacia atrás**: ordenar las reglas mixtas por impacto en legítimo (desc) y quitar **solo si el GM mejora** | `if m_gm > current_gm` |

> **Decisión abierta de escala (§9.2, abierta 8).** `N ∈ {500, 1000}` es la escala del NIDS
> (78 M flujos). En nuestro legítimo (eventos) se **declara** un **umbral relativo**
> `N = p %·(máx FP)` como **variante adicional** si el volumen lo hace degenerado. **Parámetro
> congelable**; se confirma con el tutor.

## 5. Redondeo y formato (congelados, anti-deriva)

- Porcentajes: **4 decimales** en T3/T4 (profesor: `4.3095 %`).
- Ratios `GM/TPR/FPR/Precisión/F1`: **6 decimales** (hermano: `:.6f`).
- `Usabilidad`: **4 decimales** (hermano: `round(...,4)`).
- `%Deteccion` en T2/T5: **2 decimales** (hermano: `55.45 %`).
- Separador decimal **punto**; `%` **literal** solo en el export `.xlsx` de T3/T5.
