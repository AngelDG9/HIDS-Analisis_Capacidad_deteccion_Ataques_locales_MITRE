# change-doc — Bloque `reencuadre-metrica` (R2): métrica congelada, plantillas y scripts

> Cierre. Fecha: **2026-10-16**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA** (2 salvedades: 1 corregida, 1 declarada).
> Plan de referencia: `plan.md` (raíz, `status: approved_by_human`, 913 líneas).
> **Bloque de DISEÑO + HERRAMIENTAS**: fija la **regla de medición** de todo el TFG. **No** mide, **no** toca laboratorio/corpus/`_recursos/`.

---

## 1. Objetivo

**Congelar la métrica** con la que se medirá todo (los 55 ataques, las 72 h de legítimo, Velociraptor y la comparación), crear las **plantillas** de las 5 tablas del profesor y los **scripts deterministas** que las calculan.

---

## 2. Producto

### Documentos congelados (`Soporte/Metrica/`)
| Fichero | sha256 |
|---|---|
| **`metrica_hids.md`** (16.105 B; `version: 1`, `status: congelada`) | `80216fc7c681c6ca4f0181116f12168d439455a9206cb2d2d9f544bc88a38bfd` |
| `metrica_hids.sha256` | `f7101744da47ca9711a3bca49dbf4e2894abe4ecfdcf6c91556ce95b691f02cc` |
| **`boveda_congelacion.md`** (B1–B10) | `297d0f9df2819ef974ba9e138fd43e9870736e3e4ae6660b3b5fd3ea1f88b395` |
| `boveda_congelacion.sha256` | `fef2de5f3e5546c45e4cf11ce9b307a33c3c4084272f6bdb7009df721a5e2cd0` |
| `formula_plantillas.md` | `e3036c96642bb030c7aa1f644d88f8d89b935e976092b63f4fd317af9ee0032d` |

Contenido de `metrica_hids.md`: las **3 unidades/planos** y sus denominadores; matriz de confusión; **las 7 fórmulas (+7c) literales** del Excel del profesor y del repo hermano; reglas de conteo anti-sesgo; **ventana canónica** (`_rev1` si está en `repeticiones.csv`, si no `iter1`); **casos límite L1–L11**; comparabilidad entre HIDS; **qué invalida una medida** (5 disparadores).

### Plantillas (`Hojas/`, **nuevas**; ninguna preexistente modificada)
`T1_clasificacion.csv` (89) · `T2_ataques.csv` (550) · `T3_legitimo.csv` (plantilla, `M=n/a`) · `T4_rendimiento.csv` (19) · `T5_pruning.csv` (60) · `T5_steps.csv` · `requisitos_estudio.csv` (6) · `leyenda.csv` (142).
Cabeceras **exactas** de §4, con equivalencias `SID→rule.id`, `pcap→ATA<NNN>`, `flujo→unidad`.
Export: `Estudio-Wazuh/TFG_HIDS_Wazuh_linux.xlsx` (8 hojas, reproducible) · `Estudio-Velociraptor/README.md` (placeholder; VR se puebla en V0/V1).

### Scripts (`_artefactos/scripts/`) + tests
`metrica_hids.py` (`9d6ebf66…`, módulo congelado, sin `main`) · `tabla_comun.py` (`7d55118e…`) · `tabla1_clasificacion.py` (`c4f2877a…`) · `tabla2_ataques.py` (`32816246…`) · `tabla3_legitimo.py` (`af55c5da…`) · `tabla4_rendimiento.py` (`f66e1e10…`) · `tabla5_pruning.py` (`2e23cc0c…`) · `requisitos_leyenda.py` (`7c13b329…`) · `exportar_excel.py` (`271a7a9d…`).
Tests nuevos: 32 → **`pytest`: 179 passed** (desde la raíz **y** desde `_artefactos/scripts`).

---

## 3. La prueba de humo (validación clave)

**CA-R2-09: `C1` (virgen) × `N=0` sobre el corpus congelado → `TP = 53 / FN = 2`** (`ATA013`, `ATA034`) ✅
- **Re-derivado independientemente por el `tfg-tester`** (su propia lógica sobre los CSV crudos) → coincide exacto.
- Ata la métrica nueva al resultado ya conocido de Fase 3.

---

## 4. Verificación (`tfg-tester`) — **PASA**

| CA | Resultado |
|---|---|
| R2-01/02 (doc congelado + sidecar; unidades sin ambigüedad) | ✅ |
| **R2-03 (las 7 fórmulas literales)** | ✅ verificado **celda a celda** en el Excel (`B14`,`B15`,`B16`,`B17`,`B18`) y contra el código real del repo hermano (descargado) |
| R2-04 (reglas de conteo + L1–L11) | ✅ |
| R2-05 (plantillas con cabecera exacta) | ✅ |
| R2-06 (bóveda B1–B10; hashes re-calculados) | ✅ (B10 declarado pendiente: no existe el legítimo) |
| R2-07/08 (scripts deterministas; `pytest`) | ✅ (doble ejecución = mismos bytes; 179 passed) |
| **R2-09 (53/55)** | ✅✅ re-derivado por el tester |
| R2-10 (`.xlsx` reproducible) | ✅ (export 2× → mismo `sha256`) |
| R2-11 (nada protegido tocado) | ✅ (`git status`: solo `??`, cero `M`) |
| R2-12 (sin secretos) | ✅ |
| R2-13/14 (reutiliza la pertenencia; comparabilidad fijada) | ✅ |

**Salvedades:**
- **D1 (corregida)**: el test de humo dependía del *cwd* → **anclado a la raíz**; pasa desde cualquier carpeta.
- **D2 (declarada)**: los `.py` no llevan sidecar `sha256` propio → **sus hashes quedan registrados aquí** (§2).

**Limitaciones declaradas (no defectos):**
- **`T3`/`T5`**: sin el legítimo (`L0`/`L1`) no existen `M`, `FPR`, `TNR`, `GM`, `#Alertas_FP` ni `Usabilidad` → quedan **vacíos** (nada inventado). `T4` publica **Precisión/F1** (dependen de `A_FP`, no de `M`).
- **`C2`/`C3`** (reglas propias/externas): soportadas por los scripts pero **vacías** (contingentes al gate).
- **`TFG_HIDS_Wazuh_windows.xlsx`**: pendiente del bloque `B1`.
- **Formato "largo"** en T2/T3/T5 (una fila por caso×config×umbral) y **ancho** en T4 — declarado en la cabecera de cada CSV.

---

## 5. Siguiente

1. **`legitimo-infra` (L0)**: montar **GHOSTS** + la **"internet local"** (go/no-go con plan B).
2. **`legitimo-72h` (L1)**: la captura de **72 h** (cuello de botella) + instrumentar el denominador `M`.
3. En paralelo: **`M1a`** (recorte histórico de los 55 ataques).
4. **`push`**: los commits son **locales**; publicar es del humano.
