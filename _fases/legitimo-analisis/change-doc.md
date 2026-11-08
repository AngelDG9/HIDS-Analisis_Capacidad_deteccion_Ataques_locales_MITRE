# change-doc — Bloque `legitimo-analisis` (L2 + M1b)

> **Estado: CERRADO (2026-11-08).** Plan aprobado (`b0b118b`), archivado en `_fases/legitimo-analisis/`.
> **No se ha ejecutado nada en el laboratorio** (0 VMs, 0 SSH): solo análisis de datos ya sellados.
> **Veredicto: PASA** (L2 y M1b verificados por el tester, con las correcciones de abajo).

---

## 1. Tanda L2 — análisis del legítimo (72 h)

| Métrica | Valor |
|---|---|
| `M` (endpoint `001`) | **342.966** |
| `FP_uni` (C1×N0) | **294.252** |
| **FPR** (C1×N0) | **0,857963** (85,7963 %) |
| **TNR** | **0,142037** |
| `C0×N0` (solo base) | **50** → FPR **0,000146** |
| `C1×N7` | **2** |
| `C1×N12` | **0** |
| Sin `auto_ruido` | **227.967** → FPR **0,664693** |
| `auto_ruido` | **66.285** (22,5266 %): `80791` 51.812, `80792` 13.584, `80780` 813, `80781` 74, `80782` 2 |

- **Unidad de `FP_uni` = línea de `archives`** (no `timestamp`: −15,1 %; no `id`: −27,4 %). Enlace
  verificado: multiconjunto `(timestamp, rule_id)` idéntico (294.252 = 294.252). Índice compacto
  `eventos_alerta_72h.csv.gz` (294.252 filas, 1,43 MiB) en `Dataset/Legitimo/legitimo_72h/analisis/`.
- **Catálogos**: `catalogo_ruido_72h.csv` (**11** reglas, suma 294.253) y `catalogo_M1b.csv`
  (**15** = 72 h ∪ `5402/5501/5502/5715`, con `origen_catalogo`).
- **T3** (36 filas = 10 agregadas + 26 detalle), **T4** (19 × 10), **T5** (`pruning` 60, `steps` 24,
  `doble_uso` 11). Estabilidad por día (3) y por hora (72) + campaña (11).

## 2. Tanda M1b — re-corte de los ataques

- **128/128** ventanas re-juzgadas; **130.017** filas; **0 filas cambiadas**; solo cambia el campo
  `catalogo` de la cabecera. Salida nueva en `Dataset/Ataques/Resultados/Wazuh/linux/M1b/Auditado/`;
  **originales de M1a intactos**.
- **T2**: 550 filas; **550/550 idénticas** a M1a; **53/55** (`FN = ATA013, ATA034`).
- **Sensibilidad** (catálogo 72 h puro, **NO canónica**): **54/55** (no 55/55). Solo **ATA034** pasa a
  TP; **ATA013 sigue FN** porque sus filas `5501/5502` quedan `dudosa`→ruido (el paso `dudosa` se evalúa
  antes que `novel`). Flipan **8** filas (las de ATA034); el diff total es **462** líneas en **42** de
  las 128 ventanas (**109** en **13** canónicas). Se rechaza como medida: sería un falso positivo de método.
- **T4/T5 regenerados con M1b**: **0 cambios** en datos (solo cabecera). GM: No Pruning **0,369963**;
  Pruning 500/1000 **0,233395**; Conservative **0,378306**; Generalized Conservative **0,190693**;
  Aggressive **0,547509** (quita 9 reglas y conserva `80792`).
- **Doble uso**: **4** reglas (`80781/80790/80791/80792`); **`80792` en 53/55 casos** (1.988 detecciones).

## 3. Correcciones al plan (factuales, ya aplicadas)

1. `FPR` sin `auto_ruido`: **0,664691 → 0,664693** (el plan usaba `M = 342.967`).
2. Sensibilidad: **55/55 → 54/55**, con el matiz ATA013 (`dudosa`→ruido) y **8** filas flipadas
   (no 16); diff total **462 / 42 ventanas / 109 canónicas**.

## 4. Desviaciones declaradas (ninguna afecta a los números)

- **T3**: se corrigió la presentación (`%` = 85,7963 vs ratio 0,857963); la fórmula no cambia.
- **`tabla5_pruning.py`**: el detalle de T3 se leía sin filtrar por config×umbral (bug); corregido.
- **`test_tabla3_legitimo.py`** y **`.gitignore`** (intermedio `T3_detalle.csv`, 17,5 MB): modificados,
  no listados en §7.1 del plan.
- **Scripts aditivos** no listados: `tabla2_ataques.py` (`--nota`), `tabla4_rendimiento.py`
  (`--auditado`), `cruzar_doble_uso.py` (cabeceras), `comparar_t2_m1b.py`, `test_recortar_ataques_m1b.py`.
- **`T2_ataques.csv`**: `boveda_version` 1→2 (metadato; datos idénticos).
- **T4/T5** se calcularon primero con M1a y se **regeneraron** con M1b (0 cambios).
- **`filtrar_ruido.py` no se ha modificado** (el criterio congelado se reutiliza tal cual).
- **`pytest`: 353 passed.**

## 5. Consecuencia para el TFG

- **Titular**: en actividad normal, **~86 %** de los eventos generan aviso a umbral bajo; a **N≥7**,
  **2 avisos en 72 h**; **N≥12**, **0**.
- **Regla de doble uso principal**: `80792` (cada `execve`) detecta **53/55** ataques y es también la
  que más ruido genera en la vida normal → es el hallazgo central de T5.
- **M1b confirma** que el corpus de ataques no cambia al re-juzgarlo con el legítimo nuevo (0 filas).

## 6. Siguiente

- **Windows**: `B1` (ataques) + su **ventana legítima** (espejo de Linux) — ya hay preparación y plan
  en `_fases/windows-legit-prep/`.
- **Velociraptor** (`V0/V1`).
- **A1/A2** (comparativa, gráficas y memoria).
