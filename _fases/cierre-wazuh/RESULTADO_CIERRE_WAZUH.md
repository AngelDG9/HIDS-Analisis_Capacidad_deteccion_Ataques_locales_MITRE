# Resultado — cierre del análisis de Wazuh (Linux + Windows) · 2026-11-21

> Ejecución del plan `_fases/cierre-wazuh/plan.md`. Todo lo de abajo está **recalculado desde los ficheros** (no copiado de la documentación).
> Lo que no se pudo comprobar o queda abierto está en §6.

## 1. Datos de ataque v2 (completos)
| | Linux v2 | Windows v2 |
|---|---|---|
| Ventanas | **128/128** (55 casos × 2 + 9 `_rev` × 2) | **108/108** (54 casos × 2) |
| Lanzamiento | `systemd-run` (SSH solo inicia; padre = systemd) | tarea programada (padre = `svchost`) |
| Manager | `logall_json=yes` | `logall_json=yes` |
| Verificación de completitud (recalcula sha256, cruza alertas crudas vs Detalle, comprueba `archives`) | **0 fallos** | **0 fallos** |
| Copia cruda con sha256 | `D:\TFG-VMs\ataques-linux-v2-2026-11-20\crudo` (34 ficheros) | `…\ataques-windows-v2-2026-11-20\crudo` (43 ficheros) |

Incidencias que obligaron a **repetir o corregir** (declaradas en cada `RESULTADO_F3_*.md`): 20 ventanas Linux repetidas por `archives` vacío; en Windows, `rs_origen=UNKNOWN`, `t0` mal sellado, regla `752` como artefacto de medición del FIM forzado, el vigilante de RAM.

## 2. Qué se hizo con las dudosas (NO es revisión humana)
`resolver_dudosas_por_precedente.py` copia el veredicto de la v1 **solo si** la clave `(rule_id, motivo, atribución)` tiene un único veredicto en la v1 y ≥10 filas de apoyo.
| | dudosas v2 | resueltas por precedente | siguen `dudosa` |
|---|---:|---:|---:|
| Linux v2 | 3 826 | 2 118 | **1 708** |
| Windows v2 | 2 390 | 150 | **2 240** |
Las dudosas **no entran en los conteos de detección** (la métrica solo cuenta `categoria=deteccion`). Efecto posible de las que quedan:
- **Linux**: los 2 casos sin detección (ATA013, ATA034) tienen **0 dudosas** → el TPR de C1 (53/55) no puede cambiar. Dudosas de nivel ≥7: 183 (`2902/2904/550`, instalaciones `dpkg` del pre-staging de ATA029/051/052/053; muy probablemente ruido).
- **Windows**: los 54 casos ya están detectados en N=0/3. Hay **414 dudosas de nivel ≥7** (`92213` ×263 *sin ancla*, `550` ×120, …) que repartidas en los casos podrían subir el TPR de N≥7, hoy **0/54**. **Ese 0/54 es un límite inferior condicionado a la revisión humana de esas 414 filas.**

## 3. Tablas (todas regenerables y verificadas)
| Tabla | Datos | Archivo |
|---|---|---|
| T2 / T4 / T5 (doble uso, pruning, steps) Linux | v2 (M1b sobre `Auditado_precedente`) | `Hojas/T2_ataques_v2.csv`, `T4_rendimiento_v2.csv`, `T5_*_v2.csv` |
| T2 / T4 / T5 Windows con ventana de 72 h | v2 (M1b-W + `752`) | `Hojas/T2_ataques_windows_v2.csv`, `T4_rendimiento_windows_v2.csv`, `T5_*_windows_v2.csv` |
| T3 legítimo Windows con `doble_uso` | ventana 17–20 nov | `Hojas/T3_legitimo_windows.csv` (antes `doble_uso=-`) |
| Comparación Linux↔Windows | v2 | `Hojas/comparacion_linux_windows_v2.csv` (FP/h y FP/acción, no `M` en bruto) |
Las tablas **v1 (por SSH)** no se tocan.

## 4. Resultados principales (C1 = virgen = {RS1,RS2}; Windows C0 = C1)
| | TPR N≥0/3 | TPR N≥7 | FPR N≥0/3 | FP/hora N≥3 | FP N≥7 | FP/hora N≥7 |
|---|---:|---:|---:|---:|---:|---:|
| Linux v1 (SSH) | 53/55 | 2/55 | 85,80 % | 4 086,8 | 2 | 0,028 |
| **Linux v2** | **53/55** | **2/55** | **85,80 %** | **4 086,8** | 2 | 0,028 |
| Windows v1 (SSH, T4 con baseline 8 h) | 54/54 | 2/54 | n/d | n/d | n/d | n/d |
| **Windows v2** | **54/54** | **0/54** (límite inferior, §2) | **29,39 %** | **88,1** | 143 | 1,99 |
- **El modo de lanzamiento no cambia el TPR** (Linux idéntico; Windows igual en N=0/3). Sí cambian `Precisión/F1/Usabilidad` (conteos de alertas).
- Linux C1 N≥7: 2/55; C0: 2/55 en N=0/3/7. Windows C0 = C1.
- **No comparar `M` en bruto** (Linux 342 966 con auditd; Windows 21 589): usar FP/hora y FP/acción.

## 5. Verificación y testeo (ronda final)
- **563 tests pasan** (558 previos + 5 nuevos de resolver/bitácora/verificador).
- **Reproducibilidad**: regenerando con los scripts actuales, **T2, T4 y T5 doble uso de la v1 salen idénticos** (cuerpo) y T2 v2 de Linux y Windows se reproducen; T2 Windows v1 (`_b2`) también.
- **Completitud**: `verificar_completitud_ataques_v2.py` → Linux 128/128 y Windows 108/108 sin fallos; sha256 de la copia cruda recalculados.
- **Contrarrevisión independiente**: un agente que no vio mis conclusiones recalculó 12 ventanas (6+6, semilla fija) de crudo a Detalle/Audited/T2 — resultado en `CONTRARREVISION.md`.

## 6. Límites y abierto (declarar en la memoria)
1. **Dudosas**: 1 708 (Linux) y 2 240 (Windows) sin resolver; solo precedente automático, no revisión humana (§2).
2. **TPR de Windows en N≥7** depende de 414 dudosas (§2).
3. **Windows v2 usa sesión interactiva (autologon) y tarea programada**; la v1 usaba SSH; hay más ruido de fondo por ventana. La comparación v1/v2 de Windows **no es aislada** del cambio de snapshot.
4. **Artefacto de medición del FIM forzado** en todas las ventanas Windows v2 (declarado; regla `752` en `catalogo_M1b_windows_v2.csv`).
5. `n_acciones_k/m` (O2) **vacío** en las bitácoras v2 (no se recalculó).
6. No se pudo reproducir un M1b-W de la v1 con la herramienta estándar (ventanas S1 sin cabecera de procedencia, p. ej. ATA104).
7. C2/C3 (reglas externas), Velociraptor y evasión **fuera de este cierre**.
8. Contenido de `~/lab-share` (ATA039/040) recreado: no idéntico byte a byte al de la v1.
