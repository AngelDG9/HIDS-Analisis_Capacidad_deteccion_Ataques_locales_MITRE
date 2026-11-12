# w07_LEEME.md — W-07: bruto, filtrado y exclusiones (T4b, 2026-11-12)

> **Resultado canónico (bruto):** **6 acciones / 90 alertas / `NO`** (nivel máximo 15).
> **Sensibilidad que excluye solo el artefacto de ataque:** **87 alertas / `SI`**
> (nivel máximo 6).
> **Sensibilidad que excluye además las 67 alertas ajenas:** **20 alertas / `SI`**
> (nivel 4).
> No se edita ninguna alerta a mano: el bruto sale de `w07_alertas_detalle.csv` y la
> separación se hace con `_artefactos/scripts/clasificar_w07_windows.py`, que escribe
> también `w07_variantes.csv` con las cuatro cifras.

## 1. Por qué hay cuatro cifras

La campaña atribuye alertas al caso en `[ini - 10 s, fin + 60 s]`. La ventana de W-07 es
`2026-11-12T10:05:46Z..10:06:30Z`, así que la atribución llega hasta **10:07:30Z**. En esa
ventana caen:

1. Las **20** alertas de las 6 acciones reales (10:05:47-10:06:28Z).
2. **3 artefactos de PowerShell**:
   - **1** a las **10:06:02.285Z**, `92213` (level 15), `__PSScriptPolicyTest_cmewlqsn.k2p.ps1`,
     `powershell.exe`: lo genera la **acción 3** y está **dentro** de `[t0,t1]`.
   - **2** a las **10:07:29Z**, `92213` (level 15, `sdiagnhost`) y `91823` (level 14,
     `Invoke-command`): diagnóstico posterior al `fin`.
3. **67** alertas de la ráfaga de mantenimiento programado de Windows
   (10:07:19-10:07:29Z): `UCPDMgr`, `taskhostw`, `TrustedInstaller`, `TiWorker`, `Defrag`,
   `.NET ngen`, `sdiagnhost`/`SDIAG_*`, SQL Server Express (`60798/60805/60807/60808/60809`)
   y procesos de `DESKTOP-BTMCFA5$`. Están **fuera** de `[t0,t1]`.

**Declaración:** el `92213` de las 10:06:02 es un **`artefacto_ataque`** (policy test de
PowerShell), **no una detección** de la técnica. Precedente del corpus: `92213` se clasificó
así en **ATA073/ATA097**. No se puede afirmar que las 70 exclusiones estén en 10:07: **1 de
las 70 está dentro de la ventana** y es artefacto de la acción 3.

## 2. Las cuatro cifras

| Variante | Excluye | Alertas | `level` | Resultado |
|---|---|---:|---:|---|
| **canónico** | nada (bruto) | **90** | **15** | **NO** |
| `sin_ajenas` | 67 mantenimiento (fuera de `[t0,t1]`) | **23** | **15** | **NO** |
| `sin_artefactos_ps` | 3 artefactos PowerShell (1 dentro de `[t0,t1]`, 2 a las 10:07:29Z) | **87** | **6** | **SI** |
| `sin_ambas` | 67 + 3 (sensibilidad) | **20** | **4** | **SI** |

**Lectura honesta.** El `SI` **no depende de excluir las 67 alertas ajenas**: `sin_ajenas`
sigue `NO` (23/15). Depende de excluir el **artefacto de ataque** `92213` de la acción 3:
`sin_artefactos_ps` da **87 / level 6 / SI**. El `level 6` de esa variante viene de
`92200`/`92217` (mantenimiento); si se mira solo `[t0,t1]`, el máximo es 4. El `SI` **se
sostiene** con la declaración de artefacto, pero el **canónico literal sigue siendo `NO`**
(90/15) porque la extracción de campaña no filtra artefactos. `sin_ambas` (20/4/SI) es la
tabla filtrada del caso y no es necesaria para el `SI`.

## 3. Ficheros (nombres claros)

| Fichero | Filas | Qué es |
|---|---:|---|
| `w07_alertas_bruto.csv` | **90** | Detalle bruto de la ventana de atribución (copia con cabecera propia de `w07_alertas_detalle.csv`). |
| `w07_campana_bruto.csv` | 11 casos | Tabla de campaña **canónica**: W-07 `6/90/NO`. `w07_campana.csv` es byte a byte idéntica. |
| `w07_extraer_campana.log` | - | Log reproducible del bruto: comando exacto + salida literal. |
| `w07_variantes.csv` | **4** | Las cuatro cifras: canónico, `sin_ajenas`, `sin_artefactos_ps`, `sin_ambas` (misma regla de detección: `67027` y `level < 7`). |
| `w07_alertas_caso_w07.csv` | **20** | Detalle de las acciones de W-07 (sin los 3 artefactos de policy test). |
| `w07_campana_filtrada.csv` | 11 casos | Tabla de campaña **filtrada** (sensibilidad): W-07 `6/20/SI`. `w07_campana_sin_policytest.csv` es byte a byte idéntica. |
| `w07_extraer_campana_filtrada.log` | - | Log reproducible del filtrado. |
| `w07_exclusiones.csv` | **70** | Cada alerta excluida con `motivo_exclusion` y `detalle_exclusion`: 3 artefactos de PowerShell (1 **dentro** de `[t0,t1]`, acción 3) + 67 mantenimiento **fuera**. |
| `w07_clasificacion.log` | - | Resumen de la separación (20 caso + 3 policy + 67 mantenimiento = 90) y de las cuatro variantes. |
| `w07_alertas_detalle_w07.csv` | 20 | Detalle histórico de 20 filas; contenido equivalente a `w07_alertas_caso_w07.csv` (formato distinto). |
| `w07_alertas_detalle_sin_policytest.csv` | **78** | **Intermedio**: quita `92213`×2, `92200`×9 y `92217`×1, pero **no** `91823`; **no** es la tabla filtrada del caso. |
| `w07_campana_sin_policytest.csv` | 11 casos | **Nombre ambiguo**: es la tabla de **20/SI** (idéntica a `w07_campana_filtrada.csv`), no un "sin policy test" de 78. |

## 4. Cómo se reproduce

```text
python _artefactos\scripts\clasificar_w07_windows.py ^
  --detalle Soporte\Laboratorio\windows\legit\evidencia\t4b\w07_alertas_detalle.csv ^
  --ventanas Soporte\Laboratorio\windows\legit\evidencia\t4b\w07_ventanas.tsv ^
  --caso W-07 ^
  --out-dir Soporte\Laboratorio\windows\legit\evidencia\t4b
```

Después, la extracción canónica (bruto) y la filtrada se lanzan con
`extraer_campana_windows.py`; los comandos exactos están en los dos logs
`w07_extraer_campana.log` y `w07_extraer_campana_filtrada.log`.

## 5. Criterio (determinista, sin filtro manual)

1. `fuera_ventana_atribucion`: fuera de `[ini-10 s, fin+60 s]` (0 filas).
2. `artefacto_powershell_policytest`: `92213` con `win_target` que contiene
   `__PSScriptPolicyTest`, o `91823` con `Invoke-command` en la descripción. **3 filas**:
   1 a las 10:06:02.285Z (**dentro** de `[t0,t1]`, acción 3) + 2 a las 10:07:29Z.
3. `caso_w07`: `ini = ts = fin` y no es artefacto de policy test (20 filas).
4. `mantenimiento_windows_fuera_de_accion`: `ts` posterior a `fin` y no es artefacto de
   policy test (67 filas).

Cualquier alerta que no case con 1-4 hace fallar el script; no hay lista de `rule_id`
escrita a mano. La regla de detección de las variantes es la de la campaña: `rule_id 67027`
presente y `level < 7` ⇒ `SI`.
