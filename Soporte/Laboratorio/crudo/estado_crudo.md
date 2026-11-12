# Estado del crudo (eventos y alertas) — 2026-11-10

> **Regla dura:** *se debe guardar el crudo de ataques y ventanas.* El `archives`
> (todos los eventos) es la base para re-puntuar con reglas nuevas (`+propias`/`+externas`);
> el `alerts` solo contiene lo que ya superó el nivel mínimo.

## 1. Qué se ha recuperado

Copia en `D:\TFG-VMs\crudo-ataques\` (fuera del repo, con `MANIFEST.tsv` de `sha256`):

| Directorio | Contenido | Días | Tamaño |
|---|---|---|---|
| `archives_oct/` | `archives` (todos los eventos) de octubre | 10-19/20/21/25/26/27/28 | 82 MB (gz) |
| `alerts_ataques/` | `alerts` (alertas completas) de los días de ataque | 11-08, 11-09, 11-10 | 13 MB (gz) |

Total copiado: **37 ficheros, 98,6 MB**.

## 2. Estado de la telemetría del manager

| Parámetro | Valor |
|---|---|
| `logall` | `no` |
| `logall_json` | `no` |

Por eso `archives` **solo tiene contenido hasta 2026-11-05**; desde 2026-11-08 los ficheros
están a 0 bytes.

## 3. Qué hay y qué falta

| Corpus | `alerts` (alertas) | `archives` (eventos) |
|---|---|---|
| Ventana legítima Linux (11-02..05) | sí | **sí** (`legitimo-2026-11-02/denominador/`) |
| Ataques Linux (octubre) | sí | **no** (los `archives` de octubre existen pero no contienen las anclas de ataque: `lab-attack` 0 veces) |
| Ataques Windows B1 (ATA056–087) | **sí** | **no** (`logall=no`) |
| Ataques Windows B2 (ATA088–109) | **sí** | **no** (`logall=no`) |

Evidencia: `evidencia.txt` y `evidencia2.txt` en la carpeta de copia.

## 4. Implicación

- **Re-puntuar reglas nuevas sobre eventos ya alertados**: posible con `alerts`.
- **Re-puntuar reglas nuevas sobre eventos que no alertaron**: **no** para los ataques;
  exige **re-ejecutar** (el corpus, los scripts y los snapshots están y son reproducibles).
- **W3 (ventana legítima Windows)**: hay que activar `logall_json=yes` **antes** de abrir la
  ventana y guardar el `archives` al cerrarla.

## 5. Pendiente / propuesta

1. Activar `logall_json=yes` en el manager para W3 y para cualquier re-ejecución de ataques.
2. Al cerrar cada ventana o campaña, copiar `archives` + `alerts` a `D:\TFG-VMs` con `sha256`.
3. No meter el crudo en el repo (tamaño); solo el manifiesto y esta ficha.

## 6. Crudo de la ventana legítima Windows (W3-bis) — ruta implementada

> **G-5 (T2b-1b):** la ruta del `crudo` queda **alineada con el plan** (`plan_w3bis.md`
> §7.2 C-4). La implementación **no** usa `D:\TFG-VMs\ventana-windows-<fecha>\`: usa
> **`D:\TFG-VMs\legitimo-windows-<fecha>\crudo\`** (hermano de `keepalive_2h\` de §6.2).

| Elemento | Ruta |
|---|---|
| `crudo` (archives + alerts + `MANIFEST.tsv` + `denominador_M.csv`) | `D:\TFG-VMs\legitimo-windows-<fecha>\crudo\` |
| Puerta de `cleanup` | `D:\TFG-VMs\legitimo-windows-<fecha>\crudo\crudo.done` |
| Evidencia de 2 h (§6.2) | `D:\TFG-VMs\legitimo-windows-<fecha>\keepalive_2h\` |

`<fecha>` = `t0` en UTC (`yyyy-MM-dd`), tomado de `ventana_actual.json`. Si cambia la
fecha de la ventana, cambia el directorio (no se mezclan ventanas).


## 7. Crudo real de la prueba de 2 h de Windows (T4, 2026-11-12)

| Dato | Valor |
|---|---|
| Ventana | `2026-11-12T11:00:00Z` → `13:00:00Z` |
| Destino | `D:\TFG-VMs\legitimo-windows-2026-11-12\crudo\` |
| `criterio` / `tz` / `dias` | `utc_dias_D_D+2` / `CET` / `2026-11-12,2026-11-13,2026-11-14` |
| Ficheros / `.sum` / planos | 3 / **0** / 3 |
| `MANIFEST.tsv` sha256 | `821111058096046151e604108937d9202bfd98d2f2f1d6d6b0e18a59933beb1a` |
| `M` endpoint / total | **881 / 2.440** (`boveda_version=3`, `contar_denominador.py --agent-id 002 --estricto`) |
| `crudo.done` | escrito; `M_rc=0`; `sums=0`; `planos=3` |
| `archives.json` / `alerts.json` | `a1a3129e…` (6.386.345 B) / `8b03521d…` (10.675.298 B) |
| **Intentos** | **13:02:42Z FALLO** (listado vacío por permisos de `/var/ossec/logs`); **13:03:33Z OK** con `sudo -S -p ''` |

> **Reintento declarado:** el primer `crudo` (13:02:42Z) falló con
> `crudo FALLO: no hay ficheros para dias 2026-11-12,2026-11-13,2026-11-14 TZ=CET`
> porque el listado se ejecutaba como `angel` y `/var/ossec/logs` es `wazuh:wazuh 750`.
> El fix `sudo -S -p '' bash -c '...'` está en el diff de
> `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` (**sin commit**). El
> segundo intento (13:03:33Z) terminó `crudo OK` a las 13:03:37Z y escribió `crudo.done`.

> **Declaración:** el día en curso no tenía `.gz` ni `.sum` (Wazuh rota a las 00:00). Se
> copiaron los planos vivos `archives.json`, `alerts.json` y `ossec-archive-12.json`.
> No se inventó ningún `.sum`; el campo `sums=0` queda escrito en `crudo.done`.
> La copia precede a `logall_json=no` y `M` se calcula **de la copia** con `--estricto`.
