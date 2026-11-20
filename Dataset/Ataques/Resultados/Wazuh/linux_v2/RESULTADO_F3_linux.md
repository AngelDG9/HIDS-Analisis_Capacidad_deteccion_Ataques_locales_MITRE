# F3 — ataques Linux, VERSION 2 (lanzador local + `logall_json=yes`) — COMPLETA

> Ejecutado el 2026-11-20 (dos tandas: 108 ventanas + 20 ventanas de casos con infraestructura extra). `windows_index.csv` es el índice de esta campaña (el nombre se mantiene por compatibilidad con Windows).
> La campaña original (por SSH) queda como **«versión 1 (por SSH)»** en `../linux/` y NO se ha tocado.

## Qué cambia respecto a la versión 1
| | Versión 1 (por SSH) | **Versión 2** |
|---|---|---|
| Padre del ataque | sesión SSH (`bash` → `tee`) | unidad transitoria de systemd: `sudo systemd-run --uid=angel --pipe --wait` (SSH solo la inicia; padre = `systemd`, `auid=4294967295`) |
| Manager | `logall_json=no` (solo alertas) | **`logall_json=yes`**: se guardan TODOS los eventos (`archives`) además de las alertas |
| Ciclo por ventana | manual, paso a paso | `_artefactos/scripts/orquestar_ataques_linux.py` (revert `lab-listo`, agente Active + 90 s, scp + sha256, prestage, lanzamiento, FIM forzado, +60 s, extracción) |
| Datos por ventana | Detalle/Audited/Logs | **además** líneas CRUDAS de `alerts` y `archives` del agente 001 en `[t0-60 s, t1+120 s]` y copia cruda diaria del manager con sha256 |

## Resultado
- **128 ventanas = 128 OK** (55 ataques × 2 + 9 repeticiones `_rev` × 2; mismas 128 que la versión 1). 0 pendientes, 0 fallos finales.
- **Comparación con la versión 1 sobre las 128 ventanas (categoría `deteccion` tras el filtro): 124 con detección en las dos versiones; 0 ventanas cambian de «detectado» a «no detectado» o al revés.** Sin detección en ninguna de las dos: ATA013 y ATA034 (los dos ya conocidos). Mediana de filas de alerta por ventana: 944 (v1) → 1 058 (v2).
  Lectura: **cambiar el modo de lanzamiento no cambia qué ataques ve Wazuh**; sí cambia el ruido de fondo. Es un resultado de robustez, no una mejora de TPR. *(Cálculo propio y rápido sobre `Auditado/*-Audited.csv`, no con los scripts de métrica del proyecto.)*
- Tiempo por ventana ≈ 4–6 min.

## Incidencias de la campaña (todas corregidas y repetidas)
- ATA008: el script esperaba `ATA008/src/artifact` y se copió el directorio equivocado → 2 ventanas `REVISAR`; corregido y repetido: OK.
- ATA047: su `prestaging` arranca `sink_http.py` dentro de la víctima y no se había copiado → 2 `FALLO`; corregido y repetido: OK.
- Un vigilante auxiliar fue parado por falta de memoria del PC (actualización de Edge); no afectó a la campaña.

## Los 10 casos que requerían infraestructura extra (ya hechos, con estas particularidades que hay que declarar)
| Casos | Cómo se resolvió |
|---|---|
| ATA038 (base y `_rev`) | reinicio de la víctima: tras lanzar, el orquestador espera a que cambie el `boot_id` y a que el agente 001 vuelva a `Active`; `t1` se sella 20 s después de la reconexión (como en la v1, donde `t1` lo sellaba el operador). Duración `t0→t1` ≈ 2 min (v1: ≈ 3,5 min). `boot_id` antes/después en `lanzamiento.json`. |
| ATA039, ATA040 | daemon `rsync` en el manager (puerto 9873, módulos `share` solo lectura e `incoming`), arrancado antes de la ventana y retirado después (`recurso_remoto.txt` con los sha256). **El contenido de `~/lab-share` es de juguete recreado**: la v1 solo conserva los sha256 de sus ficheros, así que los ficheros de la v2 NO son byte a byte los de la v1. |
| ATA049–ATA053 | 49 paquetes `.deb` GUI + `rclone` 1.75.1 re-descargados y verificados contra los **mismos sha256** pre-registrados (`Soporte/Ataques/c0/ATA049-053_prestaging_paquetes.md`); las versiones retiradas de `archive.ubuntu.com` se obtuvieron de Launchpad (sha256 idéntico). Material en `D:\TFG-VMs\material-linux-v2\`. |
| ATA029 `_rev` | `sqlite3` + `binutils` (10 `.deb`, mismos sha256 pre-registrados) y el `src/` de la atómica. |

## Dónde está todo
- Repo: `Logs/<tag>/` (salida del ataque, `times.log`, `lanzamiento.json`, `sha256_artefacto.txt`, `sink.log`, `prestage.out`, `recurso_remoto.txt`), `CSV/` (Detalle + raw), `Auditado/` (filtro; **las filas `dudosa` siguen pendientes de revisión humana**, ver `-Revision.csv`), `windows_index.csv`, `filtrado_resumen.csv`.
- Fuera del repo (`D:\TFG-VMs\ataques-linux-v2-2026-11-20\`): `raw/` (alerts + archives crudos por ventana), `crudo/` (alerts/archives diarios del manager con `MANIFEST.tsv` sha256 y `crudo.done`), `piloto_*` (prueba previa, no forma parte de los resultados).
- Registro de la campaña: `D:\TFG-VMs\lab-logs\ataques_linux_v2.txt` (cada línea aparece dos veces: stdout + fichero).
