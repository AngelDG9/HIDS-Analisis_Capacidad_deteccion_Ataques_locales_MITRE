# F3 — ataques Linux, VERSION 2 (lanzador local + `logall_json=yes`)

> Ejecutado el 2026-11-20 (08 y 09 h UTC-ish; ver `windows_index.csv`, que se llama así por compatibilidad con Windows pero es el índice de ESTA campaña).
> La campaña original (por SSH) queda como **«versión 1 (por SSH)»** en `../linux/` y NO se ha tocado.

## Qué cambia respecto a la versión 1
| | Versión 1 (por SSH) | **Versión 2** |
|---|---|---|
| Padre del ataque | sesión SSH (`bash` → `tee`) | unidad transitoria de systemd: `sudo systemd-run --uid=angel --pipe --wait` (SSH solo la inicia; padre = `systemd`, `auid=4294967295`) |
| Manager | `logall_json=no` (solo alertas) | **`logall_json=yes`**: se guardan TODOS los eventos (`archives`) además de las alertas |
| Ciclo por ventana | manual, paso a paso | `_artefactos/scripts/orquestar_ataques_linux.py` (revert `lab-listo`, agente Active + 90 s, scp + sha256, prestage, lanzamiento, FIM forzado, +60 s, extracción) |
| Datos por ventana | Detalle/Audited/Logs | **además** líneas CRUDAS de `alerts` y `archives` del agente 001 en `[t0-60 s, t1+120 s]` y copia cruda diaria del manager con sha256 |

## Resultado
- **128 ventanas** previstas (55 ataques × 2 + 9 repeticiones `_rev` × 2): **108 OK**, **20 PENDIENTE** (infraestructura extra, ver abajo). 0 fallos finales.
- **Comparación con la versión 1 sobre las 108 ventanas comunes (categoría `deteccion` tras el filtro): 104 con detección en las dos versiones, 0 ventanas cambian de «detectado» a «no detectado» o al revés** (los dos no detectados, ATA013 y ATA034, siguen igual). Mediana de filas de alerta por ventana: 955 (v1) → 1 053 (v2); mediana de filas `deteccion`: 3 → 3.
  Lectura: **cambiar el modo de lanzamiento no cambia qué ataques ve Wazuh**; sí cambia el ruido de fondo (más filas de ventana). Es un resultado de robustez, no una mejora de TPR.
- Tiempo por ventana ≈ 4 min (revert + arranque + 90 s de asentamiento + ataque + 30 s FIM + 60 s de espera).

## Incidencias de la campaña (todas corregidas y repetidas)
- ATA008: el script esperaba `ATA008/src/artifact` y se copió el directorio equivocado → 2 ventanas `REVISAR`; corregido (se copia `.../T1048.002/src`) y repetido: OK.
- ATA047: su `prestaging` arranca `sink_http.py` dentro de la víctima y no se había copiado → 2 `FALLO`; corregido y repetido: OK.
- Un vigilante auxiliar fue parado por falta de memoria del PC (actualización de Edge); no afectó a la campaña.

## PENDIENTE (20 ventanas = 10 casos × 2): necesitan infraestructura que no se ha montado
| Casos | Qué falta |
|---|---|
| ATA038 (base y `_rev`) | reinicio de la víctima a mitad de ventana: hay que esperar la reconexión del agente y repartir `t0/t1` |
| ATA039, ATA040 | daemon `rsync` en el manager (`rsync://192.168.65.128:9873`) y el contenido de `~/lab-share` (la versión 1 solo conserva los sha256 de los ficheros) |
| ATA049–ATA053 | 49 paquetes `.deb` GUI (Xvfb, xdotool…) a re-descargar y verificar contra los sha256 de `Soporte/Ataques/c0/ATA049-053_prestaging_paquetes.md` |
| ATA029 `_rev` | paquetes `.deb` (sqlite3/binutils) |
Estas ventanas quedan marcadas `PENDIENTE` en el índice (no se han inventado).

## Dónde está todo
- Repo: `Logs/<tag>/` (salida del ataque, `times.log`, `lanzamiento.json`, `sha256_artefacto.txt`, `sink.log`), `CSV/` (Detalle + raw), `Auditado/` (filtro; **las filas `dudosa` siguen pendientes de revisión humana**, ver `-Revision.csv`), `windows_index.csv`, `filtrado_resumen.csv`.
- Fuera del repo (`D:\TFG-VMs\ataques-linux-v2-2026-11-20\`): `raw/` (alerts + archives crudos por ventana), `crudo/` (alerts/archives diarios del manager con `MANIFEST.tsv` sha256 y `crudo.done`), `piloto_*` (prueba previa con ATA009/ATA011, no forma parte de los resultados).
- Registro de la campaña: `D:\TFG-VMs\lab-logs\ataques_linux_v2.txt` (cada línea aparece dos veces: stdout + fichero).
