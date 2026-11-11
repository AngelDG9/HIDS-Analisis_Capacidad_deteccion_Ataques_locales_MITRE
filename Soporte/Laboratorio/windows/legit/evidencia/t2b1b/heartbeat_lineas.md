# `heartbeat.jsonl` real de T2b-1b — qué es cada línea (G-7)

> **G-7: la evidencia no se cura.** Este documento declara **línea a línea** el
> `heartbeat.jsonl` que produjo el chivato. El fichero **no se ha editado, filtrado ni
> reordenado**: se copia byte a byte desde
> `Soporte/Laboratorio/windows/legit/evidencia/heartbeat.jsonl`.

| Dato | Valor |
|---|---|
| Copia de evidencia | `t2b1b/heartbeat.jsonl` |
| Original en producción | `legit/evidencia/heartbeat.jsonl` |
| Líneas | **6** (límite de la prueba: 6 latidos = ~21 min) |
| `sha256` (idéntico en las dos copias) | `d62bc1db0d7a9e3310267bf6485a19bd3d904068380c17deb3455d1e960e8dc1` |
| `seq` | **1 → 6 estrictamente creciente** |
| `ROTA_SEQ` | **0** |
| `ROTA` | **0** |
| `ka_instancias` | **1** en 6/6 |
| `ka_pid` | **4388** en 6/6 (un solo proceso emisor) |
| Emisor | `tfg_keepalive_windows.ps1 -Loop` (tarea `TFG-WinLegit-Keepalive`, SYSTEM) |
| Sink | `heartbeat_sink.py` pid 15252, `192.168.65.1:9095` |
| Arranque de la ventana de prueba | `prep` 2026-11-11T10:12:01Z (sink re-sembrado, `heartbeat.seq` del invitado ausente tras el revert) |

## 1. Las 6 líneas, una a una

> Campo `cadena` = resultado del encadenado `sha256_prev` que calcula el sink.

| # | `seq` | `ts_ciclo` (UTC) | `cadena` | `ka_pid` | `ka_instancias` | `armado` | `n_ghosts` | `win_user` | `defender` |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 1 | 2026-11-11T10:14:21Z | `INICIO` | 4388 | 1 | false | 0 | — | off |
| 2 | 2 | 2026-11-11T10:15:00Z | `OK` | 4388 | 1 | false | 0 | — | off |
| 3 | 3 | 2026-11-11T10:20:00Z | `OK` | 4388 | 1 | **true** | **1** | `DESKTOP-BTMCFA5\angel` | off |
| 4 | 4 | 2026-11-11T10:25:00Z | `OK` | 4388 | 1 | true | 1 | `DESKTOP-BTMCFA5\angel` | off |
| 5 | 5 | 2026-11-11T10:30:00Z | `OK` | 4388 | 1 | true | 1 | `DESKTOP-BTMCFA5\angel` | off |
| 6 | 6 | 2026-11-11T10:35:00Z | `OK` | 4388 | 1 | **false** | 0 | — | off |

**Qué es cada una (declarado):**

1. **Línea 1 (`seq=1`)** — primer latido del bucle que arrancó el `deploy` de `prep`.
   `cadena=INICIO` porque es la primera línea del fichero nuevo (el sink se re-sembró al
   archivar el anterior) y `sha256_prev=""` (el proceso no conoce latido previo).
   `armado=false`: `prep` no arma. `delta_s=1.555` (reloj host↔invitado, CA-W3b-21).
2. **Línea 2 (`seq=2`)** — ciclo normal a las **:15:00** (alineación a múltiplos de 5 min).
   La cadena cierra: `sha256_prev` = `body_sha256` de la línea 1 ⇒ `OK`.
3. **Línea 3 (`seq=3`)** — primer latido **después de `arm`** (10:16): la tarea de
   actividad ya corre ⇒ `armado=true`, `n_ghosts=1`, `win_user=DESKTOP-BTMCFA5\angel`.
   Es la prueba de que el `arm` **no reinició** el bucle (`ka_pid=4388` sigue igual).
4. **Línea 4 (`seq=4`)** — ciclo normal de los 5 min. Estado estable.
5. **Línea 5 (`seq=5`)** — ciclo normal a las 10:30. Es la que leyó el `watch` de las
   10:31:33Z: `HB_EDAD_MIN=1.5 SEQ=5 KA_PID=4388 KA_INSTANCIAS=1`.
6. **Línea 6 (`seq=6`)** — ciclo de las **10:35**, posterior a la limpieza de la prueba 4
   (cliente parado y `armado.flag` retirado): `armado=false`, `n_ghosts=0`. Demuestra que el
   bucle sigue latiendo aunque no haya cliente armado y que **no se reinició** (`ka_pid`
   sigue 4388). El sink se paró a las 10:35:49Z, después de esta línea.

> **No hay líneas de `-Once`.** F-1 se comprobó aparte: `prueba_once_final.log` muestra
> `heartbeat.seq` con el mismo `sha16`/`mtime` antes y después, `estado.json` intacto y
> `diagnostico modo=Once sin_latido sin_seq sin_estado`.

## 2. Ficheros archivados por `prep` (F-1: rotación, no borrado)

`prep` **no borra** el latido anterior: lo mueve a `legit/evidencia/historico/`. Son
ventanas de prueba anteriores y se dejan tal cual (no se curan):

| Fichero | Líneas | `sha256` | Qué es |
|---|---|---|---|
| `historico/heartbeat_20261111T091735Z.jsonl` | 9 | `d9e3f516a30a691f7d3dfd81805998c935414f31beacb3b6d0818cd3f3495fc3` | ventana del **T2b-1** (2026-11-10 22:02–22:15Z): **5** `REINICIO_BUCLE` por los `arm` que re-desplegaban (defecto F-1 ya corregido) y **0 `ROTA_SEQ`** |
| `historico/heartbeat_20261111T094545Z.jsonl` | 7 | `d07e92732dae0e9fa7148cca12ba761dd4670929d273e461441ff0525d6fdbdf` | primer `prep` de esta tanda (09:20–09:45Z), **antes** del arreglo de rotación de receta: `seq=6` es `REINICIO_BUCLE` porque el `arm` de las 09:40 sí re-desplegó (payload distinto: recetas regeneradas con otro `--t0`) |

`REINICIO_BUCLE` **no es manipulación**: el proceso nuevo del bucle no conoce el
`body_sha256` anterior y manda `sha256_prev=""` (contrato §4.2 del plan). `ROTA_SEQ` es
lo único que indicaría duplicado/edición, y **no aparece en ninguno de los tres ficheros**.
