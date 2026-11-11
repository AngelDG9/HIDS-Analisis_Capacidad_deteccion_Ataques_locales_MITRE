# Declaración del `heartbeat.jsonl` de T2b-1 (G-7)

> **Regla G-7 (T2b-1b):** la evidencia **no se cura**. El `heartbeat.jsonl` es el fichero
> **real** del sink, con sus líneas tal cual se escribieron. No se ha movido ninguna línea
> a un fichero «sintético» para que el resultado parezca limpio. Las líneas de prueba se
> **declaran aquí**, no se esconden.

## Fichero

`Soporte/Laboratorio/windows/legit/evidencia/t2b/heartbeat.jsonl` — 9 líneas, en orden
cronológico de `recv_utc`.

## Qué es cada línea

| # | `seq` | `recv_utc` | `cadena` | `ka_pid` | Qué es |
|---|---|---|---|---|---|
| 1 | 1 | 2026-11-10T20:18:13Z | `INICIO` | 111 | **Prueba manual** de `POST /heartbeat` (T2b-1 §7). No es el bucle. |
| 2 | 1 | 2026-11-10T20:22:20Z | `ROTA_SEQ` | 5492 | **Prueba manual** de segundo proceso: manda `seq=1` con el sink ya sembrado (`last_seq=1`) ⇒ `ROTA_SEQ`. Declarado, no manipulación. |
| 3 | 2 | 2026-11-10T20:23:20Z | `REINICIO_BUCLE` | 2824 | **Primera línea del bucle real** `-Loop` (cadena nueva tras la prueba manual). |
| 4 | 3 | 2026-11-10T20:25:02Z | `OK` | 2824 | Bucle real. |
| 5 | 4 | 2026-11-10T20:30:01Z | `OK` | 2824 | Bucle real. |
| 6 | 5 | 2026-11-10T20:35:01Z | `OK` | 2824 | Bucle real. |
| 7 | 6 | 2026-11-10T20:35:14Z | `REINICIO_BUCLE` | 840 | **`-Once` lanzado por el 1.er `arm`** (deploy). Este es el **defecto F-1**: `-Once` era un segundo emisor. |
| 8 | 7 | 2026-11-10T20:38:07Z | `REINICIO_BUCLE` | 2512 | **`-Once` lanzado por el 2.º `arm`** (deploy). Mismo defecto F-1. |
| 9 | 6 | 2026-11-10T20:40:10Z | `ROTA_SEQ` | 2824 | El bucle real (que tenía `seq=5` en memoria) vuelve a mandar `6` tras los `-Once` ⇒ **`ROTA_SEQ`**. Es el síntoma exacto de F-1. |

## Por qué esto es la prueba de F-1

Las líneas 7-8 (`ka_pid` 840 y 2512) **no son el bucle**: son los `-Once` que `deploy`
ejecutaba en cada `apply` (y por tanto en cada `arm`). Cada `-Once` incrementaba
`heartbeat.seq` y emitía su latido; el bucle, que llevaba el `seq` en memoria, volvía a
emitir un número ya usado (línea 9) ⇒ `ROTA_SEQ` ⇒ `G-W13` en ALARMA.

**Arreglo (T2b-1b):** `-Once` ya **no** emite latido, **no** toca `heartbeat.seq` y **no**
recrea `estado.json`. El único emisor es `-Loop`. La prueba limpia de T2b-1b está en
`../t2b1b/heartbeat.jsonl` (fichero nuevo, `seq` estrictamente creciente y **0**
`ROTA_SEQ`).

## Ficheros derivados (declarados, no son el crudo)

| Fichero | Qué es |
|---|---|
| `heartbeat_viejo_13min.jsonl` | **Copia derivada** de una línea real con `recv_utc`/`ts_envio` retrasados 13 min para la **prueba negativa** de frescura de `G-W13`. No es evidencia del sink. |
