# incidencias.md — ventana `legitimo-72h-v2` (2026-10-26 → 2026-10-29)

> Registro **corrido** de incidencias observadas **durante** la ventana. Solo se anota lo que se
> observa leyendo el host (registro de vigilancia, estado de tareas, servicio). **No se ha tocado
> la víctima ni el laboratorio** dentro de `[t0,t1]`.

| Hora (UTC) | Señal | Observación | Veredicto |
|---|---|---|---|
| 2026-10-26T00:00:02Z | vigilancia | Primer chequeo: `AVISO` con `arch=-1B`, `dia=-1B`, `df=n/a`, `notas=sin_df`. Sin lecturas previas con las que comparar. | **Esperado** (arranque de las señales) |
| 2026-10-26T00:30:01Z | vigilancia | `OK`. `df=4.4G`, deltas de eventos positivos. | Normal |
| 2026-10-26T08:00:02Z | vigilancia | **`ALARMA` `doing>30m`** (`doing_age=6654m`). El chequeo cae **2 s después** de que empiece el bloque (08:00:00Z) y la última acción es la del día anterior. | **Falsa alarma de borde**; el chequeo de 08:30:02Z da `OK` con `doing_age=4m`. **Se repetirá a las 08:00Z del 27 y del 28** (mismo patrón). No es persistente ⇒ no invalida (§7.2) |
| 2026-10-26T08:00:02Z | fichero | Generado `ALARMA_2026-10-26T080002Z.txt`. | Se conserva como evidencia; se explica en la ficha |
| 2026-10-26T09:40 local | host | `wuauserv` = `Stopped` / `Manual`: Windows Update **se auto-repara** el tipo de arranque (tarea de sistema `WindowsUpdate\Scheduled Start`). Política `NoAutoUpdate=1` + `NoAutoRebootWithLoggedOnUsers=1` **intacta**. | **No se toca** (dentro de la ventana). Se comprueba a diario y se declara |
| 2026-10-26T13:00:02Z | vigilancia | `OK`, `bloque=pausa`, `doing_age=2m` (comida 13:00–14:00Z). | Normal |
| 2026-10-26T14:00:05Z | vigilancia | **`ALARMA` `doing>30m`** (`doing_age=62m`). El chequeo cae **5 s después** de que reanude el bloque (14:00:00Z); la última acción es la de antes de comer. | **Falsa alarma de borde** (misma familia que la de 08:00Z). El chequeo de 14:30:02Z da `OK` con `doing_age=5m`. No es persistente ⇒ no invalida (§7.2) |
| 2026-10-26T14:00:05Z | fichero | Generado `ALARMA_2026-10-26T140005Z.txt`. | Se conserva como evidencia |
| 2026-10-27T08:00:07Z | vigilancia | `ALARMA` `doing>30m` (`doing_age=902m`): **repite el patrón de borde** previsto al empezar la jornada. Siguiente chequeo 08:30:05Z: `OK`, `doing_age=3m`. | **Falsa alarma esperada** (3.ª de hasta 6). No persistente ⇒ no invalida |
| 2026-10-27T08:45 local | vigilancia | La **rotación al día 2** (07:45Z) **no es observable desde el host** (la señal `rot=` es post-hoc, se lee de `recovery.log` al cerrar). | **Por diseño**; se juzga en la extracción (§7.2) |

## Patrón conocido (declarado, no se corrige durante la ventana)

La vigilancia revisa cada 30 min **en punto** (`:00:02` / `:30:02`), y dos bloques de la receta
**empiezan exactamente en punto** (`08:00Z` y `14:00Z`). En esos dos chequeos la señal 1 compara con
la última acción del bloque anterior y dispara `doing>30m` **antes de que la primera acción del bloque
nuevo** haya ocurrido.

⇒ Se esperan **2 falsas alarmas por día** (08:00Z y 14:00Z) = **hasta 6** en la ventana. Todas quedan
en fichero, todas se explican en la ficha, y **el chequeo siguiente siempre sale `OK`** (no persistentes).
El café de `10:20Z` **no** dispara: el chequeo de `10:30Z` cae 10 min después del inicio del bloque
(por debajo del umbral de 15 min).

## Notas de seguimiento
- Umbral de disco: alarma < 2 GB; lectura estable en **4,4 GB**.
- Eventos: ~5 MB/h de `archives.json` (presupuesto 6,65 MB/h de fondo).
- Latido del agente `001`: 10–11 s.
