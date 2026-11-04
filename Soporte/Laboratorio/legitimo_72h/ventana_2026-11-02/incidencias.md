# incidencias.md — ventana `legitimo-v3` (2026-11-02 → 2026-11-05)

> Registro corrido de lo observado **leyendo el host**. No se ha tocado la víctima dentro de `[t0,t1]`.

| Hora (UTC) | Señal | Observación | Veredicto |
|---|---|---|---|
| 2026-11-02T00:00:03Z | vigilancia | Primer chequeo: `OK`, `bloque=fuera`, `hb=2s`, `df=4.4G`, `dia=-1B` (sin muestra previa), `wu=Stopped/Disabled`. | Normal (primer chequeo) |
| 2026-11-02T08:00:02Z | vigilancia | `OK` con `notas=gracia_borde(0m del bloque)`. | **H1 funcionando**: sin falsa alarma en el borde |
| 2026-11-02T09:30:07Z | vigilancia | `OK`, `reps=si`: el `watch` **repausó Windows Update**. | **H-6 mitigado** en producción |
| 2026-11-03T00:00:04Z | vigilancia | **`AVISO`** `arch=-246027119B`, `df=n/a`, `notas=sin_df`. Es la **rotación de medianoche** (archivos diarios a las 00:04Z): el delta sale negativo y la señal de disco pierde la muestra. | **Transitorio esperado**; se recupera solo |
| 2026-11-03T00:30:16Z | vigilancia | **`AVISO`** `df=n/a`, `notas=sin_df` (aún sin muestra tras la rotación). | **Transitorio**; a las 01:00Z ya vuelve `OK` |
| 2026-11-03T08:00:13Z | vigilancia | `OK` con `gracia_borde`; día 2 arranca con actividad (`doing_age=7m` a las 08:30Z). | Normal |
| 2026-11-03T07:00:08Z / 08:00:13Z | vigilancia | `reps=si` (segunda y tercera repausa de WU por el `watch`). | Normal (H-6) |
| 2026-11-04T16:59Z | host | **`TFG-Legit-Stop` desactivada** (no borrada) por el orquestador, para eliminar la carrera de 3 min entre la cosecha (`t1+2`) y la parada automática (`t1+5`). **No toca la víctima ni la medida**: la ventana termina en `t1`. La parada se hará **a mano** tras verificar la cosecha. | **Decisión operativa declarada**; reversible (`Enable-ScheduledTask`) |

## Notas
- **0 huecos** > 31 min entre chequeos (68 chequeos hasta 2026-11-03T09:30Z).
- **0 `ALARMA`** en la ventana.
- Agente `001`: latido 1–20 s (umbral de alarma: 10 min).
- Host **sin reinicio** desde 2026-10-29T20:25Z (antes de `t0`).
- Disco de la víctima estable en **4,4 GB**; host ~172 GB.
- El **AVISO de `sin_df` en la rotación de medianoche** se repetirá cada noche (00:00Z y quizá 00:30Z): **declarado**, no es un fallo del banco.
