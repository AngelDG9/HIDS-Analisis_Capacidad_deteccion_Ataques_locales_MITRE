# SUPERSEDED - timelines de L1 (archivadas, NO borradas)

Estas dos timelines son las del bloque **L1** (legitimo-72h, ventana 19-22/10/2026) y se
**archivan** aqui el **2026-10-21** al entrar en vigor la **receta v1** del bloque
legitimo-fix (plan S5.6). **No se borran**: su sha256 sigue citado en el B10 v1.

| Fichero | `sha256` | Por que se sustituye |
|---|---|---|
| `timeline_72h.json` | `16c63746bc814f2decc80b5a952aa92e4b4749940c12527f1480a7ccc4581a30` | 4 handlers en `Loop` con ventanas repetidas (actividad dia y noche, ~420 acciones/h) y handler `Curl` (UA aleatoria): **no determinista** y **no realista** |
| `timeline_72h.dry.json` | `476c88eb5c21635137eaaf376ace62041ab485753be2a11ecb41287702b88998` | Derivada de la anterior (ventanas abiertas) para el ensayo |

- **Sustituta**: `recetas/d1.json` (111), `d2.json` (117), `d3.json` (105) + `calendario.json`.
- **Contexto**: la ventana de L1 es **INVALIDA** (`diagnostico_fallo.md`); estas timelines no
  se usan como medida.