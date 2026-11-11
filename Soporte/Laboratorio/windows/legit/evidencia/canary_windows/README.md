# canary_windows — reportabilidad de plantillas (C5, en seco)

Generado por `_artefactos/scripts/verificar_paridad_windows.py --bloque 3`.
**No se ha ejecutado ninguna VM**: aquí solo se genera la timeline y se prueba el
verificador con un historial simulado (positivo y control negativo).

| Fichero | Qué es |
|---|---|
| `timeline_canary.json` | Timeline GHOSTS con **22 acciones**, una por plantilla de comando. `Loop=false`, ventana `00:00:00–23:59:59`. |
| `plantillas_canary.json` | Las 22 plantillas (`id`, forma, comando literal enviado). |
| `history_timeline_simulado.tsv` | Historial simulado **completo** (22/22). |
| `history_timeline_simulado_fallo.tsv` | Historial simulado **sin** `powershell`; prueba que el verificador falla cerrado. |
| `canary_dryrun.txt` | Resultado de la prueba en seco. |

## Ejecución real (C6/T4, requiere VM)

1. `prep` debe crear `C:\lab-legit\canary` en el invitado.
2. Enviar `timeline_canary.json` con `ghosts_api.py send-timeline` (o el mecanismo de T4).
3. Exportar `history_timeline` del caso (TSV/CSV con columna `command`, o la tabla de
   `psql` de WE0-2).
4. Verificar:

```python
import verificar_paridad_windows as V
res = V.verificar_canary(None, "history_timeline.tsv")
print(res["ok"], [p["id"] for p in res["faltan"]])
```

Criterio: `history_timeline == enviados`; si falta una plantilla, `ok=False` y se lista
su `id`. No se da por bueno un canary incompleto.
