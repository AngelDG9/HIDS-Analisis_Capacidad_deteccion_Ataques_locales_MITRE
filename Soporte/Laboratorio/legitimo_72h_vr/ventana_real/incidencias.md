# Incidencias de la ventana V1-L (25-28/11/2026)

Formato: hora UTC | senal | causa | accion

- 2026-11-27T03:41Z | Revision de salud: `wuauserv` en Manual y Running (no Disabled) | Windows (UsoSvc/orquestador) lo reactiva solo de vez en cuando (eventos 7040 a las 03:10 y 04:36 locales); es la causa de `reps=si` en el watch (en la ventana aparece en ~1 de cada 6 chequeos) | Ninguna: el watch lo repausa en el siguiente chequeo (cada 30 min). Es solo del PC anfitrion; no toca la VM. Declarar en la memoria.
- 2026-11-27T03:41Z | (ampliacion) `reps=si` (re-pausa de Windows Update por el watch) en **15 de 144** chequeos | Windows reactiva `wuauserv` por su cuenta (UsoSvc/orquestador) | Re-pausado en cada ocasion en el chequeo siguiente; el servicio queda `Disabled` al cierre de cada chequeo. Solo anfitrion.

## Resumen de incidencias de la ventana (cierre, 2026-11-28T00:18Z)
- **Chequeos del watch en [t0,t1]: 144 (uno cada ~30 min), los 144 `estado=OK`. 0 AVISO, 0 ALARMA**, sin ficheros `ALARMA_*` ni `.rescate`. Hueco maximo entre chequeos 30,2 min.
- Latido del cliente VR (`cli`/`hb`): casi siempre 0 s; maximo 21 s (11:00Z del 26/11, durante un bloque de actividad). Servidor VR `active` en todos.
- Espacio libre de la VM: 4,4 GB al inicio -> 4,0 GB al final (alarma a 2 GB; nunca cerca).
- PC anfitrion sin reiniciar (arranque 2026-11-24T09:54Z), 0 eventos Kernel-Power 41/42/107 en la ventana; D: libre 633 GB -> 625 GB.
- Windows Update: ver arriba (15 re-pausas). Politica `NoAutoUpdate=1` intacta; al cierre `wuauserv` -> Manual (sin usar `restaurar`).
- Recuperaciones del cliente GHOSTS (`recovery.log`): 2 rotaciones normales de jornada (07:45Z del 26 y del 27/11), `resultado=ok`. Ninguna recuperacion por fallo.
- Ensayo previo (E0, 24/11) y ensayo general del prep: ver `../ensayo_E0_vr.md` (defectos propios corregidos y sellados antes de t0; no son incidencias de la ventana real).
- **Nada se toco en la VM entre `arm` (23:40Z del 24/11) y la cosecha (00:04Z del 28/11).**
