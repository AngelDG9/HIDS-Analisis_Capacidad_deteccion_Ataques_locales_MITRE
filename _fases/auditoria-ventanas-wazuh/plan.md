---
nombre: Auditoria de las ventanas legitimas de Wazuh (Linux y Windows) antes de V1-L
fecha: 2026-11-24
estado: EJECUTADA y VERIFICADA (2026-11-24) - ver AUDITORIA.md; el plan V1-L pasa a v2
depende_de: _fases/velociraptor-v1l/plan.md (propuesto) - _fases/legitimo-v3, legitimo-72h-v2, legitimo-fix, legitimo-infra, windows-legit-prep, analisis-windows-legit
---

# Auditoria de las ventanas de Wazuh

## 1. Para que
El humano pide asegurarse, **antes de gastar 3 dias de PC en V1-L**, de que: (a) se replica lo hecho con Wazuh de forma **lo mas comparable posible**; (b) **se guarda todo**; (c) **no se ensucia la maquina** (idealmente cero rastro nuevo en la victima, y lo que haya, declarado); (d) no repetimos errores de las ventanas fallidas o con incidencias. Linux es lo prioritario; Windows tambien se audita.

## 2. Preguntas (cada hallazgo debe citar `fichero:linea` o fichero exacto)
**P1 - Dependencias de Wazuh.** Lista completa, por fichero y linea, de todo paso, script, tarea, comprobacion, fichero o dato del procedimiento de la ventana Linux que dependa de Wazuh (agente, manager, `logall_json`, `archives`, `agent_control`, `ossec`, `rule_id`...) y que haya que sustituir o descartar en V1-L; y lo que **no** depende y se reutiliza tal cual.
**P2 - Rastro en la victima.** Todo lo que el procedimiento (prep, arm, timer, keepalive, GHOSTS, campana B6, vigilancia, cosecha, parada) **escribe, cambia o ejecuta en la VM** antes y durante `[t0,t1]`: ficheros, logs, cron/timers, procesos, sesiones SSH, snapshots, ruido en auditd; y que anade el cliente de Velociraptor. Para cada cosa: ¿puede evitarse?, ¿esta declarada?, ¿afecta a la comparabilidad?
**P3 - Datos guardados y perdidos.** Que se guardo en la ventana Linux de Wazuh, que **no** se pudo guardar (limitaciones, incidencias, correcciones posteriores como el filtro del agente `000` o el orden de extraccion invertido), y que debe guardar V1-L **ademas** para no sufrir lo mismo.
**P4 - Fallos y lecciones.** Que fallo en las ventanas anteriores (L1 del 19-oct por disco lleno, v2 abortada a las 39 h 53 min, incidencias H-9..H-12 y las de v3) y si el plan V1-L los evita; riesgos del plan V1-L que no esten cubiertos.
**P5 - Comparabilidad.** Diferencias entre la ventana de Wazuh y lo planeado para V1-L, clasificadas en IGUAL / ADAPTADO / INEVITABLE, y cualquier diferencia **evitable** que el plan V1-L no haya visto.
**P6 - Windows.** Mismo analisis (P1-P5) para las ventanas de Windows (2026-11-11/12/16/17): que se hizo, que se guardo, validez, incidencias, y que se aprende para la futura ventana de Velociraptor en Windows y para la comparacion Linux<->Windows.

## 3. Metodo
1. **Tres revisores en paralelo, solo lectura** (Linux-procedimiento/rastro, Linux-datos/validez/lecciones, Windows). Cada uno escribe un borrador en `_fases/auditoria-ventanas-wazuh/borradores/` y devuelve un resumen.
2. **Verificacion**: el coordinador **comprueba por muestreo** (>= 12 afirmaciones repartidas, elegidas por impacto) leyendo el fichero citado; las que no se sostienen se descartan o se corrigen; lo no verificado se marca como tal.
3. **Sintesis** en `AUDITORIA.md`: hallazgos por gravedad, que cambia en el plan V1-L (version 2) y que preguntas quedan para el humano.

## 4. Criterios de aceptacion
- Cada hallazgo cita fuente; ninguno sin fuente entra como «hecho».
- `AUDITORIA.md` separa **verificado / no verificado**.
- El plan V1-L se actualiza **solo** con lo verificado, y declara los cambios.
- No se arranca ninguna VM ni se modifica ningun fichero fuera de `_fases/auditoria-ventanas-wazuh/` y del plan V1-L.

## 5. Lo que NO es
No reabre decisiones de la metrica ni vuelve a analizar los datos de Wazuh; no modifica ventanas ya selladas.
