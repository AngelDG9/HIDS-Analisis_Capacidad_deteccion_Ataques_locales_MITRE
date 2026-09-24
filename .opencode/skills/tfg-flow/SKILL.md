---
name: tfg-flow
description: Flujo de trabajo del TFG (HIDS + MITRE ATT&CK). Cárgala al iniciar o continuar una fase del roadmap para ejecutar el ciclo plan → gate humano → ejecución → verificación → cierre, y el ciclo por ataque (ATA<NNN>).
---

# Flujo del TFG

Ciclo de trabajo del TFG: medir la **capacidad de detección** de HIDS OpenSource (empezando
por Wazuh) frente a ataques locales mapeados a MITRE ATT&CK Enterprise.

## Ciclo de una fase

| # | Paso | Qué hace el orquestador |
|---|---|---|
| 1 | INTAKE | Recoge el objetivo de la fase (o propone el siguiente paso del `roadmap.md`). |
| 2 | PLAN | Llama a `tfg-planner` para escribir `plan.md` (v1). Lee el fichero. |
| 3 | ATAQUE (opcional) | Solo en fases de alto riesgo: revisa rigurosidad, huecos y casos límite (1-2 rondas). Anota en `reviews.md` (opcional). |
| 4 | ⛔ GATE | Presenta el plan al humano y **se detiene**. Con su OK, marca `status: approved_by_human` en `plan.md`. |
| 5 | EJECUTAR | Llama a `tfg-executor` con el plan aprobado. |
| 6 | VERIFICAR | Llama a `tfg-tester`. PASA → cierra; FALLA → vuelve al executor (máx. 3 ciclos). |
| 7 | CERRAR | Escribe `change-doc.md`; actualiza `state.md`, `roadmap.md` y `Bitacora/`. |
| 8 | ⛔ GATE FINAL | Presenta el resultado al humano. |

## Ciclo por ataque (`ATA<NNN>`)

Cada ataque del corpus tiene un identificador único `ATA001`, `ATA002`... y sigue este
ciclo (una vez el laboratorio esté listo):

```
snapshot limpio de la VM víctima
  → marcar t0
     → ejecutar el ataque (Atomic Red Team o script custom)
        → marcar t1
           → extraer alertas de Wazuh entre [t0, t1]
              → filtrar FP contra el baseline legítimo
                 → etiquetar TP / FP y clasificar por RuleSet (RS1..RS4)
                    → escribir la fila en Hojas/ATA_index.csv + Hojas/Detecciones.xlsx
                       → registrar Bitacora/ATA<NNN>.json
```

- **RuleSets (4)**: se lanza el ataque **una vez** con todas las reglas activas y luego se
  clasifica cada alerta según de qué RuleSet viene (por rango/grupos de `rule.id`). No se
  repite el ataque por RuleSet.
- **Doble iteración**: cada ataque representativo se ejecuta **dos veces** (snapshot fresco
  entre ambas). Si el número de alertas difiere, se marca `review=true` y se avisa.

## Estado y artefactos

- `state.md` — estado vivo (fase actual, paso, siguiente acción, cortes). Lo mantiene el
  orquestador. Es la memoria externa: al retomar, se lee esto primero.
- `Hojas/ATA_index.csv` — estado por ataque (`pendiente` / `en-curso` / `review` / `cerrado`).
- `Bitacora/ATA<NNN>.json` — registro append-only por ataque.
- `plan.md`, `reviews.md` (opcional), `change-doc.md` — artefactos por fase.

## Reglas del flujo

- **Gate por fase:** sin `status: approved_by_human` en `plan.md`, ni `tfg-executor` ni
  ningún otro edita/ejecuta.
- **Nunca `git push`.** Los commits se hacen en local; publicar es tarea del humano.
- **Determinismo:** lo scriptable se resuelve con scripts (sin LLM); el LLM decide y redacta.
- **KISS:** si algo se puede hacer más simple, se hace. Cuanto más liviano, mejor.
