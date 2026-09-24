# roadmap.md — Roadmap del TFG

> Derivado de `context.md` y `requirements.md`. Secuencia el trabajo en **6 fases** con su
> *Definition of Done* (DoD) y los hitos para el tutor. **Wazuh-first**: Velociraptor y el
> tercer HIDS solo aparecen si sobra tiempo.

---

## 0. Resumen ejecutivo

```
Fase 0 — Arranque del proyecto                         [~2 días]   ✔ hecho
Fase 1 — Corpus MITRE (F-01)                           [~1 semana]   ✔ hecho
Fase 2 — Laboratorio Wazuh (F-02)                      [~1 semana]   ✔ hecho
Fase 3 — Ataques y detección (F-03)                    [~2 semanas mes 1, escalable mes 2]
Fase 4 — Robustez y rendimiento (η)                    [~1 semana]
Fase 5 — Memoria y anexos (F-04)                       [~2-3 semanas]
```

**Objetivo del primer mes:** tubería funcionando + 3-4 ataques cerrados (hasta 6-8 si el
laboratorio sale liso) + proto tabla de detecciones. Suficiente para demostrar avance sólido.

---

## Fase 0 — Arranque del proyecto ✔

**Objetivo:** dejar el repo y la arquitectura de agentes listos para arrancar el trabajo.

| # | Tarea | Modo |
|---|-------|------|
| 0.1 | Repo, `.gitignore` y `README.md`. | [AUTO] |
| 0.2 | Los docs v1 se sustituyeron por la versión slim en su sitio (no se archivó nada en `_archivo/`). | [AUTO] |
| 0.3 | `opencode.json` + 4 agentes (`tfg-orchestrator`, `tfg-planner`, `tfg-executor`, `tfg-tester`) + skill `tfg-flow`. | [AUTO] |
| 0.4 | Reescribir `context.md`, `requirements.md` y `roadmap.md` en versión slim. | [AUTO] |
| 0.5 | Skeleton de carpetas. | [AUTO] |

**DoD:** repo con docs slim y arquitectura de agentes operativa.

---

## Fase 1 — Corpus MITRE (F-01) ✔

**Objetivo:** obtener la lista reproducible de técnicas host-eligible y seleccionar el
corpus de 12-15 priorizado R/E/S.

| # | Tarea | Modo |
|---|-------|------|
| 1.1 | **T-01**: descargar el STIX v19.1. | [AUTO] |
| 1.2 | **T-02**: script `extraer_tecnicas_host.py` con filtro inverso. | [AUTO] |
| 1.3 | Tests sobre técnicas conocidas (T1486 = YES; T1595 = NO red pura; T1046 = YES híbrida). | [AUTO] |
| 1.4 | **T-03**: `corpus_host.csv` + `lista_tecnicas_validas.md` priorizada. | [AUTO] |
| 1.5 | Validar la lista y elegir las 12-15 técnicas del corpus. | [HUMANO] |

**DoD:** script reproducible + lista priorizada + corpus elegido en `Hojas/ATA_index.csv`.
**✔ Cumplido (2026-09-19):** 625 técnicas host-eligible; corpus de **13 técnicas** en
`Hojas/ATA_index.csv` (`ATA001`..`ATA013`). Verificación PASA; detalle en `change-doc-fase1.md`.

---

## Fase 2 — Laboratorio Wazuh (F-02) ✔

**Objetivo:** laboratorio reproducible con Wazuh detectando y controlable en remoto.

> **Acceso:** los agentes (`opencode`) corren en el **sobremesa** (junto a las VMs); el portátil entra por **SSH sobre Tailscale**.

| # | Tarea | Modo |
|---|-------|------|
| 2.1 | **T-04**: topología + importar VMs (VMware en el sobremesa, host-only). | [HUMANO] |
| 2.2 | **T-08 (acceso)**: SSH portátil→sobremesa sobre **Tailscale** + OpenSSH en Windows. | [HUMANO] ✔ |
| 2.3 | **T-05**: Wazuh server + agentes (Linux primero). | [MIXTO] |
| 2.4 | **T-07**: detección-only + 4 RuleSets. | [AUTO] |
| 2.5 | **T-06**: baseline legítimo **2 ventanas × 4 h**. | [AUTO] |
| 2.6 | **T-08 (cierre)**: documentar SSH + `vmrun` (local). | [MIXTO] |

**DoD:** Wazuh con agentes activos, detección-only, baseline grabado y acceso remoto
verificado desde el portátil.
**✔ Cumplido (2026-09-23):** Wazuh **4.14.7** all-in-one + agente `victima-linux` **`active`**;
**detección-only** y **4 capas** con `active_ruleset.txt` **sin colisiones** (RS3 y RS4 vacías en
Fase 2, declarado); **baseline de 2 ventanas × 4 h** (12 `rule.id`, 13.574 alertas, 0 UNKNOWN,
ruido **estable**); **NAT desconectado** y snapshot **`lab-listo`** en ambas VMs; acceso y `vmrun`
documentados. Verificación **PASA**; detalle en **`change-doc-fase2.md`**.
**Pendiente:** presentar el **hito H2** al tutor (`push` a cargo del humano).

---

## Fase 3 — Ataques y detección (F-03)

**Objetivo:** cerrar ataques `ATA<NNN>` de extremo a extremo y alimentar la tabla.

| # | Tarea | Modo |
|---|-------|------|
| 3.1 | **T-09** piloto (2-3 técnicas R/E/S): artefacto + README + captura. | [MIXTO] |
| 3.2 | **T-10** + **T-11**: ejecución (con doble iteración), captura, filtrado y etiquetado. | [AUTO] |
| 3.3 | Revisar el flujo y automatizar lo repetitivo. | [MIXTO] |
| 3.4 | Escalar al resto del corpus (hasta 12-15). | [AUTO] + [HUMANO] |

**DoD:** corpus cerrado con filas en `ATA_index.csv`, CSV por ataque y primer balance de
detección de Wazuh.

---

## Fase 4 — Robustez y rendimiento (η)

**Objetivo:** cumplir el "precio de la detección" y la validación de robustez.

| # | Tarea | Modo |
|---|-------|------|
| 4.1 | Monitorizar CPU/memoria/I/O durante ataque y detección. | [AUTO] |
| 4.2 | Experimento de robustez: ataques representativos a distintas cargas del host. | [AUTO] |
| 4.3 | Calcular η por ataque y por táctica; gráficas. | [AUTO] |

**DoD:** tabla de η + gráficas + interpretación escrita.

---

## Fase 5 — Memoria y anexos (F-04)

**Objetivo:** producir la memoria siguiendo el esqueleto de los TFGs hermanos.

Se redacta con un flujo de conocimiento (investigación → redacción → revisión),
**con fuentes verificadas N1/N2**. Incluye: Introducción y Estado del Arte, Base teórica
(MITRE + HIDS), Realización de ataques, Análisis de detecciones, Resultados, Conclusiones y
Anexos (Instalación, Validación, Tabla Resumen de Ataques, Dificultades).

**DoD:** memoria entregada en formato y plazos de la ETSI.

---

## Hitos para el tutor

| Hito | Tras | Qué se le enseña |
|---|---|---|
| H0 | Fase 0 | Planificación slim + arquitectura de agentes. |
| H1 | Fase 1 | Lista de técnicas válidas + criterio de filtro inverso. |
| H2 | Fase 2 | Laboratorio Wazuh funcionando + baseline. |
| H3 | Fase 3 | Ataques piloto cerrados + proto tabla de detecciones. |
| H4 | Fase 4 | Robustez + rendimiento (η). |
| H5 | Fase 5 | Memoria lista. |

---

## Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| Wazuh indexer no indexa a tiempo | Espera de 60 s + segunda consulta a los 300 s antes de dar por "no detectado". |
| Ruido de Sysmon/auditd inunda las alertas | Baseline extenso + filtrado automático de FP. |
| Una técnica no la cubre Atomic Red Team | Script custom equivalente, mapeado a la técnica. |
| El laboratorio consume más RAM de la prevista | Linux primero; no arrancar Windows y Linux a la vez al principio. |
| Se acaba el tiempo por las fases finales | Wazuh-first garantizado: los extras caen antes que la memoria. |
