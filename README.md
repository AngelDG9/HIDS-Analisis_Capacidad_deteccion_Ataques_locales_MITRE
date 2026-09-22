# TFG — Análisis de la capacidad de detección de ataques locales de MITRE ATT&CK Enterprise mediante HIDS

Trabajo Fin de Grado (Universidad de Sevilla, Dpto. Ingeniería Telemática).
Línea de investigación del tutor: detección de ataques con herramientas OpenSource.
Este trabajo traslada la línea de los TFGs hermanos (detección de ataques de **red**)
al dominio **host/local** con **HIDS**.

## Propósito

Medir de forma reproducible la **capacidad de detección** de HIDS OpenSource frente a un
corpus de ataques locales mapeados a MITRE ATT&CK Enterprise, empezando por **Wazuh**.

## Documentación de referencia

| Fichero | Contenido |
|---|---|
| [`context.md`](context.md) | Qué es el TFG, método del profesor, recursos, glosario y decisiones fijadas. |
| [`requirements.md`](requirements.md) | Requisitos, tareas clave y flujos de trabajo. |
| [`roadmap.md`](roadmap.md) | Secuenciación en fases con plazos e hitos. |
| [`state.md`](state.md) | Estado vivo del proyecto (lo mantiene el agente `tfg-orchestrator`). |

Los recursos del profesor viven en `_recursos/` (no versionados).

## Cómo se trabaja

El proyecto se ejecuta con los agentes de opencode definidos en `.opencode/`:

- `tfg-orchestrator` — dirige el trabajo, controla las aprobaciones (gates) y el estado.
- `tfg-planner` — diseña el plan de cada fase.
- `tfg-executor` — escribe los scripts y lanza los comandos del laboratorio.
- `tfg-tester` — verifica los scripts.

El ciclo de trabajo está descrito en la skill `tfg-flow` (`.opencode/skills/tfg-flow/`).

## Acceso

Los agentes (`opencode`) **corren en el PC sobremesa**, donde viven las VMs. El **portátil**
entra al sobremesa por **SSH sobre Tailscale**; los agentes acceden a las VMs por la red
host-only. Ver `Soporte/Laboratorio/README.md`.

## Estructura

```
TFG/
├── context.md · requirements.md · roadmap.md · state.md
├── opencode.json                      (config del proyecto)
├── .opencode/                         (agentes y skills del TFG)
├── _artefactos/                       (matriz MITRE, scripts)
├── Hojas/                             (corpus, lista de técnicas, tablas, índices)
├── Dataset/                           (artefactos de ataque y resultados)
├── Soporte/                           (Wazuh, laboratorio, configuraciones)
├── Bitacora/                          (registro por ataque ATA<NNN>)
└── Estudio-Wazuh/                     (resumen y gráficas)
```
