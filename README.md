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
| [`_fases/`](_fases/) | Plan (`plan.md`) y cierre (`change-doc.md`) de cada **bloque** cerrado; en la raíz vive siempre el `plan.md` del bloque en curso. |

La documentación **operativa** vive en el repo: `Soporte/Laboratorio/` (topología, SSH y `vmrun`),
`Soporte/Wazuh/Configuracion/` (runbooks y RuleSets) y `Dataset/` (baseline y, en Fase 3, ataques y
resultados).

Los recursos del profesor viven en `_recursos/` (no versionados).

## Cómo se trabaja

El proyecto se ejecuta con los agentes de opencode definidos en `.opencode/`:

- `tfg-orchestrator` — dirige el trabajo, controla las aprobaciones (gates) y el estado.
- `tfg-planner` — diseña el plan de cada fase.
- `tfg-executor` — escribe los scripts y lanza los comandos del laboratorio.
- `tfg-tester` — verifica los scripts.

El ciclo de trabajo está descrito en la skill `tfg-flow` (`.opencode/skills/tfg-flow/`).

## ⚠️ Huellas y finales de línea

Las huellas (`sha256`) que enlazan `esperado` ↔ `audited` ↔ bitácora ↔ ficha se calculan
sobre los **bytes del fichero en disco**. El repo tiene finales de línea **mezclados** y
**no lleva normalización**: **evitar `git checkout` / `stash` / `reset` / clonar** sobre este
repositorio sin **recalcular** después las huellas afectadas. Los **binarios** (p. ej. `.png`)
**no** deben pasar por reglas de texto.

- **El riesgo no es solo al clonar:** también salta con **`git add`/commit** y por tener
  **`core.autocrlf=true`** (hoy **activo** en este repo; reescribe LF→CRLF en Windows) —
  **cualquier** operación de git que toque los finales de línea cambia los **bytes** y por tanto
  el `sha256`.
- **Cadena de huellas:** `ATA<NNN>_esperado.csv` ↔ `ATA<NNN>_ataque.sh` ↔ `-Audited.csv` /
  `-Revision.csv` ↔ `Bitacora/ATA<NNN>.json` ↔ `ATA<NNN>_meta.md`. Los scripts calculan el
  `sha256` **de los bytes en disco** → hay que **re-pasarlos** (regenerar y actualizar las citas)
  tras **cualquier** operación de git que toque los finales de línea.

## Acceso

Los agentes (`opencode`) **corren en el PC sobremesa**, donde viven las VMs. El **portátil**
entra al sobremesa por **SSH sobre Tailscale**; los agentes acceden a las VMs por la red
host-only. Ver `Soporte/Laboratorio/README.md`.

## Estructura

```
TFG/
├── README.md · context.md · requirements.md · roadmap.md · state.md
├── plan.md                            (plan de la fase EN CURSO; se archiva al cerrar)
├── opencode.json · .gitignore
├── .opencode/                         (agentes y skills del TFG)
├── _fases/                            (plan y cierre de cada bloque cerrado)
├── _artefactos/                       (matriz MITRE, scripts)
├── Hojas/                             (corpus, lista de técnicas, tablas, índices)
├── Dataset/                           (baseline legítimo, ataques y resultados)
├── Soporte/                           (Wazuh, laboratorio, configuraciones)
├── Bitacora/                          (registro por ataque ATA<NNN>)
├── Estudio-Wazuh/                     (resumen y gráficas)
└── _recursos/                         (material del profesor; solo lectura)
```
