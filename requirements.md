# requirements.md — Requisitos, tareas y flujos del TFG

> Derivado de `context.md`. Define **qué** hay que cumplir (requisitos), **qué** hay que
> hacer (tareas) y **cómo** se encadenan (flujos). La secuencia temporal vive en
> `roadmap.md`.

---

## 0. Convenciones

- **R-NN** — requisito. **T-NN** — tarea. **F-NN** — flujo.
- **[AUTO]** lo hace el agente · **[HUMANO]** lo hace el alumno · **[MIXTO]** agente propone, alumno valida.
- Gate: ninguna tarea que edite/ejecute se hace sin el `plan.md` de la fase aprobado por el humano.

---

## 1. Requisitos

| ID | Requisito | Criterio de aceptación |
|----|-----------|------------------------|
| R-01 | Trabajar sobre **MITRE ATT&CK Enterprise v19.1**. | La cabecera de las hojas indica versión y fecha. |
| R-02 | El corpus se obtiene con un **script reproducible** (no a mano). | Ejecutarlo regenera el corpus; está versionado en git. |
| R-03 | **Filtro inverso host**: incluir solo técnicas con telemetría endpoint; excluir las exclusivas de red pura. | `corpus_host.csv` con columna `host_eligible`; tests sobre técnicas conocidas (T1486 = YES, T1046 = NO). |
| R-04 | **Priorización R/E/S** (Ransomware, Exfiltración, Sabotaje). | Columna `priority` con ranking. |
| R-05 | **Wazuh** como único HIDS del núcleo. | Resultados bajo `Estudio-Wazuh/` y `Dataset/Ataques/Resultados/Wazuh/`. |
| R-06 | **Modo detección-only**: el HIDS nunca bloquea. | `active-response` desactivado; documentado. |
| R-07 | **Identificador único** `ATA<NNN>` por ataque. | `Hojas/ATA_index.csv` con `ata_id, tactica, tecnica, descripcion, artefacto, estado`. |
| R-08 | **Baseline legítimo** del endpoint (~4 h). | `Dataset/Legitimo/` con los `rule.id` de actividad normal. |
| R-09 | **4 RuleSets** con clasificación de alertas por origen (sin repetir el ataque). | Tabla comparativa RS1..RS4 por ataque. |
| R-10 | **Métrica η = √(CD·(1−FP))** por ataque y por HIDS. | Columna de η en `Hojas/Detecciones.xlsx`. |
| R-11 | **Doble iteración** de cada ataque representativo; si difiere, `review=true`. | `ATA<NNN>_iter{1,2}.csv` y aviso de revisión. |
| R-12 | **Atomic Red Team** como orquestador de ataques (custom si no cubre una técnica). | `Soporte/Ataques/atomic-red-team/` clonado y usable. |
| R-13 | **Reproducibilidad por ataque**: cada ataque tiene artefacto ejecutable + README. | `Dataset/Ataques/Comandos/T<id>-<desc>/` con script + `README.md` (víctima, comando, validación). |
| R-14 | **Arquitectura de agentes propia del TFG** (liviana). | `.opencode/` con `tfg-orchestrator`, `tfg-planner`, `tfg-executor`, `tfg-tester` + skill `tfg-flow`. |

---

## 2. Tareas

### Bloque A — Corpus MITRE

| ID | Tarea | Salida |
|----|-------|--------|
| T-01 | Descargar la matriz MITRE Enterprise v19.1 en STIX/JSON. | `_artefactos/mitre/enterprise-attack-v19.1.json`. |
| T-02 | Script `extraer_tecnicas_host.py`: parsea el STIX, extrae Data Components y aplica el filtro inverso (R-03). | `Hojas/corpus_host.csv`. |
| T-03 | Generar la lista human-legible priorizada R/E/S y elegir el corpus (**12-15 técnicas**). | `Hojas/lista_tecnicas_validas.md` + `Hojas/ATA_index.csv` + pestaña de `Hojas/Mapeos.xlsx`. |

### Bloque B — Laboratorio

| ID | Tarea | Salida |
|----|-------|--------|
| T-04 | Definir topología (VMware en el sobremesa, red host-only) e importar las VMs del profesor. | `Soporte/Laboratorio/topologia.png` + `README.md`. |
| T-05 | Levantar Wazuh (manager + indexer + dashboard) y conectar agentes (Linux primero; Windows después). | Runbooks en `Soporte/Wazuh/Configuracion/`. |
| T-06 | Grabar baseline legítimo (~4 h) en VM limpia. | `Dataset/Legitimo/ruleids_legitimos.csv`. |
| T-07 | Configurar detección-only y los 4 RuleSets (RS1..RS4). | `Soporte/Wazuh/Configuracion/` + `active_ruleset.txt`. |
| T-08 | Control remoto del laboratorio por SSH (y `vmrun` en el sobremesa). | `Soporte/Laboratorio/vmrun_config.md` + `ssh_setup.md`. |

### Bloque C — Ataques y detección

| ID | Tarea | Salida |
|----|-------|--------|
| T-09 | Implementar cada ataque como artefacto reproducible `ATA<NNN>` (Atomic Red Team o custom). | `Dataset/Ataques/Comandos/T<id>-<desc>/`. |
| T-10 | Ejecutar el ataque en snapshot limpio, con doble iteración, y capturar alertas de Wazuh [t0,t1]. | `Dataset/Ataques/Resultados/Wazuh/CSV/ATA<NNN>_iter{1,2}.csv`. |
| T-11 | Filtrar FP contra el baseline y etiquetar TP/FP; clasificar por RuleSet. | `ATA<NNN>-Audited.csv` + fila en `Hojas/ATA_index.csv`. |

### Bloque D — Agregación y memoria

| ID | Tarea | Salida |
|----|-------|--------|
| T-12 | Construir las tablas de resultados, la BBDD SQLite, las gráficas y la memoria. | `Hojas/Detecciones.xlsx`, `Hojas/Mapeos.xlsx`, `BBDD/wazuh.db`, `Estudio-Wazuh/`, memoria. |

---

## 3. Flujos

### F-01 — Corpus
```
T-01 → T-02 → T-03 → (selección de las 12-15 técnicas)
```

### F-02 — Laboratorio
```
T-04 → T-05 → T-07 → T-06 → T-08
```

### F-03 — Ataque y detección (por cada ataque)
```
T-09 → [snapshot limpio] → T-10 (doble iteración) → T-11 (filtrado + etiquetado)  → repetir
```
**Ciclo por ataque:** snapshot → t0 → ataque → t1 → extraer alertas → filtrar FP →
etiquetar TP/FP → clasificar por RuleSet → fila en `ATA_index.csv` → bitácora.

### F-04 — Agregación y cierre
```
T-12 (tablas + BBDD + gráficas) → memoria + anexos
```

---

## 4. Fuera de alcance (explícito)

- **Velociraptor, tercer HIDS y Snort**: extras, solo si sobra tiempo (R-05).
- **Mobile, ICS, Cloud**: fuera (solo Enterprise).
- **Modo bloqueo** del HIDS: fuera (R-06).
- **Comparativa cuantitativa** con los TFGs hermanos: solo cualitativa en la memoria.
