# roadmap.md — Roadmap del TFG

> Documento derivado de `context.md` y `requirements.md`. Secuencia los flujos y tareas
> (F-01..F-06, T-01..T-28) en el tiempo, en fases, con **Definition of Done (DoD)** por
> fase y claros puntos de control humano. **Wazuh-first**: Velociraptor y Tercer HIDS se
> tratan en fases finales (Fases 8-9) y solo se detallarán al iniciarlas.
>
> **Principio rector**: el agente Opencode actúa como "El Agente" orquestando F-03, F-04 y
> F-05 una vez que el laboratorio esté listo (R-11 a R-14, §3.A de requirements.md). Las
> tareas marcadas **[AUTO]** las hace el agente; **[MIXTO]** implica humano + agente;
> **[HUMANO]** solo el alumno.

---

## 0. Resumen ejecutivo

El TFG se ejecuta en **9 fases** (Wazuh-first). Las 3 primeras son configuración
infraestructura + corpus MITRE. Las fases 3 y 4 son la prueba piloto end-to-end sobre 5
técnicas con Wazuh, sirviendo para refinar el orquestador IA y los criterios de
etiquetado TP/FP. Las fases 5-7 escalan a las 30 técnicas objetivo, robustez y
rendimiento. Las fases 8-9 extienden a Velociraptor/tercer HIDS y cierran con la
memoria.

```
Fase 0: Zona de trabajo y arquitectura de automatización        [~3 días]
Fase 1: Corpus MITRE (F-01)                                      [~5 días]
Fase 2: Laboratorio Wazuh + automatización (F-02 + T-24/T-25)   [~10 días]
Fase 3: 5 técnicas piloto end-to-end (primer cierre Wazuh)       [~15 días]
Fase 4: Evaluación y ajuste de "El Agente" + T-23                   [~5 días]
Fase 5: Escalar a 30 técnicas (corpus completo)                  [~6-8 semanas]
Fase 6: Experimentos de robustez (T-20) y rendimiento (T-21/T-22) [~1 semana]
Fase 7: Replicar patrón para Velociraptor (segundo HIDS)        [~3-4 semanas]
Fase 8: Tercer HIDS + apartado extra Snort                       [~3-4 semanas]
Fase 9: Redacción memoria + anexos                              [~3-4 semanas]
```

Camino crítico: **Fase 0 → 1 → 2 → 3** (paralelizables 1 y 2) → **4 → 5 → 6** → RAMA DE
DECISIÓN: si tiempo es suficiente, **7, 8**; siempre **9**.

---

## Fase 0 — Zona de trabajo y arquitectura de automatización
**Duración estimada**: ~3 días
**Objetivo**: dejar el repo listo y arquitectura de agente documentada.

| # | Tarea | Modo |
|---|-------|------|
| 0.1 | Crear `README.md` del repo: 2-3 líneas de propósito + link a `context.md` + link a `requirements.md` y `roadmap.md` + árbol de carpetas de `requirements.md §5`. | **[AUTO]** |
| 0.2 | Crear esqueleto de carpetas de `requirements.md §5` (vacío con `.gitkeep`). | **[AUTO]** |
| 0.3 | Validar `requirements.md` y `context.md` coherentes con el profesor (entregable de la tutoría). | **[HUMANO]** |
| 0.4 | **T-28 (borrador inicial)**: decidir y documentar la configuración de Opencode como "El Agente": `_artefactos/ia/config_opencode.md` + esqueleto de las 4 skills (Ataque, Detección, Agregación, Orquestación) con objetivo, tools, hard limits y formato E/S de cada una. | **[MIXTO]** |
| 0.5 | Clonar Atomic Red Team en `Soporte/Ataques/atomic-red-team/` (sin tests todavía). | **[AUTO]** |
| 0.6 | **T-27 (arranque)**: crear `Diario.md` con la primera entrada. | **[HUMANO]** |

**DoD Fase 0**:
- Repo con `README.md`, `context.md`, `requirements.md`, `roadmap.md` y esqueleto vacío.
- Atomic Red Team clonado localmente (al menos `atomics/` disponible).
- 4 skills borrador en `_artefactos/ia/skills/` + `config_opencode.md` (T-28 borrador).
- `Diario.md` creado con primera entrada (T-27 arranque).
- Hito de tutor: pasarle los 3 docs de planificación.

---

## Fase 1 — Flujo F-01: Corpus MITRE
**Duración estimada**: ~5 días
**Objetivo**: lista human-legible de técnicas host-eligible, priorizada por R/E/S, lista
para seleccionar las 5 técnicas piloto.

| # | Tarea | Modo |
|---|-------|------|
| 1.1 | **T-01**: descargar `enterprise-attack-v19.1.json` (STIX bundle de MITRE). | **[AUTO]** |
| 1.2 | **T-02**: implementar `_artefactos/scripts/extraer_tecnicas_host.py` a partir del script del profesor (`getMitre_new_versions.py`), cambiando scraping web por parseo del JSON/STIX y aplicando filtro inverso R-03. | **[AUTO]** |
| 1.3 | Tests unitarios sobre 5 técnicas conocidas (T1486 ransomware YES, T1046 net-scan NO, etc.). | **[AUTO]** |
| 1.4 | **T-03**: generar `Hojas/corpus_host.csv` + `Hojas/lista_tecnicas_validas.md` + `Hojas/Mapeos.xlsx` pestaña C. | **[AUTO]** |
| 1.5 | Validar la lista: ¿Cubre las 14 tácticas? ¿El ranking R/E/S tiene sentido? ¿Faltan técnicas ransomware clave (T1486, T1490, T1567, etc.)? | **[HUMANO]** |

**DoD Fase 1**:
- `Hojas/corpus_host.csv` con `host_eligible=YES` para al menos 150 técnicas.
- `Hojas/lista_tecnicas_validas.md` ordenada por `priority desc`.
- Script reproducible y commiteado.

---

## Fase 2 — Flujo F-02: Laboratorio Wazuh + automatización de VMs
**Duración estimada**: ~10 días (paralelizable con Fase 1 en lo humano)

| # | Tarea | Modo |
|---|-------|------|
| 2.1 | **T-04**: descargar VMs del profesor en `ait08.us.es/MVs/Alumnos/` y crearlas en VMWare Workstation local con red host-only. Snapshot `clean_pre_ata`. | **[HUMANO]** |
| 2.2 | **T-05**: instalar Wazuh server (manager + indexer + dashboard) en una VM. Dashboard accesible. SSH del agente verificado. | **[MIXTO]** |
| 2.3 | **T-06**: instalar víctima Windows + Sysmon + Wazuh agent; víctima Ubuntu + auditd + Wazuh agent. Verificar que ambos agentes aparecen como `Active` en el manager. | **[MIXTO]** |
| 2.4 | **T-25**: configurar llaves SSH ed25519 desde el host Opencode a las 4 VMs; `ssh_config` con aliases `tfg-wazuh`, `tfg-victim-win`, `tfg-victim-linux`, `tfg-attacker`. | **[MIXTO]** |
| 2.5 | **T-24**: registrar las VMs y validar control vía `vmrun` desde PowerShell. Documentar `vmrun_config.md`. | **[MIXTO]** |
| 2.6 | **T-07**: configurar `ossec.conf` y `local_rules.xml` en modo detección-only (active-response deshabilitado). | **[AUTO]** |
| 2.7 | **T-08**: definir RuleSets `WZ-RS1..WZ-RS4` (default / +sysmon / +custom / +sigma). | **[AUTO]** |
| 2.8 | **T-09**: grabar baseline legítimo 4h Windows + 4h Linux; generar `ruleids_legitimos.csv`. | **[AUTO]** (largo) |
| 2.9 | Revisar baseline: ¿hay `rule.id` raros? ¿El ruido es manejable? | **[HUMANO]** |
| 2.10 | **T-21 (smoke test)**: lanzar el sampler de rendimiento sin ataque para verificar que captura CPU/memoria/I/O del agente y del indexer correctamente. | **[AUTO]** |

**DoD Fase 2**:
- 4 VMs arrancadas, sshable sin password, agentes Active en Wazuh dashboard.
- El agente Opencode puede `vmrun revertToSnapshot <vm> clean_pre_ata` y ssh a las 4 VMs.
- Wazuh en modo detección-only verificado con un ataque de prueba.
- `Dataset/Legitimo/{Windows,Linux}/ruleids_legitimos.csv` presente.

---

## Fase 3 — 5 técnicas piloto end-to-end (primera cierre Wazuh)
**Duración estimada**: ~15 días
**Objetivo**: completar el flujo F-03 → F-04 → F-05 sobre 5 técnicas piloto R/E/S
prioritarias sirviendo para refinar T-23 y validar el orquestador T-26 (en modo
semi-manual todavía).

| # | Tarea | Modo |
|---|-------|------|
| 3.0 | **T-23 (borrador inicial)**: redactar `criterios_etiquetado.md` versión 0.1 con heurísticas básicas a partir de etiquetar a mano la 1ª técnica piloto. Sin él no se puede invocar T-15(agente) y por tanto no se cierra ningún ataque. | **[HUMANO]** |
| 3.1 | **T-10 (subset)**: elegir 5 técnicas piloto. Propuesta orientativa: <br>· **T1486** Ransomware (Data Encrypted for Impact) Windows <br>· **T1490** Ransomware (Inhibit System Recovery) Windows <br>· **T1567.002** Exfiltración (Exfil Over FTP) Linux <br>· **T1485** Sabotaje (Data Destruction) Linux <br>· **T1059.001** Execution (PowerShell) Windows (de apoyo) | **[MIXTO]** |
| 3.2 | **T-11** por cada una: scaffolding Atomic Red Team + README + screenshots. | **[MIXTO]** |
| 3.3 | **T-21** primer uso: sampler de rendimiento probado. | **[AUTO]** |
| 3.4 | **T-12** + **T-13** + **T-14** iteración por cada RuleSet WZ-RS1..RS4 y por cada técnica. | **[AUTO]** |
| 3.5 | **T-15** modo piloto: el agente etiqueta con el borrador T-23 0.1 y el alumno **audita TODO** (es la 1ª vez). Las discrepancias alimentan el T-23 definitivo de Fase 4. | **[MIXTO]** |
| 3.6 | **T-16** parcial: `Hojas/Detecciones.xlsx` con 5 filas (proto de la tabla ataques). | **[AUTO]** |
| 3.7 | **T-17**: `Mapeos.xlsx` pestañas A, B, D (la C ya de Fase 1). | **[AUTO]** |
| 3.8 | **T-18**: portar `tablas_sqlite.sql` (`tablas.sql`→SQLite) + scripts de transformación. | **[AUTO]** |
| 3.9 | Cortar y revisar: ¿el flujo es reproducible? ¿Qué automatizar más? | **[HUMANO]** |

**DoD Fase 3**:
- 5 ataques con `ATANNN` asignado, artefactos reproducibles, snapshots tomados.
- 4 RuleSets × 5 ataques × 5 artefactos CSV (`{total, TP-auto, AutoTagged, Audited, Perf}`)
  generados.
- `Hojas/Detecciones.xlsx` y `Hojas/Mapeos.xlsx` con datos reales (proto tabla Ataques).
- `BBDD/wazuh.db` cargada con las 5 alertas_agregadas.
- Bitácora `Bitacora/ATA001..005.json` completa.
- `criterios_etiquetado.md` v0.1 presente (se refinirá en Fase 4).

---

## Fase 4 — Evaluación y ajuste: refinar "El Agente" y criterios de etiquetado
**Duración estimada**: ~5 días
**Objetivo**: cerrar la infraestructura de automatización para que la Fase 5 sea escalar
con fricción mínima.

| # | Tarea | Modo |
|---|-------|------|
| 4.1 | **T-23 (definitivo)**: refinar `criterios_etiquetado.md` a partir de las discrepancias detectadas en Fase 3 (niveles, decoders, procesos legítimos, similitud semántica técnica↔rule.description). | **[HUMANO]** |
| 4.2 | **T-26**: implementar `_artefactos/orquestador/orquestador.py` + `config.yaml` con todas las tools (ataque_run, wazuh_extract, tp_fp_filter, build_detecciones, bitacora, ata_index_update). | **[AUTO]** |
| 4.3 | Smoke test: `ataque_run("ATA005")` completo sin intervención. | **[AUTO]** |
| 4.4 | Revisar **aciertos del etiquetado automático** sobre las 5 piloto con el criterio definitivo: ¿≥80%? Si no, volver a 4.1. | **[HUMANO]** |
| 4.5 | **T-28 (refinamiento)**: revisar las 4 skills con la experiencia del piloto, endurecer instrucciones, completar `prompts/`, validar `config_opencode.md`. | **[MIXTO]** |

**DoD Fase 4**:
- Orquestador commiteado y funcional: `ataque_run("ATA005")` corre solo.
- `criterios_etiquetado.md` definitivo; ≥80% concordancia contra auditoría humana en piloto.
- 4 skills refinadas tras la experiencia del piloto (T-28 definitivo): instrucciones
  endurecidas, `prompts/` completados, `config_opencode.md` validado.

---

## Fase 5 — Escalar a 30 técnicas (corpus completo Wazuh)
**Duración estimada**: ~6-8 semanas
**Objetivo**: cubrir 30 técnicas de las 14 tácticas, priorizando R/E/S, dejando que el
agente corra el ciclo completo y el alumno audite + screenshots.

| # | Tarea | Modo |
|---|-------|------|
| 5.1 | **T-10 (resto)**: completar selección de las 25 técnicas restantes (1+ por táctica, decisión mixta alumno/agente). | **[MIXTO]** |
| 5.2 | Para cada técnica nueva: ciclo **T-11 → T-12 → T-13 → T-14 → T-15(agente)→ T-15(auditoría alumno) → T-16(regenera Detecciones) → T-19**. | **[AUTO]** + **[HUMANO]** (auditar etiquetas + screenshots) |
| 5.3 | Por semana: revisión del alumno de los `Audited.csv` y capturas pendientes (lotes de 5-10 ataques). | **[HUMANO]** |
| 5.4 | Cada 5 ataques cerrados: verificar `Hojas/Detecciones.xlsx` coherente (T-16). | **[AUTO]** |
| 5.5 | Snapshot del progreso al tutor. | **[HUMANO]** |

**DoD Fase 5**:
- 30 ataques `ATANNN` cerrados en `ATA_index.csv` con `estado=cerrado`.
- 30 × 4 RuleSets × 5 artefactos CSV por ataque (4 de F-04 + Perf de T-21).
- `Estudio-Wazuh/completamenteDetectados/` poblado; primer balance de capacidad de
  detección de Wazuh por táctica/técnica.
- Sección de Resultados en memoria lista para redactarse.

---

## Fase 6 — Experimentos de robustez y rendimiento
**Duración estimada**: ~1 semana
**Objetivo**: cumplir T-20 (robustez del HIDS) y T-21/T-22 (precio de la detección).

> **Aclaración de la captura vs análisis del rendimiento**: el **muestreo** de CPU,
> memoria, I/O del agente y del indexer (T-21) **arranca con un smoke test en Fase 2**
> (paso 2.10) y luego **corre de forma rutinaria en cada ataque de Fases 3 y 5** (paso
> 3.3 "primer uso" y dentro del ciclo del paso 5.2). La salida
> `Dataset/Ataques/Resultados/Wazuh/Perf/ATA<NNN>.csv` ya está completa al cerrar
> Fase 5. La Fase 6 **solo consolida y analiza** todos esos datos junto con los
> experimentos de robustez, y produce el cálculo de η y las gráficas.

| # | Tarea | Modo |
|---|-------|------|
| 6.1 | **T-20**: 3 ataques representativos × 4 cargas (idle, ofimática, compilar, estrés procesos). Generar `VerificacionWazuh/Resumen.csv` con `rule.id distintos` y `alertas totales` por carga. | **[AUTO]** |
| 6.2 | **T-21** consolidación: ya hay `Perf/ATA<NNN>.csv` por cada ataque; verificar que están todos y consolidar a una tabla maestra. | **[AUTO]** |
| 6.3 | **T-22**: tabla resumen de rendimiento por HIDS (η por ataque y media por táctica). | **[AUTO]** |
| 6.4 | Gráficas en `Estudio-Wazuh/Grafica*.jpg` (matplotlib): % detección por táctica, η por táctica, CPU/memoria media durante ataques, alertas por carga. | **[AUTO]** |
| 6.5 | Interpretación de resultados: ¿Wazuh pierde alertas bajo carga? ¿hay un trade-off detectable entre sensibilidad y rendimiento? | **[HUMANO]** |

**DoD Fase 6**:
- `VerificacionWazuh/Resumen.csv` completo.
- Tabla η en `Hojas/Detecciones.xlsx` bloque G.
- Gráficas generadas.
- Interpretación escrita (entradas en `Diario.md`).

---

## Fase 7 — Replicación para Velociraptor (segundo HIDS)
**Duración estimada**: ~3-4 semanas
**Objetivo**: re-ejecutar el flujo del corpus 30 TEC contra Velociraptor, reutilizando
el mismo banco de ataques (sin reimplementar T-11). Se definirá en detalle al iniciarla.

Líneas maestras:
- Reutilizar artefactos de ataque ya creados (T-11 heredado).
- Instalar Velociraptor server + agent (análogo T-05/T-06).
- Implementar `Soporte/Velociraptor/Scripts/analisis_velociraptor.py` (análogo a T-13
  pero consumiendo artifacts+results en vez de indexer).
- Reusar baseline legítimo con Velociraptor agent.
- Sistema de etiquetas equivalente con `artifact.id+result` en vez de `rule.id`.
- Bloque F en `Hojas/Detecciones.xlsx` para Velociraptor (análogo al bloque E Wazuh).
- `Estudio-Velociraptor/` carpetas ejecutivas.
- **DoD Fase 7**: tabla de resultados paralela para Velociraptor; balance comparativo
  Wazuh vs Velociraptor en la memoria.

---

## Fase 8 — Tercer HIDS + apartado extra Snort
**Duración estimada**: ~3-4 semanas
**Objetivo**: elegir tercer HIDS (OSSEC/Sagan/Splunk/Samhain) por relevancia, ejecutar
el mismo flujo; opcionalmente probar el extra de Snort NIDS con conversión logs→pcap
(`ait-aecid`). Se definirá en detalle al iniciarla.

Líneas maestras:
- Decisión del HIDS: criterios (comunidad, reglas MITRE, integración con endpoint,
  complementariedad con Wazuh/Velociraptor).
- Flujo idéntico a Fase 7 con el tercer HIDS.
- Extra Snort (secundario, sin profundidad): usar `ait-aecid` u otro conversor para
  logs→pcap y re-ejecutar Snort del repo hermano de red contra esos pcaps.
- **DoD Fase 8**: bloque G de `Hojas/Detecciones.xlsx` poblado; comparativa triple
  (Wazuh/Velociraptor/Tercero); apartado Snort documentado (si alcanzado).

---

## Fase 9 — Redacción de memoria y anexos
**Duración estimada**: ~3-4 semanas
**Objetivo**: producir la memoria siguiendo el esqueleto imitado de los TFGs hermanos
(§6.10 de `context.md`).

> **Declaración abierta del uso de IA**: la memoria dedicará un apartado en Estado del
> Arte / Metodología a describir **sin ocultismo** el uso del agente Opencode como
> infraestructura de automatización. Se explicará qué tareas automatizó (F-03, F-04,
> F-05 vía orquestador T-26), qué tareas etiquetó (T-15 agente), qué tareas mantuvo
> el alumno (T-15 auditoría, validación visual de T-11, decisiones), y los límites
> (hard limits de §3.A.3 de `requirements.md`). Las skills/prompts viven en
> `_artefactos/ia/` y se referencian en un anexo técnico.

| # | Tarea | Modo |
|---|-------|------|
| 9.1 | Índices y portada; agradecimientos; resumen/abstract; notación. | **[HUMANO]** |
| 9.2 | Cap. 1 Introducción (Motivación + Objetivos + Estado del Arte + Metodología
  4 fases). | **[MIXTO]** (agente redacta borradores) |
| 9.3 | Cap. 2 Base teórica (MITRE + Wazuh + Velociraptor + Sysmon + OSSEC...). | **[MIXTO]** |
| 9.4 | Cap. 3 Realización de ataques locales por táctica (patrón Meléndez: Víctima /
  Atacante / Ejecución / Validación). | **[MIXTO]** |
| 9.5 | Cap. 4 Análisis de detecciones por táctica/técnica. | **[MIXTO]** |
| 9.6 | Cap. 5 Resultados (Tabla Ataques, Mapeos, BBDD, Criterios, HIDS-Balance). | **[MIXTO]** |
| 9.7 | Cap. 6 Conclusiones y Líneas de continuación. | **[HUMANO]** |
| 9.8 | Anexo A Instalación (Wazuh manager/agent, Velociraptor, Sysmon). | **[MIXTO]** |
| 9.9 | Anexo B Validación por cada ATANNN (evidencia log↔ataque). | **[MIXTO]** |
| 9.10 | Anexo C Repositorio GitHub. | **[AUTO]** |
| 9.11 | Anexo D BBDD SQLite. | **[AUTO]** |
| 9.12 | Anexo E Tabla Resumen de Ataques (30 filas). | **[AUTO]** |
| 9.13 | Anexo F Dificultades encontradas (ruido Sysmon, lag indexer, OPSEC, FP por
  procesos legítimos...). | **[HUMANO]** |
| 9.14 | Revisión final y entrega. | **[HUMANO]** |

**DoD Fase 9**: memoria entregada en el formato y plazos de la ETSI.

---

## Matriz fases × flujos/tareas (resumen)

| Fase | Flujos cubiertos | Tareas principales |
|------|------------------|--------------------|
| 0 | — | readme + esqueleto + atomic clone + T-28 (borrador) + T-27 (arranque) |
| 1 | F-01 | T-01, T-02, T-03 |
| 2 | F-02 | T-04, T-05, T-06, T-07, T-08, T-09, T-24, T-25 |
| 3 | F-03, F-04, F-05 (subset 5 ataques) | T-23 (borrador), T-10, T-11 (5x), T-12, T-13, T-14, T-15, T-16, T-17, T-18, T-21 |
| 4 | F-06 | T-23 (definitivo), T-26, T-28 (refinamiento) |
| 5 | F-03, F-04, F-05 (escalar) | T-10 (resto), iteración completa ×25 |
| 6 | F-05 (robustez/perf) | T-20, T-21, T-22 |
| 7 | F-03..F-05 con Velociraptor | análogo a 3+5 con Velociraptor |
| 8 | F-03..F-05 con Tercer HIDS + Snort extra | análogo + extra |
| 9 | — | redacción memoria |

---

## Hitos de tutor previstos

| Hito | Tras fase | Qué se enseña al profesor |
|------|-----------|---------------------------|
| H0 | Fase 0 | Planificación (context/requirements/roadmap) + setup inicial de "El Agente" (skills borrador + clon Atomic). |
| H1 | Fase 1 | Lista de técnicas válidas + criterio de filtro inverso. |
| H2 | Fase 2 | Laboratorio Wazuh funcionando + baseline legítimo. |
| H3 | Fase 3 | 5 técnicas piloto cerradas con detección Wazuh (proto tabla Ataques). |
| H4 | Fase 5 | Tabla Ataques con 30 técnicas + balance Wazuh. |
| H5 | Fase 6 | Robustez + rendimiento (η). |
| H6 | Fase 8 | Resultados comparativos triple HIDS. |
| H7 | Fase 9 | Memoria lista para entregar. |

---

## Ritmo de trabajo agente vs humano

| Tipo de sesión | Qué pasa | Quién | Carga aprox. |
|---|---|---|---|
| Automatización pura (F-04, F-05) por ataque | Agente | alto tokens inicial; luego scripts deterministicos (sin LLM) |
| Decisión de selección de técnicas (T-10) | Mixto | bajo tokens (propuesta agente + ratificación alumno) |
| Auditoría de etiquetas (T-15 alumno) | Humano | 0 tokens (lee CSV) |
| Generación de scaffolding (T-11) | Agente | medio tokens por ataque |
| Snapshots/SSH/smoketest | Agente | sin LLM (vía vmrun/ssh) |
| Baseline legítimo (T-09) | Agente en background | sin LLM (script de actividad) |
| Redacción memoria (Fase 9) | Mixto | alto tokens (borrador LLM) |
| **Diario.md (T-27)** | **Humano** | **0 tokens** — el alumno anota por sesión; es insumo del Anexo F Dificultades. |

**Ahorro de tokens**: F-04 puro (query indexer + filtrado auto) y F-05 puro
(build_detecciones, tablas SQL, gráficas) son scripts puros en `orquestador.py` que el
agente limita a invocar y validar su salida. El LLM solo se activa en proposición
(etiquetado semántico T-15), selección (T-10) y generación de texto (T-11 scaffolding,
Fase 9 borradores).

---

## Riesgos del roadmap y mitigaciones

| Riesgo | Fase | Mitigación |
|--------|------|------------|
| MITRE v19.1 STIX cambia de esquema respecto al script del profesor | 1 | El script T-02 se diseña a partir de la spec STIX actual y se re-valida con tests. |
| El atacante Atomic Red Team no cubre una técnica del corpus | 3 | Anotar `custom_attack=true` y crear script propio en T-11. |
| vmrun falla con VMs con disco dinámico o snapshots obsoletos | 2 | Snapshot `clean_pre_ata` solo en estado "fresco"; nunca hacer write durante revert. |
| Wazuh indexer no indexa a tiempo tras ataque | 3,5 | Sleep 60+300s (patrón `PA.sh:1-76`); el agente hace query de sanity antes de avanzar. |
| Etiquetado agente <80% acierto en piloto | 4 | Refinar T-23 (umbrales y heurísticas); si persiste, el agente solo agrupa y el alumno etiqueta (modelo más conservador). |
| El coste en tokens escala mal con 30 ataques | 5 | T-13/T-14/T-16 sin LLM (puro script); LLM solo en T-10/T-15/T-11. |
| Fase 7-8 (Velociraptor/tercero) consumen el tiempo previsto para memoria | 7,8 | Wazuh-first garantizado: si calendario aprieta, priorizar Fase 9 y dejar 7-8 como apartado breve o anexo. |
| Las skills del agente quedan pobremente definidas y el orquestador se vuelve caótico | 0,4,5 | T-28 (borrador en Fase 0, refinado en Fase 4); cada skill tiene objetivo, tools, hard limits y E/S documentados. |

---

## Fuera de alcance explícito (recordatorio)

- Comparativa re-ejecutando con los IDS del repo hermano Snort-FG-PA (solo cualitativa en
  estado del arte).
- ICS, Mobile, Cloud (R-01 Enterprise only).
- Modo bloqueo del HIDS (R-06).
- No crear artefactos de ataque que supongan breaking changes respecto a la línea de
  investigación del tutor (mantener naming ATANNN, η, LV1/LV2, Principal/Colateral).

---

## Punto de control actual

**Próxima acción**: ejecutar **Fase 0** completa (esqueleto de repo, README, clon Atomic
Red Team, borrador de las 4 skills de "El Agente" en `_artefactos/ia/`, arranque del
`Diario.md`) y disparar **Fase 1** (F-01: descargar STIX v19.1 y construir el script de
filtro inverso). Basta confirmación del alumno para arrancar.