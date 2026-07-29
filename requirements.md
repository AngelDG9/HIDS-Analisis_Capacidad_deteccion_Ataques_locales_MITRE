# requirements.md — Requisitos, tareas clave y flujos de trabajo del TFG

> Documento derivado de `context.md`. Define **qué** hay que construir/ejecutar (tareas
> clave) y **cómo** se encadenan (flujos de trabajo), con criterios de aceptación. Es la
> base para `roadmap.md`. Cualquier decisión técnica nueva se añade aquí antes de
> implementarla.
>
> **Decisión clave (sesión de diseño)**: el TFG se ejecuta bajo una arquitectura de
> **agente IA como orquestador ("El Agente")**. El agente Opencode controla VMs vía
> `vmrun`, lanza ataques Atomic Red Team por SSH, captura detecciones del indexer, y
> etiqueta TP/FP de forma automática; el alumno **añadirá, auditará y validará** el
> trabajo del agente. Ver §3.A para el detalle de automatización.

---

## 0. Convenciones de este documento

- **R-NN** — Requisito numerado (algo que debe cumplirse).
- **T-NN** — Tarea clave numerada (una unidad de trabajo discretizada).
- **F-NN** — Flujo de trabajo (encadenamiento de tareas, con entradas/salidas).
- **Crit-Aceptación** — Criterio objetivo para dar por válido un requisito.
- Las referencias a archivos usan `ruta:linea` para navegar rápido.
- **[AUTO]** — la tarea la ejecuta el agente IA (Opencode) sin intervención humana.
- **[HUMANO]** — requiere acción manual del alumno (GUI, capturas, decisiones finales).
- **[MIXTO]** — el agente propone/ejecuta y el humano audita/valida.

---

## 1. Alcance y obstáculos no funcionales (R-01 a R-14)

| ID | Requisito | Criterio de aceptación |
|----|-----------|------------------------|
| R-01 | El TFG se ejecuta sobre **MITRE ATT&CK Enterprise vigente (v19.1 abril 2026)**, sin descartar la posibilidad de re-ejecutar sobre versiones anteriores para comparar. | El `Mapeos.xlsx` indica en cabecera la versión exacta y fecha. |
| R-02 | El corpus de técnicas se obtiene **mediante un script reproducible** (no a mano), adaptación del script del profesor (`TechniquesTacticsMitre/main_Mitre.py`). | Ejecutar el script regenera la lista de técnicas válidas; hay commit en git con el script y un `README.md` que lo documenta. |
| R-03 | **Filtro inverso** al del profesor: el corpus solo incluye técnicas/subtécnicas con telemetría **endpoint/host** aprovechable. Se **excluyen** las técnicas cuyo único Data Component sea `Network Connection Creation` (DC0078), `Network Traffic Content` (DC0082) o `Network Traffic Flow` (DC0085); se **descartan del todo** las basadas en `Network Share Access` (DC0102), `Internet Scan: Response Content` (DC0104) y `Internet Scan: Response Metadata` (DC0106). | El CSV de salida tiene columna `host_eligible` con valor `YES` solo cuando existe al menos un Data Component endpoint; hay tests unitarios que lo verifican sobre 5 técnicas conocidas (p. ej. T1486 Ransomware = YES, T1046 net-scan = NO). |
| R-04 | **Priorización** de Ransomware / Exfiltración / Sabotaje según `guia_profesor.txt:37-46`. | La lista está ordenada y existe una columna `priority` con valores `R/E/S/other` y un ranking. |
| R-05 | **Primer HIDS exclusivo**: Wazuh. No se simultanea con Velociraptor hasta cerrar el cuerpo de resultados Wazuh. | La estructura de carpetas y los CSV van bajo `Estudio-Wazuh/` y `Dataset/Ataques/Resultados/Wazuh/`. No existe `Estudio-Velociraptor/` mientras Wazuh no esté consolidado. |
| R-06 | **Modo detección-only**: el HIDS nunca bloquea. | La configuración de Wazuh (`Soporte/Wazuh/Configuracion/`) desactiva active response; se documenta en el README de esa carpeta. |
| R-07 | **Identificador único por ataque**: `ATANNN` secuencial, citado en logs, reglas, CSV, Excel y memoria. | Existe un registro maestro `Hojas/ATA_index.csv` con `ata_id, tactica, tecnica, subtecnica, descripcion, artefacto`. |
| R-08 | **Reproducibilidad por ataque**: cada ataque tiene un artefacto ejecutable + README. | `Dataset/Ataques/Comandos/T<id>-<desc>/` contiene script + `README.md` con pasos exactos, SO víctima y comando de lanzamiento. |
| R-09 | **Baseline legítimo del endpoint**: grabación de N horas de actividad legítima en VM limpia con Sysmon + Wazuh agent. | Existe `Dataset/Legitimo/` con los logs y un CSV `ruleids_legitimos.csv` con los `rule.id` que aparecen en idle. |
| R-10 | **Métrica de rendimiento heredada**: η = √(CD·(1−FP)). | El script de resultados calcula η por HIDS y por ataque, y se reporta en una tabla de "`Hojas/Detecciones.xlsx`". |
| R-11 | **Control de VMs por el agente IA vía `vmrun`**: las VMs deben estar registradas en VMWare Workstation local y el agente debe poder snapshot/arrancar/parar/revertir sin prompts. | `vmrun.exe` en PATH y `Soporte/Laboratorio/vmrun_config.md` documenta nombres de VM y rutas `.vmx`. El agente ejecuta `vmrun snapshot ...` y `vmrun revertToSnapshot ...` con éxito en una VM de prueba. |
| R-12 | **Orquestador de ataques fijado: Atomic Red Team**. Tests atómicos en PowerShell/bash invocables por técnica MITRE. | `Soporte/Ataques/atomic-red-team/` clonado y `Invoke-AtomicTest T<id>` funciona en Windows; `atomic-red-team` Linux runner funciona en Ubuntu. |
| R-13 | **Acceso SSH sin password del agente** a víctima y atacante (llaves configuradas). | `ssh victim@<ip> echo ok` y `ssh attacker@<ip> echo ok` funcionan sin prompt desde la máquina donde corre Opencode. |
| R-14 | **Etiquetado TP/FP por el agente, auditoría humana**: el agente propone etiqueta TP / FP No Relacionado / FP Eventos de Sistema por cada `rule.id`; el alumno audita posteriormente. | Existe `Soporte/Wazuh/Scripts/criterios_etiquetado.md` con las reglas heurísticas del agente; para cada ataque se generan `ATA<NNN>-AutoTagged.csv` (agente) y `ATA<NNN>-Audited.csv` (alumno). η final se calcula solo sobre `Audited`. |

---

## 2. Tareas clave (T-01 a T-28)

> Agrupadas por bloques. Cada tarea indica entrada, salida y dependencias.

### Bloque A — Corpus MITRE (lista de técnicas válidas)

#### T-01 — Descargar la matriz MITRE Enterprise v19.1 en STIX/JSON
- **Entrada**: URL oficial `https://github.com/mitre/cti` (STIX bundles) o
  `https://attack.mitre.org/resources/attack-data/` (enterprise-attack.json).
- **Salida**: `_artefactos/mitre/enterprise-attack-v19.1.json` (o `.stix`).
- **Por qué**: el script del profesor raspa la web a base de `requests + BeautifulSoup`
  con sleep de 3s por página (~30 min por ejecución, frágil ante cambios HTML). Trabajar
  sobre el bundle STIX oficial es más estable y permite **identificar Data Components por
  ID (DC0078, DC0082, etc.)** sin parsear HTML. **Mantiene compatibilidad**: el script del
  profesor se puede reutilizar como *fallback* o para validación cruzada.
- **Dependencias**: —.

#### T-02 — Extender el script del profesor con inventario completo de Data Components
- **Entrada**: datos de T-01 + `0MITRE-Tecnicas_detectables_por_Red.txt` (mapeo DC↔nombre).
- **Salida**: script `_artefactos/scripts/extraer_tecnicas_host.py` que produce
  `Hojas/corpus_host.csv` con columnas:
  `technique_id, name, tactic_ids, subtechnique_ids, dcs_endpoint, dcs_network, dcs_excluded, host_eligible, ransomware_relevance, exfil_relevance, sabotage_relevance, priority`.
- **Por qué**: el script actual solo marca `Yes/No` para 6 DCs. Necesitamos la **lista
  completa de DCs** por técnica (Process, File, Command, Windows Registry, Driver, WMI,
  Sysmon, etc.) para justificar elegibilidad host y para enriquecer la tabla Mapeos.
- **Dependencias**: T-01.

#### T-03 — Generar lista human-legible priorizada
- **Entrada**: `Hojas/corpus_host.csv`.
- **Salida**: `Hojas/lista_tecnicas_validas.md` (tabla markdown ordenada por prioridad
  R/E/S) + `Hojas/Mapeos.xlsx` (pestaña C "Tabla MITRE completa") con flags
  `Implementada · Detectable por Host · Sólo Detectable por Host · Detectable por patrones
  (host) · Mecanismo de detección · DCs`.
- **Dependencias**: T-02.

### Bloque B — Laboratorio (VMs + HIDS)

#### T-04 — Definir topología de VMs
- **Entrada**: VMs del profesor en `ait08.us.es/MVs/Alumnos/`, restricción VMWare
  Workstation Pro/Player (R-11).
- **Salida**: `Soporte/Laboratorio/topologia.png` + `Soporte/Laboratorio/README.md`
  con: manager Wazuh, VM víctima Windows (Windows 10/11 + Sysmon), VM víctima Linux
  (Ubuntu 22.04+ + auditd), VM atacante (Kali Linux con nmap, hydra, metasploit,
  mimikatz, etc.), red host-only aislada.
- **Topología fijada** (4 VMs en VMware Workstation Pro/Player con red host-only):
  - **Wazuh server** — manager + indexer + dashboard.
  - **victim_win** — Windows 10/11 + Sysmon + Wazuh agent.
  - **victim_linux** — Ubuntu 22.04+ + auditd + Wazuh agent.
  - **attacker** — **Kali Linux** (herramientas preinstaladas: nmap, hydra, metasploit,
    mimikatz, etc.). Reutilizar el arsenal de los TFGs hermanos.
- **Por qué**: el repo hermano usa topología `cliente → host IDS → log compartido`
  (`fg.sh:10`). En host se transforma en `atacante → víctima con Wazuh agent → indexer`.

#### T-05 — Levantar Wazuh manager + indexer + dashboard
- **Salida**: VM con Wazuh server accesible por SSH y dashboard por https.
- **Salida adicional**: `Soporte/Wazuh/Configuracion/wazuh-server-install.md` (Anexo
  Instalación) — documentación reproducible comando a comando.
- **Dependencias**: T-04.

#### T-06 — Levantar VMs víctima y instalar agent + Sysmon (Windows) / auditd (Linux)
- **Salida**: VM Windows con Sysmon + Wazuh agent, VM Ubuntu con auditd + Wazuh agent,
  ambos reportando al manager.
- **Salida adicional**: `Soporte/Wazuh/Configuracion/{wazuh-agent-windows,wazuh-agent-linux,sysmon-config}.md`.
- **Dependencias**: T-05.

#### T-07 — Configurar Wazuh en modo detección-only
- **Salida**: `Soporte/Wazuh/Configuracion/ossec.conf` y `local_rules.xml` en el manager
  con `<active-response>` deshabilitado y reglas extra de Sysmon/auditd cargadas.
- **Crit-Aceptación**: tras un ataque de prueba, el ataque se ejecuta completo aunque
  Wazuh genere alertas.
- **Dependencias**: T-06.

#### T-08 — Definir RuleSets análogos a RS1–RS4
- **Entrada**: doctrina del repo Snort-FG-PA que define 4 RuleSets crecientes (Talos
  Community → Talos Registered → ETOpen → ETOpen optimizado).
- **Salida**: en Wazuh, los 4 RuleSets serán:
  - **WZ-RS1**: reglas por defecto de Wazuh.
  - **WZ-RS2**: + reglas de Sysmon mapeadas a MITRE.
  - **WZ-RS3**: + `local_rules.xml` con reglas custom para cada técnica del corpus.
  - **WZ-RS4**: + integración de feed externo (p. ej. Sigma rules convertidas a Wazuh
    vía `sigmaossec` o `wazuh-rulembedded`).
- **Dependencias**: T-07.

### Bloque C — Baseline legítimo

#### T-09 — Grabar baseline legítimo del endpoint (Fase I del TP/FP)
- **Entrada**: VM víctima limpia.
- **Acción**: ejecutar batería de actividad legítima (navegación, ofimática, compilación,
  scripts internos) durante **mínimo 4 h** en Windows y 4 h en Linux (equivalente local
  al `Dataset/Legítimo/pcaps/` del repo hermano y al dataset SWaT de Meléndez).
- **Salida**: `Dataset/Legitimo/{Windows,Linux}/` con `alerts.json` y `ruleids_legitimos.csv`.
- **Dependencias**: T-07.

### Bloque D — Ataques (corpus)

#### T-10 — Elegir 1 técnica/subtécnica por táctica (iteración 1)
- **Entrada**: `Hojas/lista_tecnicas_validas.md` (T-03).
- **Criterio**: cubrir las **14 tácticas Enterprise** con al menos 1 técnica cada una,
  priorizando R/E/S. Empieza con 5 técnicas piloto (`notas_reunion.txt:124`) y luego
  crecer hasta el objetivo "30 TEC".
- **Salida**: `Hojas/ATA_index.csv` con las técnicas seleccionadas y su `ata_id`.
- **Dependencias**: T-03.

#### T-11 — Implementar cada ataque como artefacto reproducible **[MIXTO]**
- **Por cada ataque**: crear `Dataset/Ataques/Comandos/T<id>-<desc>_<fuente>/` con:
  - `attack.{ps1,sh}` o invocación de `Invoke-AtomicTest T<id>` / atomic-red-team runner.
  - `README.md` con "Equipo Víctima / Atacante / Ejecución / Validación" (patrón
    Meléndez).
  - Evidencia de ejecución (`Soporte/Ataques/capturas/T<id>/` con capturas).
- **Orquestador fijado (R-12)**: **Atomic Red Team** (`https://github.com/redcanaryco/atomic-red-team`).
  Tests atómicos aislados por técnica en PS1/bash/YAML. Ligerísimo, scripteable por SSH,
  ejecutable desde el agente. Para técnicas no cubiertas por Atomic, se crea un script
  custom equivalente mapeado a la técnica.
- **Diseño de cada ataque**: además de Atomic Red Team, **consultar el campo "Procedure
  Examples" de la técnica en MITRE ATT&CK** — ahí MITRE lista herramientas reales
  (WannaCry para T1486, Mimikatz para T1003.001, etc.) que sirven de inspiración
  realista. La pila "Atomic Red Team + Procedure Examples MITRE" cubre el máximo
  posible de técnicas; si ambas fallan, script custom libre basado en la descripción
  de la técnica.
- **Automatización**: el agente genera el scaffolding del artefacto (clone del atomic
  test, README con metadata MITRE, script de invocación). El humano valida que el ataque
  corresponde a la técnica y añade screenshots.
- **Dependencias**: T-10, T-06.

#### T-12 — Ejecución doble para validación de robustez
- **Entrada**: artefacto de ataque + VM limpia + Wazuh.
- **Acción**: ejecutar el ataque **dos veces** en snapshot fresco; registrar alertas
  ambas veces. Es el patrón `fg.sh:28-32` del repo hermano.
- **Salida**: `Dataset/Ataques/Resultados/Wazuh/{CSV,Logs}/ATA<NNN>_iter{1,2}.csv`.
- **Crit-Aceptación**: si el número de alertas difiere, se marca `review=true` en el CSV
  maestro.
- **Dependencias**: T-11, T-07.

### Bloque E — Captura y normalización de detecciones

#### T-13 — Extraer alertas de Wazuh indexer por timeframe
- **Entrada**: timestamp inicial y final del ataque (equivalente local al
  `PRIMERA_LINEA=$(wc -l <log>+1)` usado por `fg.sh:10`).
- **Salida**: por cada ataque, `Dataset/Ataques/Resultados/Wazuh/CSV/ATA<NNN>.csv` con
  campos: `timestamp, rule.id, rule.level, rule.description, decoder.name, data.srcip,
  data.dstip, data.process.pid, data.process.name, data.cmd, agent.name`.
- **Implementación**: script `Soporte/Wazuh/Scripts/analisis_wazuh.py` (análogo a
  `analisis_snortv5.py:12-67`) usando la API REST del indexer (`POST
  /wazuh-alerts-*/_search`) con query por `@timestamp` range y `rule.groups`.
- **Dependencias**: T-12, T-05.

#### T-14 — Filtrado automático de FP contra baseline
- **Entrada**: `ATA<NNN>.csv` + `ruleids_legitimos.csv`.
- **Acción**: eliminar `rule.id` que aparezcan en el baseline legítimo. Es el equivalente
  exacto de `filtradoTPv4.py:5-19`, cambiando `df['SID']` por `df['rule.id']`.
- **Salida**: `ATA<NNN>TP.csv` (solo alertas supervivientes) + dos columnas extra en
  `ATA<NNN>.csv`: `tp_auto` y `fp_auto`.
- **Dependencias**: T-13, T-09.

#### T-15 — Etiquetado TP/FP residual (agente) + auditoría (alumno) **[MIXTO]**
- **Acción del agente [AUTO]**: para cada `rule.id` superviviente en `ATA<NNN>TP.csv`,
  aplicar las heurísticas de `Soporte/Wazuh/Scripts/criterios_etiquetado.md` (ver T-23) y
  producir `ATA<NNN>-AutoTagged.csv` con columnas `rule.id, etiqueta, justificacion,
  confianza`. Etiquetas: `TP` / `FP No Relacionado` / `FP Eventos de Sistema`.
- **Acción del alumno [HUMANO]**: auditar `ATA<NNN>-AutoTagged.csv`, corregir
  etiquetados con confianza baja o malos, generar `ATA<NNN>-Audited.csv` final. El alumno
  puede aceptar el 100% del etiquetado del agente o discrepar caso a caso.
- **Crit-Aceptación**: η final se calcula **exclusivamente** sobre `ATA<NNN>-Audited.csv`.
- **Dependencias**: T-14, T-23.

### Bloque F — Agregación y presentación de resultados

#### T-16 — Construir `Hojas/Detecciones.xlsx` (la "Tabla Ataques")
- **Salida**: Excel con la estructura de `context.md §6.2` (bloques A–H). Una fila por
  ataque `ATANNN`.
- **Mecanismo**: script `BBDD/Scripts/build_detecciones.py` que lee todos los CSV por
  ataque y vuelca al Excel con `openpyxl` (patrón del repo hermano).
- **Dependencias**: T-15.

#### T-17 — Construir `Hojas/Mapeos.xlsx`
- **Salida**: cuatro pestañas (A tabla Táctica×Técnica, B Táctica×Subtécnica, C MITRE
  completo con flags, D recuentos) según `context.md §6.3`.
- **Dependencias**: T-03.

#### T-18 — Construir BBDD SQLite réplica
- **Entrada**: `BBDD/SQL/tablas.sql` del repo hermano (406 líneas, HyperSQL).
- **Salida**: `BBDD/SQL/tablas_sqlite.sql` portado a SQLite con tablas `alertas_ataque_wazuh`,
  `alertas_legitimo_wazuh`, `deteccion_wazuh`, `caracterizacion_ataque`, `resumen` (sin el
  prefijo "pcaps_"). + `BBDD/Scripts/csv_comas.py` y `transformaAlertasWazuh.py` (análogos
  a `csv_comas.py`, `transformaAlertasFG.py:5-40`).
- **Dependencias**: T-16.

#### T-19 — Carpeta ejecutiva `Estudio-Wazuh/`
- **Salida**: `Estudio-Wazuh/completamenteDetectados/`, `noDetectados/`,
  `ataques_completamente_detectados_Wazuh.{csv,xlsx,txt}` (plantilla:
  `Estudio-FG/ataques_completamente_detectados_FG.csv`) y `Grafica*.jpg`.
- **Dependencias**: T-16.

#### T-20 — Experimento de robustez `VerificacionWazuh/`
- **Acción**: 3 ataques representativos ejecutados a **4 cargas del host** distintas
  (idle / ofimática / compilar / estrés de procesos) — análogo local a las 7 tasas de
  `VerificacionFG/Resumen.csv:1-4`.
- **Salida**: `VerificacionWazuh/Resumen.csv` con `rule.id distintos` y `alertas totales`
  por carga.
- **Dependencias**: T-13, T-09.

### Bloque G — Monitorización de rendimiento

#### T-21 — Script de métricas de rendimiento durante ataque+detección
- **Entrada**: VM víctima con Wazuh agent.
- **Acción**: Sampling periódico (cada 5 s) de CPU, memoria, I/O del proceso `wazuh-agent`
  y del indexer durante el intervalo [t0-15s, t1+60s] de cada ataque.
- **Salida**: `Dataset/Ataques/Resultados/Wazuh/Perf/ATA<NNN>.csv` con columnas
  `timestamp, cpu_agent, mem_agent_mb, cpu_indexer, mem_indexer_mb, events_per_sec`.
- **Justificación**: "precio de la detección" (`notas_reunion.txt:16`).
- **Cadencia**: el sampler arranca como smoke test en Fase 2 (T-21 smoke test), corre de
  forma rutinaria en cada ataque de Fases 3-5 (T-11/F-03 → T-21 inicio), y se
  **consolida y analiza** en Fase 6 junto con T-20 y T-22.
- **Dependencias**: T-06.

#### T-22 — Tabla resumen de rendimiento por HIDS
- **Salida**: tabla en `Hojas/Detecciones.xlsx` bloque G con η por ataque y por HIDS, más
  la media por táctica.
- **Métrica**: η = √(CD·(1−FP)) heredada de García Borja (Tabla 5-1) — donde CD es la
  "% detección eficaz ataques" y FP es la fracción de alertas marcadas FP.
- **Dependencias**: T-16, T-21.

### Bloque H — Automatización con IA (infraestructura del "El Agente")

#### T-23 — Documentar criterios de etiquetado automático TP/FP **[HUMANO]**
- **Salida**: `Soporte/Wazuh/Scripts/criterios_etiquetado.md` con heurísticas que el
  agente aplica por `rule.id`. Reglas tipo:
  - `rule.level >= 12` y `data.process.name` coincide con artefacto del ataque → `TP` (alta confianza).
  - `rule.level <= 3` y `decoder.name` en `{sysmon, auditd, auth}` → `FP Eventos de Sistema`.
  - `rule.id` aparece en `ruleids_legitimos.csv` con frecuencia > 0.5/h → `FP No Relacionado`.
  - Similitud semántica entre `rule.description` y `technique.name` > umbral → `TP`.
- **Progresión**: se redacta un **borrador inicial** en Fase 3 (con la experiencia de
  etiquetar a mano la 1ª técnica piloto), y un **criterio final** en Fase 4 tras auditar
  las 5 técnicas (umbral ≥80% concordancia contra auditoría humana).
- **Crit-Aceptación**: el fichero es legible por el agente; el alumno acepta que el 80%+
  de las etiquetas automáticas son correctas antes de escalar a Fase 5.
- **Dependencias**: T-09 (baseline) — un corpus de `ruleids_legitimos` es necesario para
  definir frecuencias.

#### T-24 — Configurar `vmrun` y validar control de VMs desde el agente **[MIXTO]**
- **Acción [HUMANO]**: registrar las VMs (víctima Windows, víctima Linux, atacante,
  Wazuh server) en VMWare Workstation; documentar nombres y rutas `.vmx`.
- **Acción [AUTO]**: el agente ejecuta `vmrun list`, `vmrun snapshot`,
  `vmrun revertToSnapshot`, `vmrun start`, `vmrun stop` y vuelca resultados en
  `Soporte/Laboratorio/vmrun_smoketest.txt`.
- **Salida**: `Soporte/Laboratorio/vmrun_config.md` con `vm_names: {wazuh_server,
  victim_win, victim_linux, attacker}`, rutas `.vmx` y nombres base de snapshots
  (`clean_pre_ata`).
- **Crit-Aceptación**: el agente puede revertir una VM a snapshot `clean_pre_ata` y
  confirmar SSH vivo en < 90 s sin prompts interactivos.
- **Dependencias**: T-05, T-06.

#### T-25 — Setup de llaves SSH víctima/atacante/manager **[MIXTO]**
- **Acción [HUMANO]**: generar par de llaves `ed25519` en la máquina Opencode y
  distribuirlas a las 3 VMs (`victim_win`, `victim_linux`, `attacker`, `wazuh_server`);
  crear usuario `tfg` en cada una con sudo sin password para los comandos del agente.
- **Acción [AUTO]**: validar `ssh <vm> echo ok` sin prompt y volcar salida a
  `Soporte/Laboratorio/ssh_smoketest.txt`.
- **Salida**: `Soporte/Laboratorio/ssh_setup.md` (procedimiento reproducible) y
  `~/.ssh/config` con aliases `tfg-wazuh`, `tfg-victim-win`, `tfg-victim-linux`,
  `tfg-attacker`.
- **Crit-Aceptación**: el agente puede ssh a las 4 VMs sin password.
- **Dependencias**: T-05, T-06.

#### T-26 — Implementar el orquestador "El Agente" **[AUTO]**
- **Salida**: `_artefactos/orquestador/orquestador.py` + `config.yaml` con la
  especificación de §3.A. Es el script Python que el **agente Opencode invoca** como tool
  para orquestar F-03, F-04 y F-05 (no es la IA misma, es la herramienta que la IA llama).
  Funciones expuestas:
  - `ataque_run(ata_id)`: snapshot revert → start perf → t0 → atomic test → t1 → stop
    perf → snapshot post.
  - `wazuh_extract(ata_id, ruleset)`: switch ruleset → restart manager → query indexer
    [t0,t1] → CSV.
  - `tp_fp_filter(ata_id)`: aplicación de filtrado automático + etiquetado agente.
  - `build_detecciones()`: regenera `Hojas/Detecciones.xlsx` + BBDD SQLite.
  - `bitacora(ata_id, evento, payload)`: append JSON en `Bitacora/ATA<NNN>.json`.
  - `ata_index_update(ata_id, estado)`: actualiza `Hojas/ATA_index.csv`.
- **Crit-Aceptación**: ejecutar `ataque_run("ATA005")` end-to-end sobre una técnica
  piloto sin intervención humana.
- **Dependencias**: T-13, T-21, T-23, T-24, T-25.

#### T-27 — Mantener `Diario.md` (bitácora personal del alumno) **[HUMANO]**
- **Salida**: `Diario.md` en la raíz del repo, append-only, una entrada por sesión de
  trabajo. Formato sugerido por entrada: `## YYYY-MM-DD (h)`, bullets con:
  - Decisiones tomadas (y por qué).
  - Bloqueos encontrados.
  - Avances concretos.
  - Cosas aprendidas / sorpresas.
- **Por qué**: complementa la `Bitacora/ATA<NNN>.json` (técnica) con perspectiva humana.
  Sirve como insumo para el Anexo F "Dificultades encontradas" de la memoria y para
  recordar el razonamiento cuando vuelvas al TFG tras días sin tocarlo.
- **Crit-Aceptación**: al cerrar cada fase, el `Diario.md` tiene al menos 1 entrada por
  sesión. Sucesivas sesiones no sobreescriben las anteriores.
- **Dependencias**: — (se puede empezar desde Fase 0).

#### T-28 — Definir skills/prompts del agente Opencode "El Agente" **[MIXTO]**
- **Salida**: carpeta `_artefactos/ia/` con:
  - `skills/ataque.md` — instrucciones para la skill de Ataque (qué hacer por técnica,
    qué invocar, qué validar).
  - `skills/deteccion.md` — instrucciones para la skill de Detección (consulta indexer,
    switch RuleSet, parseo CSV).
  - `skills/agregacion.md` — instrucciones para la skill de Agregación (build Detecciones,
    Mapeos, BBDD, Estudio-Wazuh).
  - `skills/orquestacion.md` — instrucciones de la skill de Orquestación (cuándo invocar
    cada una, parada segura en `review=true`, gestión de `Bitacora/` y `ATA_index.csv`).
  - `prompts/` — plantillas de prompt para etiquetado TP/FP, generación de scaffolding
    T-11, etc.
  - `config_opencode.md` — configuración del agente Opencode (modelo, permisos,
    aliases SSH, ubicación de `vmrun`).
- **Por qué**: una sola mega-skill es inmanejable; varias skills a demanda son más
  modulares, depurables y reutilizables. Tenerlas por escrito (no improvisadas) es
  imprescindible para la transparencia y reproducibilidad del TFG.
- **Fase**: se redacta un **borrador inicial** en Fase 0.4 (lo justo para arrancar la
  Fase 1) y se **refina** en Fase 4 (cuando se sepa qué funcionó y qué no en el
  piloto).
- **Crit-Aceptación**: cada skill tiene: objetivo, comandos/tools que invoca, formato de
  entrada/salida, hard limits que respeta. Existe test manual en al menos 1 escenario
  por skill.
- **Dependencias**: T-24, T-25, T-26.

---

## 3. Flujos de trabajo (F-01 a F-06)

> Los flujos encadenan las tareas de §2. Se describen con entrada → pasos → salida. En
> `roadmap.md` se secuenciarán en el tiempo.

### F-01 — Flujo de Corpus MITRE
```
T-01 (descargar STIX v19.1)
   └─→ T-02 (extender script profesor, extraer DCs por técnica)
          └─→ T-03 (lista human-legible priorizada R/E/S)
                 └─→ T-10 (seleccionar 1 técnica/táctica iteración 1)
                        └─→ (iteración 2, 3, ... crece el corpus)
```
**Salida final**: `Hojas/lista_tecnicas_validas.md` + `Hojas/ATA_index.csv` + pestaña C
de `Mapeos.xlsx`. **Cadencia**: se ejecuta una vez al completo; re-ejecutar solo si MITRE
publica una nueva versión o se amplía el corpus.

### F-02 — Flujo de Preparación del Laboratorio
```
T-04 (topología VMs)
   ├─→ T-05 (Wazuh server: manager + indexer + dashboard)
   │      └─→ T-07 (config detección-only) ──→ T-08 (RuleSets WZ-RS1..RS4)
   │             └─→ T-09 (baseline legítimo 4h×2)
   └─→ T-06 (agentes: Windows+Sysmon / Linux+auditd)
```
**Salida final**: laboratorio reproducible. **Cadencia**: una vez; se repite tras
snapshots frescos entre ataques.

### F-03 — Flujo de Ataque (por cada técnica del corpus)
```
T-11 (implementar artefacto T<id>-<desc>_<fuente>)
   └─→ snapshot fresco de VM víctima (vmrun revertToSnapshot clean_pre_ata)
          └─→ arrancar captura de rendimiento (T-21 inicio)
                 └─→ marcar t0 = timestamp inicial
                        └─→ ejecutar ataque (invocación de Atomic Red Team por SSH)
                               └─→ marcar t1 = timestamp final
                                      └─→ detener captura de rendimiento (T-21 fin)
                                             └─→ snapshot post-ataque para rollback
```
**Entrada** por iteración: un artefacto de T-11 y una VM limpia.
**Salida** por iteración: logs del SO (Sysmon/auditd) + `Perf/ATA<NNN>.csv` + capturas en
`Soporte/Ataques/capturas/T<id>/`. **Reentrada**: tras este flujo se ejecuta F-04.

### F-04 — Flujo de Detección (por cada ataque, por cada RuleSet WZ-RS1..RS4)

> **Precondición**: T-12 (ejecución doble) ya ha corrido: el ataque se ha ejecutado
> **dos veces** en snapshot fresco y se han registrado los timestamps `[t0_1, t1_1]`
> e `[t0_2, t1_2]`. F-04 procesa las alertas de **ambas iteraciones** (T-13 depende
> de T-12, ver matriz §4).

```
T-13 (query indexer entre [t0_1, t1_1]∪[t0_2, t1_2] → ATA<NNN>_<RS>.csv)
   └─→ T-14 (filtrado automático FP vs baseline → ATA<NNN>_<RS>TP.csv)
          └─→ T-15 AUTO (agente etiqueta con T-23 → ATA<NNN>_<RS>-AutoTagged.csv)
                 └─→ T-15 HUMANO (alumno audita → ATA<NNN>_<RS>-Audited.csv)
                        └─→ comparar #alertas iter1 vs iter2; si difieren, review=true
```
**Nota**: el ajuste del RuleSet activo en el manager se documenta en
`Soporte/Wazuh/Configuracion/active_ruleset.txt`; entre RuleSets se reinicia el manager.
**Salida final por ataque**: 4 RuleSets × 5 artefactos CSV (`{total, TP-auto,
AutoTagged, Audited, Perf}`). El quinto es el CSV de T-21 (`Perf/ATA<NNN>.csv`) que se
genera en F-03 y se consume en F-05.

### F-05 — Flujo de Agregación y Reporte
```
T-16 (build Detecciones.xlsx)
   ├─→ T-17 (Mapeos.xlsx)
   ├─→ T-18 (SQLite réplica + scripts transformación)
   ├─→ T-19 (Estudio-Wazuh/ carpetas ejecutivas + gráficas)
   └─→ T-22 (tabla resumen de rendimiento η)
```
**Entrada**: todos los CSV de F-04 por ataque + Perf de T-21.
**Salida final**: `Hojas/Detecciones.xlsx`, `Hojas/Mapeos.xlsx`, `BBDD/wazuh.db`,
`Estudio-Wazuh/*`, `VerificacionWazuh/Resumen.csv`. **Cadencia**: incremental; se
regenera tras cada ataque cerrado.

### F-06 — Flujo de Orquestación con IA ("El Agente") — CENTRAL
> Orquesta F-03, F-04 y F-05. El **agente Opencode** asume este rol (ver §3.A). El script
> de soporte está definido en T-26.

**Responsabilidades del orquestador (agente + T-26)**:
1. Mantener un `ATA_index.csv` vivo con estado por ataque (`pendiente/en-curso/cerrado`).
2. Restaurar snapshot de VM víctima antes de cada ataque (`vmrun revertToSnapshot`).
3. Lanzar F-03 (ataque) y registrar t0/t1 en `ATA_index.csv`.
4. Lanzar F-04 (detección) por cada RuleSet; etiquetar TP/FP con T-23.
5. Llamar F-05 (agregación) automáticamente al cerrar un ataque.
6. Hacer rollback/limpieza post-técnica.
7. Guardar bitácora estructurada `Bitacora/ATA<NNN>.json` con todo lo anterior.
8. Validar que se genera el CSV de perf y el CSV de alertas antes de avanzar.

**Política de parada segura**: si F-04 reporta diferencia entre iter 1 e iter 2, el
agente marca `review=true` en `ATA_index.csv` y **espera confirmación del alumno** antes
de avanzar al siguiente ataque.

---

## 3.A. Automatización con IA (Opencode como "El Agente")

Esta sección describe explícitamente qué tareas de cada flujo son automatizables por el
agente IA (Opencode) y cuáles no. Es la base para `roadmap.md`. Toda la orquestación se
apoya en el script `T-26` (`_artefactos/orquestador/orquestador.py`), expuesto al agente
como un conjunto de *tools*.

### A.1 — Decisiones fijadas en sesión de diseño

| # | Decisión | Requisito asociado |
|---|----------|--------------------|
| D1 | **VMWare controlado por `vmrun` desde PowerShell**. El agente puede snapshot/arrancar/parar/revertir las VMs sin prompts. | R-11, T-24 |
| D2 | **Orquestador de ataques: Atomic Red Team** (tests atómicos en PS1/bash por técnica). Scripteable por SSH. | R-12, T-11 |
| D3 | **Llaves SSH ed25519** sin password del agente a las 4 VMs. | R-13, T-25 |
| D4 | **Etiquetado TP/FP por el agente, auditoría humana posterior**. η final se calcula sobre etiquetas auditadas. | R-14, T-15, T-23 |

### A.2 — Matriz de automatización por tarea

| Tarea | Modo | Comentario |
|-------|------|------------|
| T-01 Descargar STIX v19.1 | **[AUTO]** | Una llamada al orquestador (`download_stix("v19.1")`). |
| T-02 Extender script profesor | **[AUTO]** | El agente genera `extraer_tecnicas_host.py` a partir del código del profesor. |
| T-03 Lista human-legible + Mapeos pestaña C | **[AUTO]** | Script determinista. |
| T-04 Topología VMs | **[HUMANO]** | El alumno crea las VMs en VMWare GUI + red host-only. El agente solo documenta `topologia.png`. |
| T-05 Wazuh server (manager+indexer+dashboard) | **[MIXTO]** | El alumno instala; el agente genera `wazuh-server-install.md` a partir de los comandos ejecutados. |
| T-06 Víctimas + agent + Sysmon/auditd | **[MIXTO]** | Igual que T-05. |
| T-07 Config detección-only | **[AUTO]** | El agente edita `ossec.conf` y `local_rules.xml`. |
| T-08 RuleSets WZ-RS1..RS4 | **[AUTO]** | El agente define los 4 RuleSets y los switchea con `switch_ruleset`. |
| T-09 Baseline legítimo 4h×2 | **[AUTO]** (largo) | El agente lanza el script de actividad legítima y espera; genera `ruleids_legitimos.csv`. |
| T-10 Elegir 1 técnica/táctica | **[MIXTO]** | El agente propone la lista basándose en prioridad R/E/S; el alumno ratifica. |
| T-11 Implementar artefacto Atomic | **[MIXTO]** | El agente genera scaffolding + README; el alumno valida y añade screenshots. |
| T-12 Ejecución doble para robustez | **[AUTO]** | `ataque_run`×2 con snapshot revert entre ambas. |
| T-13 Extraer alertas indexer | **[AUTO]** | `wazuh_extract`. |
| T-14 Filtrado automático FP | **[AUTO]** | `tp_fp_filter` (automático contra baseline). |
| T-15 Etiquetado TP/FP residual | **[AUTO]** + **[HUMANO]** | El agente etiqueta (`AutoTagged.csv`); el alumno audita (`Audited.csv`). |
| T-16 `Detecciones.xlsx` | **[AUTO]** | `build_detecciones`. |
| T-17 `Mapeos.xlsx` | **[AUTO]** | Script determinista. |
| T-18 SQLite réplica | **[AUTO]** | El agente porta `tablas.sql` y genera `tablas_sqlite.sql`. |
| T-19 `Estudio-Wazuh/` | **[AUTO]** | Generación de carpetas ejecutivas + gráficas vía matplotlib. |
| T-20 `VerificacionWazuh/` | **[AUTO]** | Tres ataques × 4 cargas. |
| T-21 Métricas de rendimiento | **[AUTO]** | Sampler periódico en background. |
| T-22 Tabla resumen rendimiento | **[AUTO]** | Cálculo de η. |
| T-23 Criterios de etiquetado | **[HUMANO]** | El alumno redacta; el agente los aplica. |
| T-24 vmrun config | **[MIXTO]** | El alumno registra VMs; el agente valida. |
| T-25 SSH setup | **[MIXTO]** | El alumno distribuye llaves; el agente valida. |
| T-26 Orquestador "El Agente" | **[AUTO]** | El agente lo implementa y expone como tool. |
| T-27 Diario.md | **[HUMANO]** | El alumno anota decisiones/bloqueos/avances por sesión. |
| T-28 Skills/prompts IA | **[MIXTO]** | Una skill por flujo; se redacta en Fase 0.4 y se refina en Fase 4. |

### A.3 — Hard limits del agente (lo que NUNCA hace)

- Crear VMs en VMWare GUI ni instalar SOs operativos (T-04, parte de T-06).
- Hacer commits git sin visto bueno del alumno (podría cometer archivos sensibles/secretos).
- Borrar artefactos o snapshots de forma irreversible sin confirmación explícita.
- Firmar η final: la métrica legítima usa `ATA<NNN>-Audited.csv`, no las etiquetas
  automáticas del agente.
- Validar visualmente que un ataque "se ejecutó con éxito" (capturas en
  `Soporte/Ataques/capturas/T<id>/`): tarea humana (T-11).
- Decidir go/no-go entre RuleSets cuando iter 1 ≠ iter 2.

### A.4 — Estado persistente (en ficheros, no en sesión)

La sesión de Opencode no es persistente entre días. Todo el estado vive en:

- `Hojas/ATA_index.csv` — columna `estado` ∈ {`pendiente`,`en-curso`,`review`,`cerrado`}.
- `Bitacora/ATA<NNN>.json` — registro append-only con cada evento `{ts, tool, args,
  result}` para reproducibilidad.
- `Soporte/Wazuh/Configuracion/active_ruleset.txt` — RuleSet actualmente activo en el
  manager (para saber dónde retomar).

Cada vez que se abre Opencode, el agente lee `ATA_index.csv` y continúa desde el primer
ataque `en-curso` o `pendiente`. No requiere memoria de sesión.

### A.5 — Ritmo de operación trabajo/coste

- **Determinismo sí, IA no**: las tareas puramente scriptables (T-13, T-14, T-16, T-17,
  T-18, T-19, T-22) las realiza el orquestador (Python), no el LLM. Se ahorra tokens.
- El **LLM actúa cuando decisión/proposición** (T-10 selección, T-15 etiquetado
  semántico, T-11 generación de scaffolding, recuperación tras errores).
- **Paradas para humano** programadas: después de T-09 (revisar baseline), después de las
  5 técnicas piloto end-to-end (auditar etiquetas T-15), y en cualquier `review=true`.

---

## 4. Matriz de dependencias (tarea → tareas previas)

| Tarea | Depende de |
|-------|------------|
| T-01  | — |
| T-02  | T-01 |
| T-03  | T-02 |
| T-04  | — |
| T-05  | T-04 |
| T-06  | T-05 |
| T-07  | T-06 |
| T-08  | T-07 |
| T-09  | T-07 |
| T-10  | T-03 |
| T-11  | T-10, T-06 |
| T-12  | T-11, T-07 |
| T-13  | T-12, T-05 |
| T-14  | T-13, T-09 |
| T-15  | T-14, T-23 |
| T-16  | T-15 |
| T-17  | T-03 |
| T-18  | T-16 |
| T-19  | T-16 |
| T-20  | T-13, T-09 |
| T-21  | T-06 |
| T-22  | T-16, T-21 |
| T-23  | T-09 |
| T-24  | T-05, T-06 |
| T-25  | T-05, T-06 |
| T-26  | T-13, T-21, T-23, T-24, T-25 |
| T-27  | — |
| T-28  | T-24, T-25, T-26 |

**Camino crítico** (PERT; lo más largo hasta tener `ATA<NNN>` cerrado con η calculado):
- **Rama corpus (bloqueante para T-15)**: T-01 → T-02 → T-03 → T-10 → T-11 → T-12 →
  T-13 → T-14 → T-15 → T-16.
- **Rama laboratorio (bloqueante para T-23)**: T-04 → T-05 → T-06 → T-07 → T-09 → T-23.
- **T-15** requiere T-14 (rama corpus) **Y** T-23 (rama lab): las dos ramas convergen
  ahí. T-04..T-07 no bloquean a T-11/T-12 directamente, pero la rama lab debe llegar
  a T-23 antes de cerrar T-15.
- **Rama de automatización (no bloquea F-03/F-04)**: T-24 → T-25 → T-26; conviene
  tener T-26 listo antes de escalar más allá de las 5 técnicas piloto.
- **Rama humana/anexa (no bloquea)**: T-27 (Diario.md) y los pasos de validación
  visual de T-11.

---

## 5. Estructura final del repo (resultado de aplicar todas las tareas)

```
<repo>/
├── README.md
├── Diario.md                   # bitácora personal del alumno (T-27, append-only)
├── context.md                  # §1: alto nivel
├── requirements.md             # este fichero
├── roadmap.md                  # secuencia temporal de tareas
├── _recursos/                  # recursos del profesor (read-only, ya existe)
├── _artefactos/
│   ├── mitre/{enterprise-attack-v19.1.json}
│   ├── scripts/{extraer_tecnicas_host.py, orquestador/}
│   └── ia/
│       ├── skills/{ataque, deteccion, agregacion, orquestacion}.md   # T-28
│       ├── prompts/                                                 # T-28
│       └── config_opencode.md                                       # T-28
├── BBDD/
│   ├── SQL/{tablas_sqlite.sql, views.sql, datos.sql}
│   ├── CSV/{caracterizacion_ataque.csv, deteccion_wazuh.csv, ...}
│   ├── Scripts/{csv_comas.py, transformaAlertasWazuh.py, build_detecciones.py}
│   └── wazuh.db
├── Dataset/
│   ├── Ataques/
│   │   ├── Comandos/T<id>-<desc>_<fuente>/{attack.*, README.md}
│   │   └── Resultados/Wazuh/{CSV/, Logs/, Perf/}
│   └── Legitimo/{Windows,Linux}/{alerts.json, ruleids_legitimos.csv}
├── Estudio-Wazuh/
│   ├── completamenteDetectados/
│   ├── noDetectados/
│   ├── ataques_completamente_detectados_Wazuh.{csv,xlsx,txt}
│   └── Grafica*.jpg
├── Hojas/
│   ├── Detecciones.xlsx        # tabla ataques (~250 columnas)
│   ├── Mapeos.xlsx             # 4 pestañas
│   ├── lista_tecnicas_validas.md
│   ├── corpus_host.csv
│   ├── ATA_index.csv
│   └── README.md
├── Soporte/
│   ├── Ataques/{capturas/T<id>/, ficheros/T<id>/}
│   ├── Laboratorio/{topologia.png, README.md, vmrun_config.md, ssh_setup.md}
│   ├── Wazuh/{Configuracion, Reglas, Scripts, README.md}
│   └── Otros/
├── VerificacionWazuh/{Resumen.csv, *.log}
└── Bitacora/{ATA<NNN>.json}    # salida del orquestador F-06
```

---

## 6. Riesgos identificados y mitigaciones

| Riesgo | Impacto | Mitigación |
|--------|---------|------------|
| MITRE cambia HTML y rompe el script del profesor | T-02 bloqueado | Usar STIX bundle (T-01) como fuente primaria; mantener script del profesor como fallback. |
| Wazuh indexer no indexa alertas a tiempo | T-13 da falsos "no detectado" | Sleep de 60 s post-ataque antes de query; una segunda query a los 300 s como respaldo (patrón `PA.sh:1-76`). |
| Ruido de Sysmon inunda Wazuh | Muchos FP | Filtros en `ossec.conf` por `event_id` ruidosos; baseline legítimo extenso (T-09). |
| renovación del corpus entre versiones MITRE | Ataques Q3 2026 mapeados a v19.1, pero v20 salga antes de entrega | Documentar la versión en `Mapeos.xlsx`; dejar el script re-ejecutable. |
| Reproducibilidad de VMs | Resultados no repetibles | Snapshot base `clean_pre_ata` en cada VM; el agente hace
  `vmrun revertToSnapshot` antes de cada ataque (F-06). Solo se crean snapshots
  adicionales `post-ATA<NNN>` si una investigación post-ataque lo requiere. |
| Artefacto de ataque se escapa (acción real en el host físico) | Riesgo de seguridad | VM aislada en red host-only; SO invitado sin compartir carpetas con el anfitrión. |
| Falsos "eventos de sistema" colapsan el etiquetado del agente | T-15 no es viable | Subcategoría de FP "Eventos de Sistema" pre-filtrada por `rule.level ≤ 3` antes del
  etiquetado del agente; el alumno audita posteriormente las discordancias. |
| Wazuh no tiene regla cubriendo una técnica | Falso "no detectado" | Añadir regla custom en `WZ-RS3` para esa técnica (T-08); registrar en `local_rules.xml`. |

---

## 7. Fuera de alcance (explícito)

- **Velociraptor y tercer HIDS**: se diseñan los esquemas (`Hojas/`, `BBDD/`,
  `Estudio-*/`) para soportarlos, pero no se implementan hasta cerrar Wazuh end-to-end
  (R-05).
- **Apartado extra de Snort por conversión log→pcap**: solo si hay tiempo; se documentará
  como anexo optativo siguiendo `01_TFG4-HIDS` (auxiliar) línea 35-37 (`ait-aecid`).
- **Mobile, ICS, Cloud**: fuera (R-01 restringe a Enterprise).
- **Bloqueo activo**: fuera (R-06).
- **Comparativa con TFGs hermanos**: solo cualitativa en memoria; no se re-ejecutan
  sus herramientas.

---

## 8. Siguiente paso inmediato

`roadmap.md` ya está creado y secuencia los flujos F-01..F-06 en 9 fases (Wazuh-first).
La próxima acción es ejecutar la **Fase 0** (esqueleto de repo, README, clon de Atomic
Red Team, borrador de las 4 skills de "El Agente" en `_artefactos/ia/`, arranque del
`Diario.md`) y disparar la **Fase 1** (F-01: T-01 → T-02 → T-03 → lista de técnicas
válidas human-legible priorizada por R/E/S).