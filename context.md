# context.md — Contexto del TFG

> **Versión:** v2 (reencuadre R1) · **Estado:** vigente · **Fecha:** 2026-10-16.
> Documento de contexto **estable**: qué es el TFG, el marco aprobado, el método, el glosario y
> las decisiones fijadas. El detalle de requisitos y recursos vive en `requirements.md` y la
> secuencia/hitos/riesgos en `roadmap.md`; el estado vivo, en `state.md`.
>
> **Anclas:** `(R0 §X.Y)` = sección del **marco aprobado** `_fases/reencuadre/plan.md`
> (v2, 2026-10-16). `(histórico)` / `(obsoleto)` = del marco anterior, ya no vigente.

---

## 1. Qué es el TFG

**Título:** *Análisis de la capacidad de detección de ataques locales de la matriz MITRE ATT&CK
Enterprise mediante HIDS.*

**Tutor:** D. F. Javier Muñoz Calle (Universidad de Sevilla, Dpto. Ingeniería Telemática).

**Línea de investigación:** el tutor ya dirige TFGs de detección de **ataques de red** con
IDS/NIPS (Snort, FortiGate, Palo Alto) y uno de entornos **ICS**. Este trabajo es el paso
siguiente: del dominio **red** al **host/local** y del IDS/NIPS al **HIDS**.

**Objetivo general** (`R0 §3.1`, redacción de referencia):

> Analizar la capacidad de detección de ataques locales de la matriz MITRE ATT&CK Enterprise
> (subconjunto **P1**: Impact / Exfiltration / Collection) mediante dos HIDS open-source
> —**Wazuh** y **Velociraptor**— en su configuración "de fábrica" (**virgen**), y cuantificar
> tanto la detección (**TPR**) como el error sobre la actividad legítima (**FP**), a varios
> niveles de severidad/configuración y en las plataformas **Linux** y **Windows**, produciendo
> un conjunto de **tablas homogéneas** con los trabajos hermanos del grupo.

**HIDS a evaluar** (`R0 §3.3`): **Wazuh** y **Velociraptor**, en ese orden y **sin mezclar**.
*(histórico: el borrador previo planteaba un **tercer HIDS** y Wazuh como único núcleo; ambos
criterios quedan **obsoletos**.)*

**Entregable final** (`R0 §3.2 O7`, `§5`): el conjunto de **5 tablas del profesor** (**T1–T5**)
+ hoja **"Requisitos de estudios"** + **"Leyenda"**, homogéneas con los TFGs hermanos, más la
**memoria**.

---

## 2. Objetivos específicos (`R0 §3.2`)

| # | Objetivo | Se ve en |
|---|---|---|
| **O1** | **Clasificar** las técnicas P1 host-eligible (filtro inverso host ≡ **Tabla 1** del profesor invertida). | Tabla 1 |
| **O2** | **Ejecutar** los ataques P1 y caracterizarlos como **"paquete equivalente a pcap"** (criterio ART + telemetría). | Tabla 2 |
| **O3** | **Medir el error en legítimo** (FP/TN con acciones reales, **GHOSTS**). | Tabla 3 |
| **O4** | **Calcular métricas** (TPR, FPR, Precisión, F1, GM, Usabilidad) por nivel/config. | Tabla 4 |
| **O5** | **Medir el efecto del *pruning*** (500/1000, Conservative, Generalized, Aggressive). | Tabla 5 |
| **O6** | **Evaluar Velociraptor** con el mismo corpus y **compararlo con Wazuh**. | T2/T4 (ambos HIDS) |
| **O7** | **Homogeneidad** con los TFGs hermanos (plantillas, excels, nomenclatura). | Requisitos + Leyenda |
| **O8** | Redactar la **memoria** con el esqueleto de los hermanos. | Fase memoria |

---

## 3. Alcance y marco (`R0 §3.3`, `§14`)

- **Alcance de técnicas:** **solo P1** (Impact / Exfiltration / Collection) → **89 técnicas
  host-eligible** (**72 Linux**, 17 no-Linux).
- **HIDS:** **Wazuh + Velociraptor**.
- **Configuración:** **"virgen" primero** (sin reglas/artifacts propios); `+propias`/`+externas`
  (Wazuh) y `+custom` (VR) forman un **eje de configuración contingente a un gate** posterior.
- **Plataformas:** **Linux primero**; **Windows** después (segunda plataforma víctima).
- **Qué NO entra** (`R0 §14`): el **tercer HIDS** (OSSEC/Sagan/Splunk/Samhain); **Snort/pcaps**
  y el análisis de red pura; el **coste computacional** (solo experimento opcional declarado);
  **InfoStealer** como exfiltración ("a decidir" a futuro); las técnicas **P2/P3**; el **modo
  bloqueo** (solo detección); la **comparativa cuantitativa** con los hermanos (solo cualitativa).

---

## 4. Método (los 4 pasos del profesor, actualizados) (`R0 §3.2`, `§5.2`, `§2.3`)

1. **Clasificar.** Identificar las técnicas MITRE host-eligible con el **filtro inverso host**,
   que equivale a **`NOT(Only Network Detection)`**: se excluyen las técnicas cuyo **único**
   Data Component sea de red pura (`Network Connection Creation`, `Network Traffic Content`,
   `Network Traffic Flow`). El resultado se **espeja** con la **Tabla 1 (v17)** del profesor.
2. **Implementar los ataques.** Cada caso es un **"paquete equivalente a pcap"**: carpeta por
   ataque con **contexto** (artefacto/plataforma/*inputs*) + **acciones** (guion/comando) +
   **telemetría** (alertas/evidencias), siguiendo el **criterio de ART**. Cobertura por
   **Tácticas → Técnicas → Subtécnicas**.
3. **Detectar** con **Wazuh** y **Velociraptor** en configuración **virgen**.
4. **Analizar** los resultados con las tablas **T1–T5 + Requisitos + Leyenda**.

**Prioridad de los ataques** (`guia_profesor.txt:37-46`, vigente): Ransomware · Exfiltración ·
Sabotaje (**R/E/S**), que el reencuadre identifica con el subconjunto **P1**.

**Notas operativas del método** (vigentes): sistema víctima según la técnica (Linux, Windows o
ambos; **Linux** por comodidad si ambos) · todo en **VM** sobre **VMware** · **modo
detección-only** (el HIDS nunca bloquea).

*(obsoleto: "iterar añadiendo 1 técnica por táctica hasta un buen conjunto" — se sustituye por
**solo P1**; el "precio de la detección" de la Fase 4 pasa a **experimento opcional**, `R0 §14`.)*

---

## 5. La métrica, en resumen (`R0 §4`)

La métrica se mide en **dos planos** (como el NIDS de referencia) más un **plano de alerta**;
se **congela** en el bloque `reencuadre-metrica` (**R2**) **antes de medir**:

| Plano | Unidad | Métrica principal |
|---|---|---|
| **Ataque** | caso = ventana `ATA<NNN>` | **TPR** (= TP / N) |
| **Legítimo** | unidad de actividad legítima (evento) | **FPR** (= FP / M) |
| **Alerta** | un `rule.id` (Wazuh) / una fila de *artifact* (VR) | **Precisión**, **F1**, **GM**, **Usabilidad** |

- **Titular:** la unidad legítima es el **evento/registro**. **Comparación entre HIDS:** unidad
  **común** = **acción de GHOSTS** / **hora** (FTTAR).
- **GM = √(TPR·(1−FPR))** · **Usabilidad = #Alertas_FP / #Alertas_TP** (ambas del profesor).
- *El detalle (fórmulas, reglas de conteo y sesgos declarados) se **congela en R2**; aquí solo
  se resume.* (`R0 §4`, `§12 CA-R4`)

---

## 6. Guía del profesor: vigente vs obsoleta (`R0 §3.4`)

La `guia_profesor.txt` es **rectora en lo esencial**, pero está **desactualizada** en varios
puntos y **no se aplica tal cual**:

| Punto de la guía | Estado | Ahora |
|---|---|---|
| Alcance de técnicas (**la guía no fija cifra**; el borrador antiguo decía "12-15") | **obsoleto** | **Solo P1** (89 host-eligible) |
| Un **tercer HIDS** además de Wazuh | **obsoleto** | **Fuera** (solo Wazuh + Velociraptor) |
| **Snort** a partir de logs / "convertir logs en pcap" | **obsoleto** | **Fuera** (solo HIDS) |
| `ait-aecid` / `kyoushi-environment` como herramienta | **obsoleto** | **Solo cita** en el estado del arte (otro paradigma: HIDS *por anomalías*) |
| Baseline de **actividad sintética de pocas horas** | **obsoleto** | **GHOSTS + 72 h** |
| FortiEDR (comercial) | **fuera** | Solo HIDS **open-source** |
| **Filtro inverso host** | **VIGENTE** | Se conserva (`Hojas/corpus_host.csv`) |
| **Prioridad R/E/S** | **VIGENTE** | Se conserva (columna `priority`) |

---

## 7. Homogeneidad con los trabajos hermanos (`R0 §5`, `§3.2 O7`)

Prioridad del tutor: *"si no se reaprovecha, dejar **ficheros equivalentes** en la misma línea"*.
Se **imita** (sin copiar resultados):

| Elemento | Se imita | Fuente |
|---|---|---|
| Plantillas de resultados | **T1–T5 + "Requisitos de estudios" + "Leyenda"** (`SID`→`rule.id`, `pcapng`→`ATA<NNN>`) | Excel del profesor |
| Estructura de carpetas | `Hojas/` · `Dataset/{Ataques,Legitimo}` · `Soporte/` · `Estudio-<HIDS>/` · `BBDD/` | repo **Snort-FG-PA** |
| Nomenclatura | `ATA<NNN>`, "paquete equivalente a pcap", TP/FP, "análisis manual" | notas del humano |
| Método de métricas | `GM = √(TPR·TNR)`, `Usabilidad = #Alertas_FP / #Alertas_TP`, doble conteo (*Raw* vs *Diff-Alerts/Flow*) | repo **NIDS** hermano |
| Esqueleto de la memoria | Introducción/Estado del arte → Base teórica → Ataques → Análisis → Resultados → Conclusiones → Anexos | roadmap |

**Lo que NO se copia** (es del mundo NIDS o está superado): columnas de red (flujos, `SID`,
`tranalyzer`, nº de mensajes), la vista "solo-red" (**solo como espejo**: la nuestra es
**host**), ni resultados ajenos. De lo ajeno se reutiliza la **metodología y las plantillas**.

---

## 8. Decisiones fijadas (`R0 §3.3`, `change-doc §3`)

| Tema | Decisión |
|---|---|
| **Alcance** | **Solo P1** (Ransomware/Exfiltración/Sabotaje); **89 host-eligible** (72 Linux, 17 no-Linux). |
| **HIDS** | **Wazuh + Velociraptor** (fuera el tercero). |
| **Configuración** | **Virgen primero**; `+propias`/`+externas`/`+custom` = **eje contingente a gate**. |
| **Orden** | **Linux Wazuh → Windows Wazuh → Velociraptor (Linux y Windows)**; **sin mezclar HIDS**. |
| **Corridas de legítimo** | **POR SEPARADO** (un HIDS a la vez, sin el otro instalado). |
| **Legítimo** | **No es "línea base": es cuantificar el error (FP/TN)** con **acciones reales (GHOSTS)** y **72 h** (ampliable). El baseline sintético anterior de pocas horas queda **(histórico)**. |
| **Métrica** | **Del profesor**, a dos planos (ataque→TPR; legítimo→FPR) + plano alerta. *(Sustituye a la fórmula combinada propia del borrador, **(obsoleto)**.)* |
| **Resultados** | **T1–T5 + Requisitos + Leyenda** (estructura del Excel del profesor). |
| **Umbral** | **`rule.level ≥ N`** (Wazuh) × config × HIDS × SO; perfiles **P1–P4** (VR). |
| **Internet** | **Lab aislado + "internet local" simulada y declarada** (alternativa híbrida documentada). |
| **Clasificación** | `corpus_host.csv` (v19.1) **+ Tabla 1 (v17)** como espejo, con equivalencia y **3 discrepancias** declaradas. |
| **Identificador de ataque** | **`ATA<NNN>`** (`ATA001`, `ATA002`, …, un caso = una ventana). |
| **Validación** | **Doble iteración** por ataque representativo; si difiere → `review=true`. |
| **Modo** | **Detección-only** (el HIDS nunca bloquea). |
| **Laboratorio** | VMware en el **sobremesa** (16 GB), red **host-only**; agentes en el sobremesa; **portátil → sobremesa por SSH sobre Tailscale**. |
| **BBDD SQLite** | **alternativa opcional** a las hojas (no requisito del núcleo). *(histórico: era requisito.)* |
| **Git** | Local. **`git push` lo hace el humano**; `_recursos/` solo lectura. |

> **Cifra vigente del corpus:** **55 técnicas / 128 ventanas / 53 detectadas** (P1-Linux).
> P1 host-eligible total = **89** (72 Linux · 17 no-Linux). *(histórico: el borrador hablaba de
> "unas pocas técnicas"; ver `state.md`, nota "cifras desfasadas".)*

---

## 9. Glosario

**MITRE y corpus**
- **MITRE ATT&CK Enterprise** — catálogo público de tácticas/técnicas. Corpus en **v19.1**; la
  Tabla 1 del profesor es **v17**.
- **Táctica / Técnica / Subtécnica** — fase del ataque / el "cómo" (`T1486`) / refinamiento
  (`T1486.001`).
- **Data Component** — fuente de telemetría necesaria para detectar (proceso, fichero,
  registro…). Antes *Data Sources*.
- **P1–P4 (perfiles)** — subconjuntos por táctica: **P1 = Impact / Exfiltration / Collection**
  (nuestro alcance); P2/P3 quedan fuera.
- **Filtro inverso host** — criterio de elegibilidad: **`host_eligible ≡ NOT(Only Network
  Detection)`**.
- **ATA<NNN>** — identificador único de cada caso del corpus (`ATA001`…); un caso = una
  **ventana** de ataque.
- **"Paquete equivalente a pcap"** — carpeta por ataque con **contexto + acciones + telemetría**
  (criterio ART).
- **Análisis manual** — cómo se verificó que el ataque ocurrió de verdad.

**Métrica**
- **Caso / unidad legítima / alerta** — las tres unidades (ataque / legítimo / alerta).
- **Plano ataque / legítimo / alerta** — ver §5.
- **TPR** (Recall / CD) — TP / N de casos; **FPR** — FP / M de unidades legítimas;
  **TNR = 1 − FPR**.
- **Precisión / F1 / GM / Usabilidad (FTTAR)** — ver §5.
- **Raw vs correlacionadas** — nº de alertas brutas vs nº de `rule.id` distintos por unidad
  (`#Alertas` vs `#Flow-correlated Alerts` del profesor).
- **Pruning** — poda de reglas ruidosas (Tabla 5).

**HIDS y configuración**
- **HIDS / NIDS** — detector basado en **host** / basado en **red**.
- **Wazuh** — HIDS libre: *manager* + *indexer* + *dashboard* + *agents*.
- **Velociraptor (VR)** — HIDS de recolección; su "detección" es un **artifact** que emite
  **filas** (perfiles P1–P4). **No es un motor de reglas**.
- **Virgen** — configuración "de fábrica": ruleset por defecto **sin reglas/artifacts propios
  ni de terceros**; la **telemetría estándar** (auditd/Sysmon) **sí** se activa (es fuente, no
  regla).
- **Config Wazuh** — `C0 = RS1` · `C1 = RS1+RS2` (virgen) · `C2 = +RS3` · `C3 = +RS4`.
- **Umbral** — `rule.level ≥ N` (Wazuh); perfiles **P4 ≤ P3 ≤ P2 ≤ P1** (VR).
- **RuleSet (RS1..RS4)** — capas de reglas: RS1 default · RS2 auditd · RS3 propias · RS4
  externas.
- **`rule.id`** — identificador de alerta en Wazuh (análogo al `SID` de Snort).
- **GHOSTS** — generador de actividad legítima (*NPCs*, CMU-SEI).

**Infraestructura y método**
- **Sysmon / auditd** — generadores de telemetría en Windows / Linux.
- **Atomic Red Team (ART)** — biblioteca de pruebas atómicas MITRE; orquestador de ataques.
- **STIX bundle** — JSON oficial con toda la matriz MITRE.
- **VM / snapshot / vmrun / SSH / Tailscale** — máquina virtual; estado al que revertir;
  herramienta de VMware por línea de comandos; acceso remoto por shell; VPN de malla
  (WireGuard) que conecta el portátil con el sobremesa.

---

## 10. Recursos (`R0 §1.1`, `§1.4`, `§1.5`)

`_recursos/` (material del profesor, **solo lectura**, no versionado):

| Ruta | Utilidad |
|---|---|
| `reuniones/02/guia_profesor.txt` + `notas_reunion.txt` | Guía rectora (vigente en lo esencial; ver §6). |
| `reuniones/03/` | Material nuevo: `notas reunion TFG.txt`, `ghost.txt`, **`Tabla 1 - Matriz MITRE Enterprise v17.xlsx`**, `Tablas 2, 3, 4, 5 (con FG-PA).xlsx`, `TFM - Velociraptor como HIDS.pdf`, `TFM_JORGE_LINARES.pdf`, `TFM_Jose_Manuel_Peña_Ramírez.pdf`, `Detección_de_Ataques_en_Red_v7.pdf`. |
| `recursos_profesor/documentacion-y-scripts-profesor/` | `Detecciones Red (Ref).xlsx` + scripts de extracción MITRE; `01_TFG4-HIDS … (obsoleto)`. |
| `recursos_profesor/repos-similares/Snort-FG-PA-…/` | TFG hermano de red: **estándar de facto** de carpetas (`Hojas/`, `Dataset/`, `Soporte/`, `BBDD/`). |
| `recursos_profesor/tfgs-similares/` | 3 TFGs hermanos en PDF. |

**Hermanos citados:** repo **NIDS**
(`ignmercam/mitre-attack-ids-detection-optimization`, **Ignacio Merchán**, mismo tutor, 2026) y
los **TFMs** de **Linares**, **Peña** y **Velociraptor** (detalle en `requirements.md` §1).

---

## 11. Referencias externas (`R0 §16`)

| URL | Para qué |
|---|---|
| https://attack.mitre.org/matrices/enterprise/ | Matriz MITRE ATT&CK Enterprise. |
| https://attack.mitre.org/resources/versions/ | Versiones de la matriz. |
| https://github.com/mitre/cti | STIX bundles oficiales. |
| https://docs.velociraptor.app/ | Documentación de Velociraptor. |
| https://documentation.wazuh.com/ | Documentación de Wazuh. |
| https://github.com/redcanaryco/atomic-red-team | Atomic Red Team. |
| https://github.com/cmu-sei/GHOSTS/ | GHOSTS (generador de actividad legítima). |
| https://github.com/ignmercam/mitre-attack-ids-detection-optimization | Repo hermano **NIDS** (referencia metodológica). |
| https://github.com/javgarbor10/Snort-FG-PA-Analisis_Capacidad_deteccion_Ataques_red | Repo del TFG hermano de red (resultados). |
| http://ait08.us.es/MVs/Alumnos/ | VMs del profesor. |
