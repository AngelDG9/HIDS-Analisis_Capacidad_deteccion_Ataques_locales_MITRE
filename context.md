# context.md — Contexto del TFG

> Documento de contexto **estable** del Trabajo Fin de Grado: qué es, el método acordado
> con el profesor, los recursos y las decisiones fijadas. El detalle operativo (tareas y
> fases) vive en `requirements.md` y `roadmap.md`; el estado vivo, en `state.md`.
>
> Fuentes principales: `_recursos/reuniones/02/guia_profesor.txt` y
> `_recursos/reuniones/02/notas_reunion.txt` (la reunión 01 es obsoleta).

---

## 1. Qué es el TFG

**Título:** *Análisis de la capacidad de detección de ataques locales de la matriz
MITRE ATT&CK Enterprise mediante HIDS.*

**Tutor:** D. F. Javier Muñoz Calle (Universidad de Sevilla, Dpto. Ingeniería Telemática).

**Línea de investigación:** el tutor ya ha dirigido TFGs sobre detección de **ataques de
red** con IDS/NIPS (Snort, FortiGate, Palo Alto) y uno sobre **entornos ICS**. Este trabajo
es el paso siguiente: del dominio **red** al dominio **host/local** y del IDS/NIPS al
**HIDS**.

**Objetivo** (`guia_profesor.txt:3`):
> Realizar ataques locales y analizar la capacidad de detección con HIDS (OSSEC, Sagan,
> Splunk, Samhain, ...) y herramientas de extracción/análisis de logs.

**HIDS a evaluar:**
1. **Wazuh** — el núcleo del trabajo. Se cierra Wazuh de extremo a extremo antes de nada más.
2. **Velociraptor** y **un tercero** (OSSEC/Sagan/Splunk/Samhain) — **extras**: solo si
   sobra tiempo. No se mezclan HIDS a la vez.

**Entregable final:** una **tabla por técnica/subtécnica** (análoga a la "Tabla Ataques"
de los TFGs hermanos) que cuantifique la capacidad de detección de cada HIDS frente a un
corpus reproducible de ataques locales mapeados a MITRE ATT&CK Enterprise.

---

## 2. Método del profesor

### Paso 1 — Identificar técnicas MITRE válidas
Se consideran válidas las técnicas/subtécnicas:
- **Solo Host** (exclusivamente locales), o
- **Híbridas Host/Red** (tienen una parte local aprovechable).

**Filtro inverso** (lo que NO entra): las técnicas cuyo **único** Data Component sea de red
pura — `Network Connection Creation`, `Network Traffic Content`, `Network Traffic Flow`.
`Network Share Access` e `Internet Scan: Response Content/Metadata` **no** otorgan elegibilidad (pero **no** anulan una técnica con telemetría host).

### Paso 2 — Implementar los ataques
Localizar y usar las herramientas necesarias; capturar el proceso; guardar evidencias
(logs, procesos). Cobertura por prioridad: **Tácticas → Técnicas → Subtécnicas**.

### Paso 3 — Detección con HIDS OpenSource
1º Wazuh · 2º Velociraptor · 3º otro (OSSEC, Sagan, Splunk, Samhain...).

### Paso 4 — Análisis de resultados
Metodología heredada de los TFGs hermanos (tabla de detecciones, métricas, criterios).

### Prioridad de los ataques
El profesor pide centrarse en (`guia_profesor.txt:37-46`):
- **Ransomware**
- **Exfiltración** (envío masivo de ficheros)
- **Sabotaje** (borrado de ficheros de sistema)

### Notas de la tutoría
- Iterar añadiendo 1 técnica por táctica hasta un buen conjunto.
- Sistema víctima según la técnica: Linux, Windows o ambos (si ambos, **Linux** por comodidad).
- Todo en **VM** orquestadas con **VMware**.
- **Modo detección-only**: el HIDS nunca bloquea, solo detecta.
- Valorar el **precio de la detección** (monitorizar CPU/memoria durante ataque y detección).

---

## 3. Decisiones fijadas

| Tema | Decisión |
|---|---|
| HIDS | **Wazuh** como núcleo. Velociraptor / tercero / Snort = extras. |
| Corpus | **12-15 técnicas**, 1-2 por táctica, foco Ransomware/Exfiltración/Sabotaje. |
| RuleSets | **4** (RS1 default → RS4 + externas), clasificando las alertas por origen sin repetir el ataque. |
| Baseline | 2 ventanas × 4 h de actividad legítima (VM en segundo plano). |
| Validación | Cada ataque se ejecuta **dos veces** (snapshot fresco); si difieren las alertas, `review=true`. |
| SO víctima | **Linux primero**; Windows cuando una técnica lo exija. |
| Orquestador de ataques | **Atomic Red Team** (tests atómicos por técnica); script custom si no cubre. |
| Laboratorio | VMware en el **sobremesa** (16 GB), red **host-only**. Los **agentes (opencode) corren en el sobremesa**, junto a las VMs. |
| Acceso | El **portátil** (8 GB) controla el sobremesa por **SSH sobre Tailscale**; los agentes, ya en el sobremesa, acceden a las VMs por la red host-only. |
| Métrica | **η = √(CD·(1−FP))** (heredada). |
| Identificador de ataque | **ATA<NNN>** (`ATA001`, `ATA002`, ...). |
| Base de datos | **SQLite** (portada del diseño de los TFGs hermanos). |
| Técnicas de captura | `rule.id` de Wazuh (análogo al `SID` de Snort). |
| Git | Se trabaja en local. **`git push` lo hace el humano**, nunca los agentes. |

> **Nota (corpus actual):** la selección vigente son **13 técnicas** (7 Impact / 3 Exfiltration /
> 3 Collection), que **no** sigue el "1-2 por táctica"; la variedad por táctica queda **pendiente
> de comentar con el tutor** (hito H1).

---

## 4. Glosario

- **MITRE ATT&CK Enterprise** — catálogo público de tácticas/técnicas de ataque sobre
  ordenadores. Versión vigente: **v19.1**.
- **Táctica** — fase del ataque (p. ej. *Execution*). **Técnica** — el "cómo" (p. ej.
  `T1486`, ransomware). **Subtécnica** — refinamiento (`T1486.001`).
- **Data Component** — fuente de telemetría necesaria para detectar (proceso, fichero,
  registro, red...). Antes se llamaban *Data Sources*.
- **HIDS / NIDS** — detector basado en host / basado en red (Snort).
- **Wazuh** — HIDS libre: *manager* (decide) + *indexer* (guarda/busca) + *dashboard* (web)
  + *agents* (en cada máquina vigilada).
- **Sysmon / auditd** — generadores de telemetría en Windows / Linux.
- **TP / FP** — alerta que sí es el ataque / alerta por actividad normal (ruido).
- **CD** — capacidad de detección. **η** — rendimiento combinado (ver §3).
- **Baseline legítimo** — grabación de actividad normal para identificar el ruido.
- **RuleSet** — conjunto de reglas de detección activas.
- **Atomic Red Team** — biblioteca de scripts que reproducen técnicas MITRE.
- **STIX bundle** — fichero oficial JSON con toda la matriz MITRE.
- **VM / snapshot / vmrun / SSH** — máquina virtual; estado guardado al que revertir;
  herramienta de VMware por línea de comandos; acceso remoto por shell.
- **Tailscale** — VPN de malla (WireGuard) que conecta el portátil con el sobremesa para el
  acceso remoto.
- **ATA<NNN>** — identificador único de cada ataque del corpus.

---

## 5. Recursos

`_recursos/` (material del profesor, **solo lectura**, no versionado):

| Ruta | Utilidad |
|---|---|
| `reuniones/02/guia_profesor.txt` | Guía oficial (referencia rectora). |
| `reuniones/02/notas_reunion.txt` | Notas del alumno sobre la reunión. |
| `recursos_profesor/documentacion-y-scripts-profesor/` | Excels y scripts previos (extracción automática de técnicas MITRE, `Detecciones Red (Ref).xlsx`). **Muy reutilizables.** |
| `recursos_profesor/repos-similares/Snort-FG-PA-.../` | Repo GitHub del TFG hermano de red: **estándar de facto** a imitar en host. |
| `recursos_profesor/tfgs-similares/` | 3 TFGs hermanos en PDF. |

---

## 6. Referencias externas

| URL | Para qué |
|---|---|
| https://attack.mitre.org/matrices/enterprise/ | Matriz MITRE ATT&CK Enterprise. |
| https://attack.mitre.org/resources/versions/ | Versiones de la matriz. |
| https://github.com/mitre/cti | STIX bundles oficiales. |
| https://docs.velociraptor.app/ | Documentación de Velociraptor. |
| https://github.com/redcanaryco/atomic-red-team | Orquestador de ataques atómicos. |
| https://github.com/javgarbor10/Snort-FG-PA-Analisis_Capacidad_deteccion_Ataques_red | Repo del TFG hermano (resultados). |
| http://ait08.us.es/MVs/Alumnos/ | VMs del profesor. |
