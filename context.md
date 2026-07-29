# context.md — Contexto del TFG

> Documento "single source of truth" del Trabajo Fin de Grado. Recoge el objetivo, la
> metodología acordada con el tutor, los recursos disponibles y el conocimiento extraído
> del análisis previo del repositorio. Cualquier decisión o cambio de rumbo debería
> reflejarse aquí primero.
>
> Referencias clave de donde sale este contexto:
> - `_recursos/reuniones/02/guia_profesor.txt` — guía oficial escrita por el profesor.
> - `_recursos/reuniones/02/notas_reunion.txt` — notas del alumno sobre la reunión 02.
>   (La "reunión 01" está en `_recursos/reuniones/01 (obsoleto)/` y **se considera
>   obsoleta**: no se tendrá en cuenta salvo contradicción expresa con la 02.)
> - `_recursos/recursos_profesor/documentacion-y-scripts-profesor/...` — scripts y
>   excels del profesor reutilizables.
> - `_recursos/recursos_profesor/repos-similares/Snort-FG-PA-Analisis_Capacidad_deteccion_Ataques_red/`
>   — repo de GitHub de un TFG anterior (línea de investigación del mismo tutor).
> - `_recursos/recursos_profesor/tfgs-similares/` — 3 TFGs PDF de antiguos alumnos.

---

## 1. Qué es el TFG

### 1.1 Motivo y título
Título provisional: **"Análisis de la capacidad de detección de ataques locales de la
matriz MITRE ATT&CK Enterprise mediante HIDS"**.

Objetivo de alto nivel, en palabras del profesor (`guia_profesor.txt:3`):
> *Realizar ataques locales y analizar la capacidad de detección con HIDS (OSSEC, Sagan,
> Splunk, Samhain, ...) y herramientas de extracción/análisis de logs.*

Es decir, este TFG se inscribe en una **línea de investigación del tutor** (D. F. Javier
Muñoz Calle, Universidad de Sevilla, Dpto. Ingeniería Telemática) que ya ha producido
varios TFGs hermanos sobre detección de **ataques de red** con IDS/NIPS (Snort, FortiGate,
Palo Alto) y otro sobre detección en **entornos ICS**. Nuestro trabajo es el siguiente
punto de la línea: pasar del dominio de red al dominio **host/local** y del IDS/NIPS al
**HIDS**.

### 1.2 HIDS a evaluar (por orden)
1. **Wazuh** — el más importante. **Por ahora el TFG se centra exclusivamente en Wazuh**
   hasta tener un primer cuerpo de resultados consolidado.
2. **Velociraptor** — el segundo. El profesor avisó que en cuanto se publique un TFG
   paralelo que estudia Velociraptor nos mandará la info (`notas_reunion.txt:13`).
3. **Un tercero a elegir por el alumno** basándonos en relevancia, entre: **OSSEC, Sagan,
   Splunk, Samhain, ...** (`guia_profesor.txt:29`, `notas_reunion.txt:13`).

Solo se trabaja con un HIDS a la vez; no se mezclan a la vez.

### 1.3 Apartado extra opcional (valorado positivamente)
Análisis de ataques locales con **Snort (NIDS)** mediante análisis de logs de servidores
(p. ej. "escalado de privilegios"). Idea: usar una herramienta que convierta el log del
servidor en "pcap" y comprobar si Snort es capaz de detectarlo. Es secundario, **sin
profundidad** (`notas_reunion.txt:14`, `guia_profesor.txt:30-32`).
Herramienta de análisis de logs de equipos mencionada por el profesor: **ait-aecid**.

### 1.4 Qué se quiere entregar al final
Una **tabla final por técnica/subtécnica** (análoga a la "Tabla Ataques" de los TFGs
hermanos) que cuantifique la **capacidad de detección** de cada HIDS frente a un corpus
reproducible de ataques locales mapeados a MITRE ATT&CK Enterprise. El objetivo final
declarado por el profesor es llegar a cubrir **Tácticas → Técnicas → Subtécnicas**, en
ese orden de prioridad (`guia_profesor.txt:21-24`).

---

## 2. Metodología oficial definida por el profesor

Definida en `guia_profesor.txt:5-34`. Respeto textualmente el esquema porque es la guía
oficial:

### Paso 1 — Identificar técnicas MITRE válidas
Identificar las técnicas MITRE ATT&CK Enterprise que sean:
- **Solo Host** (exclusivamente locales), o
- **Híbridas Host/Traffic network** (tienen parte local aprovechable).

Filtro de exclusión dentro de las que "tocan red" (`guia_profesor.txt:7-14`):

| v17 (Datasources) | v19 (Datacomponents)                 | ¿IDS? |
|-------------------|--------------------------------------|-------|
| Network Traffic    | Network Connection Creation, Network Traffic Content y Network Traffic Flow | **Sí** |
| Network Share      | Network Share Access                 | No — supervisión de acceso a recursos compartidos, fuera del objetivo de un IDS |
| Internet Scan      | Response Content y Response Metadata | No — sondeos hechos por nosotros, no detección del atacante; fuera del objetivo de un IDS |

Por tanto, **las técnicas/subtécnicas EXCLUSIVAMENTE basadas en** `Network Connection
Creation`, `Network Traffic Content`, `Network Traffic Flow` **no entran** en el corpus
del TFG (son Nat IDS de red). Sí entran las técnicas puramente host y las híbridas donde
la parte host sea aprovechable para detección HIDS.

> Nota terminológica MITRE v17→v18/v19:
> - `Datasources` (v17.1) ≡ `Datacomponents` (v18+).
> - El campo MITRE "Detection" lista para cada técnica los Data Components en los que se
>   apoya la detección. Es en ese campo donde miramos si aparece *Network Connection
>   Creation* etc. (fuente: `_recursos/recursos_profesor/documentacion-y-scripts-profesor/MITRE/0MITRE-Tecnicas_detectables_por_Red.txt`).

### Paso 2 — Implementar los ataques
- Localizar y usar las **herramientas de ataque necesarias**. Ejemplos del profesor:
  Tripwire, IoC (Cuckoo, ...), análisis de logs (kyoushi-environment, ...).
- **Capturar el ataque**: el proceso.
- **Guardar evidencias**: logs generados, etc.
- **Dimensionar según dificultad**.
- Objetivos por orden: 1º Tácticas · 2º Técnicas · 3º Subtécnicas.

### Paso 3 — Detección con HIDS OpenSource
- 1º **Wazuh**.
- 2º **Velociraptor** (`https://docs.velociraptor.app/`).
- 3º Otras opciones: OSSEC, Sagan, Splunk, Samhain, ...
- 3º (extra) Snort convirtiendo logs de servidor en pcap.

### Paso 4 — Análisis de resultados
Sin más detalle por parte del profesor; es donde entra la metodología de los TFGs
hermanos (ver §6).

### Mensaje adicional del profesor (importante)
Selección de técnicas principalmente enfocada a tres tipos de ataque (`guia_profesor.txt:37-46`):

- **Ransomware**
- **Exfiltración** (envío masivo de ficheros, ...)
- **Sabotaje** (borrado de ficheros de sistema, ...)

### Notas adicionales del alumno (reunión 02, `notas_reunion.txt`)
- **Iteración**: ir añadiendo 1 técnica/subtécnica por cada táctica e iterar hasta un buen
  conjunto.
- **Sistema víctima**: función de la técnica — Linux, Windows o ambos. Si ambos, preferir
  Linux por comodidad. Todo en **VM** (orquestadas con **VMWare**). El profesor da acceso
  a VMs en `http://ait08.us.es/MVs/Alumnos/`.
- **Modo detección-only**: configurar el HIDS para que **no bloquee** los ataques, solo
  detecte. Probablemente **durante el ataque** (no post-ataque).
- **Precio de la detección**: aunque no se mencionó en la tutoría, se valorará
  positivamente **monitorizar el rendimiento** (CPU, memoria, ...) **durante ataque y
  detección** (`notas_reunion.txt:16`).
- **Misma matriz MITRE ya da guías** de qué herramientas usar y cómo implementar los
  ataques — muy útiles (`notas_reunion.txt:10`).
- Material auxiliar valioso en `_recursos/recursos_profesor/documentacion-y-scripts-profesor/`:
  scripts previos del profesor capaces de extraer qué técnicas/subtécnicas son solo de
  red. Reutilizable para la matriz v18/v19 (comprobarlo) y se pueden reaprovechar muchas
  cosas (`notas_reunion.txt:5`).

### Roadmap provisional del alumno (no vinculante, `notas_reunion.txt:20-126`)
Plan "30 TEC" para asegurar 30 técnicas. Líneas maestras que sí se van a aplicar:
1) Estudiar otros TFGs y el propio.
2) Estudiar flujos de trabajo y tareas clave.
3) Crear infraestructura IA para automatizar esos flujos.

Bloques del roadmap (con pinzas, puede cambiar):
- Preparación de zona de trabajo (repo, context.md, requirements.md, roadmap.md).
- **Lista de técnicas válidas**: estudiar scripts existentes → adaptar script a la nueva
  matriz + filtrado inverso por los que NO sean exclusivamente *Network Traffic* → lista
  human-legible → priorizar por ransomware/exfiltración/sabotaje.
- **Preparado de laboratorio**: VMs, elección y configuración para fácil acceso con IA.
- **Preparado de flujos/procesos**: idea de construir infraestructura sólida basada en IA
  que automatice lo automatizable. Flujos definidos:
  - *Flujo de Ataque con IA* — diseño y ejecución de ataques con IA, modus operandi,
    elección/config de herramientas, payloads, replicables.
  - *Flujo de Análisis con IA* — guardado de evidencias (logs, procesos) gestionado por
    IA; monitorización de rendimiento.
  - *Flujo de Detección con IA* — preparación del HIDS y captura de lo que detecta.
  - *Flujo de Registro/Orquestación con IA "El Agente"* — orquesta los demás y guarda
    registros de todo (scripts, configs, evidencias, salida del HIDS) para análisis final
    y redacción final. Limpiar/rollback post-técnica, entornos estériles.
- Primeras 5 técnicas.

---

## 3. Recursos disponibles en el repositorio

### 3.1 Guion y notas oficiales
- `_recursos/reuniones/02/guia_profesor.txt` — guía del profesor (la referencia
  principal). También hay un vídeo de la reunión (`_recursos/reuniones/02/tfg-02.mp4`).
- `_recursos/reuniones/02/notas_reunion.txt` — notas del alumno sobre el vídeo.
- `_recursos/reuniones/01 (obsoleto)/` — reunión anterior **obsoleta**; se ignora salvo
  contradicción expresa con la 02.

### 3.2 Documentación y scripts del profesor
`_recursos/recursos_profesor/documentacion-y-scripts-profesor/`:

| Ruta | Descripción / utilidad |
|------|------------------------|
| `01_TFG4-HIDS (...)` (txt) | Guía del profesor para un TFG propuesto (VelociRaptor + FortiEDR). **Documento auxiliar histórico — su contenido está desfasado**; la referencia rectora del TFG es siempre `guia_profesor.txt` de la reunión 02. Se cita aquí solo como antecedente del mismo tutor. |
| `Detecciones Red (Ref).xlsx` | Excel de referencia con la estructura de la "Tabla Ataques" de los TFGs hermanos (red). Sirve de plantilla de columnas. |
| `MITRE/0MITRE (Matriz y Buscador).txt` | URLs oficiales de la matriz MITRE Enterprise (v16/v17/v18) y del MITRE ATT&CK Navigator. Aviso: en el Navigator, aunque ponga "Techniques", el total que muestra es "Técnicas + Subtécnicas". **Versión vigente a la fecha del TFG: v19.1 (abril 2026)**; los excels del profesor llegan hasta v18 y el script se adaptará a v19. |
| `MITRE/0MITRE-Tecnicas_detectables_por_Red.txt` | Mapeo datasources v17 ↔ datacomponents v18+. Lista explícita de `Network Traffic` (Sí IDS), `Network Share` (No) e `Internet Scan` (No). Incluye relación `Data Source <=> Data Component` lista para v18 y enlaces a *Detection Strategies*. **Es el criterio de filtrado a invertir**. |
| `MITRE/Extraccion automatica Tacticas-Tecnicas de web MITRE/` | **Scripts + Excels del TFG previo del profesor que extraen automáticamente las técnicas/tácticas MITRE de la web.** Versiones `TechniquesTactics_v15 … v18` (la v18 lleva fecha 02-11-2025, la más reciente). Incluye `TechniquesTacticsMitre (Codigo).zip` con el código y un `changes.txt`. **Muy reutilizable**: se adaptará a la versión vigente (v19.1) usando el bundle STIX oficial como fuente primaria en lugar del scraping web, y se le aplicará el filtro inverso (técnicas NO exclusivamente Network Traffic, o con componente host aprovechable). |

### 3.3 Repositorios similares
`_recursos/recursos_profesor/repos-similares/Snort-FG-PA-Analisis_Capacidad_deteccion_Ataques_red/`
— Repo de GitHub (TFG anterior de la misma línea de investigación). Estudia la capacidad
de detección de Snort + FortiGate + PaloAlto contra **todas** las técnicas de red de la
matriz MITRE ATT&CK. Es nuestro **estándar de facto** a replicar en el dominio host.

Estructura clave:
```
BBDD/        → esquema SQL + CSV (HyperSQL; en este TFG usaremos SQLite)
Dataset/     → Ataques/{PCAPS, Resultados/{IDS}/CSV+Logs}/ y Legítimo/...
Estudio-XX/  → carpetas ejecutivas: completamenteDetectados/, noDetectados/, Grafica*.jpg
Hojas/       → Detecciones.xlsx + Mapeos.xlsx (la "Tabla Ataques" final, ~250 columnas)
Soporte/     → Ataques/{capturas,ficheros}/T<id>/, IDS/{Configuracion,Reglas,Scripts}/
VerificacionFG/ → experimento de robustez a distintas tasas (Resumen.csv)
```
Detalle en profundidad en §6.

### 3.4 TFGs similares (PDF)
`_recursos/recursos_profesor/tfgs-similares/`:

- **García Borja, Javier** (`García Borja, Javier _G5425.pdf`) — 2024. *"Análisis de la
  capacidad de detección de ataques en red mediante los IDS Snort y FortiGate"*. 137
  PCAPs, cobertura 100% técnicas / 50% subtécnicas detectables por red. Define la
  **Tabla Resumen de Criterios** (Tabla 5-1) y la métrica de **Rendimiento**
  **η = √(CD·(1−FP))**. FortiGate casi sin FP; Snort necesita integrar RuleSets externos
  (Emerging Threats) para llegar al máximo.
- **Meléndez Casado, Andrés** (`Melendez Casado, Andrés_G5479.pdf`) — 2025. *"... IDS
  Snort, FortiGate y Palo Alto NGFW en entornos ICS bajo la matriz MITRE ATT&CK"*. 72
  ataques, 10/12 tácticas (faltan Evasion y Persistence por limitaciones de recursos).
  Introduce el patrón por ataque **"Equipo Víctima / Atacante / Ejecución / Validación"**,
  el **baseline legítimo SWaT** para entrenar el procedimiento automático de FP, y un
  Anexo E "Dificultades encontradas".
- **Moreno Pérez, Alejandro** (`Moreno Pérez, Alejandro_G5469.pdf`) — 2025. *"Análisis de
  la capacidad de detección de ataques en red mediante el IDS Snort y PaloAlto NGFW"*.
  Usa un **script Python para filtrar las técnicas MITRE por "Network Traffic"** (patrón
  de script que necesitamos, pero invertido), y emplea **MITRE Caldera** como
  orquestador de pruebas atómicas — muy transferible a nuestro escenario host.

Patrones comunes (esqueleto de memoria a imitar):
Intro → Base teórica (MITRE + HIDS) → Realización de ataques por táctica → Análisis de
detecciones → Resultados (Excel Detecciones + Excel Mapeos + BBDD + Criterios) →
Conclusiones + Líneas → Anexos (Instalación, Validación, GitHub, BBDD, **Tabla Resumen de
Ataques**).

---

## 4. Glosario crítico (porque se mezclan versiones y términos)

- **MITRE ATT&CK Enterprise** — la matriz con la que trabajamos. Cubre tácticas post-
  compromiso (Initial Access → Exfiltration/Impact). No ICS, no Mobile, no Cloud.
- **Táctica** — la "columna" de la matriz (fase del kill chain). P. ej. TA0008
  *Execution*.
- **Técnica** — el "qué hace el atacante" dentro de una táctica. P. ej. T1059
  *Command and Scripting Interpreter*.
- **Subtécnica** — refinamiento de una técnica. P. ej. T1059.001 *PowerShell*.
- **Data Source / Data Component** — en MITRE, de dónde sale la telemetría para
  detectar la técnica. v17 los llamaba *Data Sources*; v18+ los llama *Data Components*.
  Los que nos interesan para HIDS: `Process`, `File`, `Command`, `Windows Registry`,
  `Driver`, `WMI`, `Sysmon`, `Network` (en su parte local), etc. Los que **no**
  aprovechamos como exclusivos: `Network Connection Creation`, `Network Traffic Content`,
  `Network Traffic Flow`. Los que **descartamos** del todo: `Network Share Access`,
  `Internet Scan: Response Content`, `Internet Scan: Response Metadata`.
- **HIDS** — Host-based IDS: audita logs/eventos del propio equipo (endpoint/Host).
- **NIDS** — Network-based IDS: audita tráfico de red (Snort). Es el dominio de los TFGs
  hermanos.
- **FP/TP** — Falso Positivo / Verdadero Positivo. El procedimiento dual manual +
  automático es el estándar de la línea.
- **η = √(CD·(1−FP))** — Rendimiento combinado (Capacidad de Detección y (1 − tasa de
  FP)). Métrica heredada; la usaremos para comparar HIDS.

---

## 5. Recursos externos (URLs) que el profesor ha dado

| URL | Para qué |
|-----|----------|
| https://attack.mitre.org/matrices/enterprise/ | Matriz MITRE ATT&CK Enterprise. |
| https://attack.mitre.org/resources/versions/ | Versiones de la matriz (v16, v17, v18, ...). |
| https://attack.mitre.org/datasources/ y https://attack.mitre.org/versions/v18/datacomponents/ | Data Sources / Data Components (clave del filtro). |
| https://attack.mitre.org/detectionstrategies/ | Detection Strategies. |
| https://mitre-attack.github.io/attack-navigator/ | MITRE ATT&CK Navigator. Aviso: aunque ponga "Techniques", el total que muestra es "Técnicas + Subtécnicas". |
| https://docs.velociraptor.app/ | Documentación de Velociraptor. |
| https://idus.us.es/items/475282dd-3bcf-4bff-8964-44ebc36e361d | TFG "Snort + FG" (García Borja). |
| https://idus.us.es/items/420fa825-1184-4a94-b55c-18207e6c2852 | TFG "Snort + PA (+ FG)" (Moreno Pérez). |
| https://idus.us.es/items/ebf43169-5ace-462c-803c-12751eb8c21d | TFG ICS (Meléndez Casado). |
| https://github.com/javgarbor10/Snort-FG-PA-Analisis_Capacidad_deteccion_Ataques_red | Repo GitHub con los resultados (copia local en `repos-similares/`). |
| http://ait08.us.es/MVs/Alumnos/ | VMs del profesor accesibles para los alumnos. |

---

## 6. Conocimiento extraído del análisis previo (lecciones de los TFGs hermanos)

> Esta sección resume lo aprendido al leer el repo Snort-FG-PA y los 3 PDFs. Es la base
> para diseñar nuestro requirements.md, roadmap.md y la estructura del repo. **Todo
> aquí se puede revisar** — el alumno decide lo que aplica.

### 6.1 Esqueleto del repo ideal (patrón del repo Snort-FG-PA, trasladado a HIDS)
```
<repo>/
├── README.md                              # portada + índice a context/requirements/roadmap
├── Diario.md                              # bitácora personal del alumno (append-only)
├── context.md                             # este archivo (single source of truth)
├── requirements.md                        # requisitos, tareas, flujos
├── roadmap.md                             # secuenciación temporal
├── _recursos/                             # recursos del profesor (read-only)
├── _artefactos/
│   ├── mitre/{enterprise-attack-v19.1.json}
│   ├── scripts/{extraer_tecnicas_host.py, orquestador/}
│   └── ia/
│       ├── skills/{ataque,deteccion,agregacion,orquestacion}.md
│       ├── prompts/
│       └── config_opencode.md
├── BBDD/{SQL,CSV,Scripts,README.md}      # réplica en SQLite (no HyperSQL)
├── Dataset/
│   ├── Ataques/
│   │   ├── Comandos/T<id>-<desc>/         # artefactos del ataque (PS1/bash/payloads)
│   │   └── Resultados/{Wazuh,Velociraptor}/{CSV,Logs}/
│   └── Legitimo/                          # baseline de actividad legítima del endpoint
├── Estudio-Wazuh/                         # carpeta ejecutiva (igual que Estudio-FG/PA)
│   ├── completamenteDetectados/
│   ├── noDetectados/
│   ├── ataques_completamente_detectados_Wazuh.{csv,xlsx,txt}
│   └── Grafica*.jpg
├── Estudio-Velociraptor/                  # idem
├── Hojas/
│   ├── Detecciones.xlsx                   # "Tabla Ataques" final (~250 columnas adaptadas)
│   ├── Mapeos.xlsx                        # matriz MITRE completa con flags
│   └── README.md
├── Soporte/
│   ├── Ataques/{capturas/T<id>/, ficheros/T<id>/}
│   ├── Laboratorio/{topologia.png, vmrun_config.md, ssh_setup.md, README.md}
│   ├── Wazuh/{Configuracion, Rules, Scripts, README.md}
│   ├── Velociraptor/{Scripts, README.md}
│   └── Otros/                             # utilidades
└── VerificacionWazuh/                     # experimento de robustez
```

### 6.2 Tabla "Detecciones" (nuestra "Tabla Ataques")
Adaptación de `Hojas/Detecciones.xlsx` del repo Snort-FG-PA. Bloques de columnas:

- **(A) Caracterización MITRE**: TÁCTICA · ID TÁCTICA · TÉCNICA · ID TÉCNICA ·
  SUBTÉCNICA · ID SUBTÉCNICA · ATAQUE · HERRAMIENTA.
- **(B) Caracterización del ataque host** (equivalente a "caracterización del tráfico"
  pero en host): Nº total de procesos generados · Nº de hijos · Nº de ficheros tocados ·
  Nº de claves de registro · Nº de conexiones outbound · Nº de eventos generados ·
  ATAQUES COLATERALES · EXPLICACIÓN.
- **(C) Detectabilidad/Implementación**: DETECTABLE POR PATRONES (endpoint) ·
  MECANISMO DE DETECCIÓN · DETALLES DE IMPLEMENTACIÓN · PROCESO DE GENERACIÓN ·
  VALIDACIÓN DE EJECUCIÓN DEL ATAQUE · FORMATO DE LOG (✔/✘) · DETECTABILIDAD ·
  VERIFICACIÓN DE INTEGRIDAD DEL ARTIFACTO (✔/✘).
- **(D) Categorización de contexto**: NIVEL DE ATAQUE (Contexto) = **LV1/LV2**
  (LV1 = siempre ataque; LV2 = puede confundirse con actividad legítima del endpoint) ·
  JUSTIFICACIÓN LV · NIVEL DE ATAQUE (Tipo de telemetría): actividad de sistema /
  actividad de usuario / actividad de red del host.
- **(E) Wazuh** (un bloque por configuración de reglas, análogo a los RuleSets RS1–RS4
  de Snort):
  - `rule.id` distintos · `#rule.id` · número total de alertas
  - `rule.id` en legítimo y ataque · `rule.id` TP (Automático) · `#rule.id TP` ·
    Nº total de alertas TP (Automático)
  - `rule.id` FP (Manual/Automático) · `rule.id` FP "No Relacionados" ·
    `rule.id` FP "Eventos de sistema"
  - `rule.id` TP "Todas/Algunas Alertas" (Manual) · `#rule.id TP (Manual)` ·
    Nº total de alertas (Manual)
  - Nº TOTAL DE EVENTOS DETECTADOS · Nº DE PROCESOS CON ATAQUE DETECTADOS ·
    Nº DE INSTANCIAS (ATAQUES) DETECTADOS
  - Porcentajes: % DETECCIÓN EVENTOS · % DETECCIÓN PROCESOS · % DETECCIÓN ATAQUES ·
    % DETECCIÓN EFICAZ (Manual)
  - ANÁLISIS MANUAL REALIZADO (✔/✘) · COMENTARIOS DE LAS DETECCIONES WAZUH.
- **(F) Velociraptor** (análogo usando artifact+result en vez de `rule.id`).
- **(G) (Tercer HIDS)**.
- **(H) Cierre**: USADO PARA CÁLCULO DE CAPACIDAD DE DETECCIÓN (✔/✘) — flag que excluye
  del análisis final a ataques con problemas.

### 6.3 Tabla "Mapeos"
Adaptación de `Hojas/Mapeos.xlsx`. Pestañas:
- **(A)** Tabla binaria Táctica × Técnica con ✔.
- **(B)** Idem con Subtécnicas.
- **(C)** Tabla MITRE completa con flags: `Implementada · Detectable por Host/Endpoint ·
  Sólo Detectable por Host · Detectable mediante patrones (host) · Mecanismo de detección`.
  (En el repo de red usaban `Detectable por Red`; aquí invertido a host.)
- **(D)** Recuentos implementadas / no implementadas por táctica + total.

### 6.4 Procedimiento dual TP/FP (clave; lo heredamos y automatizamos con IA)
1. **Fase I — Entrenamiento**: grabar actividad **legítima** del endpoint (sysmon + Wazuh
   agent en VM limpia, usuario navegando/ofimática/scripts durante horas). Se obtiene el
   banco de `rule.id` que aparecen en legítimo. Cualquier `rule.id` que salga **en ambos**
   (legítimo y ataque) se marca **automáticamente como FP**.
2. **Fase II — Trabajo sobre ataque**: las alertas supervivientes al filtro automático se
   etiquetan en dos pasos:
   1. **Agente IA etiqueta** (T-15 AUTO): aplicando las heurísticas de
      `Soporte/Wazuh/Scripts/criterios_etiquetado.md` (T-23) produce
      `ATA<NNN>-AutoTagged.csv` con `rule.id, etiqueta, justificacion, confianza`
      (etiquetas: `TP` / `FP No Relacionado` / `FP Eventos de Sistema`, análogos a los
      "Eventos de red" de los TFGs de red).
   2. **Alumno audita** (T-15 HUMANO): revisa `AutoTagged.csv`, corrige los de baja
      confianza o disconformes y firma `ATA<NNN>-Audited.csv`. **η final se calcula
      exclusivamente sobre `Audited.csv`.**

Equivalente script del repo hermano: `Soporte/Snort/Scripts/filtradoTPv4.py`
(filtra SIDs presentes en legítimo). Lo reimplementaremos para `rule.id` de Wazuh.

### 6.5 Métricas y criterios de análisis (Tabla Resumen de Criterios)
Adaptación de la "Tabla 5-1" de García Borja / "Tabla 6-1" de Moreno:
- Fuente de Alertas · Proc. Identificación Alertas y FP · Densidad · Efectividad
- Detección a nivel de **procesos / eventos / instancias (ataques)** (en los TFGs de red
  era flujos/mensajes/instancias)
- Tipo de ataque (proceso/archivo/registro/red-local)
- **LV1/LV2** (contexto) · L2/L3 → en host equivaldría a "rastro en SO vs rastro en red
  del host"
- **Principal/Colateral** (un mismo ataque genera eventos laterales; muy útil en HIDS)
- **Detecciones Reales vs Eficaces**
- **Rendimiento η = √(CD·(1−FP))**
- **Grado de Implementación** (% tácticas / % técnicas / % subtécnicas cubiertas)

### 6.6 Identificador único de ataque
Patrón compartido por los 3 TFGs: código **ATANNN** por ataque (ATA1…ATA137 en red).
Nosotros adoptaremos el mismo: **ATANNN** secuencial por ataque, citado en logs, reglas,
CSV, Excel y memoria. Sirve para trazabilidad ante el tribunal.

### 6.7 Naming de artefactos
Patrón del repo hermano: `T<id>[-<sub>]-<descriptor>_<fuente>[-FIX]`.
Ejemplos nuestros (inventados): `T1486-DataEncrypted-RansomwareSim_[PowerCat].ps1`,
`T1567.002-ExfilOverFTP_[AtomicRedTeam].yaml`. Sufijo `-FIX` para artefactos
"reparados/corregidos" (en host tendrá menos sentido; lo dejamos reservado).

### 6.8 Orquestación y robustez
El repo hermano tiene dos patrones trasladables:
- **Doble iteración del experimento**: lanzar el ataque dos veces y comparar número de
  alertas (`fg.sh:28-32`). Si difieren, marca el caso para revisión. Barato y muy
  convincente para el tribunal. Lo aplicaremos con Wazuh.
- **Experimento de validación de robustez**: `VerificacionFG/` repite 3 pcaps a 7 tasas
  distintas (0,1 / 1 / 10 / 100 / 1000 / 10000 Mbps y MAX) e informa de `attackids`
  distintos + alertas totales. Nuestro análogo `VerificacionWazuh/` medirá `rule.id`
  distintos y alertas totales a distintas cargas del host (idle / ofimática / compilar /
  estrés de procesos) para ilustrar si Wazuh pierde alertas.

### 6.9 Orquestador de ataques atómicos locales (fijado)
De los 3 TFGs, **Moreno Pérez** ya usa **MITRE Caldera** con éxito para emular ataques y
**Meléndez** lo cita como línea futura. Para nuestro TFG **fijamos** como orquestador
**Atomic Red Team** (`https://github.com/redcanaryco/atomic-red-team`): tests atómicos
aislados por técnica MITRE en PS1/bash/YAML, ligerísimos y scripteables por SSH. Es lo
que permite que el agente Opencode lance ataques automáticamente (ver §3.A de
`requirements.md`). Para técnicas no cubiertas por Atomic Red Team se creará un script
custom equivalente mapeado a la técnica.

### 6.10 Estructura de la memoria (a imitar)
Portada → Agradecimientos → Resumen/Abstract → Índice / Índice de Tablas / Índice de
Figuras / Notación → Introducción (Motivación + Objetivos + Estado del Arte + Metodología
en 4 fases) → Base teórica (MITRE + HIDS: Wazuh, Velociraptor, Sysmon, OSSEC...) →
Realización de ataques locales por táctica → Análisis de detecciones por táctica/técnica
→ Resultados (Excel/BBDD/Criterios/HIDS/Balance) → Conclusiones y Líneas de continuación
→ Anexos (Instalación, Validación, GitHub, BBDD, **Tabla Resumen de Ataques**,
Dificultades).

Anexos a recordar:
- Anexo de Instalación (manager Wazuh, agent Wazuh, Velociraptor server/agent, Sysmon).
- Anexo de Validación (por cada ATANNN, evidencias de que el ataque se ejecutó y de que
  el log/alerta coincide con el evento esperado).
- Anexo de Dificultades (ruido de Sysmon, retardo en indexado de Wazuh, evasiones por
  OPSEC, falsos por procesos legítimos...).
- Anexo de **Tabla Resumen de Ataques** (columnas: Táctica · ID Táctica · Técnica ·
  ID Técnica · Subtécnica · ID Subtécnica · Ataque · Artefacto/log fuente ·
  Documentación · Apartado · ATA · Validación).

### 6.11 Scripts reutilizables del repo hermano (a reimplementar para Wazuh)
- `Soporte/Snort/Scripts/analisis_snortv5.py` — patrón del pipeline "para cada artefacto
  → corre HIDS → genera CSV/Logs → cuenta".
- `Soporte/Snort/Scripts/filtradoTPv4.py` — núcleo del filtrado automático TP/FP. Cambiar
  `df['SID']` por `df['rule.id']` y usar baseline de reglas Wazuh en idle.
- `BBDD/SQL/tablas.sql` (406 líneas) — modelo relacional a portar a SQLite.
- `BBDD/Scripts/transformaAlertasFG.py` — patrón de normalización `(pcap, attackid, tp)`.
- `Estudio-FG/ataques_completamente_detectados_FG.csv` y
  `Estudio-PA/completamenteDetectados/completamenteDetectados.csv` — plantillas de la
  tabla resumen ejecutivo por HIDS.
- `VerificacionFG/Resumen.csv` — plantilla del experimento de robustez.

---

## 7. Restricciones y decisiones acuerdadas con el profesor

- **No mezclar HIDS**: primero Wazuh de extremo a extremo; luego Velociraptor; luego el
  tercero.
- **Ataques prioritarios**: Ransomware, Exfiltración (envío masivo de ficheros) y
  Sabotaje (borrado de ficheros de sistema).
- **Modo detección-only**: el HIDS nunca debe bloquear el ataque, solo detectar.
- **VMWare** para orquestar VMs; VMs del profesor disponibles en `ait08.us.es/MVs/Alumnos/`.
- **SO víctima**: depende de la técnica; si la técnica es multi-SO, preferir Linux por
  comodidad.
- **Cobertura objetivo**: por orden Tácticas → Técnicas → Subtécnicas; iteración de 1
  técnica/subtécnica por táctica hasta un buen conjunto (idea "30 TEC" del alumno).
- **Repo de referencia a imitar**: `Snort-FG-PA-Analisis_Capacidad_deteccion_Ataques_red`.
- **BBDD**: se usará **SQLite** (no HyperSQL como en los TFGs anteriores) por
  accesibilidad. Reaprovechamos el diseño de `tablas.sql`.
- **Identificador único de ataque**: ATANNN (heredado de la línea).
- **Métrica de rendimiento**: η = √(CD·(1−FP)) (heredada).
- **Procedimiento TP/FP**: dual (filtrado automático contra baseline legítimo del endpoint
  + etiquetado por agente IA auditado por el alumno). Heredado y adaptado a IA.
- **Reunión 01 obsoleta**: solo se usa la **reunión 02**.
- **Orquestador de ataques**: **Atomic Red Team** (fijado en sesión de diseño, R-12).
- **Automatización con IA**: el agente Opencode actúa como orquestador "El Agente";
  controla VMs por `vmrun`, lanza ataques por SSH, captura detecciones del indexer, y
  etiqueta TP/FP automático; el alumno añade, audita y valida. Ver §3.A de
  `requirements.md`.
- **Control de VMs**: `vmrun` desde PowerShell (R-11); acceso SSH con llaves ed25519 (R-13).
- **Topología fijada** (4 VMs en VMware Workstation Pro/Player con red host-only, ver
  T-04 en `requirements.md`): **Wazuh server** (manager + indexer + dashboard),
  **victim_win** (Windows + Sysmon + agent), **victim_linux** (Ubuntu + auditd + agent),
  **attacker** = **Kali Linux** (herramientas preinstaladas: nmap, hydra, metasploit,
  mimikatz, etc.; reutiliza el arsenal de los TFGs hermanos).
- **Diseño de cada ataque** (ver T-11 en `requirements.md`): además de Atomic Red Team,
  se consulta el campo *Procedure Examples* de MITRE ATT&CK como capa adicional de
  inspiración realista (WannaCry para T1486, Mimikatz para T1003.001, etc.).

---

## 8. Estados y siguientes pasos

Documentos de planificación creados:
- `context.md` — este archivo (single source of truth).
- `requirements.md` — requisitos, tareas T-01..T-28, flujos F-01..F-06 y matriz de
  automatización con IA (§3.A).
- `roadmap.md` — secuenciación en 9 fases (Wazuh-first), con DoD por fase e hitos de
  tutor H0-H7.

**Próximo hito lógico**: ejecutar **Fase 0** del roadmap (esqueleto de repo, README, clon
de Atomic Red Team) y disparar **Fase 1** (F-01: descargar bundle STIX v19.1 de MITRE,
adaptar el script del profesor con el filtro inverso R-03, generar la lista de técnicas
válidas human-legible priorizada por R/E/S).