---
bloque: fase-02b-diseno
fase: 2b — Laboratorio Windows (bloque de DISEÑO/ESTUDIO)
nombre: Diseño del laboratorio Windows
version: 2
status: approved_by_human
fecha: 2026-10-02
fecha_aprobacion: 2026-10-02
aprobado_por: humano
autor: tfg-planner
gate: **APROBADO (2026-10-02)**: **ISO virgen** (descartada la plantilla del profesor por ensuciar la línea base) · **Defender OFF** · **telemetría** (Sysmon curado + Seguridad 4688 + PowerShell 4104 + Syscheck) · **fases `fase-02b`/`fase-03b`** · **piloto = ~5 técnicas** (2 ART + 2 propias + 1-2 de comparación Linux↔Windows) · **pasos y material del montaje** aceptados (la VM la crea el humano; el orquestador guía). **⏳ ABIERTO: W10 vs W11** → lo decide el humano **tras el estudio T-W1**.
---

# Bloque `fase-02b-diseno` — Diseño del laboratorio Windows

> **Naturaleza del bloque: ESTUDIO/DISEÑO.** No se crea ninguna VM, no se instala ni se
> descarga nada, no se ataca nada, no se toca Linux, no se modifica ningún fichero existente
> ni `_recursos/`. El entregable es un **conjunto de decisiones razonadas** + el
> **inventario P1-Windows** + el **estudio W10/W11** + la **lista de pasos y material para el
> humano**, materializados en documentos **nuevos** bajo `Soporte/Laboratorio/windows/` y
> `Hojas/`.
>
> Estado de partida verificado: **Linux cerrado en lo esencial** — 55 técnicas medidas, 53
> detectadas, **P1-Linux cerrada** (`Hojas/cobertura_p1_linux.csv`, 72 filas, `state.md:10-12`);
> Wazuh **4.14.7** (`Soporte/Wazuh/Configuracion/version_wazuh.txt`); lab `192.168.65.0/24` en
> `VMnet1` (`Soporte/Laboratorio/README.md:26`); NAT desconectado (`state.md:67`).
>
> **Relación con la v1 de este plan.** La v1 recomendaba **importar la plantilla del profesor**
> (`Windows10-DIT-MV.7z`). El humano ha decidido lo contrario (ver D2). Esta v2 **sustituye** a la
> v1 y deja constancia del descarte y de su motivo.

---

## 0. Objetivo, alcance y resultado esperado

**Objetivo.** Dejar **decidido y documentado** cómo se montará la víctima **Windows** y cómo se
reutilizará la maquinaria ya madura de Linux, **sin ejecutar** todavía el laboratorio ni los
ataques. Incluye un **estudio W10/W11** con criterios, evidencias y recomendación razonada.

**Resultado esperado.** Un documento de decisiones (D1…D7), un estudio W10 frente a W11, un
inventario reproducible `P1-Windows` con factibilidad y cobertura ART, la telemetría/Defender
diseñados, el diseño de 2-3 pilotos y una lista de pasos + material en lenguaje sencillo para
que el humano monte la VM.

**Lo que NO es este bloque.** No es el montaje (`fase-02b-construccion`) ni la tanda de ataques
(`fase-03b`). Aquí solo se **decide, se estudia y se escribe**.

---

## 1. Diagnóstico

### 1.1 Qué cubre ya la convención por SO (se reutiliza)

La convención **"un dueño por cosa, sin duplicar"** ya está fijada y **aplica también a Windows**
(dos ganchos previstos en `state.md:98-103`; nota de plataforma en `Soporte/Ataques/criterio_ataques.md`
**§D**):

| Activo | Dónde | Por qué sirve tal cual |
|---|---|---|
| Criterio de elección de ataque (ART / manual / pre-staging) | `criterio_ataques.md` (§A-C) | **Neutro de plataforma**; su **§D** ya anticipa Windows ("el reparto cambia, la línea base cambia; el criterio no"). |
| Criterio de doble iteración (v2) | `criterio_doble_iteracion.md` | Depende de `[t0,t1]` y del estado limpio, no del SO. |
| Métrica congelada (O1 SÍ/NO + `rule_id` + evidencia · O2 acciones `k/m`) | `politica_filtrado_ruido.md` §6, `state.md:47` | No se cambia **cómo se cuenta**. |
| Categorías y **orden de decisión** del filtro (`auto_ruido`/`deteccion`/`ruido_conocido`/`dudosa`/`artefacto_ataque`) | `politica_filtrado_ruido.md` §2 (`filtrar_ruido.py:11-36`) | La **lógica** es reutilizable; los **datos** y las **listas de ruido** son de Linux (cambian). |
| Plantilla de señales esperadas (7 columnas) | `plantilla_esperado.md` §1 | El **esquema** se reutiliza; el **contenido de `campo`** cambia en Windows. |
| Anti-enmascaramiento (preflight C1/C2) | `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md`; `rulesets_diseno.md` §9 | La norma "toda regla propia pasa el examen" aplica a RS3/RS4 de Windows. |
| RuleSets RS1..RS4 por **fichero de origen** | `rulesets_diseno.md:42-47,119-136` | El criterio de clasificación no depende del SO. |
| Reglas/decoders Windows en el manager | `Soporte/Wazuh/Configuracion/active_ruleset.txt` | El manager **4.14.7 ya trae y tiene activas** `0330-sysmon` (39), `0430-ms_wdefender` (3), `0575/0580/0585/0590/0595/0600/0601/0602/0605/0610/0615/0620-win-*`, `0800/0810/0820/0830-sysmon_id_*`, `0840-win_event_channel` — todas **RS1**. No hay que instalar ruleset Windows. |
| Mapa ART con `tests_windows` | `Hojas/cobertura_atomic.csv` (columna `tests_windows`) | Se reutiliza tal cual; se añadirán filas de los `ATA` Windows. |

### 1.2 Qué **cambia** con Windows

1. **No existe `auditd`.** En Linux la capa que decide es `audit` (`execve`/`watch`) → reglas
   `807xx` (RS2) y campos `data.audit.*`. En Windows la telemetría es **registro de eventos**
   (Seguridad / Sysmon / PowerShell) + **FIM/Syscheck** + **registro** (ver D4).
2. **Los campos de telemetría son otros.** `extraer_alertas.py` extrae `data.audit.{exe,cwd,key,file,…}`
   y `syscheck.path`; en Windows viven en `data.win.eventdata.*` / `data.win.system.*`
   (`politica_filtrado_ruido.md:38-41`, `state.md:102`).
3. **El filtro lleva supuestos de Linux dentro.** `filtrar_ruido.py` codifica procesos del propio
   Wazuh (`wazuh-agentd`…), `ATTACK_ROOT = /home/angel/lab-attack/`, `OPERADOR_SRCIPS = {192.168.65.1}`
   con `5715`/`19004`, y el grupo de ejecución `audit_command` (`politica_filtrado_ruido.md:53-75,119-131`).
   **Nada de eso existe en Windows.**
4. **Hay una defensa nativa propia (Defender)** que en Linux no existe → puede **medir al antivirus
   en vez de a Wazuh** y **bloquear/aislar** el ataque (ver D3).
5. **Coste de máquina.** El host tiene **16 GB** (`Soporte/Laboratorio/README.md:16`) y el manager
   consume **6 GB** (`README.md:51`). La víctima Windows exige **no arrancar `victima-linux` a la
   vez** (riesgo ya previsto en `roadmap.md:162`).
6. **Asimetría de carpetas pendiente.** `Dataset/Ataques/Resultados/Wazuh/linux/` ya existe, pero el
   baseline Linux sigue **plano** en `Dataset/Legitimo/` (`state.md:101`: "se mueve el día que Windows
   se confirme"). Mover ficheros Linux **rompería la cadena de huellas** (`state.md:59`) → **no se
   mueve nada** (ver §10).
7. **Discrepancia numérica a declarar (no es un bug de datos).** Filtrar `Hojas/corpus_host.csv` por
   `priority=P1` devuelve **93** filas porque 4 (`T1020.001`, `T1030`, `T1557.002`, `T1602`) tienen
   `host_eligible=NO` (*solo_red*). La piscina canónica (host-eligible) es **P1 = 89**
   (`Hojas/lista_tecnicas_validas.md:17`); el inventario se calcula sobre **89**.
8. **La plantilla del profesor se descartó** (D2): una máquina con software preinstalado variado
   **ensucia la línea base** y hace que los resultados **no sean plenamente atribuibles al HIDS**.
   Se usará **ISO virgen**. Queda constancia en D2 y en `Soporte/Laboratorio/windows/README.md`.

### 1.3 Hallazgos que se declaran (no se corrigen aquí)

- El manager ya trae `0600-win-wdefender_rules.xml` (**113 reglas**, RS1) y `0430-ms_wdefender` (3)
  → con Defender activo, Wazuh alertaría sobre **eventos del antivirus**, contaminando la medida (D3).
- **Todas** las P1 con Linux (72) **también declaran Windows** → la piscina híbrida repetible en
  Windows es **72/72** (verificado contra `corpus_host.csv` y `cobertura_atomic.csv`).
- La fecha de hoy (**2026-10-02**) hace que **Windows 10 esté EOL** desde el **2025-10-14**
  (Microsoft: fin de soporte; ESU consumer hasta 2026-10-13 / comercial hasta 2027). Es un dato
  **vigente** y se usará en el estudio T-W1.

---

## 2. Decisiones D1…D7

> Todas las decisiones se documentan en `Soporte/Laboratorio/windows/README.md`. **Solo D2-W10/W11
> queda abierta** (la decide el humano tras el estudio T-W1); el resto se dan por **recomendadas**
> y se validan en el gate.

### D1 — Estructura de fases: `fase-02b` (laboratorio Windows) y `fase-03b` (ataques Windows)

**Decidido (propuesta del humano).** Se adoptan las fases **`fase-02b`** y **`fase-03b`**; cada
bloque se archiva como `_fases/fase-02b-<nombre>/` / `_fases/fase-03b-<nombre>/`. **Este bloque =
`fase-02b-diseno`**.

- Bloques previstos: `fase-02b-diseno` (este) → `fase-02b-construccion` (VM + red + agente +
  telemetría + snapshots) → `fase-02b-baseline`; y después `fase-03b-*` (tandas de ataques).
- Orden: **`fase-02b` antes de `fase-03b`** (no se ataca sin laboratorio y baseline Windows).
- `ATA<NNN>` **se continúan** desde `ATA055` (no se reinician); misma técnica en otro SO = **otra
  fila/otro `ATA`**, comparable con Linux.

**Compartido con Linux (un solo dueño por documento) vs específico de Windows:**

| Elemento | Dueño | Cómo |
|---|---|---|
| Criterio ART/manual/pre-staging | `Soporte/Ataques/criterio_ataques.md` | **Ampliar §D** con la concreción Windows (no crear criterio paralelo). |
| Doble iteración | `criterio_doble_iteracion.md` | Reutilizar **sin cambios**. |
| Métrica congelada | `politica_filtrado_ruido.md` / `state.md` | **No se toca**. |
| Señales esperadas | `plantilla_esperado.md` | Ampliar con la **tabla de campos Windows** y el `ATTACK_ROOT` Windows. |
| RuleSets RS1..RS4 | `rulesets_diseno.md` | Añadir **§Windows** (ver D7). |
| Anti-enmascaramiento | `preflight_enmascaramiento.md` | Aplica igual a RS3/RS4 Windows. |
| Mapa ART | `Hojas/cobertura_atomic.csv` | Reutilizar; añadir filas de los `ATA` Windows. |
| **Baseline** | `Dataset/Legitimo/windows/` | **Nuevo** subárbol (no se toca el Linux). |
| **Resultados de ataque** | `Dataset/Ataques/Resultados/Wazuh/windows/` | **Nuevo** subárbol (`state.md:101`). |
| **Artefactos/comandos** | `Dataset/Ataques/Comandos/windows/<T>-<desc>/` | **Nuevo** subárbol. |
| **Agente Wazuh** | `Soporte/Wazuh/Configuracion/runbook_agente_windows.md` | **Nuevo** (espejo del de Linux). |
| **Defender / telemetría / VM** | `Soporte/Laboratorio/windows/` | **Nuevo**. |

> **Declaración:** cada documento ampliado llevará una nota "*aplica a Linux y Windows; en Windows …*"
> para que nadie crea que hay dos métodos distintos. **Los directorios `windows/` se crean cuando
> llegue el primer dato** (`fase-02b-construccion`); en este bloque solo se **documenta la
> convención** (KISS: no dejar carpetas vacías).

### D2 — Sistema operativo: **ISO virgen** (no plantilla) y elección W10/W11

**Decidido por el humano: ISO VIRGEN.**

- **Motivo (rigor metodológico):** una VM con software preinstalado variado (plantilla del profesor
  `Windows10-DIT-MV.7z`, `http://ait08.us.es/MVs/Alumnos/`, `context.md:150`) **ensucia la línea
  base**: introduce procesos, servicios y ruido ajenos al laboratorio y hace que los resultados **no
  sean plenamente atribuibles al HIDS**. Una ISO **virgen** da un **estado de partida conocido y
  reproducible**.
- **Constancia del descarte:** la plantilla del profesor **se evaluó y se descartó** por ese motivo;
  se deja escrito en `Soporte/Laboratorio/windows/README.md` (no se borra el hallazgo; se explica).
- **Consecuencia asumida:** el montaje sube de coste (instalación desde cero + VMware Tools + parches
  de instalación), pero se gana **atribuibilidad** y **reproducibilidad**. Sigue la línea del
  laboratorio Linux (SO limpio + snapshot `base-limpia`).

**⏳ Abierto: Windows 10 vs Windows 11 → se decide con el estudio T-W1 (§3).**
Resumen del estado asumido por el humano: **W10 EOL → limitación a declarar**; la decisión final la
toma el humano. Recomendación preliminar en §3.4.

### D3 — Windows Defender: **DESACTIVAR** (control ambiental declarado)

**Decidido por el humano: Defender OFF** (Tamper Protection → protección en tiempo real →
nube/comportamiento). Motivo: **bloquearía/aislaría** los ataques (falso "no detectado" por Wazuh)
y las **113 reglas** de `0600-win-wdefender` (RS1) **inflarían "detecciones"** midiendo al antivirus,
no al HIDS.

Efectos de Defender activo (por qué se apaga): (1) cuarentena del artefacto → el ataque no se
ejecuta → falso negativo; (2) alertas propias de Defender convertidas en "detecciones"; (3)
aislamiento/corrección a mitad de ventana → contamina `[t0,t1]` y la doble iteración.

Se trata como **control ambiental declarado** (igual que "NAT desconectado" y "detección-only"),
con:
- **procedimiento** de desactivación (Tamper Protection primero, luego real-time, luego cloud/behavior);
- **verificación previa a cada ventana** (checklist) de que sigue apagado;
- **declaración** de que el objeto de medida es **Wazuh**;
- **trabajo futuro opcional** (fuera de alcance): repetir una técnica con Defender ON para comparar
  "Wazuh vs. antivirus nativo".

### D4 — Telemetría de Windows (sustituto de `auditd`)

**Decidido por el humano:** **Sysmon (config curada) + Registro de Seguridad (4688) + PowerShell
(4104) + FIM (ficheros y claves)**, como equivalente de `auditd`.

| Capa | Aporta | Cómo se recoge | Cobertura en el corpus |
|---|---|---|---|
| **Sysmon** (config curada) | `Process Create (1)`, `Network (3)`, `File Create/Delete`, `Registry`, `ProcessAccess (10)`, `ImageLoad (7)` | Binario Sysmon (Sysinternals) + `sysmonconfig.xml` (**pre-staging**); el agente lee `Microsoft-Windows-Sysmon/Operational` | Procesos y ficheros: núcleo de Impact/Collection/Exfil |
| **Registro de Seguridad** | `4688` creación de proceso (con línea de comandos), `4624/4625` logon, `7045` servicio, cuentas | Canal `Security` vía `<localfile><log_format>eventchannel</log_format>` | Servicios (T1489), cuentas (T1531), shutdown (T1529) |
| **PowerShell 4104** | Script Block Logging (muchos tests ART Windows) | GPO + canal `Microsoft-Windows-PowerShell/Operational` (reglas `0915-win-powershell`) | Ejecución vía PowerShell |
| **Syscheck / FIM** | Ficheros y **claves de registro** vigiladas | `<syscheck>` del agente (espejo del de Linux) | Ransomware, borrado, defacement, manipulación (T1486/T1485/T1491/T1565) |
| **Sysmon 12/13/14 + FIM de registro** | Modificación de claves (persistencia, T1490) | Sysmon/eventchannel | T1490, persistencia |
| **Estado del agente** | Conexión/desconexión (equivale a `503`/`506`) | Reglas internas Wazuh | T1529 |

- **Sysmon sin filtro genera muchísimo evento** → exige **config curada** + **baseline** (riesgo
  `roadmap.md:160`). La config por defecto **no vale**.
- **Mapa capa→técnica** del corpus en `Soporte/Laboratorio/windows/telemetria_windows.md` (equivalente
  al *Data Component* del criterio §B).

### D5 — Agente Wazuh 4.14.7 (MSI, offline/pre-staging)

- **Versión:** la **misma que el manager, 4.14.7** (`version_wazuh.txt`); MSI para Windows
  `wazuh-agent-4.14.7-1.msi`. Sigue la lección de sincronía repo↔manager (`state.md:64`).
- **Instalación offline (pre-staging, §C de `criterio_ataques.md`):** el **MSI**, el **Sysmon** y la
  **config Sysmon** se traen **antes de `t0`**, con **URL + `sha256`** registradas; el NAT se activa
  **solo** para descargarlos y se **desconecta** antes de baseline/ataques
  (`Soporte/Laboratorio/vmrun_config.md:70-85`). Los binarios quedan **fuera del repo** (solo se
  versiona el sidecar con URL+sha256).
- **Alta en el manager:** agente `victima-windows`, IP estática **`192.168.65.130`** (libre en
  `192.168.65.0/24`), apuntando a `192.168.65.128:1514`. **No revierte el manager** durante los
  ataques (`vmrun_config.md:66-68`).
- **Verificación extremo a extremo:** un intento de logon fallido controlado → alerta en el manager
  por el `agent.id` de la víctima Windows (espejo del runbook Linux, `runbook_agente_linux.md:130-155`).

### D6 — Recogida y filtro: **parametrizar por perfil de plataforma** (no bifurcar)

**Decidido por el humano.** No se crea una lógica paralela.

1. **`extraer_alertas.py`** gana un **perfil Windows**: además de `data.audit.*`/`syscheck.path`,
   emite un **esquema normalizado** `data.win.*` (p. ej. `win_image`, `win_parent_image`,
   `win_command_line`, `win_cwd`, `win_target`, `win_user`). El **agregado por `rule.id`/`rs_origen`
   no cambia**.
2. **`filtrar_ruido.py`** gana un **perfil de plataforma** (config declarativa), con las mismas
   **categorías, orden de decisión y guardarraíles**; cambian los **datos**:
   - **procesos auto-ruido**: Linux `wazuh-*`; Windows `wazuh-agent.exe` + firmas internas del manager;
   - **`ATTACK_ROOT`**: Linux `/home/angel/lab-attack/`; Windows `C:\lab-attack\<ATA>`;
   - **predicado OPERADOR**: Linux `5715`/`19004` por IP; Windows: logon RDP/red desde la IP del host
     `192.168.65.1` (a confirmar con datos reales);
   - **evento de ejecución**: Linux grupo `audit_command`; Windows Sysmon `1` / Seguridad `4688`.
3. **Métrica congelada: intacta.**
4. **Baseline Windows obligatorio:** `Dataset/Legitimo/windows/` con el **mismo criterio** que Linux
   (2 ventanas, preferentemente en horas distintas) para poblar el catálogo de ruido y **demostrar
   `deteccion=0`** sobre la línea base (`state.md:71`).

> **Nota de honestidad (KISS):** esto es **diseño**; la implementación es de `fase-02b-construccion`.
> El plan fija la **interfaz** (perfil de plataforma) para no reescribir la lógica a posteriori.

### D7 — RuleSets RS1..RS4 en Windows

- **RS1** = default (incluye **todo** el ruleset Windows ya activo: `0330-sysmon`, `0430-ms_wdefender`,
  `0575`–`0620-win-*`, `0800`–`0830-sysmon_id_*`, `0840-win_event_channel`, `0915-win-powershell` —
  verificado en `active_ruleset.txt`).
- **RS2 = vacía en Windows** (declararlo): el "slot" RS2 nació como capa `auditd`
  (`rulesets_diseno.md:45`); sin `auditd` no aplica. **Sysmon es telemetría** (config en la víctima),
  **no** un fichero de reglas del manager.
- **RS3** = nuestras reglas Windows (`local_rules.xml` en el manager, reserva 100 000–100 499), que
  pasan el **preflight** anti-enmascaramiento antes de activarse.
- **RS4** = reglas externas curadas (decisión de `rulesets_diseno.md` §2), si se usan en Windows.

---

## 3. Tarea **T-W1** — Estudio Windows 10 vs Windows 11

> **Tarea del bloque** (producto documental, sin ejecutar el laboratorio). Produce
> `Soporte/Laboratorio/windows/estudio_w10_vs_w11.md` con **criterios, evidencias y recomendación
> razonada**. **La decisión final la toma el humano.**

### 3.1 Criterios (los 5 del humano)

| # | Criterio | Qué se mide |
|---|---|---|
| C1 | **Soporte/vigencia** | ¿Está el SO en soporte? ¿EOL? ¿Declarable como limitación? |
| C2 | **Compatibilidad Sysmon + agente Wazuh 4.14.7** | ¿Corren ambos? ¿Hay conflictos (p. ej. Sysmon integrado)? |
| C3 | **Ruido de fondo** | Servicios, telemetría y updates → impacto en la **línea base** |
| C4 | **Cobertura ART** | Nº de tests ART Windows ejecutables en cada versión y **qué tests se caen** |
| C5 | **Coste de montaje** | Defender (Tamper), requisitos (TPM/Secure Boot/RAM/CPU), esfuerzo |

### 3.2 Evidencias que debe citar el estudio (verificables)

1. **Local (repo):** `Hojas/cobertura_atomic.csv` / índices del clon ART
   (`Soporte/Ataques/atomic-red-team/atomics/Indexes/Indexes-CSV/windows-index.csv`) → **tests por
   técnica**; inspección de los `.md`/`.yml` de los tests candidatos para detectar **dependencias de
   versión** (p. ej. `wmic`).
2. **Microsoft Lifecycle:** W10 fin de soporte **2025-10-14** (ESU consumer hasta 2026-10-13;
   comercial hasta 2027); W11 versiones soportadas (**25H2** hasta 2027-10; **24H2** hasta 2026-10).
3. **Wazuh:** matriz de compatibilidad del agente (Windows 10, 11, Server 2016-2025) y notas de
   versión 4.14.x.
4. **Sysmon:** documento de Sysinternals/Microsoft (Sysmon *standalone* corre en **Windows 10+**);
   **Sysmon integrado** es una característica opcional de Win11 (desde feb-2026) y **no coexiste** con
   el *standalone*.
5. **`wmic`:** retirado de Windows 11 **24H2/25H2** (ya no es FoD) y de **26H1**; en Windows 10 22H2
   sigue presente (deprecado). Muchos tests ART Windows usan `wmic`.
6. **La plantilla del profesor** (`Windows10-DIT-MV.7z`) se documenta como **evaluada y descartada**;
   no es una opción.

### 3.3 Formato del estudio

Por cada criterio: **dato → fuente/cita → consecuencia para el laboratorio**. Cierre con una **tabla
comparativa W10 vs W11** y un **apartado "Recomendación"** con el nivel de confianza y lo que queda
por verificar en el montaje.

### 3.4 Recomendación preliminar del planificador (a confirmar/refutar por T-W1)

**Recomendación preliminar: Windows 10 Pro 22H2 x64** — por (a) **máxima fidelidad ART** (los tests
Windows se escriben mayoritariamente para Win10 y muchos dependen de `wmic`, presente por defecto en
W10 22H2 y retirado en W11 24H2+; en 26H1 ya no es FoD), (b) **menor ruido y RAM**, y (c) **Defender
más fácil de domar**. **Coste:** hay que **declarar la EOL** de Windows 10 (2025-10-14) como
**limitación acotada del laboratorio** (aislado, sin internet, sin datos reales, con las medidas de
Defender/NAT/documentación ya previstas).

**Alternativa si el tutor exige un SO vigente: Windows 11 Pro 25H2**, asumiendo (i) la **pérdida de
tests ART que usan `wmic`** (o su pre-staging como FoD en versiones donde aún exista — no en 26H1),
(ii) **más ruido de base** y (iii) **Defender/Tamper más duro**. El estudio T-W1 debe **cuantificar
(i)** con datos del clon antes de decidir.

> Esta recomendación es **preliminar y honesta**: si T-W1 demuestra que la pérdida ART de W11 es
> pequeña, la vigencia de W11 pasa a pesar más y la recomendación se invierte.

---

## 4. Inventario P1-Windows

**Fuente:** `Hojas/corpus_host.csv` (columna `priority`, `host_eligible`, `plataformas`) +
`Hojas/lista_tecnicas_validas.md:17` (piscina canónica **P1=89**) + índices ART del clon
(`windows-index.csv`, `index.csv`, `linux-index.csv`). Unidad: **host-eligible**. **Verificado en
este bloque** con cálculo directo (reproducible por `inventario_p1_windows.py`).

### 4.1 Cuadre de la piscina

| Conjunto | Nº | Comentario |
|---|---|---|
| P1 (host-eligible) | **89** | `lista_tecnicas_validas.md:17`. *(El CSV crudo da 93; 4 son `solo_red`.)* |
| P1 ∧ Linux | **72** | = `cobertura_p1_linux.csv` (P1-Linux cerrada). |
| P1 **sin** Linux | **17** | No citan Linux. |
| · de esas, **host Windows** | **5** | T1114.001, T1114.002, T1185, T1213.002, T1557.001. |
| · de esas, **sin host Windows** | **12** | Solo nube/SaaS/IaaS/Network Devices (no factibles en VM local). |
| P1 híbridas (Linux **y** Windows) que **repiten** en Windows | **72** | Todas las P1-Linux citan Windows (72/72). |

### 4.2 Las 17 P1 "sin Linux"

| Técnica | Nombre | Plataformas | ART Win | Factibilidad en VM Windows local |
|---|---|---|---|---|
| T1114.001 | Local Email Collection | Windows | 1 | Media (requiere cliente de correo/perfil local) |
| T1114.002 | Remote Email Collection | Office Suite; Windows | 0 | Baja (servidor Exchange/nube) |
| T1185 | Browser Session Hijacking | Windows | 0 | Media-baja (navegador con sesión; manual) |
| T1213.002 | Sharepoint | Office Suite; Windows | 0 | **No factible** (SaaS) |
| T1557.001 | Name Resolution Poisoning and SMB Relay | Windows | 1 | Media (LLMNR/NBNS + SMB en host-only; precauciones) |
| T1213.001 | Confluence | SaaS | 0 | **No factible** (SaaS) |
| T1213.003 | Code Repositories | SaaS | 0 | **No factible** (SaaS) |
| T1213.004 | CRM Software | SaaS | 0 | **No factible** (SaaS) |
| T1213.005 | Messaging Applications | Office Suite; SaaS | 0 | **No factible** (SaaS) |
| T1485.001 | Lifecycle-Triggered Deletion | IaaS | 0 | **No factible** (nube/IaaS) |
| T1496.003 | SMS Pumping | SaaS | 0 | **No factible** (SaaS) |
| T1496.004 | Cloud Service Hijacking | SaaS | 0 | **No factible** (SaaS) |
| T1530 | Data from Cloud Storage | IaaS; Office Suite; SaaS | 0 | **No factible** (nube) |
| T1537 | Transfer Data to Cloud Account | IaaS; Office Suite; SaaS | 0 | **No factible** (nube) |
| T1557.004 | Evil Twin | Network Devices | 0 | **No factible** (dispositivo de red) |
| T1602.001 | SNMP (MIB Dump) | Network Devices | 0 | **No factible** (dispositivo de red) |
| T1602.002 | Network Device Configuration Dump | Network Devices | 0 | **No factible** (dispositivo de red) |

**Conclusión:** de las 17, solo **5 son de host Windows** (2 con prueba ART Windows: T1114.001 y
T1557.001). Las **12 restantes son nube/SaaS/IaaS/red** → **"no factible"** (mismo motivo
`otra_plataforma` que en `cobertura_p1_linux.csv`).

### 4.3 Las 72 híbridas y su cobertura ART Windows (verificado)

- **36** tienen **≥1 prueba ART Windows** → **ART tal cual/adaptado** previsible.
- **36** tienen **0 pruebas ART Windows** → **ataque propio** (`art_no_prueba_plataforma`), salvo
  reutilizar adaptada la versión Linux ya medida.

**36 con prueba ART Windows:**

`T1005 · T1020 · T1025 · T1039 · T1041 · T1048 · T1048.002 · T1048.003 · T1056 · T1056.001 ·
T1056.002 · T1056.004 · T1074 · T1074.001 · T1113 · T1114 · T1115 · T1119 · T1123 · T1125 ·
T1485 · T1486 · T1489 · T1490 · T1491 · T1491.001 · T1496 · T1529 · T1531 · T1557 · T1560 ·
T1560.001 · T1567 · T1567.002 · T1567.003 · T1567.004`

**36 sin prueba ART Windows:**

`T1011 · T1011.001 · T1029 · T1048.001 · T1052 · T1052.001 · T1056.003 · T1074.002 · T1114.003 ·
T1213 · T1213.006 · T1491.002 · T1495 · T1496.001 · T1496.002 · T1498 · T1498.001 · T1498.002 ·
T1499 · T1499.001 · T1499.002 · T1499.003 · T1499.004 · T1557.003 · T1560.002 · T1560.003 · T1561 ·
T1561.001 · T1561.002 · T1565 · T1565.001 · T1565.002 · T1565.003 · T1567.001 · T1657 · T1667`

> **Nota:** el mapa `Hojas/cobertura_atomic.csv` solo cubre los `ATA` ya medidos (56 filas); el
> inventario P1-Windows se calcula contra los **índices completos del clon**, no contra ese CSV.

### 4.4 Criterio de selección del corpus Windows (DECIDE el humano)

1. **Todas las técnicas se intentan**; se priorizan por valor y factibilidad.
2. Primero las **36 híbridas con ART Windows** — sobre todo **R/E/S** (Impact/Exfiltration/Collection),
   porque **reutilizan la técnica ya medida en Linux** → permiten la **comparación Linux↔Windows**,
   valor añadido del TFG.
3. Añadir las **Windows-only factibles** (§4.2): T1114.001, T1557.001 (y valorar T1185).
4. **No forzar** las 12 nube/SaaS/red: declararlas **no factibles**.
5. Para las **36 sin ART Windows**, ataque **propio** con `motivo_codigo` (o versión Linux adaptada),
   según `criterio_ataques.md` §A. Los **DoS** (T1498/T1499) se ejecutan **acotados** (precedente
   Linux, `state.md:11`).

> **Nada de esto se ejecuta aquí:** el inventario se entrega como CSV reproducible
> (`Hojas/inventario_p1_windows.csv`) para que el humano elija en el gate.

---

## 5. Diseño de pilotos Windows (2-3 acotados primero)

**Decidido por el humano:** antes de escalar a las 36 híbridas con ART + Windows-only factibles, se
ejecutan **2-3 pilotos acotados** (como en Linux), uno de cada tipo, para **validar la tubería y el
filtro** en Windows:

| Piloto | Tipo | Candidato propuesto | Por qué |
|---|---|---|---|
| **W1** | **ART Windows** (tal cual/adaptado) | **T1490** — Inhibit System Recovery (ART Windows usa `vssadmin`/`wmic shadowcopy delete`; medida en Linux: `ATA003`) | Ejercita ART real y, de paso, **ilustra la dependencia de `wmic`** (C4 del estudio) |
| **W2** | **Propia, sin ART Windows** | **T1565.002** — Transmitted Data Manipulation (0 ART Windows; medida en Linux: `ATA026`) | Valida el **camino manual** en Windows |
| **W3** | **Híbrida ya medida en Linux** (comparación) | **T1486** — Data Encrypted for Impact (ART Windows; medida en Linux: `ATA001`) | Valida la **comparación Linux↔Windows** del mismo HIDS |

- Los **tres** se eligen del pool híbrido, de modo que cada uno tiene **contrapartida Linux medida**.
- El humano puede sustituir candidatos; la decisión se sella en el gate.
- Tras los pilotos, se **escala** a las **36 híbridas con ART** + **Windows-only factibles**, en
  tandas (mismo ritmo que Linux).
- **Cada piloto** sigue el ciclo completo ya congelado: `criterio_ataques.md` (ART/manual/pre-staging
  → C0 → prueba del efecto → `esperado` validado por el humano), `criterio_doble_iteracion.md`
  (2 iteraciones), métrica congelada y filtro por perfil.

---

## 6. Pasos y material para el HUMANO

> **Lenguaje sencillo. Todo esto lo hace el humano**; los agentes **no pueden crear VMs ni instalar
> SO**. La VM Windows **no se enciende a la vez** que `victima-linux` (16 GB de RAM).
> El detalle se materializa en `Soporte/Laboratorio/windows/pasos_humano.md`.

### 6.1 Pasos de montaje (ordenados)

1. **Descargar la ISO virgen** de Windows (W10 o W11 según se decida en el gate) desde la web
   oficial de Microsoft. **Anotar versión exacta, tamaño y `sha256`**.
2. **Crear la VM** en VMware Workstation (máquina nueva, disco ≥ 40 GB, 2 vCPU, 4 GB RAM), apagada.
   Guardarla en `D:\TFG-VMs\victima-windows\`.
3. **Instalar Windows** desde la ISO (instalación limpia, usuario local de laboratorio). No instalar
   software adicional.
4. **Adaptador de red:** dejar **solo `VMnet1` (host-only, `192.168.65.0/24`)** activo. Añadir un
   segundo adaptador **NAT** (para descargar material), **desconectado al arrancar**
   (`ethernet1.startConnected = "FALSE"`, como en Linux).
5. **IP fija `192.168.65.130`**, hostname `victima-windows`, **sin DNS ni ruta por defecto** por la
   interfaz host-only.
6. **Desactivar actualizaciones automáticas** de Windows (reproducibilidad).
7. **Desactivar Windows Defender** para las ventanas: **Tamper Protection → protección en tiempo real
   → nube/comportamiento**. **Verificar** que queda apagado y **anotar cómo se hizo**.
8. **Con NAT encendido temporalmente (pre-staging):** descargar y **fijar con URL + `sha256`** el
   **agente Wazuh 4.14.7 (MSI)**, **Sysmon** (Sysinternals) y la **config Sysmon curada**. Guardar
   fuera del repo.
9. **Con NAT apagado:** instalar el **agente Wazuh** (nombre `victima-windows`, manager
   `192.168.65.128:1514`), instalar **Sysmon** con su config, y activar las **políticas de auditoría**
   (4688 con línea de comandos, PowerShell script block logging 4104).
10. **Comprobar telemetría:** generar un evento controlado (p. ej. logon fallido) y ver la alerta en
    el manager por el `agent.id` de la víctima Windows.
11. **Crear snapshots:** `base-limpia` (SO recién instalado) y **`lab-listo-windows`** (lab listo:
    agente activo, Sysmon, Defender off, NAT off). Punto de partida de cada ataque.
12. **Apagar la VM** entre sesiones; durante los ataques, **`wazuh-server` no se revierte**.

### 6.2 Material a pre-descargar (con URL + `sha256`)

| Material | Origen | Cómo se fija |
|---|---|---|
| **ISO de Windows** (W10 22H2 o W11 25H2) | Web oficial de Microsoft | Versión + tamaño + `sha256` |
| **Agente Wazuh 4.14.7 MSI** | `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi` | URL + `sha256` |
| **Sysmon** (Sysinternals) | `https://download.sysinternals.com/files/Sysmon.zip` | URL + `sha256` |
| **Config Sysmon curada** | Repo con **commit fijado** (p. ej. `sysmon-modular`) | URL + commit + `sha256` |
| **VMware Tools** | Incluido en VMware Workstation | (versión del hipervisor) |
| **(Si se usa ART en Windows)** módulo `Invoke-AtomicRedTeam` + `powershell-yaml` + clon ART | `Soporte/Ataques/atomic-red-team/` (pin `388942a`) | commit + `sha256` |

> Todo el material y su URL+`sha256` se registran en `Soporte/Laboratorio/windows/` (documento de
> pre-staging). **Los binarios no entran al repo** (repo público, `state.md:89`).

---

## 7. Entregables del bloque y documentación a actualizar

### 7.1 Entregables de ESTE bloque (ficheros nuevos; nada existente se modifica)

| # | Entregable | Contenido |
|---|---|---|
| E1 | `Soporte/Laboratorio/windows/README.md` | **Decisiones D1–D7** + estructura de fases B + compartido/específico + **constancia del descarte de la plantilla** |
| E2 | `Soporte/Laboratorio/windows/estudio_w10_vs_w11.md` | **T-W1**: criterios, evidencias, tabla comparativa y recomendación |
| E3 | `Soporte/Laboratorio/windows/telemetria_windows.md` | Capas D4 + mapa capa→técnica |
| E4 | `Soporte/Laboratorio/windows/defender_off.md` | Procedimiento de desactivación + checklist (control ambiental) |
| E5 | `Soporte/Laboratorio/windows/pasos_humano.md` | Pasos §6 + material §6.2 (pre-staging) |
| E6 | `Hojas/inventario_p1_windows.csv` | Inventario §4 (89→72/17→5/12; 36/36 ART) reproducible |
| E7 | `_artefactos/scripts/inventario_p1_windows.py` (+ tests) | Genera E6 de forma determinista (R-02/R-13) |
| E8 | `change-doc.md` (al cerrar) | Resumen del bloque (lo escribe el orquestador) |

### 7.2 Documentación existente a actualizar — **y en qué bloque**

| Documento | Qué se añadirá | Bloque |
|---|---|---|
| `context.md` §3 (SO víctima) | Windows por técnicas (fase-02b/03b) + ISO virgen | Cierre de este bloque (orquestador) |
| `roadmap.md` | Fases `fase-02b`/`fase-03b` + tareas Windows | Cierre de este bloque |
| `Soporte/Ataques/criterio_ataques.md` §D | Concreción Windows (§D ampliada) | Cierre de este bloque |
| `Soporte/Wazuh/Configuracion/rulesets_diseno.md` | §Windows (RS2 vacía, resto por fichero) | Cierre de este bloque |
| `requirements.md` (R-05/T-05) | Agente Windows y telemetría | `fase-02b-construccion` |
| `Soporte/Laboratorio/README.md` | §VM Windows (red/IP/versión/snapshots) | `fase-02b-construccion` |
| `Soporte/Wazuh/Configuracion/runbook_agente_windows.md` | Instalación real offline | `fase-02b-construccion` |
| `politica_filtrado_ruido.md` / `plantilla_esperado.md` | Perfil Windows (campos, `ATTACK_ROOT`, OPERADOR) | `fase-02b-construccion` |
| `state.md` | Estado vivo | Cada transición (orquestador) |

---

## 8. Verificación (bloque de estudio) y criterios de aceptación

En un bloque **sin ejecución**, `tfg-tester` verifica **coherencia documental y reproducibilidad de
las cifras**, no capturas. Método:

1. **Reproducir el inventario** desde las fuentes (`corpus_host.csv`, `lista_tecnicas_validas.md`,
   índices ART) y comprobar **89 · 72 · 17 · 5 · 12** y el reparto ART (**36/36**).
2. **Resolver las citas** (que todo dato del estudio y del inventario tenga su fichero/fuente).
3. **Comprobar el estudio T-W1:** que cada criterio (C1–C5) tenga **dato + cita + consecuencia** y que
   la recomendación sea coherente con las evidencias (aunque el humano decida otra cosa).
4. **`git status`/diff:** solo aparecen los ficheros nuevos declarados (E1–E7); **ninguno** de
   `_recursos/`, `Dataset/`, scripts existentes ni ficheros Linux.
5. **No cambio de estado del laboratorio** (VMs apagadas; no se ejecutó ni descargó nada).

### Criterios de aceptación (CA)

- **CA1.** `Soporte/Laboratorio/windows/README.md` contiene **todas** las decisiones (ISO virgen +
  descarte de la plantilla, W10/W11 abierta, Defender OFF, telemetría, agente, recogida/filtro,
  RuleSets, estructura de fases B, compartido/específico).
- **CA2.** `Hojas/inventario_p1_windows.csv` **reproduce** el cuadre 89/72/17/5/12 y la cobertura ART
  (36 con prueba Windows / 36 sin) y se regenera **byte a byte** con `inventario_p1_windows.py`.
- **CA3.** `estudio_w10_vs_w11.md` cubre **C1–C5** con evidencias citadas y una recomendación razonada
  (W10/W11 queda **abierta al humano**).
- **CA4.** `pasos_humano.md` cubre los 12 pasos (§6.1) + el material con URL+`sha256` (§6.2), en
  lenguaje sencillo.
- **CA5.** El **cambio** queda **acotado**: ningún fichero preexistente modificado; `_recursos/`
  intacto; cadena de huellas Linux intacta; **nada de Linux movido**.
- **CA6.** Ninguna decisión contradice los criterios vigentes (ART/manual/pre-staging, doble
  iteración, métrica congelada, anti-enmascaramiento).
- **CA7.** Este `plan.md` está `status: approved_by_human` antes de que `tfg-executor` escriba nada.

---

## 9. Riesgos y mitigaciones

| Riesgo | Mitigación |
|---|---|
| **RAM:** host 16 GB; manager 6 GB + Windows 4 GB. No encender `victima-linux` a la vez. | Regla operativa explícita + apagar la víctima inactiva (`roadmap.md:162`). |
| **Defender se reactiva** y bloquea/cuenta. | Desactivar Tamper tal como indica D3; **checklist** antes de cada ventana; declararlo. |
| **Sysmon inunda** de eventos → ruido/performance. | Config **curada** + **baseline** Windows + filtro por perfil. |
| **No hay `auditd`** → pérdida de telemetría en algunas técnicas. | Declarar la capa disponible por técnica (mapa D4); Sysmon/Seguridad como sustituto. |
| **Campos de telemetría distintos** → el filtro Linux falla. | Perfil de plataforma + esquema normalizado + tests + prueba `deteccion=0` en baseline. |
| **Windows 10 EOL** (si se elige W10) y **`wmic` ausente en W11** (si se elige W11). | Declarar la limitación; el **estudio T-W1** cuantifica el impacto ART antes de decidir. |
| **W11: Sysmon integrado no coexiste con el standalone.** | Usar **Sysmon standalone**; verificar que el integrado está deshabilitado (criterio C2). |
| **Coste de montaje de ISO virgen** (instalación + tools + políticas). | Es el precio de la atribuibilidad (D2); se documenta paso a paso (§6). |
| **Cadena de huellas Linux** si se reorganizan carpetas. | **No mover** ficheros Linux; subárboles `windows/` nuevos. |
| **Licencia/activación de Windows** en VM. | Verificar al instalar; declarar en `README`. |

---

## 10. Fuera de alcance (lo que NO entra)

- **No** se crean VMs, **no** se instala Windows ni el agente, **no** se descarga nada (eso es el
  humano y/o `fase-02b-construccion`).
- **No** se ejecuta ningún ataque ni prueba ART (`fase-03b`).
- **No** se toca Linux (ni datos, ni scripts, ni huellas, ni carpetas). **No se mueve nada.**
- **No** se modifica `_recursos/` (solo lectura).
- **No** se implementan los cambios de `extraer_alertas.py`/`filtrar_ruido.py` (solo se diseña la
  interfaz).
- **No** entran las 12 P1 nube/SaaS/IaaS/red (se declaran no factibles).
- **No** se mide con Defender activo (trabajo futuro opcional).
- **No** se abre P2 ni el bloque de evasión.

---

## 11. Gate humano (decisiones en lenguaje sencillo)

1. **¿Qué Windows usamos?** → **ABIERTA**. Primero T-W1 produce el estudio. Recomendación preliminar:
   **Windows 10 Pro 22H2 por ISO virgen** (máxima compatibilidad ART); **alternativa Windows 11 Pro
   25H2** (vigente, pero pierde tests que usan `wmic` y mete más ruido). **Tú decides.**
2. **¿ISO virgen en vez de la plantilla del profesor?** → **Confirmar**: sí, ISO virgen; la plantilla
   **se descartó** porque ensucia la línea base y rompe la atribuibilidad.
3. **¿Defender OFF durante las medidas?** → Recomendado **sí**, declarado como control ambiental.
4. **¿Telemetría acordada?** → Recomendado **Sysmon (config curada) + Seguridad 4688 + PowerShell 4104
   + Syscheck (ficheros y claves)**.
5. **¿Dos fases nuevas (`fase-02b`/`fase-03b`)?** → Recomendado **sí**, compartiendo criterios/métrica/
   filtro con Linux (un solo dueño por documento).
6. **¿Qué técnicas atacamos y con qué alcance?** → Recomendado: **1 bloque de pilotos con ~5 técnicas** (NO 1 por piloto) que cubra **las tres vías**: **2 con ART Windows** + **2 escritas por nosotros** (sin ART) + **1-2 ya medidas en Linux** (validar la **comparación Linux↔Windows**). Y **después** escalar a las **36 híbridas con ART Windows** + **Windows-only factibles** (T1114.001, T1557.001). Las 12 nube/red → **no factibles**. *(Razón del tamaño: 1 sola técnica no distingue si falla **el método** o **esa técnica**; con 5 quedan validadas las tres vías y **sigue siendo un piloto** — en Linux fueron 3).*

> **Actualización (2026-10-02, decisión del humano):** el **piloto = ~5 técnicas** (2 ART + 2 propias + 1-2 de comparación), **no 2-3 pilotos de 1 técnica**. La decisión previa de "2-3 pilotos (W1/W2/W3)" queda **sustituida** por este diseño.
7. **¿Aceptas los pasos y el material de §6?** → Confirmar la lista y el material a pre-descargar.

---

## 12. Referencias

- Estado vivo: `state.md` (convención de carpetas §98-103; lecciones del filtro §64, §71; huellas §59).
- Roadmap: `roadmap.md:86-108` y `roadmap.md:155-163`.
- Criterios: `Soporte/Ataques/criterio_ataques.md` (§D Windows), `criterio_doble_iteracion.md`,
  `plantilla_esperado.md`.
- Filtro: `_artefactos/scripts/filtrar_ruido.py`, `_artefactos/scripts/extraer_alertas.py`,
  `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §2-§3.
- RuleSets: `Soporte/Wazuh/Configuracion/rulesets_diseno.md`; reglas Windows en `active_ruleset.txt`.
- Inventario: `Hojas/corpus_host.csv`, `Hojas/lista_tecnicas_validas.md`, `Hojas/cobertura_p1_linux.csv`,
  `Hojas/cobertura_atomic.csv`, índices ART del clon `Soporte/Ataques/atomic-red-team/`.
- Laboratorio: `Soporte/Laboratorio/README.md`, `vmrun_config.md`, `ssh_setup.md`;
  `Soporte/Wazuh/Configuracion/version_wazuh.txt`, `runbook_agente_linux.md`.
- Externas (T-W1): Microsoft Lifecycle (Windows 10 EOL 2025-10-14; W11 24H2/25H2/26H1; retirada de
  `wmic` en W11 24H2+), documentación Wazuh del agente Windows (10/11/Server 2016-2025) y
  documentación Sysmon de Microsoft/Sysinternals (standalone en Windows 10+; integrado en W11 sin
  coexistencia).
