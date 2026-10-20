---
bloque: legitimo-fix
nombre: L1-fix v3 — causa raíz, actividad legítima REALISTA y determinista, navegador headless evaluado y descartado, vigilancia que mide «hacer» y repetición lista
version: 3
status: approved_by_human
fecha: 2026-10-21
fecha_aprobacion: 2026-10-21
aprobado_por: humano
autor: tfg-planner
depende_de: legitimo-72h (L1, EJECUTADO y FALLIDO · ventana INVÁLIDA) · legitimo-infra (L0, cerrado) · reencuadre-metrica (R2, métrica congelada)
ventana_objetivo: t0 = 2026-10-26T00:00:00Z → t1 = 2026-10-29T00:00:00Z (72 h; **propuesta ABIERTA** · la firma el humano en el gate · este bloque NO la ejecuta)
gate: |
  **APROBADO (2026-10-21).** Q1 receta ✔ · Q2 NPC+semilla descartado ✔ · Q3 `df` desde el agente ✔ · Q4 keepalive acotado ✔ · Q5 **fecha ABIERTA** (propuesta 26/10; la firma el humano antes de `legitimo-72h-v2`) · Q6 PC 3 días sin suspensión + no tocar la víctima ✔ · Q7 plan en git ✔ · Q8 `boveda_version` → 2 ✔ · Q9 navegador headless descartado ✔ (sesión *browser-like* con `curl`). Este bloque **no ejecuta** las 72 h: deja el laboratorio **arreglado, con una
  actividad legítima nueva y probada, vigilado y snapshoteado** (`lab-listo-legit-v2`) y la **repetición**
  especificada. La ventana la ejecutará **`legitimo-72h-v2`** con su propio gate.
  Decisiones que el humano debe ratificar: (1) la **receta** de actividad (§5); (2) el **descarte del
  NPC+semilla** con la evidencia de §4; (3) el `df` **sin tocar la timeline** (§7.2); (4) el keepalive
  **acotado** (§6.3); (5) la **fecha 26/10** (§11, propuesta abierta); (6) el **descarte del navegador
  headless** con la evidencia de **§4.4–§4.8** y la regla pre-registrada de **DT-B** (§4.7).
---

# plan.md — Bloque `legitimo-fix` (v3)

> **Qué es.** El bloque que **arregla la causa** del fallo de L1 (stdout sin tope → disco al 100 %), **rediseña
> la actividad legítima** para que sea una **jornada de oficina real y determinista** (decisión del humano,
> 2026-10-20), **evalúa y descarta el navegador headless** con evidencia de código y una prueba en seco
> acotada (§4.4–§4.8), **blinda** la vigilancia para que un fallo así no vuelva a desapercibido, **conserva la
> evidencia**, **prueba en seco** (incluida la **doble ejecución** de la actividad) y deja un **snapshot limpio
> nuevo** (`lab-listo-legit-v2`) desde el que **repetir** las 72 h.
>
> **Qué NO es.** **No mide** (la ventana anterior es inválida y **no se rescata**). **No ejecuta** las 72 h
> nuevas (eso es `legitimo-72h-v2`). **No toca** la métrica congelada, el corpus, `Hojas/`, `_recursos/`,
> `Dataset/` ni la configuración ni el ruleset de Wazuh. **No instala un navegador en la ventana** (se prueba
> en seco y, si no pasa, se descarta antes de crear el snapshot).
>
> **Frase que resume el bloque:** *quitar la causa, medir «hacer» en vez de «estar», hacer que la actividad
> parezca la de una persona —y sea repetible al milisegundo de secuencia—, decidir en el laboratorio si el
> navegador aporta o estorba, y no arrancar hasta que todo pase una prueba en seco.*

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Causa raíz y hallazgos (v1 + nuevos)](#2-causa-raíz-y-hallazgos-v1--nuevos)
3. [Los 9 puntos del diagnóstico → qué se hace](#3-los-9-puntos-del-diagnóstico--qué-se-hace)
4. [Investigación y decisiones: NPC, semilla y **navegador headless**](#4-investigación-y-decisiones-npc-semilla-y-navegador-headless)
5. [Diseño de la actividad legítima (la receta)](#5-diseño-de-la-actividad-legítima-la-receta)
6. [Los arreglos, fichero por fichero](#6-los-arreglos-fichero-por-fichero)
7. [Vigilancia y guardarraíles](#7-vigilancia-y-guardarraíles)
8. [Extracción corregida (rotación diaria)](#8-extracción-corregida-rotación-diaria)
9. [Snapshot nuevo y evidencia del fallo](#9-snapshot-nuevo-y-evidencia-del-fallo)
10. [Prueba en seco (obligatoria, con doble ejecución)](#10-prueba-en-seco-obligatoria-con-doble-ejecución)
11. [La repetición: bloque, procedimiento y fecha](#11-la-repetición-bloque-procedimiento-y-fecha)
12. [Análisis de seguridad (no romper · no ensuciar · no ocultar)](#12-análisis-de-seguridad-no-romper--no-ensuciar--no-ocultar)
13. [Riesgos y mitigaciones](#13-riesgos-y-mitigaciones)
14. [Criterios de aceptación (verificables)](#14-criterios-de-aceptación-verificables)
15. [Gate humano (lenguaje sencillo)](#15-gate-humano-lenguaje-sencillo)
16. [Ficheros que se tocarán](#16-ficheros-que-se-tocarán)
17. [Trazabilidad](#17-trazabilidad)
18. [Lo que no cuadra y decisiones abiertas](#18-lo-que-no-cuadra-y-decisiones-abiertas)

---

## 0. Resumen ejecutivo

La ventana de 72 h **falló por una sola causa mecánica**: el cliente GHOSTS escribía su log `Trace` a
**stdout** y el lanzador lo redirigía a un fichero **sin tope** (`ghasts.out`) → **4,78 GB** en ~14 h →
**disco al 100 %** → muere la orquestación de la timeline (14:38Z) y, 8 h después, `wazuh-agentd`. La
vigilancia **no lo vio** porque medía *«el proceso está»* y no *«el proceso está haciendo»*.

Este bloque hace **ocho cosas**:

1. **Corta la causa por dos vías independientes**: consola NLog a **`Warn`** **y** tope duro del fichero
   (**20 MB × 2 = 40 MB**) puesto **donde se crea** (lanzador + keepalive). **No** se manda a `/dev/null`.
2. **Rediseña la actividad legítima** (decisión del humano): de un bucle de **209 acciones/180 s** a una
   **jornada de oficina** de **9 h** (09:00–18:00 local) con **ráfagas y pausas reales** (café, comida,
   reuniones, cierre) y **3 días distintos** (lun/mar/mié). **111 / 117 / 105 acciones/día ≈ 333 en la
   ventana** (frente a las ~5,9 k del intento fallido). Ver §5.
3. **Demuestra que el NPC+semilla de GHOSTS no sirve** y lo descarta con evidencia de código: el *modo NPC*
   solo **arranca y para** el cliente; la semilla (`AnimatorRandom.Seed`) solo afecta a la **generación de
   identidades**, no a la actividad; y **la actividad es aleatoria no sembrada** (`new Random()` en varios
   puntos). **Decisión: receta determinista** (§4).
4. **Evalúa el navegador headless y lo descarta** (encargo nuevo del humano, 2026-10-21) con evidencia de
   código y criterios objetivos: es **reproducible en la secuencia de acciones** (solo con `browse` + URL
   fijas + `Loop:false` + `jitter 0`), pero **no en su huella de eventos** (cientos de escrituras por sesión,
   no acotables), **infla `M`** (bajaría el FPR de forma mecánica), cuesta **300–400 MB de disco y 300–600 MB
   de RAM** (VM de 3 GB, **swap 0**), exige **driver offline** y añade modos de fallo (bucle caliente en
   Firefox, hilo muerto silencioso y orfandades en Chrome). Además, **ningún ATA del corpus usa navegador**.
   Se deja una **prueba en seco acotada (DT-B, 90 min)** que puede revertir la decisión con datos; **mientras
   no pase**, se adopta una **sesión web *browser-like* con `curl`** (mismos binarios probados). Ver
   §4.4–§4.9 y §5.7.
5. **Resuelve el `df` sin tocar nada**: el agente **ya reporta el disco** al manager cada **360 s**
   (`df -P` por `localfile` de la config por defecto; **verificado en los archives del intento fallido**:
   220 muestras el 19/10, 100 % a las **14:03:39Z**). Se **elimina** la sonda `df` que v1 añadía a la
   timeline: **la timeline no se toca por telemetría** (§7.2).
6. **Convierte el keepalive en un vigilante de verdad y lo hace *más* restrictivo**: reinicia solo si el
   cliente está **vivo y sin hacer** (dos confirmaciones separadas ≥ 5 min, dentro de bloque, **2
   recuperaciones** máximo, nunca con < 1 GB libre) + **rotación diaria** de la receta (2 reinicios). Todo
   **declarado**, registrado y con regla de validez escrita (§6.3, §11.4).
7. **Rehace la vigilancia host-side** cada **30 min** sin tocar la víctima: **edad de la última acción
   (con calendario de pausas)**, **`last keep alive`** del agente (no `is-active`), **daemons**, **entrada
   de eventos**, **disco de la víctima leído del propio agente** (valor + **tasa**), disco del host, BD de
   GHOSTS, **RAM (solo post-hoc)** → **OK/AVISO/ALARMA** con aviso al humano (§7.1, §7.4).
8. **Deja la repetición lista**: extracción con rotación + dedupe, **snapshot `lab-listo-legit-v2`**,
   **prueba en seco DT0–DT13 + DT-B0–DT-B5** (incluida la **doble ejecución** de la receta, §10-DT9),
   procedimiento y **fecha propuesta: 26/10** (§11).

**Tres datos que cambian el diseño de la vigilancia y de la actividad** (medidos/verificados):

- En el intento fallido, **el disco de la víctima estaba en los `archives` del manager cada 6 min**: la
  señal existía desde el principio; **nadie la leía**. A las **13:03Z** quedaban **1,11 GB** y a las
  **14:03:39Z** ya eran **0 B**. La tasa era **≈ 1,1 GB/h**: un umbral de **3 GB** habría avisado ~2 h
  antes y uno de **2 GB** ~1 h 20 min antes.
- La actividad del intento era **~420 acciones/h** (209 en 180 s). La receta nueva hace **≈ 14,5/h en los
  bloques activos** (12,3/h sobre la jornada de 9 h) y **0** de noche. Eso reduce el denominador `M`
  (declarado en §18).
- **El `auditd` de la víctima no filtra por ruta**: `execve` (80792) **y** `creat/truncate/unlink/rename`
  (80780) se capturan **para todo el sistema** (`Soporte/Wazuh/Reglas/auditd_tfg.rules:20-25`). Por eso la
  **huella de eventos** de una aplicación con *churn* de caché (un navegador) **no es acotable** y **no es
  reproducible** aunque su secuencia de acciones sí lo sea.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

Dejar el laboratorio **en condiciones de repetir** la captura legítima de 72 h **sin repetir el fallo** y
**con una actividad que represente a una persona**, con: (a) causa raíz eliminada y medida; (b) actividad
**realista, determinista y de 3 días distintos**; (c) **navegador headless evaluado y decidido con datos**
(§4.4–§4.8); (d) vigilancia que detecta **«no hacer»**, el **disco** (valor y tasa) y la **caída real del
agente**; (e) extracción corregida; (f) evidencia del fallo preservada; (g) **snapshot limpio nuevo**;
(h) **prueba en seco** que demuestra cada arreglo, **la doble ejecución** y la decisión del navegador;
(i) repetición especificada y fechada.

### 1.2 Entra

- Cortar el stdout (nivel NLog + tope por rotación).
- **Rediseñar la actividad** (`recetas/`): 3 timelines diarias + generador/validador + calendario de bloques.
- **Evaluar el navegador headless** (encargo 2026-10-21): investigación con fuentes, **DT-B (90 min, tope
  duro)**, decisión y, si procede, integración en **un** bloque; si no, descarte declarado (§4.4–§4.9).
- **Sesión web *browser-like* con `curl`** (adoptada con independencia de DT-B): UA fija y honesta, cookies,
  `Referer`, `Accept-Encoding` y descarga de los **requisitos de página** (§5.7).
- **Rotación diaria** de la receta desde el keepalive (declarada).
- Keepalive con heartbeat de actividad, topes y registro.
- Vigilancia por niveles (OK/AVISO/ALARMA) y alarma visible.
- Guardarraíles en `prep` (abortar si el entorno no es el esperado).
- Extracción con rotación + dedupe + verificación de cobertura.
- Evidencia: snapshot del estado roto + extractos + manifiesto + archivo de logs.
- Snapshot `lab-listo-legit-v2` y prueba en seco completa (DT0–DT13 + DT-B0–DT-B5).
- Documentación de la repetición (procedimiento + fecha).

### 1.3 NO entra (fuera de alcance)

- **Volver a medir o «rescatar»** la ventana del 19–22/10: es **INVÁLIDA** (`diagnostico_fallo.md`). Sus
  ficheros se usan **solo** como banco de pruebas de la extracción **y como evidencia** (los `df -P`), nunca
  como medida.
- **Ejecutar las 72 h nuevas** → bloque `legitimo-72h-v2` (§11).
- **Cambiar el ruleset, `ossec.conf`** (salvo `logall_json`, ya diseñado), **la métrica, la bóveda (solo
  sidecar), el corpus, `Hojas/`, `_recursos/`, `Dataset/`**.
- **Arreglar bugs de GHOSTS**: se **declaran y se vigilan** (§2.4). El binario es parte del banco.
- **Instalar software nuevo en la ventana**: si el navegador pasa DT-B, se **pre-estea antes de `t0`** y
  viaja **congelado en `v2`**; si no pasa, **no se instala nada**. Nunca se instala durante `[t0,t1]`.
- **Medir dos opciones de actividad**: la prueba en seco **decide una**; a la ventana va **una sola receta**
  (§4.7).
- **Añadir DNS o TLS al laboratorio**: el "internet local" es HTTP y resuelve por `/etc/hosts`; montar
  HTTPS+CA o un *resolver* es **otro bloque** (§4.6), no este.
- **`git commit` / `push`** (los hace el orquestador/humano; **sí** debe guardarse este plan al aprobarse,
  §15-Q7).
- **Añadir un `df` a la timeline**: no hace falta (§7.2).

> **Cambio de alcance declarado (v2).** v1 decía «no ampliar la actividad ni cambiar la timeline de
> régimen». El humano ha decidido (2026-10-20) **rediseñarla** por realismo. Esto **sustituye** aquella
> restricción y se declara aquí y en §3 (punto 9). Sigue **prohibido** tocar la timeline **por telemetría**
> (el `df` de v1 **desaparece**).

---

## 2. Causa raíz y hallazgos (v1 + nuevos)

### 2.1 La cadena del fallo (resumen de `diagnostico_fallo.md`, verificado)

| # | Hecho | Evidencia |
|---|---|---|
| 1 | `nlog.config` manda **todo el `Trace`** al target **`console`**; el lanzador lo redirige a un fichero **sin rotación ni tope** | `nlog.config` (línea 23 del original) · `client_ctl.sh:15` · `tfg_keepalive.sh:20` |
| 2 | El fichero creció a **4 783 345 664 B** (49 % del FS de 9,8 G) en **~14 h** | `df`, `stat` (2026-10-20 12:57Z) |
| 3 | **14:02:33Z** primer `No space left on device`; **14:38:36Z** última acción; **14:39:52Z** última línea de `app.log` | `logs/app.log` |
| 4 | **21:59:56Z** último keep-alive del agente; **22:00:11Z** `CRITICAL (1107)` al rotar el log de medianoche | `ossec.log`, `agent_control` |
| 5 | El **proceso** del cliente seguía vivo y `statusUp` se refrescaba ⇒ **la vigilancia veía `Up`** | log de vigilancia 18:00Z y 21:00Z |
| 6 | El keepalive solo comprobaba **existencia del proceso** (`if ! pgrep`) ⇒ **zombi funcional** | `tfg_keepalive.sh:19` |

**Mecanismo único:** *stdout sin tope* → *disco lleno* → *orquestación muerta* → *agente muerto*. No hubo
red, ni configuración de Wazuh, ni actualizaciones, ni OOM, ni reinicio de VM.

### 2.2 Tres defectos de diseño que hicieron el fallo «invisible»

1. **La vigilancia medía «estar», no «hacer»** (`statusUp` lo refresca el hilo de socket).
2. **`systemctl is-active wazuh-manager` no prueba que el agente esté dentro** (la unit sigue `active` con
   `wazuh-agentd` muerto).
3. **La vigilancia era cada 3 h y sin umbrales**.

### 2.3 Hallazgos de v1 (se mantienen)

| # | Hallazgo | Evidencia | Qué se hace |
|---|---|---|---|
| **H-A** | `client_ctl.sh start` arranca una **segunda instancia** si ya hay una | `client_ctl.sh:14-15` | **Se arregla** (§6.2): idempotente |
| **H-B** | `stop` usa solo `SIGTERM`: un cliente colgado no muere | `client_ctl.sh:20` | **Se arregla**: `TERM` → `KILL` a los 5 s |
| **H-C** | GHOSTS acumula `Result` en `Bash.cs` (`Result += …`): cada fila de `history_timeline` lleva todo lo anterior | `src/ghosts.client.linux/Handlers/Bash.cs` | **No se parchea**; se **vigila** y se **declara**. Con la receta nueva hay ~333 acciones (antes ~5,9 k): la proyección de crecimiento baja de forma cuadrática |
| **H-D** | `archives.json` y `ossec-archive-20.json` son el **mismo** contenido (hardlink) ⇒ copiar ambos duplicaría `M` | `diagnostico_fallo.md` §3 y §5 | **Dedupe por `sha256`** (§8) |
| **H-E** | `archives.json` **solo** contiene el día en curso; lo anterior en `.gz`; `t1` cae en la rotación | `ossec-archive-19.json.gz` (mtime 00:04Z) | Copia **por días** + regla de borde (§8) |
| **H-F** | `logall_json_ctl.sh` reinicia el manager con `systemctl restart` frágil (`wazuh_apid` huérfanos) | `diagnostico_fallo.md` §4.6 y §5.3 | Reinicio robusto (§6.7) |

### 2.4 Hallazgos NUEVOS de v2 (con evidencia)

| # | Hallazgo | Evidencia (verificada) | Qué se hace |
|---|---|---|---|
| **H-G** | **GHOSTS no tiene semilla para la actividad.** Todo el azar del cliente es `new Random()` sin semilla: `BaseHandler.cs:15` (`_random`), `Jitter.cs:13`, `DelayExtensions.cs:10` (delays `{Random:true}`), `Bash.cs` (comando `random` + `execution-probability`), `TimelineBuilder.cs:82`, y **`UserAgentManager.Get()`** (el handler `Curl` añade `-A "<UA aleatoria>"`, `Curl.cs:33,105`). El único `Seed(int)` del repo (`AnimatorRandom.cs:11`) **no tiene ni un llamador** (`grep '.Seed('` → 0 en `src/`) y **solo afecta a la generación de perfiles NPC**, no a la timeline | §4 | **Receta determinista** (prohibido `"Command":"random"` y delays aleatorios) |
| **H-H** | **El agente Wazuh ya reporta el disco.** La config por defecto de la rama 4.14 (`v4.14.0/etc/ossec-agent.conf`) trae `<localfile><log_format>command</log_format><command>df -P</command><frequency>360</frequency></localfile>`, **y el agente real del laboratorio (4.14.7) lo ejecuta**: en los archives del intento fallido hay **220 muestras** del agente `001` el 19/10 (`location:"df -P"`, 00:03:17Z → 21:57:51Z, cadencia 6 min), con la raíz al **100 % desde las 14:03:39Z** | `%TEMP%\tfg-legit-72h-fallo\ossec-archive-19.json.gz` (filtro `"id":"001"` + `location:"df -P"`) | **No se añade `df` a la timeline**; el watch **lee esta señal** del manager (§7.2) |
| **H-I** | **`syscollector`/`hardware` NO recoge disco** (CPU, RAM, placa; 4.14 añadió usuarios/grupos/extensiones/servicios, no disco). La vía «oficial» de Wazuh para disco es *command monitoring*, que **exige** tocar `agent.conf`/`local_internal_options.conf` + reglas | docs Wazuh *System inventory* + *Disk space utilization* | **Descartada** (prohibido tocar config/ruleset) **y además innecesaria** por H-H |
| **H-J** | **Los reinicios del cliente no deberían cambiar el `machineid`**: el id se guarda en `instance/id.json` y solo se pide al servidor si **falta** (`CheckId.cs`) | `CheckId.cs` | Aun así el watch consultará **todos** los ids de `victima-linux` (defensa ante duplicados) y la rotación se prueba en seco (DT5b) |

---

## 3. Los 9 puntos del diagnóstico → qué se hace

| Punto (`diagnostico_fallo.md` §4) | Acción en este plan |
|---|---|
| 1. **[CRÍTICO] Acotar la salida de GHOSTS** | §6.1 (NLog a `Warn`) + §6.2 (tope 20 MB × 2) |
| 2. **[CRÍTICO] Presupuesto de disco y guardarraíl en `prep`** | §7.3 (≥ 4 GB → aborta) + alarmas de disco por **valor y tasa** (§7.1-5) |
| 3. **[CRÍTICO] Vigilancia que mida *hacer*** | §7.1 (edad de la última acción **con calendario**, `df`, `last keep alive`, daemons) cada **30 min** |
| 4. **Keepalive con heartbeat** | §6.3 (`app.log` mtime + bloques/pausas + confirmación + topes) |
| 5. **Alarma de «agente desconectado»** | §7.1-2 (`last keep alive` > 10 min ⇒ ALARMA) |
| 6. **Reinicio robusto del manager** | §6.7 |
| 7. **Extracción con rotación** | §8 |
| 8. **Re-verificar el presupuesto de `M`** | §8.4 (nuevo presupuesto, medido en DT11) |
| 9. **Timeline** | **CAMBIA (decisión del humano)**: se **rediseña** como jornada de oficina (§5). **Desviación declarada**: el diagnóstico decía «no tocarla» porque el problema no era ella; el humano pide ahora **realismo**. **Lo que sí se respeta**: no se toca **por telemetría** (el `df` de v1 se elimina) y las ventanas **no cruzan medianoche** (limitación de `WorkingHours`) |

---

## 4. Investigación y decisiones: NPC, semilla y navegador headless

### 4.1 Qué se ha mirado

- Código del cliente Linux y de la librería `Ghosts.Domain` (azar, delays, handlers, orquestador).
- `Ghosts.Animator` (NPC) y la documentación oficial del repo clonado (**v8.3.1**, commit
  `4d2e160860f508f699f935472b5515358f534844`).
- Documentación de handlers (`docs/core/handlers/npc_system.md`) y de la API (`docs/core/api/timelines.md`).

### 4.2 Hallazgos (con fuente exacta)

| Pregunta | Respuesta | Fuente |
|---|---|---|
| ¿Existe un «modo NPC» en el cliente? | **Sí, pero no hace lo que parece**: el handler `NpcSystem` solo ejecuta `Start`/`Stop` de la timeline (el binario sigue vivo «sin hacer nada») | `docs/core/handlers/npc_system.md` (texto literal: *«only used to turn the client on and off… not used to control the client's behavior»*) · `src/ghosts.client.linux/Handlers/NpcSystem.cs` |
| ¿«NPC» genera actividad? | **No**: NPC = **identidades sintéticas** (nombre, dirección, carrera, familia…) que genera el *Animator*; sirve para poblar perfiles, no para producir acciones en el endpoint | `docs/animator/index.md` · `src/Ghosts.Animator/Npc.cs` |
| ¿Hay semilla? | **Sí, pero solo para el Animator**: `AnimatorRandom.Seed(int seed)` | `src/Ghosts.Animator/AnimatorRandom.cs:11-14` |
| ¿Se usa esa semilla? | **No**: **cero llamadas** a `.Seed(` en todo `src/` | `grep -rn '\.Seed\(' src` → 0 resultados |
| ¿La actividad del cliente es reproducible? | **No**: `Random` sin semilla en `BaseHandler` (`_random`), `Jitter`, `DelayExtensions` (delays aleatorios), `Bash` (`random`, `execution-probability`), `TimelineBuilder`; y el handler `Curl` añade una **User-Agent aleatoria** por instancia | `BaseHandler.cs:15` · `Jitter.cs:13` · `DelayExtensions.cs:10` · `Bash.cs:69-90` · `TimelineBuilder.cs:82` · `Curl.cs:33,105` · `UserAgentManager.Get()` (`PickRandom()`) |
| ¿Hay una opción de config/CLI para sembrar? | **No**: ni `application.json` ni `CommandLineFlagManager` exponen semilla | `Soporte/Laboratorio/ghosts/client_config/application.json` · `CommandLineFlagManager.cs` |
| ¿Se puede cambiar la actividad en caliente (API)? | El update de tipo `Timeline` **solo escribe el fichero**; **no** recarga el orquestador, y la recarga en caliente **mata** al cliente v8.3.1 | `Comms/Updates.cs:98-99` · `README.md` §3 (hallazgo ya documentado en L1) |

### 4.3 **DECISIÓN: receta determinista** (no NPC+semilla)

Aplicando el criterio del humano (*si existe, es fácil y es más realista → NPC; si no → receta*):

| Criterio | NPC+semilla | Veredicto |
|---|---|---|
| **¿Existe?** | No para la actividad: `NpcSystem` = on/off; la semilla solo afecta a perfiles | **No** |
| **¿Es fácil?** | Requeriría **parchear** el cliente (semilla global en `BaseHandler`/`Jitter`/`DelayExtensions`) → cambiaría el banco de trabajo y B10 | **No** |
| **¿Es más realista?** | No: «NPC» no aporta comportamiento; el realismo lo da la **receta** (jornada, pausas, variedad) | **No** |

⇒ **Se usa la receta** (§5), que además es **reproducible por construcción**: JSON estático, sin `random`,
sin delays aleatorios, sin User-Agent aleatoria, bloques **disjuntos en el tiempo** (sin concurrencia) ⇒
**misma secuencia en dos ejecuciones** (§10-DT9).

**Prueba de laboratorio asociada (DT0, 15 min):** ejecutar dos veces una timeline mínima con
`"Command":"random"` + `DelayAfter` aleatorio y comprobar que las secuencias **difieren**. Es la
demostración empírica de que **no hay semilla** y de que la variabilidad nativa de GHOSTS **no** cumple el
criterio de reproducibilidad. (Si por algún motivo salieran iguales, se repetiría con más eventos; el
resultado esperado —y el que decide— es que **difieran**.)

**Una sola opción en la ventana, como pide el humano:** no hay A/B. Se mide con la receta; si algo falla,
**se repite** (§11.4).

---

### 4.4 Navegador headless: qué permite GHOSTS v8.3.1 (fuentes)

**Encargo del humano (2026-10-21):** evaluar meter un navegador headless en el bloque de "navegar" porque
"sería más realista" (procesos hijos, caché, DNS, TLS). Criterio **literal** que se respeta:

> *Si es **reproducible** (misma secuencia en dos ejecuciones, como la receta) **y mejora de verdad** los
> resultados (más realismo sin romper la comparación) → **se usa**. Si da **problemas** (fragilidad,
> RAM/CPU, no determinista, complicación) → **se descarta** y se sigue con `curl`. **No** se hacen dos
> mediciones "por si acaso": se decide **en el laboratorio** y a la ventana entra **una sola opción**.*

Lo primero: **sí hay navegador en el cliente**, y no es un `curl` disfrazado. Es **Selenium**.

| Pregunta | Respuesta | Fuente exacta (v8.3.1, `4d2e160`) |
|---|---|---|
| ¿Hay handler de navegador en el cliente Linux? | **Sí, dos**: `BrowserFirefox` y `BrowserChrome` (Selenium WebDriver). El orquestador lanza **un hilo por handler** | `src/ghosts.client.linux/Handlers/Browser{Firefox,Chrome}.cs` · `TimelineManager/Orchestrator.cs:164-169` |
| ¿Headless? | **Sí**: `"isheadless": "true"` añade `--headless` (Firefox) / `headless` (Chrome). **Chrome headless no necesita `Xvfb`** | `BrowserFirefox.cs:236-239` · `BrowserChrome.cs:139-142` |
| ¿Qué comandos hay? | `random`, `randomalt`, `browse`, `download`, `crawl`, `click*`, `type*`, `js.executescript`, `manage.window.size`, `outlook`, `sharepoint`, `blog` | `BaseBrowserHandler.cs:96-270` · `docs/core/handlers/browser.md` |
| ¿Qué es **determinista**? | **`browse`** (URL fija de `CommandArgs[0]`) y **`download`**. **No** lo son `random`/`randomalt` (eligen URL con `_random.Next`, **sin semilla**), ni `stickiness`, ni `browse-probability`, ni `delay-jitter` | `BaseBrowserHandler.cs:209-219, 386, 396, 490, 496` · `BaseHandler.cs:15` |
| ¿Y las variables de URL? | `{uuid}`, `{n}`, `{c}` y `url-replace` se sustituyen **en cada petición** con azar; `{now}` con la fecha local | `Ghosts.Domain/Code/RequestBuilder.cs:24-44` |
| ¿Cuándo arranca el navegador? | **Chrome: al abrir su ventana** (`Init`→`WorkingHours.Is` **antes** de crear el driver). **Firefox: al arrancar el cliente** (no llama a `Init`) ⇒ RAM 24/7 | `BrowserChrome.cs:20-26` · `BaseHandler.cs:17-20` · `BrowserFirefox.cs:24-30, 103, 120` |
| ¿Y si el driver falla? | **Firefox**: `while (!hasRunSuccessfully)` **sin espera ni tope** ⇒ **bucle caliente infinito** (`_log.Debug(e)` en cada vuelta, **que además mantiene fresco `app.log`**: engaña al heartbeat) | `BrowserFirefox.cs:28-30, 149` |
| | **Chrome**: excepción ⇒ `_log.Error` y **el hilo muere** (fallo **silencioso**: 0 acciones) | `BrowserChrome.cs:63` |
| ¿Orfandades? | El cierre mata por etiqueta `--browser-id` (`ps … \| grep \| xargs kill`) **solo si el hilo se desenrolla**; un `SIGKILL` del cliente (escalada del `stop`) **deja el navegador vivo** | `BaseBrowserHandler.cs:297-330` · `BrowserChrome.cs:113-121` |
| ¿De dónde sale el driver? | El cliente publicado **no trae `geckodriver` ni `chromedriver`**, pero **sí `selenium-manager`**: sin driver local **intenta descargarlo** (la víctima **no tiene NAT**) | listado de `D:\TFG-VMs\material-ghosts\client-linux\` · `client-linux/selenium-manager/linux/selenium-manager` · `ghosts.client.linux.csproj:29-30` |
| ¿Cómo se pasan los args? | `ContainsKeyWithOption` compara **string exacto**: hay que escribir **`"true"`/`"false"`**; un booleano JSON lanza `InvalidCastException` | `Ghosts.Domain/Code/Helpers/DictionaryExtensions.cs:9-12` |

### 4.5 Navegador headless: qué cuesta en **este** laboratorio

| Concepto | Dato | Fuente / medida |
|---|---|---|
| SO víctima | Ubuntu Server 24.04.5, **sin escritorio** (los ataques GUI pre-estean `Xvfb`) | `Laboratorio/README.md` §4 · `Dataset/Ataques/.../ATA053/README.md` §2 |
| RAM | **3 GB** (2,9 útiles), **swap 0**; 616 MB usados con el cliente GHOSTS | `Laboratorio/README.md` §4 · `diagnostico_fallo.md` §1 |
| Disco | LV **9,8 GB**; tras borrar `ghasts.out` quedan **~4,8 GB**; **G-2 exige ≥ 4 GB** | `diagnostico_fallo.md` §1 |
| Navegador + driver + libs | **≈ 300–400 MB** en disco (zip de Chrome for Testing ~150 MB + chromedriver + libs de sistema; Firefox tarball + GTK, similar) | a medir en **DT-B0** |
| RAM del navegador | **+300–600 MB** (1 pestaña + 2-3 *renderers*) ⇒ **~31 %** de la RAM de la víctima | a medir en **DT-B2** |
| Red | El "internet local" es **HTTP** y los "dominios" son **`/etc/hosts`** ⇒ **no hay DNS ni TLS** que ejercitar | `internet_local/README.md` §4-§5 |
| Versiones | Cliente con **Selenium 4.25.0** ⇒ obliga a versiones de navegador **antiguas y emparejadas** con su driver; **sin NAT**, `selenium-manager` no resuelve nada | `ghosts.client.linux.csproj:29-30` |
| Trabajo | **DT-B0…DT-B5 ≈ 90 min** (tope duro) + **≈ 2 h** de integración **solo si pasa** | este plan |

### 4.6 Qué mejoraría **de verdad** y qué no

| Promesa | ¿Se cumple aquí? | Por qué |
|---|---|---|
| **Procesos hijos** | **Sí** | zygote + *renderer* + GPU ⇒ 4–8 `execve` nuevos (80792) |
| **Caché / ficheros** | **Sí, pero…** | perfil temporal con SQLite y caché ⇒ **cientos de `creat/unlink`** (80780). **Eso es el problema, no la virtud** (ver abajo) |
| **Peticiones web reales** | **Sí** | 6–30 peticiones por sesión con `Referer`, `Accept`, `Accept-Encoding` reales |
| **DNS** | **No** | resolución por `/etc/hosts`; **cero paquetes DNS** |
| **TLS** | **No** | el sitio es **HTTP**; exigiría servidor HTTPS + CA propia (otro bloque) |
| **Mejora de la medida** | **No; la degrada** | el `auditd` captura **todo** `execve` y **toda** escritura **sin filtro de ruta** ⇒ el navegador **infla `M`** y **baja el FPR de forma mecánica** (dilución del denominador) |
| **Utilidad para *estos* ataques** | **Ninguna directa** | **0** ATA del corpus usan navegador (`firefox\|chrome\|chromium\|navegador\|browser` en `Dataset/Ataques/Comandos/**` → **0 coincidencias**) |

> **La trampa del denominador, explícita.** `FPR = FP / M`. Un navegador añade **miles de eventos benignos
> de alta frecuencia** (caché, SQLite, `.parentlock`, *journal*) que **no** son actividad del usuario y que
> **no** discriminan nada. El FPR bajaría **sin que la detección mejore**: sería un número mejor y una medida
> peor. Es justo lo contrario de lo que el TFG debe hacer (§18.3-1 ya advierte de la sensibilidad de `M`).

### 4.7 La prueba en seco que lo decide (**DT-B**, 90 min, tope duro)

**Regla pre-registrada** (se escribe **antes** de mirar los datos y no se cambia después):

> *El navegador se usa en **un solo bloque (B3, la sesión web)** **solo si DT-B0…DT-B5 pasan TODOS**. Cualquier
> fallo ⇒ **se descarta** y B3 sigue con `curl`. No hay repetición "por si acaso" ni segunda opción en la
> ventana.*

Se ejecuta **fuera de la ventana**, sobre un **revert desechable** de `lab-listo-legit` (después se revierte
otra vez: no queda nada), con manager + GHOSTS + internet local arriba y `logall_json` **ON** para DT-B4.
Navegador candidato: **Chrome for Testing** (zip oficial, versión **emparejada** con chromedriver, sin
auto-actualización, sin `snap`, sin `Xvfb`). **Firefox queda descartado de entrada** por el bucle caliente
(`BrowserFirefox.cs:28-30`) y por arrancar al inicio del cliente.

| # | Prueba | Cómo | Pasa si (umbral objetivo) | Tiempo |
|---|---|---|---|---|
| **DT-B0** | **Pre-staging** | Bajar **Chrome for Testing + chromedriver** (URL+tamaño+`sha256` a `browser_eval.md`), descomprimir en `~/browser/`, resolver libs (`ldd chrome \| grep 'not found'`), `chrome --version` == `chromedriver --version`, `chrome --headless=new --dump-dom about:blank` | **0** libs ausentes; versiones **emparejadas**; arranque headless OK; **disco libre ≥ 3,5 GB** | 30 min |
| **DT-B1** | **¿Misma secuencia?** (2 ejecuciones) | `browser_dry.json`: **1 handler `BrowserChrome`**, `Loop:false`, `Initial:about:blank`, **6 eventos `browse`** con URL fijas (sin `{uuid}`/`{n}`/`{c}`/`{now}`), `DelayAfter` **fijo**, `delay-jitter` **ausente**, `isheadless:"true"`, `ua-string` **fija**, `incognito:"false"`, `block*:"false"`. **run 1** → `stop` → **run 2** | **(a)** `history_timeline` (`handler=BrowserChrome`, `command=browse`) → **misma lista de `CommandArg`** (6, mismo orden). **(b)** `web_access.log` del host → **mismo conjunto de rutas** y **mismo conteo por ruta** en ambos runs (los 6 *top-level* en el mismo orden) | 20 min |
| **DT-B2** | **Ciclo de vida y orfandades** | `ps -o rss` cada 30 s; luego `client_ctl.sh stop`; luego `kill -9` del cliente (escalada real) | **0** procesos `chrome`/`chromedriver` huérfanos en **los dos** casos (si no: `client_ctl.sh` debe limpiarlos y se re-prueba) | 20 min |
| **DT-B3** | **Recursos** | Durante B1/B2: `free -m`, `vmstat 5`, `df`, tamaño del perfil | RAM libre **mínima ≥ 512 MB**, **swap 0**, `load1 < 3`; perfil+caché **≤ 50 MB/sesión**; free **≥ 3,5 GB** | (incluido) |
| **DT-B4** | **Impacto en `M`** | `logall_json` ON: una sesión de **6 páginas** con navegador vs. la **misma** sesión con `curl` (8 peticiones); contar eventos del agente `001` en cada ventana y separar `80792` (execve) de `80780` (escritura) | **eventos/sesión navegador ≤ 1 500** **y** `M_con_navegador / M_sin_navegador ≤ 1,4` **por día** | 15 min |
| **DT-B5** | **Modo de fallo (negativo)** | Ocultar el driver del `PATH` y arrancar el cliente 5 min | **No** bucle caliente (`CPU < 20 %`, `app.log` < 1 MB/5 min) **y** el watch marca el bloque sin acciones; **0** acciones perdidas en silencio | 5 min |

- **Registro**: `Soporte/Laboratorio/legitimo_72h/browser_eval.md` con la salida literal de cada DT, hora
  UTC, cifras de RAM/disco/eventos y veredicto **PASS/FAIL** por prueba + veredicto final.
- Si **DT-B0** falla (libs, versiones, offline): **se para ahí** (30 min perdidos, no 90).
- Si pasa todo: se **integra en B3** (solo esa sesión), se regeneran `d1/d2/d3` (**+1 h**) y `v2` lleva el
  navegador. Si falla algo: **`v2` no lleva nada de navegador** y el revert lo garantiza.

### 4.8 **DECISIÓN v3: se descarta el navegador** (con el criterio del humano)

> Esta es la **decisión pre-registrada**. **DT-B (§4.7) es su test de falsación**: si pasa completo, esta
> tabla se marca «superada por DT-B» y el navegador entra en B3. Mientras no pase, **no entra**.

| Criterio del humano | Navegador (Chrome for Testing, B3) | Veredicto |
|---|---|---|
| **¿Reproducible?** (secuencia) | **Sí, pero solo desactivando casi todo** (`Loop:false`, sin `random`, sin `stickiness`, sin jitter, sin placeholders) ⇒ **6 páginas/día**, no una sesión de navegación | **Empate técnico**: lo que se gana en realismo se pierde en configuración |
| **¿Reproducible?** (huella de eventos) | **No**: cientos de `creat/unlink` por sesión, dependientes del *scheduler* y de SQLite; **no acotable** | **No** |
| **¿Mejora de verdad la medida?** | **No**: infla `M` y **baja el FPR mecánicamente**; ningún ATA usa navegador | **No** |
| **¿Fragilidad?** | **Sí**: driver offline + versiones emparejadas; Firefox = bucle caliente; Chrome = hilo muerto silencioso; orfandades con `SIGKILL` | **Sí** |
| **¿RAM/CPU?** | **+300–600 MB** sobre 2,9 GB **sin swap** (un pico = OOM *kill* aleatorio); pico de CPU al arrancar el *renderer* | **Sí** |
| **¿Complicación?** | **Sí**: +300–400 MB de disco (margen G-2 a 400 MB), pre-staging con `sha256`, integración +1 h, y un modo de fallo nuevo en **la única ventana** que tenemos | **Sí** |
| **¿Fecha?** | 26/10 con 15 h ya planificadas; esto añade **3–4 h** | **No cabe con holgura** |

⇒ **Se descarta.** No es "no me gusta": es que **falla cinco de los seis criterios** que fijó el humano y,
en el único que aprueba (la secuencia), solo aprueba **vaciándolo de lo que lo hacía interesante**.

**Qué revertiría la decisión** (declarado, para que no parezca terquedad):

1. que **DT-B pase completo** (entonces se usa en B3, y este apartado se marca «superado por DT-B»);
2. que exista **infraestructura local con HTTPS+CA y DNS** (hoy no la hay: §4.6);
3. que GHOSTS arregle el bucle caliente de Firefox y el cliente fije versión de Selenium
   (`BrowserFirefox.cs`, `ghosts.client.linux.csproj`);
4. que la víctima tenga **más RAM** (o swap) y **más disco**.

**Lo que sí se adopta** (§5.7): una **sesión web *browser-like* con `curl`** —mismos binarios ya probados—
con **UA fija y honesta**, **cookies de sesión**, **`Referer`**, **`Accept-Encoding`** y descarga de los
**requisitos de página** (CSS/JS/SVG) en orden. Da parte del realismo (varias peticiones encadenadas,
sesión, descarga, caché en disco) **sin** proceso nuevo, **sin** RAM, **sin** driver y **sin** azar. Y no
cambia el recuento de acciones (§5.3).

### 4.9 Presupuesto de RAM (nuevo, y por qué importa)

La víctima tiene **3 GB y swap 0**: si se pasa, el *OOM killer* mata **un proceso cualquiera** (podría ser
`wazuh-agentd` o el propio cliente) y la ventana se pierde **sin traza clara**.

| Componente | RSS esperado | Estado |
|---|---|---|
| Línea base medida (SO + agente + cliente GHOSTS) | **616 MB** de 2,9 GB | medida en el intento fallido (`diagnostico_fallo.md` §1) |
| **Añadido del bloque** (receta + `curl` + logs) | **≤ 100 MB** | presupuesto; se **mide** en DT3/DT9 y se declara |
| Navegador headless (si DT-B pasara) | **+300–600 MB** (10–20 % de la RAM) | **descartado**; si se usara, G-12 subiría a **2000 MB** libres en `prep` |
| **Regla** | free ≥ **1,5 GB** en `prep` (G-12) y **≥ 512 MB** durante la ventana (post-hoc) | §7.3, §4.10 |

### 4.10 Cómo se vigila la RAM sin tocar la víctima

- **No** hay señal de RAM libre en los `archives` (el `syscollector` reporta **inventario** —CPU/RAM/placa—,
  no muestras de memoria libre; y el `df -P` solo trae disco).
- **Solución declarada (coste 0 eventos)**: el keepalive lee `/proc/meminfo` **con `read` de bash** (sin
  `fork`, sin `execve`) cada 10 min, escribe `ram_free_mb=` en `keepalive.log` y **`ALARMA_RAM`** si < 256 MB.
  Se lee **al cerrar** (post-hoc) ⇒ **no es vigilancia en tiempo real** y así se declara.
- `prep` **sí** puede mirar la víctima antes de `t0` (G-12: `free -m` ≥ 1,5 GB) y es donde se aborta.

---

## 5. Diseño de la actividad legítima (la receta)

### 5.1 Principios

1. **Jornada de oficina real** en hora local (Europe/Madrid, **CET = UTC+1** desde el 25/10):
   **09:00–18:00 local = 08:00–17:00 UTC**. Fuera de ahí, el usuario **no está**.
2. **Ráfagas y pausas de verdad**: trabajo en ráfagas de 3–6 acciones (30–70 s) separadas por pausas de
   4–12 min; **café** (20 min) y **comida** (60 min) **sin actividad**; reuniones de tarde con huecos largos.
3. **Determinismo**: solo `Command` (bash). **Prohibido** `"Command":"random"`, `{Random:true}`, el handler
   `Curl` (inyecta UA aleatoria) y **cualquier handler de navegador** (`BrowserFirefox`/`BrowserChrome`:
   azar en `random`/`stickiness`/placeholders y huella de eventos no acotable — §4.8). Todo `curl` va
   **dentro** del `Command` con `-A` fija, cookies y `Referer` (§5.7).
4. **Bloques disjuntos** (una ventana por bloque, sin solape) ⇒ **sin concurrencia** ⇒ orden global
   determinista.
5. **Legítimo por construcción**: lista blanca de binarios y rutas; nada que se parezca a un TTP
   (`nc`, `base64 -d`, `chmod 777`, `rm -rf`, descargas+ejecución, `/etc`, `/tmp` del sistema…).
6. **Cobertura de operaciones** (lo que el HIDS debe saber que es normal): `mkdir, echo, cat, cp, mv, tar,
   gzip, md5sum, sha256sum, ls, find, du, df, wc, date, curl` (web, descarga, `POST`, WebDAV `-T`/`PROPFIND`),
   y `rm -f` acotado a ficheros temporales propios.

### 5.2 Calendario del día (UTC · local = UTC+1)

| Bloque | UTC | Local | Min | Qué pasa | Acciones | Ritmo |
|---|---|---|---|---|---|---|
| **B1 Llegada** | 08:00–08:12 | 09:00–09:12 | 12 | login, fecha, agenda, comprobar intranet, primer correo | **9** | ráfaga 30–90 s |
| **B2 Correo y mañana** | 08:12–10:00 | 09:12–11:00 | 108 | leer/responder correo, adjuntar, ordenar carpetas | **26** | ráfagas de 3 a 40–70 s + huecos 4–8 min |
| **P1 Café** | 10:00–10:20 | 11:00–11:20 | 20 | **PAUSA** (sin actividad) | 0 | — |
| **B3 Documentos** | 10:20–13:00 | 11:20–14:00 | 160 | informe: escribir secciones, copias, comprimir, huellas, contar, revisar | **42** | ráfagas de 5–6 a 30–60 s + huecos 3–7 min |
| **P2 Comida** | 13:00–14:00 | 14:00–15:00 | 60 | **PAUSA** (sin actividad) | 0 | — |
| **B4 Reuniones/tarde** | 14:00–16:15 | 15:00–17:15 | 135 | acta, compartir en nube, descargar plantilla, consultar portal | **22** | huecos 4–12 min |
| **B5 Cierre** | 16:15–17:00 | 17:15–18:00 | 45 | copia de seguridad, subir a nube, huellas, `df`/`du`, limpiar temporales | **12** | 60–120 s |
| **Noche** | 17:00–08:00 | 18:00–09:00 | 900 | **sin actividad GHOSTS** (ruido de fondo del endpoint: auditd/syscheck/SCA/`df -P` del agente) | 0 | — |

- **Jornada: 9 h de reloj** (08:00–17:00Z), con **1 h 20 min de pausas** ⇒ **7 h 40 min de actividad**
  (111 acciones ⇒ **≈ 14,5 acciones/h** en los bloques activos; **12,3/h** sobre la jornada).
- **Hueco máximo dentro de bloque: 12 min** (B4). Umbral del keepalive: **30 min** (×2,5 de margen).
- **Hueco máximo legítimo del día: 15 h** (noche) ⇒ **la vigilancia NO juzga fuera de 08:00–17:00Z**.

### 5.3 Día 1 (lunes) — «cierre de informes» (111 acciones)

Detalle por bloque (los comandos exactos los fija `receta_legitima.py`; aquí va el **contenido aprobable**):

| # | Bloque | Acción (familia) | Comando tipo |
|---|---|---|---|
| 1 | B1 | sello de llegada | `date -u +%FT%TZ > /home/angel/Documentos/llegada_$(date -u +%F).txt` |
| 2 | B1 | listar carpeta de trabajo | `ls -la /home/angel/Documentos` |
| 3 | B1 | crear estructura del día | `mkdir -p /home/angel/Documentos/{informes,actas,copias,correo} /home/angel/Descargas` |
| 4 | B1 | agenda del día | `echo '09:30 reunion de area; 12:00 informe' > /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 5 | B1 | leer agenda | `cat /home/angel/Documentos/agenda_$(date -u +%F).txt` |
| 6 | B1 | comprobar intranet | `curl -s -o /dev/null -w '%{http_code}' http://intranet.local:8080/` |
| 7 | B1 | titulares | `curl -s http://intranet.local:8080/noticias.html -o /home/angel/Descargas/noticias.html` |
| 8 | B1 | tamaño de lo descargado | `wc -c /home/angel/Descargas/noticias.html` |
| 9 | B1 | primer correo (borrador) | `echo 're: estado del informe' > /home/angel/Documentos/correo/borrador_1.txt` |
| 10-17 | B2 | **correo (×3 rondas)**: consultar buzón (paste), escribir, releer | `curl -s -X POST -d 'consulta_buzon' http://intranet.local:9090/paste` · `echo … >> …/correo/borrador_1.txt` · `cat …` |
| 18-25 | B2 | **adjuntos**: crear informe base, empaquetar, huella, tamaño | `echo … > …/informes/informe.txt` · `tar -czf …/informes/adjunto_$(date -u +%F).tar.gz -C …/informes informe.txt` · `sha256sum …` · `du -sh …` |
| 26-35 | B2 | **ordenar**: copias, renombrar, listar, contar ficheros | `cp -f …/informe.txt …/informe.bak` · `mv …/borrador_1.txt …/correo/enviado_1.txt` · `find …/Documentos -type f \| wc -l` |
| 36-40 | B3 | **consulta web** (intranet, ayuda, plantilla) + descarga CSV | `curl -s http://intranet.local:8080/ayuda.html -o /dev/null` · `curl -s http://intranet.local:8080/descargas/plantilla_informe.csv -o /home/angel/Descargas/plantilla_informe.csv` |
| 41-49 | B3 | **redactar** (6 secciones: `echo` + `cat` + `wc -l`), en 3 ráfagas | `echo '1. alcance …' >> …/informes/informe.txt` · `cat …` · `wc -l …` |
| 50-59 | B3 | **comprimir y verificar**: `gzip -k`, `md5sum`, `sha256sum`, `ls`, `du` | `gzip -kf …/informes/informe.txt` · `md5sum …/informe.txt.gz` |
| 60-69 | B3 | **consolidar**: `tar -czf`, copiar a Descargas, huella, `find`/`du` de control | `tar -czf …/Descargas/informes.tar.gz -C …/Documentos informes` · `du -sh …` |
| 70-77 | B3 | **repaso**: `grep -c`, `head`, `tail`, `wc`, `ls -la`, `df -h /` (una vez) | `head -n 5 …/informe.txt` · `df -h /` |
| 78-87 | B4 | **reunión**: acta (crear, escribir, leer), copiar a carpeta compartida | `echo 'acta de reunion del area' > …/actas/acta_$(date -u +%F).txt` · `cp …/actas/… …/actas/…` |
| 88-99 | B4 | **nube**: subir acta e informe (`curl -T`), listar (`PROPFIND`), consultar portal y noticias | `curl -s -T …/actas/acta_$(date -u +%F).txt http://nube.local:9092/nube/actas/` · `curl -s -X PROPFIND -H 'Depth: 1' http://nube.local:9092/nube/` |
| 100-111 | B5 | **cierre** (12): `tar` de copia, `sha256sum`, leer huella, subir copia, `PROPFIND`, `du`, `df`, `cp` a Descargas, `wc -c`, `rm -f` temporales, `date`, `ls` final | `tar -czf …/copias/copia_$(date -u +%F).tar.gz -C …/Documentos informes actas` · `curl -s -T …/copias/… http://nube.local:9092/nube/copias/` · `rm -f /home/angel/Descargas/tmp_*.csv` (sin `tmp_*` previos ⇒ **no-op** benigno) |

> **Nota sobre `df -h /`**: aparece **una vez**, en B3, como lo haría un usuario. **No** es telemetría: la
> telemetría de disco es del agente (§7.2).
>
> **Nota sobre la web (v3)**: las acciones web de B1 y B3 se reformulan como **una sesión *browser-like***
> (§5.7) **sin cambiar el recuento** de la tabla. No se añade ningún handler de navegador (§4.8).

### 5.4 Días 2 y 3 (variedad)

| Día | Tema | Delta respecto a D1 | Acciones |
|---|---|---|---|
| **D2 (martes)** | «reuniones y portal» | +6 en B2 (más correo y dos adjuntos), −8 en B3 (menos redacción), **+8 en B4** (dos reuniones: acta + compartir + descarga de la plantilla de acta + `PROPFIND`), B5 igual | **117** |
| **D3 (miércoles)** | «revisión y copias» | −4 en B2 (menos correo), **+4 en B3** (auditoría de ficheros: `find`/`du`/`wc`/`ls`), **−6 en B4** (una sola reunión), B5 igual (copia completa + verificación de huellas) | **105** |

- **Variedad real**: cambian los **contenidos** (secciones, nombres de fichero con fecha, orden de las
  ráfagas), los **volúmenes** y la **tarde**; no es «el mismo día tres veces».
- **Total ventana**: **333 acciones** (vs. ~5,9 k estimadas del intento fallido).

### 5.5 Cómo se garantiza (generador + validador)

`_artefactos/scripts/construir_receta_legitima.py` (nuevo, stdlib) contiene la **receta como datos**
(horas, bloques, acciones) y:

1. **Genera** `recetas/d1.json`, `d2.json`, `d3.json` (timelines GHOSTS completas) y
   `recetas/calendario.json` + `recetas/bloques.env` (misma fuente para watch y keepalive).
2. **Calcula los delays** desde las horas objetivo y aplica el **guardián de fin de bloque**: el último
   evento de cada bloque duerme **hasta 6 min más allá** de `UtcTimeOff` ⇒ el bloque **termina limpio** y
   al día siguiente empieza por el **primer** evento (sin derives ni repeticiones).
3. **Valida (`--check`)**: `Status=Run`; 1 handler por bloque con ventana; `suma(delays) ≥ duración`;
   **hueco máximo intra-bloque ≤ 20 min**; recuento por día = 111/117/105; **cero** `random` y **cero**
   delays aleatorios; **cero comillas dobles** en comandos; binarios y rutas en **lista blanca**; sin
   `sudo`; sin rutas del sistema fuera de `/home/angel`.
4. **Emite** `recetas/receta_resumen.md` (tabla hora→acción de los 3 días) para el gate y el TFG.

**Artefactos generados que se versionan**: los 3 JSON + calendario + `bloques.env` + resumen (con `sha256`).
El **modo dry** (para la prueba en seco) **no** se versiona: se genera al vuelo con `--dry --base HH:00Z`
(comprime ×40 y mapea los bloques en secuencia) y su `sha256` se anota en `prueba_en_seco.md`.

### 5.6 Qué se hace con la timeline vieja

`timeline_72h.json` y `timeline_72h.dry.json` **no se borran**: se **archivan** en
`Soporte/Laboratorio/legitimo_72h/recetas/superseded/` con una nota (`SUPERSEDED.md`: por qué, cuándo y que
su `sha256` sigue citado en B10 v1). **No se oculta nada** (§12.3).

### 5.7 La sesión web *browser-like* con `curl` (lo que se adopta del encargo del navegador)

El navegador **se descarta** (§4.8), pero **no se ignora lo que pedía**: que "navegar" parezca navegar.
Se consigue **reformulando 8 acciones que ya existen** (mismo recuento: **111/117/105**), no añadiendo
ninguna. Diferencias con v2: **sesión con cookies**, **`Referer`**, **`Accept`/`Accept-Encoding`**,
**descarga de los requisitos de página** (CSS/JS/SVG) y **descarga real de un PDF**, todo con **UA fija**.

| Acción v2 (nº) | Acción v3 (misma posición, mismo número) | Comando (plantilla) |
|---|---|---|
| B1-6 "comprobar intranet" | **abrir portal (sesión)** | `curl -sS -A 'TFG-Legit/1.0 (Linux; x86_64; sesion-web)' -c /home/angel/.cache/tfg-web/cookies.txt -H 'Accept: text/html,application/xhtml+xml;q=0.9,*/*;q=0.8' --compressed -o /home/angel/.cache/tfg-web/index.html -w '%{http_code}' http://intranet.local:8080/` |
| B1-7 "titulares" | **requisitos de la página (3 peticiones)** | `curl … -b …/cookies.txt -e http://intranet.local:8080/ --compressed -o …/styles.css http://intranet.local:8080/styles.css && curl … portal.js && curl … assets/logo.svg` |
| B1-8 "tamaño de lo descargado" | **tamaño + huella del portal** | `wc -c …/index.html && sha256sum …/styles.css` |
| B3-36 "consulta web (intranet)" | **navegar a noticias (con `Referer`)** | `curl … -b cookies -e …/index.html --compressed -o /home/angel/Descargas/noticias.html http://intranet.local:8080/noticias.html` |
| B3-37 "ayuda" | **ayuda.html (con `Referer`)** | `curl … -b cookies -e …/noticias.html -o /dev/null -w '%{http_code}' http://intranet.local:8080/ayuda.html` |
| B3-38 "descarga CSV" | **descarga de la plantilla (caché)** | `curl … -b cookies -o /home/angel/.cache/tfg-web/plantilla_informe.csv http://intranet.local:8080/descargas/plantilla_informe.csv` |
| B3-39 "descarga PDF" | **descarga del manual (PDF real)** | `curl -sS … -o /home/angel/Descargas/manual_empleado.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` |
| B3-40 "verificar descarga" | **tamaño + huella del PDF** | `wc -c …/manual_empleado.pdf && sha256sum …/manual_empleado.pdf` |

**Por qué esto sí es determinista** (y el navegador no): cada petición es un `execve` declarado, con URL
fija, orden fijo, **sin placeholders** (`{uuid}`/`{n}`/`{c}`/`{now}`), **sin `random`** y **sin UA
aleatoria**. El `Result` de cada acción es estable (`%{http_code}` = `200`, `wc -c` y `sha256` de ficheros
fijos). **Coste**: 0 procesos nuevos, 0 MB de RAM, 0 MB de disco relevante (caché < 2 MB), **+8–10 `execve`
al día** (≈ 0,01 % de `M`).

**Lo que NO se simula** (y se declara en el TFG, §18.3): procesos hijos de un navegador, caché de un motor
real, **DNS** y **TLS**. Si algún día se quieren, es **otro bloque** con infraestructura propia (§4.6).

**Validación en el generador** (`--check`, DT10): `web_session=1`; **UA fija y honesta** (`TFG-Legit/…`, no
suplanta un navegador); **cookie jar + `Referer`** en las 8; **3 requisitos**; **0** placeholders; **0**
handler `BrowserFirefox|BrowserChrome`; recuento por día **111/117/105** (sin cambios).

---

## 6. Los arreglos, fichero por fichero

### 6.1 `nlog.config` — el nivel de la consola (copia versionada en el repo)

**Fichero nuevo:** `Soporte/Laboratorio/ghosts/client_config/nlog.config` (copia del cliente con **una**
línea cambiada). Se instala con `deploy_client.ps1` (§6.5).

```diff
-    <logger name="*" minlevel="Trace" writeTo="console" />
+    <!-- TFG L1-fix: la consola (stdout → client.out) solo lleva AVISOS y ERRORES.
+         app.log (1 MB × 20) sigue con TODO a Trace menos HEALTH/TIMELINE; clientupdates.log
+         (500 KB × 20) sigue con HEALTH/TIMELINE. No se pierde nada diagnóstico. -->
+    <logger name="*" minlevel="Warn" writeTo="console" />
```

```diff
-  <target name="logfile" ... archiveAboveSize ="1000000" maxArchiveFiles="2" />
+  <target name="logfile" ... archiveAboveSize ="1000000" maxArchiveFiles="20" />
```

**Por qué `Warn` y no `Info` ni `/dev/null`:**

- **`Info` no basta**: el volumen lo generan los mensajes **por acción** (`Curl`, `Command`), que a `Trace`
  llenaron 4,78 GB; a `Info` seguirían saliendo. `Warn` deja **solo** lo que sirve para diagnosticar
  (`IOException`/`ENOSPC` incluidos).
- **`/dev/null` se descarta**: si el cliente **no arranca** (.NET, config inválida, máquina duplicada), lo
  único que lo cuenta es stdout/stderr ⇒ tirarlo **ocultaría** el próximo fallo.
- **`app.log` a 21 MB** (1 MB × 21): con 3 MB, un fallo en la hora 60 podía **rotar fuera** la causa. Aumento
  acotado que no afecta a la actividad medida.

### 6.2 `Soporte/Laboratorio/ghosts/client_ctl.sh` — tope duro y arranque/parada correctos

| Cambio | Detalle | Por qué |
|---|---|---|
| **Tope por rotación** | `TFG_CLIENT_OUT_MAX_MB` (def. **20**); antes de arrancar y **cada 30 s** (keepalive): si `client.out` > 20 MB → `cp client.out client.out.1` + `: > client.out` (**copytruncate**, seguro con `O_APPEND`) | **Tope duro por construcción**: 20 + 20 = **40 MB máximo** |
| **Append, no truncar** | `>> "$DIR/client.out"` | Conservar el historial de todos los arranques |
| **Nombre nuevo** | `client.out` (se deja de usar `ghasts.out`) | Evitar confusión con el fichero envenenado (que queda documentado) |
| **`start` idempotente** (H-A) | Si `pgrep -f ghosts.client.linux` → **sale** (rota y avisa) | Evitar **dos instancias** (duplicaría acciones) |
| **`stop` escalado** (H-B) | `TERM` → espera 5 s → `KILL` → informa | Poder recuperar un cliente **colgado** |
| **Limpieza de navegador** (solo si DT-B pasara) | Tras el `KILL`: `pkill -f 'chrome-linux64/chrome'` y `pkill -f chromedriver` (procesos **del banco**, declarado) | Evitar **orfandades** que se acumulen día a día (§4.4, DT-B2). **Con el navegador descartado, esta rama no se instala** |
| **`log`** | `tail` de `client.out` (y `.1`) | Diagnóstico |

### 6.3 `guest/tfg_keepalive.sh` (v3) — heartbeat, rotación y **la decisión del keepalive**

#### 6.3.1 Señales

| Señal | Dónde | Qué prueba | Uso |
|---|---|---|---|
| `pgrep -f ghosts.client.linux` | invitado | el proceso **existe** | arrancar si falta |
| **mtime de `logs/app.log`** | invitado | ha **ejecutado** una acción (NLog escribe por acción) | **heartbeat** |
| `max(createdutc)` de `history_timeline` | host | ha **reportado** una acción | vigilancia (§7.1) |
| `statusUp` / `lastReportedUtc` (API) | host | el **socket** sigue | solo «proceso vivo» (NO «haciendo») |

#### 6.3.2 **DECISIÓN: reinicio acotado y *más restrictivo* que v1** (no «solo avisar»)

**Criterio: mínima intromisión, máxima validez.** El razonamiento, explícito:

1. El modo de fallo demostrado fue **«vivo pero sin hacer»**. Si solo avisamos, el hueco sigue creciendo
   hasta que alguien mire: **se pierden horas o la ventana entera** (3 días de reloj + gate + repetición).
2. Un **reinicio del cliente** es **actividad del banco**, no acceso del operador: nadie entra por SSH/RDP/
   `vmrun`, y su telemetría (un `execve` + unas líneas de log) es **declarada** y **cuantificada**.
3. **Se acota para que no pueda empeorar nada**: solo **dentro de bloque**, exigiendo **dos confirmaciones
   separadas ≥ 5 min**, **2 recuperaciones** como máximo en la ventana, enfriamiento 30 min, y **nunca** con
   < 1 GB libre.
4. **Se registra** en `recovery.log` y **se juzga** con reglas escritas (§6.3.4).

**Lo que NO se hace:** reiniciar fuera de bloque (la noche es silencio legítimo de 15 h), reiniciar en bucle,
ni reiniciar por un hueco de pausa (café/comida están en el calendario y **no se evalúan**).

**Alternativas consideradas (y por qué se descartan):**

| Alternativa | Coste | Veredicto |
|---|---|---|
| **Solo avisar** (sin reinicio) | Un cuelgue no detectado = **ventana perdida** (3 días) | Descartada: el coste de no actuar es incomparablemente mayor que el de actuar |
| **Heartbeat por CPU** (`/proc/<pid>/stat`) | Un `Thread.Sleep` legítimo también da CPU≈0 ⇒ **falsos positivos** en cada pausa | Descartada: no distingue «dormido» de «colgado» |
| **Heartbeat por `clientupdates.log`** (HEALTH) | Lo escribe el **hilo de socket**, que sobrevive al motor muerto ⇒ **no mide «hacer»** | Descartada: reproduce el punto ciego |
| **Reinicio con tope 6** (v1) | Más intrusiones y más acciones declaradas | **Sustituida por 2** (más restrictivo) |
| **Heartbeat = `app.log` + calendario + confirmación** | 2 reinicios como máximo, ~10 eventos cada uno (**0,0004 %** de `M`) | **ELEGIDA** |

#### 6.3.3 Reglas (implementación)

```
DUR_H              = 74            (el servicio muere con la VM en t1+5)
BLOQUES            = leer de recetas/bloques.env   (08:00-08:12, 08:12-10:00, 10:20-13:00, 14:00-16:15, 16:15-17:00)
TFG_STALE_MIN      = 30            (silencio que ya no es ocio, DENTRO de bloque)
TFG_GRACIA_MIN     = 15            (no evaluar hasta 15 min después del inicio de bloque)
TFG_CONFIRMA_MIN   = 5             (dos lecturas stale separadas ≥5 min)
TFG_MAX_RECUP      = 2             (por ejecución)
TFG_MAX_ARRANQUES  = 3             (proceso ausente)
TFG_COOLDOWN_MIN   = 30
TFG_MIN_FREE_MB    = 1000          (por debajo: NO reiniciar, solo ALARMA)
TFG_CLIENT_OUT_MAX_MB = 20         (tope del stdout, §6.2)
TFG_ROTACION_UTC   = 07:45         (15 min antes de B1; salta el día 1 si el sha ya coincide)
bucle cada 30 s:
  1) rotar client.out si > tope
  2) rotación diaria (solo si now >= t0, si toca y el sha objetivo ≠ el actual):
        cp config/timeline.d<k>.json config/timeline.json ; client_ctl.sh stop|start
        log: ROTACION dia=k sha=<8> (una sola vez por día: estado en rotacion.estado)
  3) si NO hay proceso            -> arrancar (log: ARRANQUE; cuenta ≤3)
  4) si hay proceso y estamos EN BLOQUE y (now - inicio_bloque) >= 15 min
        y edad(app.log) > 30 min  y confirmado >=5 min y free >= 1000 MB
        y recuperaciones < 2 y cooldown OK
                                      -> stop (TERM→KILL) + start
                                         log: RECUPERACION motivo=heartbeat edad_min=N
  5) si hay proceso y free < 1000 MB -> log: ALARMA_DISCO free_mb=N (no reinicia)
```

- `k` (día de la receta) = `1 + ((fecha_utc − fecha_t0) mod 3)`, **solo si `fecha_utc ≥ fecha_t0`** (antes de
  `t0` **no se rota**: el cliente arranca a `t0−5 min` con `d1` ya colocado por `prep`); `TFG_DIA_OVERRIDE=1|2|3`
  **solo** para la prueba en seco.
- `edad(app.log)`: si **no existe** → se trata como «sin actividad» (arranque nuevo).
- Variables **sobrescribibles por entorno** (para DT5): así se prueba el mecanismo **sin** tocar la ventana.
- `recovery.log` (UTC, una línea): `ts accion=rotacion|arranque|recuperacion|alarma_disco dia=… edad_min=…
  pid_viejo=… pid_nuevo=… recuperaciones=N free_mb=… sha_timeline=…`.
- `keepalive.log`: traza general (inicio, fin, disco).

#### 6.3.4 Regla de validez asociada (para `legitimo-72h-v2`, escrita ahora)

| Situación | Efecto |
|---|---|
| 0 recuperaciones y 2 rotaciones OK | ventana normal |
| 1 recuperación, sin huecos > 30 min sin declarar | **VÁLIDA**, con la incidencia en `ventana_meta.md` |
| 2 recuperaciones | **revisión humana** con evidencia (`recovery.log` + `history_timeline`) |
| ≥ 3 arranques, o recuperación fallida, o una **rotación fallida** | **revisión humana**; la rotación fallida **no** invalida por sí sola (el día se repite y **se declara**) |
| un **bloque entero sin acciones** | **INVÁLIDA** → se repite |

### 6.4 `deploy_client.ps1` + `guest/verificar_arreglos.sh` (nuevo)

- `deploy_client.ps1`: añade `Copy-Item client_config\nlog.config → client-linux\nlog.config` y copia
  `recetas/d1.json` → `config/timeline.json` + `recetas/d{1,2,3}.json` → `config/timeline.d{1,2,3}.json`.
- **`guest/verificar_arreglos.sh`** (nuevo): comprueba **de verdad** el invitado; la usa `prep` (aborta) y la
  prueba en seco. Imprime `clave=valor` y termina en `RESULT=PASS|FAIL`:
  ```
  nlog_console=<minlevel del logger writeTo="console">      -> Warn
  nlog_sha=<sha256>                                         -> == repo
  client_ctl_cap=<TFG_CLIENT_OUT_MAX_MB por defecto>        -> 20
  keepalive_v3=<0|1>  (heartbeat+bloques+rotacion)          -> 1
  recetas=<d1_sha,d2_sha,d3_sha>                            -> == repo
  timeline_activa=<sha256 de config/timeline.json>          -> == d1
  web_session=<0|1> (UA fija + cookies + referer)           -> 1
  receptor_navegador=<none|chrome>  (según DT-B)            -> none
  ram_free_mb=<libre en /proc/meminfo>  swap_mb=<...>       -> ≥ 1500 / 0
  timer=<not-found|disabled|enabled>                        -> NOT-FOUND (el snapshot NO lo lleva)
  df_free_mb=<libre en />  df_inodes_libres_pct=<...>
  ```
  Sale con **código 40** si `FAIL`. *(`df_agente` —que el `df -P` del agente llegue al manager— **no** lo
  puede comprobar el invitado: lo comprueba `prep` en **G-6**, desde el manager.)*

### 6.5 `guest/tfg-ghosts-legit.{timer,service}` + `instalar_tarea_invitado.sh`

- **Timer parametrizado**: la fecha se pasa al instalar (`T0` → `OnCalendar=<t0−5min> UTC`);
  `Persistent=false`.
- **`instalar_tarea_invitado.sh`**: acepta `T0`, sustituye la fecha, verifica `systemctl list-timers` y
  **rechaza** instalar si `T0` no es futuro. **Nuevo**: instala también
  `config/timeline.d{1,2,3}.json` si no están (idempotente) y verifica sus `sha256`.
- **El snapshot NO lleva el timer** (se instala en `arm`, 20 min antes de `t0`).

### 6.6 `logall_json_ctl.sh` — reinicio robusto (punto 6)

`reiniciar_manager()`: `systemctl stop` → `pkill -9 -f wazuh_apid` → `systemctl reset-failed` →
`systemctl start` → **verificación** (`is-active` **y** `agent_control -l`) → hasta **3 intentos** (15 s).
El resto (semántica `on`/`off`, `rm -f archives.json`) **no cambia**.

### 6.7 Huellas y sidecar: `sha256sums.txt` + `b10_sellado.md`

- Se **regenera** `sha256sums.txt` con los ficheros nuevos/modificados.
- Se **actualiza** `b10_sellado.md` con: `nlog.config` (+`sha256`, `Warn`, `maxArchiveFiles=20`), tope de
  stdout (20 MB × 2), `client_ctl.sh` v2, keepalive v3 (+ parámetros), **receta v1** (`d1/d2/d3` + `sha256` +
  **calendario** + **generador**), **política de rotación** (2 reinicios en ventana), **política de
  recuperación** (2), **la retirada del `df` de la timeline** (H-H), **la decisión del navegador** (§4.8 +
  `sha256` de `browser_eval.md` + `receptor_navegador`) y **la sesión web *browser-like*** (§5.7). Snapshot
  `lab-listo-legit-v2`.
- **`Soporte/Metrica/` no se toca**: lo aplica el humano/orquestador. Si decide **bump** de `boveda_version`
  a 2, recalcula su `.sha256`.

---

## 7. Vigilancia y guardarraíles

### 7.1 La vigilancia nueva (host-side, **sin tocar la víctima**), cada **30 min**

**Principio:** todo lo que se mira es **host** o **manager**. La víctima **solo** se mira **a través de**
(a) lo que ella misma reporta a GHOSTS y (b) lo que el agente entrega al manager.

| # | Señal | Cómo se obtiene (sin tocar la víctima) | Umbrales |
|---|---|---|---|
| **1** | **¿Está haciendo?** | PostgreSQL del host: `max(createdutc)` de `history_timeline` para **todos** los ids de `victima-linux` (H-J). Se compara con el **calendario** (`recetas/calendario.json`) | **EN BLOQUE**: ≤ 15 min OK · 15–30 **AVISO** · **> 30 ALARMA** <br> **EN PAUSA** (café/comida): no se juzga · **FUERA de 08:00–17:00Z**: no se juzga (informativo) |
| **2** | **¿El agente está dentro?** | manager: `agent_control -i 001` → `Last keep alive` (epoch) ⇒ `edad`; y `Status` | ≤ 60 s OK · ≤ 10 min **AVISO** · **> 10 min ALARMA** |
| **3** | **¿Los daemons están?** | manager: `systemctl is-active wazuh-manager` **y** `pgrep -c -f 'wazuh-remoted\|wazuh-analysisd'` | unit `active` **y** ≥ 1 de cada ⇒ OK; si no ⇒ **ALARMA** |
| **4** | **¿Entran eventos?** | manager: crecimiento de `archives.json` y del diario de alertas **vs. chequeo anterior** | 0 crecimiento en **2 chequeos** dentro de bloque ⇒ **ALARMA** |
| **5** | **¿Disco de la víctima?** | manager: `archives.json`, líneas `"location":"df -P"` del agente `001`, **última línea de `/`** (H-H). Lectura **incremental** por offset (`tail -c +N`), reset si el tamaño baja (rotación) | libre ≥ 3 GB OK · 2–3 **AVISO** · **< 2 GB ALARMA** <br> **tasa** (2 muestras): < −500 MB/h **AVISO** · < **−1 GB/h ALARMA** <br> sin muestra > 20 min ⇒ **AVISO** |
| **6** | **¿Disco del host?** | `Get-PSDrive D` | ≥ 60 GB OK · 20–60 **AVISO** · **< 20 GB ALARMA** |
| **7** | **¿BD de GHOSTS?** | `pg_database_size('ghosts')` (H-C) | < 4 GB OK · 4–10 **AVISO** · **> 10 GB ALARMA** |
| **8** | **¿Recuperaciones/rotaciones?** | `recovery.log` del invitado (se lee **al cerrar**) | informativo; se juzga con §6.3.4 |

- **Formato**: una línea compacta por chequeo:
  `2026-10-26T08:30:05Z [watch] estado=OK doing_age=3m bloque=si hb=8s ag=Active mgr=active/2 arch=+2MB dia=+1MB df=5.2G tasa=-40MB/h db=68MB host=180G ram=post-hoc notas=`
- **Niveles**: `estado = max(nivel de cada señal)`; la línea dice **qué señal** disparó.
- **RAM (señal 9, solo post-hoc)**: el watch **no** puede leer la RAM de la víctima en vivo (el `syscollector`
  reporta inventario, no memoria libre; §4.10). Se registra `ram=post-hoc` y se juzga **al cerrar** con el
  `ram_free_mb` que el keepalive deja en `keepalive.log` (lectura de `/proc/meminfo` **sin `fork`**).
  **Umbral**: mínimo de la ventana **≥ 512 MB**; `< 256 MB` con `ALARMA_RAM` ⇒ **revisión humana** al cerrar.
- **Alarma al humano**: (1) línea `[ALARMA]`; (2) fichero `ALARMA_<UTC>.txt` con el detalle; (3) aviso de
  escritorio `msg.exe` (mejor esfuerzo). **2 ALARMA consecutivas de la misma señal** ⇒ `PERSISTENTE`.
- **La vigilancia NUNCA actúa**: solo lectura (no reinicia, no para, no arranca). Se verifica con `grep`
  (CA-08): en `watch` no puede haber `192.168.65.129`, `$Vic`, `vmrun` ni `scp`.

### 7.2 **El `df`: la alternativa menos invasiva** (decisión)

**No se añade `df` a la timeline.** El disco lo reporta **el propio agente** al manager:

1. **Lo que existe (verificado)**: el agente 4.14.7 trae por defecto
   `<localfile><log_format>command</log_format><command>df -P</command><frequency>360</frequency></localfile>`
   (`etc/ossec-agent.conf`) y **en este laboratorio funciona**: 220 muestras del agente `001` el 19/10, una
   cada **6 min**, con la raíz al **100 % desde 14:03:39Z** (8 h antes de que muriera el agente).
2. **Lo que NO sirve**: `syscollector`/`hardware` **no recoge disco** (CPU/RAM/placa). La vía oficial
   (command monitoring en `agent.conf` + reglas) exige **tocar Wazuh** ⇒ **prohibido** y **además
   innecesario**.
3. **Cómo se lee**: el watch, en el manager (host-side, solo lectura), mantiene un **offset** sobre
   `archives.json` y extrae las líneas `df -P` del `001`. **Coste**: 0 acciones nuevas, 0 cambios de config,
   **0 eventos nuevos** (esos eventos ya estaban en `M`).
4. **Cobertura**: 24/7 (también de noche), cada 6 min. **Mejor** que la sonda de v1 (que solo existía dentro
   de la franja).
5. **Si fallara** (no hubiera muestras): **fallback declarado** = el keepalive ya mide el disco localmente y
   su `ALARMA_DISCO` queda en `recovery.log` (se lee al cerrar); además se activa el guardarraíl de `prep`
   y la alarma por crecimiento de `archives.json`. **No** se vuelve a meter `df` en la timeline.

> **Evidencia del valor de esta señal**: con los umbrales de §7.1-5, el intento fallido habría dado
> **AVISO a las ~11:20Z** (free < 3 GB) y **ALARMA a las ~12:40Z** (free < 2 GB **o** tasa < −1 GB/h),
> **~1 h 20 min–2 h 40 min antes** del llenado. La señal estaba ahí; faltaba leerla.

### 7.3 Guardarraíles de `prep` (abortar antes de `t0`, no después)

`prep` termina con **código ≠ 0** y mensaje claro si falla cualquiera de estas comprobaciones:

| # | Comprobación | Código |
|---|---|---|
| G-1 | El snapshot **`lab-listo-legit-v2`** existe (`vmrun listSnapshots`) | 41 |
| G-2 | Tras revertir: **disco libre ≥ 4 GB** y **inodos libres ≥ 20 %** en `/` (si `receptor_navegador=chrome`, ≥ **3,5 GB**) | 42 |
| G-3 | `verificar_arreglos.sh` = **PASS** (nlog `Warn`, tope, keepalive v3, recetas, `timeline_activa=d1`, **timer ausente**) | 40 |
| G-4 | **Receta válida**: `construir_receta_legitima.py --check` → `PASS`; `sha256` de `d1/d2/d3` == `sha256sums.txt`; **mapeo de días** correcto (26/10→d1, 27→d2, 28→d3) | 20 |
| G-5 | **Agente**: `pgrep -f wazuh-agentd` = 1 **y** `agent_control -i 001` = `Active` (aquí **sí** se puede mirar el invitado: es antes de `t0`) | 43 |
| G-6 | **`df -P` del agente llega**: con `logall_json` ON, en **≤ 7 min** hay una muestra del `001` en `archives.json` (si no ⇒ 46 y **no se arma**) | 46 |
| G-7 | `logall_json` = `yes` y manager `active` con **todos** sus daemons | 44 |
| G-8 | **NAT desconectado**: `ip route` sin `default`; la “internet local” responde (8080/9090/9092) | 45 |
| G-9 | **Sonda de rotación**: se lista `/var/ossec/logs/archives/<AAAA>/<Mes>/` y se registra el `mtime` del último `.gz` (debe ser **00:0xZ**) | (aviso) |
| G-10 | **Host**: Windows Update pausado; **`D:` ≥ 60 GB**; **sesión iniciada** | 47 |
| G-11 | Guardar en el log el/los `machineid` de `victima-linux` (los usa la vigilancia) | — |
| G-12 | **RAM**: `free -m` → libre ≥ **1500 MB** y **swap = 0**; si el navegador estuviera activo (solo si DT-B pasara), libre ≥ **2000 MB** | 48 |

> **Regla de oro:** si un guardarraíl falla, **no se arma nada**; se arregla y se repite `prep`.

---

## 8. Extracción corregida (rotación diaria)

### 8.1 Lo que se sabe (medido)

- `archives.json` es un **hardlink** del fichero del día; rota a **00:00Z** a
  `/var/ossec/logs/archives/<AAAA>/<Mes>/ossec-archive-<DD>.json.gz` (+ `.sum`).
- El **`t1 = 00:00:00Z`** cae **exactamente** en la rotación (H-E).
- Día 19 (hasta el corte): 1.552.236 líneas, **99,1 %** del agente `001`; **≈ 70,6 k eventos/h** (con la
  actividad «ametralladora» del intento) ⇒ **≈ 5,1 M / 72 h**.
- **Con la receta nueva la tasa bajará** (menos acciones ⇒ menos `80792` y menos FIM). **Se mide en DT11** y
  se **declara**; el presupuesto se revisa con el dato real (§8.4).
- `logall_json_ctl.sh off` **borra** `archives.json` ⇒ **copiar antes**.

### 8.2 Procedimiento (orden fijo)

```
t1            stop víctima (soft)                      [TFG-Legit-Stop, t1+5 min]
t1+30..+90    esperar la rotación y COPIAR el denominador      (reintentos: 3 × 10 min)
              ├─ .gz de los días D, D+1, D+2   + .sum
              ├─ plano ossec-archive-<DD>.json de esos días (si existe)
              ├─ archives.json  (vivo; día D+3)
              └─ MANIFIESTO con tamaño, mtime y sha256 de CADA fichero
              DEDUPE: mismo sha256 (hardlink) → se conserva UNO
t1+40         contar M:  contar_denominador.py --desde t0 --hasta t1 <ficheros únicos>
t1+60         logall_json off  (restaura ossec.conf + diff + reinicio robusto)
```

- **Regla de borde (escrita)**: ventana **`[t0, t1]` con ambos extremos inclusive**. Los tres `.gz` cubren
  `[t0, t1)`; el **vivo** solo puede aportar eventos con `timestamp` **exactamente** `t1`
  (`00:00:00.000Z`). **No hay solape por construcción** y además se **verifica** (§8.3).
- Si el `.gz` de `D+2` **no** está a `t1+30` ⇒ reintentos. Si sigue sin estar ⇒ se usa el **plano** (queda
  registrado) y **se declara**.
- Los `.gz` del **intento fallido** **no se tocan** en el manager (evidencia).

### 8.3 `_artefactos/scripts/contar_denominador.py` — cambios (aditivos, con tests)

1. **Imprimir por fichero el rango** `primer_ts .. ultimo_ts`.
2. **`--estricto`**: si dos ficheros **solapan** en tiempo ⇒ **exit 3** (y explica cuáles).
3. **`--manifest`** (opcional): `manifest.tsv` con `fichero<TAB>bytes<TAB>sha256<TAB>primer<TAB>ultimo`.
4. **Tests nuevos** (pytest): `.gz` real, dos contiguos que **no** solapan, dos que **sí** (falla), y
   duplicado por `sha256`.
5. **Nada más cambia**: la unidad y la cabecera `metrica_version`/`boveda_version`/`sha256` siguen igual.

### 8.4 Presupuesto y disparador del fallback

- Esperado (a **medir** en DT11): ≈ **4–6 MB/h** ⇒ **≈ 300–450 MB** y **≈ 1–2 M eventos** a 72 h.
- El **disparador** de `L11` (fallback a `FP/acción`+`FP/hora`) sigue siendo **> ~5 GB** o decodificación no
  fiable: **se evalúa al cerrar** `legitimo-72h-v2` y se **declara**.
- **`M` titular** = fila `endpoint` (agente `001`); `total` como complemento (decisión heredada, abierta).

---

## 9. Snapshot nuevo y evidencia del fallo

### 9.1 **DECISIÓN: `lab-listo-legit-v2`** (se **conserva** `lab-listo-legit`)

**Por qué no se rehace el actual:** (1) **red de seguridad**; (2) **trazabilidad** (v1 está citado en
`vmrun_config.md`, en el plan de L1 y en B10); (3) **comprobación diferencial** (v2 = v1 + arreglos);
(4) **nombre explícito**: `prep` exige `v2` (G-1), así que una reversión por inercia a `v1` **aborta**.

**Contenido de `v2` (y prueba de que es limpio):**

| Elemento | Estado esperado en `v2` |
|---|---|
| Base | `lab-listo-legit` (revert) — **sin datos de la ventana fallida** |
| `nlog.config` | el versionado (consola `Warn`, `maxArchiveFiles=20`) |
| `client_ctl.sh` | v2 (tope 20 MB × 2, `start` idempotente, `stop` escalado) |
| **`config/timeline.json`** | **`d1`** (sha == repo) |
| **`config/timeline.d1.d2.d3.json`** | **presentes** y con sha == repo |
| `logs/` | **vacío**; sin `client.out`, sin `keepalive.log`, sin `recovery.log` |
| `ghasts.out` | **ausente** (los residuos de prueba se eliminan **antes** de crear v2) |
| `~/Documentos`, `~/Descargas` | **vacíos** (como en `v1`) |
| `tfg-ghosts-legit.{timer,service}` | **NO instalados** (`NOT-FOUND`) |
| **Navegador** | **AUSENTE** (decisión §4.8). Si DT-B pasara, **Chrome for Testing + chromedriver** en `~/browser/` con `sha256` y `receptor_navegador=chrome` |
| Agente Wazuh | `active`, `agentd` vivo, sin cambios |

- Se crea **con la VM apagada** (`vmrun snapshot` tras `shutdown` limpio) ⇒ snapshot **disco-solo**.
- Después se **arranca una vez** para verificar (§10-DT12) y **se revierte a `v2`** otra vez.

### 9.2 Evidencia del intento fallido (qué se conserva y qué se elimina)

| Qué | Acción | Justificación |
|---|---|---|
| **Estado completo de la víctima rota** (incluido `ghasts.out` de 4,78 GB) | **Snapshot `fallo-2026-10-19-disco-lleno-NO-USAR`**, tomado antes de tocar nada | **No se destruye nada**. Nombre en mayúsculas para que nadie lo use |
| **Extractos legibles** (≤ ~5 MB) | `fallo_2026-10-19/evidencia/`: `head`/`tail` de `ghasts.out`, líneas `No space left`, `df -h`, `df -i`, `dmesg -T`, `stat`, `wc -l`, `sha256sum`, `nlog.config` y `client_ctl.sh` originales, **y la serie `df -P` del agente** (H-H, 220 líneas) | **Se versiona** lo que explica el fallo, con huellas |
| **`MANIFEST.md`** | Tamaño, `mtime`, `sha256` de cada extracto + declaración de que el fichero completo **solo** está en el snapshot de evidencia | Trazabilidad sin arrastrar 4,78 GB al repo |
| **`legitimo_host_control.log` + `vigilancia_legitimo.log`** del intento | Se **copian** a `fallo_2026-10-19/` **verificando `sha256`** y se **retiran** del sitio de trabajo | Conserva la evidencia y evita mezclar ventanas |
| Ficha `Dataset/Legitimo/legitimo_72h/ventana_meta.md` | **NO se toca aquí** (regla dura) | Se declara; `legitimo-72h-v2` la archivará y escribirá la nueva |
| Datos del denominador del intento | Siguen **fuera del repo** (`%TEMP%\tfg-legit-72h-fallo\`, 32 MB, con huellas) | Ventana **inválida**: no se versiona como medida |

> **Lo único que se elimina**: (a) **residuos de la prueba en seco** dentro del invitado (ficheros de
> `~/Documentos`, logs del ensayo) — se borran **antes** de crear `v2`; (b) el `ghasts.out` del invitado al
> revertir (el original queda en el snapshot de evidencia). **Nada del repo se borra**; los dos logs se
> **mueven con verificación de huella**, y las timelines viejas se **archivan** (§5.6).

---

## 10. Prueba en seco (obligatoria, con doble ejecución)

> Una sola sesión, **fuera de la ventana**, sobre la instancia arreglada (antes de crear `v2`), con manager,
> GHOSTS e “internet local” arriba. Lo que ensucie se descarta revirtiendo a `v2` (§9).

### 10.1 Pruebas base (DT0–DT13)

| # | Prueba | Cómo | Pasa si |
|---|---|---|---|
| **DT0** | **¿Hay semilla? (decisión NPC)** | Timeline mínima con `"Command":"random"` + `DelayAfter` aleatorio; 2 ejecuciones de 5 min | Las **secuencias DIFIEREN** ⇒ GHOSTS no es reproducible sin parchear ⇒ **receta** (§4.3) |
| **DT1** | **Arreglos y receta presentes** | `verificar_arreglos.sh` + `sha256` | `RESULT=PASS`; `nlog_console=Warn`; `recetas` == repo; `timer=NOT-FOUND` |
| **DT2** | **Tope del stdout** | `TFG_CLIENT_OUT_MAX_MB=1`; escribir 3 MB; `start` + un par de vueltas del keepalive | `client.out` ≤ 1 MB **y** `client.out.1` ≤ 1 MB; el proceso sigue vivo |
| **DT3** | **Crecimiento real con `Warn`** | Dejar correr **30 min** con la receta dry | **≤ 5 MB/30 min** y, en todo caso, **≤ 40 MB** (tope). *Línea base del fallo: ~340 MB/h* |
| **DT4** | **La vigilancia detecta «estar sin hacer»** | `kill -STOP` al cliente; forzar el calendario (`TFG_FORZAR_BLOQUE=1`) → 2 chequeos | `statusUp` sigue **fresco** (punto ciego) **y** el watch da `AVISO`→`ALARMA` por `doing_age` |
| **DT5a** | **Autocuración** | Overrides (`TFG_STALE_MIN=2`, `TFG_CONFIRMA_MIN=1`, `TFG_MAX_RECUP=2`): `kill -STOP` | `stop`(TERM→KILL)+`start`; acciones reanudadas; `recovery.log` con **1** línea `recuperacion`; 1 proceso |
| **DT5b** | **Rotación de receta (2 veces)** | `TFG_DIA_OVERRIDE=1` → arrancar → `TFG_DIA_OVERRIDE=2` en el siguiente ciclo | `config/timeline.json` cambia con el **sha esperado**; el cliente se reinicia; **sigue viva la misma `machineid`**; `recovery.log` con `accion=rotacion dia=2` |
| **DT6** | **Alarma de agente desconectado** | `systemctl stop wazuh-agent` → 1–2 chequeos → `start` | `is-active` sigue `active` (**engaño reproducido**), el watch da **ALARMA** por `hb` y vuelve a OK |
| **DT7** | **Disco leído del agente** | Con `logall_json` ON: escribir/borrar ~500 MB en el invitado para mover el uso; esperar 2 muestras | El watch extrae `df=` y **coincide** (±5 %) con el `df` real; la **tasa** se calcula; sin muestras > 20 min ⇒ AVISO |
| **DT8** | **Extracción con rotación (datos REALES)** | Copiar los ficheros del intento a `/tmp` **del host**; `contar_denominador.py --desde … --hasta … --estricto --manifest` | Cuenta `M`; **detecta el duplicado por `sha256`**; rangos coherentes; **exit 0**; **no** escribe en `Dataset/` |
| **DT9** | **DOBLE EJECUCIÓN de la receta (misma secuencia)** | `--dry --base HH:00Z` (d1 comprimido ×40); **run 1** (≈15 min) y **run 2** idéntico; exportar `command` ordenado por `createdutc` de cada run | **Listas idénticas** (misma longitud y mismo orden); `recovery.log` **vacío** en ambos; `history_timeline` de cada run contiene **111** acciones |
| **DT10** | **Invariantes de la receta** | `construir_receta_legitima.py --check` | 111/117/105; hueco máximo ≤ 20 min; 0 `random`; 0 UA aleatoria; **0 handlers `Browser*`**; `web_session=1` (UA fija, cookies+`Referer`, 3 requisitos, 0 placeholders); lista blanca OK; mapeo de días OK |
| **DT11** | **Ritmo y coste reales (bloques B1+B2 reales)** | Arrancar **B1 (12 min) + B2 (20 min)** sin comprimir; medir acciones, huecos y Δ`archives.json` | Las acciones caen **en su minuto** (±2 min); huecos ≥ 30 s; **≈ 15–18 acciones/h** (B1+B2); MB/h medidos (base de §8.4) |
| **DT12** | **Snapshot `v2` limpio + verificación post-snapshot** | Crear `v2` (VM apagada) → arrancar → `verificar_arreglos.sh` + lista de residuos → revertir a `v2` | `PASS`; sin `client.out`/logs; `recetas` presentes; **`receptor_navegador=none`**; `df` ≥ 4 GB; `lab-listo-legit` **sigue existiendo** |
| **DT13** | **El laboratorio queda cerrado** | Al final: 0 VMs, 0 tareas `TFG-*`, firewall retirado, `logall_json=no`, GHOSTS/internet local parados | Todo a cero |

### 10.2 Evaluación del navegador (**DT-B0…DT-B5**, 90 min, tope duro)

> Se ejecuta **en T2b**, **antes** de generar la receta (T3), porque su resultado decide si `d1/d2/d3`
> llevan bloque de navegador. Sobre un **revert desechable** de `lab-listo-legit`; al terminar se **revierte
> otra vez** (no queda software ni configuración). **Antes de arrancar se despliega el cliente arreglado**
> (`nlog.config` a `Warn` + tope de 20 MB de T2) para **no repetir el fallo del stdout** durante la prueba;
> el revert posterior no importa porque `prep` vuelve a desplegar. Manager + GHOSTS + internet local arriba,
> `logall_json` **ON** para DT-B4. Detalle y umbrales en **§4.7**. Navegador candidato: **Chrome for Testing**
> (nunca Firefox, por el bucle caliente: `BrowserFirefox.cs:28-30`).

| # | Prueba | Pasa si | Tiempo |
|---|---|---|---|
| **DT-B0** | Pre-staging (zip + `sha256` + libs + versiones emparejadas + headless OK) | 0 libs ausentes; versiones emparejadas; disco ≥ 3,5 GB | 30 min |
| **DT-B1** | **Doble ejecución**: misma secuencia de `browse` y mismo conjunto/conteo de rutas en `web_access.log` | Listas idénticas (6) y conteo por ruta idéntico | 20 min |
| **DT-B2** | Ciclo de vida: `stop` y `kill -9` | **0** huérfanos `chrome`/`chromedriver` | 20 min |
| **DT-B3** | Recursos: RAM libre mínima, swap, load, tamaño de perfil | ≥ 512 MB libres; swap 0; ≤ 50 MB/sesión | (incluido) |
| **DT-B4** | **Impacto en `M`**: navegador vs `curl`, misma sesión | ≤ 1 500 eventos/sesión **y** `M_nav/M_curl ≤ 1,4`/día | 15 min |
| **DT-B5** | **Modo de fallo**: driver oculto, 5 min | Sin bucle caliente (`CPU < 20 %`, `app.log` < 1 MB/5 min) | 5 min |

- **Veredicto**: `browser_eval.md` con PASS/FAIL por prueba + decisión. **Todos PASS** ⇒ el navegador entra
  en B3 (se regenera la receta, +1 h). **Cualquier FAIL** ⇒ **se descarta** (lo esperado: §4.8) y **la
  receta no cambia**.
- **No es bloqueante para el resto del plan**: si DT-B falla, se sigue con DT2… sin tocar nada más.
- **Regla de higiene**: si se descarta, el revert a `lab-listo-legit` **antes** de T3 es obligatorio y se
  verifica (`receptor_navegador=none`, `df` recuperado, `sha256` de `verificar_arreglos` == repo).

- **Registro**: `prueba_en_seco.md` con salida literal (recortada) de cada DT (**incluidos DT-B0…DT-B5**,
  con `browser_eval.md` como anexo), hora UTC y veredicto. **Si algún DT falla**: se corrige y se repite
  **el DT completo**; **no** se crea `v2` hasta que pasen todos. (Un fallo de **DT-B no bloquea**: solo
  descarta el navegador.)
- **DT9 es la salvaguarda que pidió el humano**: dos ejecuciones, **misma secuencia**. Si fallara (no debería:
  no hay azar en la receta), se revisaría la receta **antes** de la ventana.
- **DT4/DT7 necesitan el calendario**: se usan overrides **solo de prueba** (`TFG_FORZAR_BLOQUE`,
  `TFG_LOGALL_TEST`) que **no** viajan a la ventana (lo comprueba `verificar_arreglos.sh` en DT1: el script
  instalado **no** contiene esos nombres salvo en la rama de test, desactivada por defecto).

---

## 11. La repetición: bloque, procedimiento y fecha

### 11.1 **DECISIÓN: la ejecuta un bloque nuevo, `legitimo-72h-v2`**

1. **La unidad de trabajo es el plan/bloque**: un bloque de 5 días (arreglos + 72 h) mezcla «modificar el
   laboratorio» con «medir».
2. **El arreglo debe poder cerrarse y verificarse sin esperar 3 días.**
3. **Aislamiento de fallos**: si la ventana nueva fallara, el arreglo **ya estaría cerrado**.
4. **Gate en el momento justo**: la fecha y el «PC encendido 3 días» se firman **la víspera**.
5. **Coste mínimo**: hereda todo (scripts probados, receta, snapshot, procedimiento, extracción).

### 11.2 Procedimiento de la repetición (lo deja escrito este bloque)

1. **`legitimo-72h-v2`**: plan fino + **gate** (fecha + PC 3 días + confirmación de no tocar la VM).
2. **Víspera**: `pausar_windows_update.ps1 pausar` · `registrar_tareas.ps1 -T0 <t0>` (tareas en `Ready`,
   `NextRun` **verificado en UTC**) · `TFG_GUEST_PW` como variable de **usuario**.
3. **`t0−45`**: `prep` (revierte a **`lab-listo-legit-v2`**, pasa **G-1…G-12** y **aborta** si falla).
4. **`t0−20`**: `arm` (instala el timer con `t0`, arranca el cliente, checklist).
5. **`t0−5`**: timer del invitado → keepalive v3 en marcha.
6. **`[t0,t1]`**: **cero acceso** a la víctima; `watch` cada **30 min**; las únicas acciones dentro son
   **del propio banco** (keepalive: **rotación diaria** + recuperaciones), **declaradas**.
7. **`t1+5`**: `stop`. **`t1+30..90`**: copia del denominador. **`t1+40`**: conteo. **`t1+60`**:
   `logall_json off` (reinicio robusto + `diff`).
8. **Extracción** (alertas 3–4 diarios + acciones + `M`) y **veredicto V1–V8** (con la regla §6.3.4).
9. **Cierre**: `cleanup` (VMs, GHOSTS, internet local, firewall, **Windows Update restaurado**),
   `registrar_tareas -Eliminar`, `-ClearSecret`, **B10** aplicado por el humano, `change-doc`.

### 11.3 **Fecha propuesta: `t0 = 2026-10-26T00:00:00Z` → `t1 = 2026-10-29T00:00:00Z`** (abierta)

> **Estado (v3): propuesta, NO ratificada.** El humano dijo "el 26 ya veremos". Este bloque **no la cambia**
> y **no la ejecuta**: la firma él en el gate (Q5) la víspera. Si elige otra, deben cumplirse las mismas
> condiciones de la tabla (días laborables, sin cambio de hora dentro, `t0`/`t1` a medianoche UTC).

| Motivo | Detalle |
|---|---|
| **No cruza el cambio de hora** | El DST europeo termina el **25/10/2026** (01:00Z). La ventana empieza **después** ⇒ `08:00Z = 09:00 local` los tres días, sin saltos |
| **Días de la semana** | lunes 26 → jueves 29 (3 jornadas de oficina: lun, mar, mié) |
| **Cortes diarios** | `t0`/`t1` a medianoche UTC ⇒ **3 días de calendario exactos** ⇒ 3 `.gz` + 1 vivo |
| **Margen** | 21–25/10 para ejecutar arreglos + receta + **DT0–DT13** + `v2` **sin prisa** |

- **`21/10 queda descartado (y se dice por qué)**: hoy es 20/10; entre el gate, 8 tandas, **3 recetas**, la
  **doble ejecución** y el snapshot `v2` hay **> 1 día** de trabajo real. Armar a las 23:15Z del 20/10 sería
  exactamente lo contrario de «nada a lo loco».
- **Alternativas** (si la fecha no encaja): `27/10` o `28/10` (mismo esquema). **Nunca** con el 25/10 dentro.
- **Hora local equivalente**: `t0` = 26/10 **01:00** local · `prep` = 26/10 **00:15** local · primera acción
  = 26/10 **09:00** local · `stop` = 29/10 **01:05** local.

### 11.4 Cómo se evita repetir el fallo (resumen)

1. **Causa eliminada por construcción** (nivel `Warn` **y** tope 40 MB) → **medido** en DT2/DT3.
2. **Independencia de señales**: aunque el nivel se quedara en `Trace`, el tope corta a 40 MB.
3. **Guardarraíl de arranque**: < 4 GB libres ⇒ **no se arranca** (G-2).
4. **Disco del agente** con **valor y tasa** + alarmas a 3 GB / 2 GB / −1 GB/h (§7.1-5).
5. **Vigilancia de «hacer»** con calendario + **autocuración acotada** (DT4/DT5a).
6. **Alarma de agente por `last keep alive`** (DT6).
7. **Regla de validez escrita** (§6.3.4): nada se maquilla.
8. **Una sola ventana**: no A/B; **si algo falla, se repite** (con la evidencia delante).

---

## 12. Análisis de seguridad (no romper · no ensuciar · no ocultar)

### 12.1 No romper nada

| Activo | Riesgo | Control |
|---|---|---|
| **Config/ruleset de Wazuh** | Cambiar algo sin querer | **No se toca** `ossec.conf` (salvo `logall_json`) ni el ruleset. `prep`/`cleanup` hacen **`diff` contra `ossec.conf.tfg-bak`** y exigen `CONFIG_IDENTICA`; ruleset por huella (CA-14) |
| **Métrica congelada** | «Arreglar» la métrica | `Soporte/Metrica/**` **prohibido**; solo **sidecar** |
| **Corpus / `Hojas/` / `_recursos/` / `Dataset/`** | Tocar datos de medida | **Ningún fichero** de esas rutas se modifica (CA-14: `git status` acotado) |
| **Laboratorio de los ataques** | Cambiar scripts compartidos | Solo `Soporte/Laboratorio/ghosts/*`, `legitimo_72h/*`, `recetas/*` y `_artefactos/scripts/{contar_denominador,construir_receta_legitima}.py`. `extraer_alertas.py` y `filtrar_ruido.py` **intactos** |
| **Los ataques (Fase 3)** | Regresión | No se ejecuta ni se revertea nada del lab de ataques; `lab-listo` intacto |
| **El invitado** | Dejarlo roto | `v2` se **verifica arrancando** (DT12) y `v1` se conserva; todo cambio es **antes** de `t0` |
| **La herramienta de extracción** | Romper lo que ya funcionaba | `contar_denominador.py` cambia **de forma aditiva** + tests; `--estricto` es opt-in |
| **El invitado (software nuevo)** | Meter un navegador «de paso» | **Prohibido** hasta que DT-B lo justifique; si se prueba, **revert** verificado y `receptor_navegador=none` (CA-27) |
| **El manager** | Dejarlo muerto | Reinicio robusto (§6.6) + `diff` + `agent_control` |
| **Secreto** | Filtrarlo | Contraseña **solo** por variable de entorno/STDIN; CA: `git grep` sin coincidencias |

### 12.2 No ensuciar nada

- **Todo lo que se hace en el invitado es ANTES de `t0`** y **se descarta** revirtiendo a `v2`.
- Lo único que **actúa dentro** de la ventana es el **keepalive**, **declarado** y **cuantificado**:
  **≤ 2 recuperaciones** + **≤ 2 rotaciones** (día 1 se salta) + **≤ 3 arranques**; **≈ 40–60 eventos** en
  total (0,002–0,004 % de `M`), todos con `recovery.log`.
- **La ventana arranca de un snapshot limpio** (`v2`) y la limpieza se **prueba** (DT12).
- **Las tareas del host quedan SIN registrar** al cerrar (como en L1): la ventana **no puede re-armarse sola**.
- **La prueba en seco ensucia** (BD de GHOSTS, logs, filas de `history_timeline`): se **declara** y **no**
  afecta a la ventana (`[t0,t1]` filtra; `prep` reconcilia la máquina).
- **El navegador (si se prueba) no deja rastro**: DT-B corre sobre un **revert desechable**, con
  `logall_json` ON solo durante la prueba; al terminar se **revierte a `lab-listo-legit`** y se verifica
  (`receptor_navegador=none`, disco recuperado). Lo que se conserve de la prueba son **textos y cifras**
  (`browser_eval.md`), **no** software ni configuración.
- **Añadidos al banco de trabajo** (declarados, no ocultos): **receta nueva** (333 acciones), **sesión web
  *browser-like*** (caché `< 2 MB` en `~/.cache/tfg-web` + cookie jar), **rotaciones** (§6.3.3), **más
  ficheros de log** en `logs/` (21 MB) y **los `df -P` del agente** (240/día, ya existían). Todo se declara
  en `ventana_meta` y en B10 (CA-11).

### 12.3 No ocultar nada

- **Nada se borra sin justificar** (§9.2): se conserva el snapshot roto, los extractos y las huellas; las
  **timelines viejas se archivan** (§5.6), no se borran.
- **El diagnóstico no se reescribe**: `diagnostico_fallo.md` queda **congelado**.
- **La interpretación no se toca**: la ventana fallida **no se «arregla»**; se repite.
- **Toda desviación del plan de L1 y del diagnóstico se declara** (§1.3, §3 punto 9, §6.1, §7.2).
- **El cambio de actividad se declara como decisión del humano**, no como ocurrencia del planificador.
- **El descarte del navegador se declara con su evidencia** (§4.4–§4.8), incluida la parte incómoda: **no se
  puede afirmar** que un navegador "mejore" la medida; se **mide** (DT-B4) y se razona por qué **no** se usa.
  Si DT-B pasara, el apartado se marcaría «superado» y se usaría en B3; **no se oculta** ni el intento ni el
  resultado.

---

## 13. Riesgos y mitigaciones

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| R1 | **El tope no funciona** | Vuelve el fallo | DT2 con 3 MB; **dos** vías (nivel + tope); guardarraíl; alarma |
| R2 | **`Warn` sigue generando volumen** | Disco | DT3 mide el ritmo; tope duro; `ALARMA_DISCO` |
| R3 | **Bucle de reinicios** | Actividad falsa | 2 recuperaciones + cooldown 30 min + solo en bloque + confirmación |
| R4 | **Falso positivo del heartbeat** en una pausa | Reinicio innecesario | El calendario **excluye** café/comida; hueco máx. 12 min ≪ 30; 2 confirmaciones |
| R5 | **La receta no se comporta como se diseñó** (solapes, repeticiones, huecos) | Medida sesgada | **Validador estático** + DT10 + DT11 (ritmo real) + DT9 (secuencia) |
| R6 | **La rotación falla** (sha, copia, reinicio) | Un día repite | Fallback: **se queda la receta actual**, se registra `ALARMA` y se declara; la ventana **no** se invalida por eso |
| R7 | **Los reinicios duplican la máquina** en GHOSTS | `machineid` cambia | Watch por **todos** los ids (H-J); DT5b lo verifica |
| R8 | **El `.gz` de D+2 llega tarde** | Copia incompleta | Reintentos 10 min × 3 + plano + declaración |
| R9 | **Doble conteo** por hardlink | `M` inflado | Dedupe `sha256` + `--estricto` + `MANIFEST` |
| R10 | **DST** (25/10) | Disparadores 1 h desplazados | Ventana **después**; `NextRun` en UTC |
| R11 | **Windows Update reinicia el host** | Ventana perdida | Política + `wuauserv` parado + G-10; se restaura |
| R12 | **El humano toca la víctima** | Contaminación | Regla dura + V4 + recordatorio en el gate |
| R13 | **Crecimiento de la BD de GHOSTS** (H-C) | Disco/POST grandes | Con 333 acciones la proyección baja mucho; señal 7 + D: 186 GB; declarado |
| R14 | **Se usa `v1` por error** | Repite el fallo | G-1 exige `v2`; `v1` marcado «superado» en `vmrun_config.md` |
| R15 | **Los snapshots llenan `D:`** | Sin espacio | 186 GB; se mide antes/después |
| R16 | **El `df -P` no se parsea** (formato/campo) | Se pierde la señal | DT7 lo prueba con valor real; si falla ⇒ fallback §7.2-5 |
| R17 | **El plan se pierde otra vez** (como L1) | Retrabajo | **Se guarda en git al aprobarse** (gate Q7); copia en `_fases/legitimo-fix/plan.md` |
| R18 | **Menos acciones ⇒ `M` menor y FPR menos comparable** | Interpretación | Se **declara** y se mide (§18-1); el TFG informa del **volumen** junto al FPR |
| R19 | **DT-B se alarga y se come el calendario** | Retraso | **Tope duro 90 min** y **corte en DT-B0**; es **no bloqueante** y no cambia la receta si falla |
| R20 | **El navegador se cuela en la ventana por inercia** | `M` inflado / disco / RAM | `verificar_arreglos.sh` exige `receptor_navegador=none`; G-3 aborta; `v2` se crea **después** del revert |
| R21 | **Se «mejora» el FPR diluyendo `M`** | Medida engañosa | DT-B4 con umbral `M_nav/M_curl ≤ 1,4`; si lo supera, **descarte**; se declara en el TFG (§18.3) |
| R22 | **RAM olvidada** (VM de 3 GB, swap 0) | OOM *kill* silencioso | Presupuesto (§4.9), G-12 en `prep`, `ram_free_mb` post-hoc en el keepalive |

---

## 14. Criterios de aceptación (verificables)

| # | Criterio | Verificación |
|---|---|---|
| **CA-01** | **Causa eliminada**: `minlevel="Warn"` en consola y `maxArchiveFiles="20"`; `sha256` invitado == repo | `verificar_arreglos.sh` + `sha256sum` |
| **CA-02** | **Tope probado**: con `TFG_CLIENT_OUT_MAX_MB=1` y 3 MB, `client.out` + `.1` ≤ 2 MB; proceso vivo | DT2 |
| **CA-03** | **Ritmo de stdout**: ≤ 5 MB/30 min; extrapolación declarada; tope duro 40 MB | DT3 |
| **CA-04** | **`prep` aborta** si falta `v2`, si el disco < 4 GB, si el timer está presente, si los arreglos fallan o si `df -P` no llega (códigos 40–47) | Transcripción de una ejecución negativa |
| **CA-05** | **La vigilancia detecta «estar sin hacer»**: `kill -STOP` ⇒ `statusUp` fresco **y** `AVISO`→`ALARMA` | DT4 |
| **CA-06** | **Autocuración**: reinicia y **las acciones se reanudan**; `recovery.log` con **1** línea; 1 proceso | DT5a |
| **CA-07** | **Alarma de agente**: `is-active` miente, el watch da **ALARMA** por `hb` en ≤ 2 chequeos y vuelve a OK | DT6 |
| **CA-08** | **La vigilancia no toca la víctima**: en `watch` no aparecen `192.168.65.129`, `$Vic`, `vmrun` ni `scp` | `grep` del script + log |
| **CA-09** | **Disco leído del agente**: valor correcto (±5 %) y **tasa** calculada; sin muestras ⇒ AVISO | DT7 |
| **CA-10** | **Extracción con datos reales**: dedupe, rangos, `--estricto`, exit 0; `pytest` en verde | DT8 + `pytest -q` |
| **CA-11** | **Declaración de instrumentación**: `ventana_meta` + `b10_sellado.md` listan receta, **2 rotaciones**, **≤2 recuperaciones**, 21 MB de `app.log`, los `df -P` del agente, **la decisión del navegador** y **la sesión web *browser-like***; **no** hay acción `df` añadida a la timeline | Docs + `grep` de la receta |
| **CA-12** | **Snapshot `lab-listo-legit-v2`** creado (VM apagada), `lab-listo-legit` intacto, `v2` verificado al arrancar | `listSnapshots` + DT12 |
| **CA-13** | **`v2` limpio**: sin `client.out`, sin `logs/*`, `~/Documentos` y `~/Descargas` vacíos, `timeline.json`=`d1`, `recetas` presentes | Listado tras el revert |
| **CA-14** | **Cero daño colateral**: `git status` solo muestra las rutas permitidas; `git diff --stat` **vacío** para `Soporte/Metrica/`, `Hojas/`, `_recursos/`, `Dataset/`, corpus y `extraer_alertas.py`; `ossec.conf` `CONFIG_IDENTICA`; ruleset con la misma huella | `git status`/`git diff` + `diff` |
| **CA-15** | **Sin secretos**: 0 coincidencias de la contraseña; ningún fichero nuevo con asignación de `TFG_GUEST_PW`/`TFG_MANAGER_PW` | `git diff` + `git status` |
| **CA-16** | **Evidencia conservada**: snapshot `fallo-…-NO-USAR`; `fallo_2026-10-19/evidencia/**` + `MANIFEST.md` con `sha256` (incluida la serie `df -P`); logs archivados con huella | `sha256sum -c` |
| **CA-17** | **Documentación**: `README.md` v3 (receta + procedimiento + rotación), `b10_sellado.md`, `sha256sums.txt`, `vmrun_config.md`, `prueba_en_seco.md`, `receta_resumen.md` | Lectura + huellas |
| **CA-18** | **Laboratorio cerrado y NO armado**: 0 VMs, 0 tareas, firewall retirado, `logall_json=no`, GHOSTS + internet local parados, `TFG_GUEST_PW` borrada | DT13 |
| **CA-19** | **Repetición especificada**: bloque, procedimiento y **fecha 26/10** (sin commits del bloque) | Este plan + `git log` |
| **CA-20** | **Receta determinista (doble ejecución)**: dos ejecuciones del **mismo** fichero producen la **misma secuencia** (lista idéntica) y **111** acciones | DT9 |
| **CA-21** | **Invariantes de la receta**: 111/117/105; hueco máximo ≤ 20 min; 0 `random`; 0 UA aleatoria; lista blanca; mapeo 26/27/28 → d1/d2/d3 | DT10 + `--check` |
| **CA-22** | **Rotación probada**: cambia `timeline.json` al sha esperado, el cliente se reinicia y la `machineid` **no** cambia | DT5b |
| **CA-23** | **Decisión NPC documentada**: §4 con fuentes (fichero:línea) + DT0 (secuencias distintas) ⇒ **receta** | Lectura + DT0 |
| **CA-24** | **El plan se conserva**: al aprobarse, queda **en git** (y en `_fases/legitimo-fix/`) | `git log -- plan.md` |
| **CA-25** | **Navegador evaluado con fuentes**: §4.4 con `fichero:línea` (handlers, `Init`/ventana, bucle caliente, driver/`selenium-manager`, placeholders, `ContainsKeyWithOption`) y §4.5 con costes | Lectura + `grep` de las líneas citadas |
| **CA-26** | **DT-B ejecutado o declarado**: `browser_eval.md` con PASS/FAIL de las 6 pruebas **y** decisión; o nota explícita de **no ejecutado** y por qué | `browser_eval.md` + `prueba_en_seco.md` |
| **CA-27** | **Una sola opción en la ventana**: `verificar_arreglos.sh` → `receptor_navegador=none` (o `chrome` **solo** si DT-B pasó) y `web_session=1`; **0** handlers `Browser*` en `d1/d2/d3` (o **1**, en B3, si pasó) | DT1 + `grep` de las recetas |
| **CA-28** | **Sesión web *browser-like***: UA fija y honesta, cookie jar + `Referer` en las 8 acciones, 3 requisitos, 0 placeholders; recuento **111/117/105** sin cambios | `construir_receta_legitima.py --check` (DT10) |
| **CA-29** | **RAM declarada**: presupuesto (§4.9), G-12 en `prep` (código 48) y `ram_free_mb`/`ALARMA_RAM` en `keepalive.log` | Transcripción G-12 + `recovery.log`/`keepalive.log` |

---

## 15. Gate humano (lenguaje sencillo)

> **Qué te pido aprobar.** No vamos a medir nada todavía: vamos a **arreglar** lo que rompió la ventana,
> **cambiar la actividad para que parezca la de una persona**, **probarlo** y **dejar el laboratorio listo**
> para repetir.

1. **Qué pasó (en una frase).** Un fichero de registro del programa de actividad (GHOSTS) creció **sin
   límite** hasta **4,8 GB**, llenó el disco de la máquina víctima y se llevó por delante la actividad y,
   horas después, el agente de Wazuh. **Nadie lo vio** porque la vigilancia miraba si el programa «estaba
   abierto», no si «estaba haciendo algo» — y porque **el aviso del disco ya llegaba** (el agente lo manda
   cada 6 minutos) pero **no había nadie leyéndolo**.
2. **Qué cambia respecto a la versión anterior del plan.**
   - **La actividad se rediseña** (lo pediste): una **jornada de oficina** de 09:00 a 18:00 (hora local),
     con **café**, **comida** y **reuniones**, y **tres días distintos**. Se pasa de **209 acciones en 3
     minutos** a **111 / 117 / 105 acciones al día** (~15 por hora mientras trabaja; 0 de noche). **De noche
     no hay actividad de usuario** (solo el ruido normal del sistema).
   - **Se descarta el «modo NPC con semilla»** (lo pediste investigar): ese modo **no genera actividad**
     (solo enciende y apaga el cliente), la semilla solo sirve para inventar **identidades**, y la actividad
     **no es repetible** (usa azar sin semilla). Lo he comprobado en el código y lo pruebo en el laboratorio
     (dos ejecuciones y se comparan). **Conclusión: receta.**
   - **El `df` de la timeline desaparece**: no hace falta. **El propio agente de Wazuh ya manda el disco**
     cada 6 minutos (lo he verificado en los datos del intento fallido: 220 muestras en un día, y el 100 %
     a las 14:03Z, ocho horas antes de que muriera el agente). **No se toca ni Wazuh ni la timeline.**
   - **El keepalive es más restrictivo que antes**: antes 6 reinicios posibles; ahora **2**, solo dentro de
     la jornada, con **dos comprobaciones separadas** y nunca con el disco bajo. Y hace **una rotación diaria**
     de la receta (2 reinicios en la ventana, antes de empezar la jornada).
   - **El navegador headless (lo pediste evaluar): se descarta.** GhostS **sí** tiene navegador (Firefox y
     Chrome con Selenium), pero: su **secuencia** solo es repetible si se le quita casi todo (sin `random`,
     sin *stickiness*, sin jitter, sin variables de URL), su **huella de eventos** (cientos de escrituras de
     caché por sesión) **no es repetible ni acotable**, y **hincha el denominador `M`**, con lo que el FPR
     bajaría **sin que la detección mejore** (un número mejor y una medida peor). Además cuesta **300–400 MB
     de disco**, **300–600 MB de RAM** en una VM de 3 GB **sin swap**, exige driver offline y añade modos de
     fallo (Firefox entra en **bucle caliente** si falla el driver; Chrome muere en silencio y deja procesos
     huérfanos). Y **ningún ataque del corpus usa navegador**. **En su lugar** las acciones web se hacen
     "como un navegador" con `curl` (cookies, `Referer`, CSS/JS/SVG, PDF), **sin cambiar el número de
     acciones**. Aun así, **lo pruebo en seco (90 min, tope duro)**: si el navegador pasa las 6 pruebas, se
     usa en **ese** bloque; si falla una, se descarta. **A la ventana entra una sola opción.**
3. **Lo que NO cambia.** **No** toco Wazuh (ni reglas ni configuración), ni la métrica, ni el corpus, ni las
   hojas, ni los datos de los ataques. **La evidencia no se tira**: congelo el estado roto en un snapshot
   *NO USAR* y guardo copias con huellas; `lab-listo-legit` **se conserva**.
4. **Prueba en seco.** **21 pruebas** (DT0–DT13 + DT-B0…DT-B5 + la negativa de G-12): provoco el fallo a
   propósito, compruebo que la vigilancia lo canta y que el reinicio lo arregla, **ejecuto la receta dos
   veces y comparo que la secuencia es idéntica**, compruebo la rotación de días, mido el ritmo real y pruebo
   la extracción con los ficheros reales del intento fallido. **Si una falla, no se crea el snapshot nuevo.**
   (Las DT-B solo deciden el navegador; si fallan, se descarta y se sigue.)
5. **Qué necesito de ti ahora.**
   - **Q1.** ¿**Apruebas la receta** (§5): jornada 09:00–18:00 local, café 20 min, comida 60 min, 3 días
     distintos, ~15 acciones/hora mientras trabaja y **noche sin actividad**?
   - **Q2.** ¿**Apruebas descartar el NPC+semilla** con la evidencia de §4 (y la prueba DT0)?
   - **Q3.** ¿**Apruebas el `df` sin tocar nada** (leerlo del agente, §7.2) y **quitar** la sonda `df` de la
     timeline que proponía la v1?
   - **Q4.** ¿**Apruebas el keepalive** con **2 recuperaciones** + **2 rotaciones** (máx. 3 arranques)?
   - **Q5.** ¿**Apruebas la fecha `lunes 26/10 00:00Z → jueves 29/10 00:00Z`** (01:00 local → 01:00 local)?
     El **21/10 queda descartado**: no da tiempo a hacerlo bien (§11.3). **La fecha sigue abierta**: si
     prefieres otra, debe respetar las condiciones de §11.3 (laborables, sin cambio de hora dentro, cortes a
     medianoche UTC).
   - **Q6.** ¿Te comprometes al **PC encendido sin suspensión 3 días** y a **no tocar la máquina víctima**?
   - **Q7.** ¿**Apruebas que este plan se guarde en git** al aprobarse (para no repetir la pérdida del plan
     de L1)?
   - **Q8.** ¿`boveda_version` **bump a 2** al aplicar B10? (recomiendo **sí**: cambia la config del legítimo).
   - **Q9.** ¿**Apruebas descartar el navegador** (§4.8) con esta evidencia, **y** que la prueba DT-B (90 min,
     tope duro) pueda revertir la decisión **solo si pasa las 6 pruebas** —usándose entonces únicamente en el
     bloque de la sesión web—? **No** habrá dos opciones en la ventana: la que quede, queda **congelada en
     `v2`** y verificada por `verificar_arreglos.sh`.
6. **Qué NO vas a ver.** No habrá números nuevos de ataques ni de falsas alarmas: la ventana anterior **no
   vale** y no se «recicla». Los números salen de la **repetición**. Y como la actividad es ahora realista
   (mucho menor), **el número total de eventos medidos bajará** y el FPR se calculará sobre esa base: se
   dirá explícitamente en el TFG (§18.3-1).

---

## 16. Ficheros que se tocarán

### 16.1 Nuevos

| Ruta | Qué |
|---|---|
| `Soporte/Laboratorio/ghosts/client_config/nlog.config` | Copia versionada del `nlog.config` arreglado |
| `Soporte/Laboratorio/legitimo_72h/recetas/LEEME.md` | La receta contada en prosa (jornada, bloques, pausas, por qué) |
| `Soporte/Laboratorio/legitimo_72h/recetas/d1.json` · `d2.json` · `d3.json` | **Timelines de los 3 días** (generadas y versionadas) |
| `Soporte/Laboratorio/legitimo_72h/recetas/calendario.json` · `bloques.env` | Calendario (bloques/pausas/días) para watch y keepalive (misma fuente) |
| `Soporte/Laboratorio/legitimo_72h/recetas/receta_resumen.md` | Tabla hora→acción de los 3 días (gate y TFG) |
| `Soporte/Laboratorio/legitimo_72h/recetas/superseded/{timeline_72h.json,timeline_72h.dry.json,SUPERSEDED.md}` | Las timelines de L1 **archivadas** (no borradas) |
| `_artefactos/scripts/construir_receta_legitima.py` | **Generador + validador** de la receta (stdlib) |
| `Soporte/Laboratorio/legitimo_72h/browser_eval.md` | **Evaluación del navegador**: investigación con fuentes, pre-staging pinneado (URL+tamaño+`sha256`), salida literal de **DT-B0…DT-B5** y **decisión** (§4.4–§4.8) |
| `Soporte/Laboratorio/legitimo_72h/guest/verificar_arreglos.sh` | Comprobación de los arreglos en el invitado |
| `Soporte/Laboratorio/legitimo_72h/prueba_en_seco.ps1` (+ `prueba_en_seco.md`) | Suite **DT0–DT13 + DT-B0–DT-B5** y su registro |
| `Soporte/Laboratorio/legitimo_72h/fallo_2026-10-19/MANIFEST.md` + `evidencia/` | Evidencia del fallo (extractos + huellas + serie `df -P`) |
| `Soporte/Laboratorio/legitimo_72h/snapshot_v2.md` | Qué contiene `v2` y cómo se verifica |
| `_fases/legitimo-fix/{plan.md,reviews.md,change-doc.md}` | Artefactos del bloque (al archivar; **plan en git al aprobar**) |

### 16.2 Modificados (deliberadamente, uno por uno)

| Ruta | Cambio | Motivo |
|---|---|---|
| `Soporte/Laboratorio/ghosts/client_ctl.sh` | append + tope 20 MB×2 + `start` idempotente + `stop` TERM→KILL + `client.out` | §6.2 |
| `Soporte/Laboratorio/ghosts/deploy_client.ps1` | copia `nlog.config` + las 3 recetas | §6.4 |
| `Soporte/Laboratorio/ghosts/logall_json_ctl.sh` | `reiniciar_manager()` robusto | §6.6 |
| `Soporte/Laboratorio/legitimo_72h/guest/tfg_keepalive.sh` | **v3**: heartbeat + bloques + confirmación + topes + **rotación** + `recovery.log` + rotación de stdout | §6.3 |
| `Soporte/Laboratorio/legitimo_72h/guest/tfg-ghosts-legit.timer` | fecha parametrizada, `Persistent=false` | §6.5 |
| `Soporte/Laboratorio/legitimo_72h/guest/instalar_tarea_invitado.sh` | acepta `T0`, verifica recetas, rechaza fechas pasadas | §6.5 |
| `Soporte/Laboratorio/legitimo_72h/legitimo_host_control.ps1` | `$Snap=v2` · G-1…G-**12** · **watch nuevo** · `prep/arm/drytest` adaptados a la receta y a la rotación | §7 |
| `Soporte/Laboratorio/legitimo_72h/vigilancia_legitimo.ps1` | delega en el watch nuevo | §7.1 |
| `Soporte/Laboratorio/legitimo_72h/registrar_tareas.ps1` | `-T0` (sin fechas duras), watch cada **30 min**, `NextRun` en UTC | §11.2 |
| `Soporte/Laboratorio/legitimo_72h/exportar_denominador.sh` | modo `copiar-ventana` (rotación + dedupe + manifiesto) | §8 |
| `_artefactos/scripts/contar_denominador.py` (+ tests) | rangos por fichero, `--estricto`, `--manifest` | §8.3 |
| `_artefactos/scripts/construir_receta_legitima.py` | **+** validación de la sesión web (§5.7): UA fija, cookies+`Referer`, 3 requisitos, 0 placeholders, **0** handlers `Browser*` (o 1 en B3 si DT-B pasó) | §5.7 |
| `Soporte/Laboratorio/legitimo_72h/README.md` | v3: receta, rotación, procedimiento, 9 puntos | docs |
| `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` | sellos nuevos (nlog, tope, keepalive v3, receta, snapshot) | §6.7 |
| `Soporte/Laboratorio/legitimo_72h/sha256sums.txt` | regenerado | huellas |
| `Soporte/Laboratorio/legitimo_72h/resultado.md` | sección «fallo + arreglo + receta» | evidencia |
| `Soporte/Laboratorio/vmrun_config.md` | inventario: `lab-listo-legit-v2`, `fallo-…-NO-USAR`, `v1` *superado* | docs |
| `state.md`, `roadmap.md` | los actualiza el **orquestador** | flujo |

### 16.3 **Prohibido tocar** (verificado por CA-14)

`_recursos/**` · el **corpus** (`Soporte/Ataques/**`, `Dataset/Ataques/**`, `Bitacora/**`) · `Hojas/**` ·
`Soporte/Metrica/**` · `Dataset/**` · `_artefactos/scripts/extraer_alertas.py` ·
`_artefactos/scripts/filtrar_ruido.py` · `Soporte/Laboratorio/legitimo_72h/diagnostico_fallo.md` ·
snapshots `base-limpia`, `lab-listo`, `lab-listo-legit` (**no se borran**).

### 16.4 Tandas de ejecución (para el ejecutor)

| Tanda | Contenido | Estimación |
|---|---|---|
| **T1** | Evidencia: snapshot `NO-USAR` + harvest por SSH (incl. serie `df -P`) + `MANIFEST` + archivar logs | ~1 h |
| **T2** | Cliente: `nlog.config` + `client_ctl.sh` + `deploy_client.ps1` + `verificar_arreglos.sh` | ~1,5 h |
| **T2b** | **Evaluación del navegador**: pre-staging + **DT-B0…DT-B5** + `browser_eval.md` + **revert** | **90 min (tope duro)** |
| **T3** | **Receta**: `construir_receta_legitima.py` + `d1/d2/d3` + calendario + `--check` + `receta_resumen.md` + archivar las viejas | ~3 h |
| **T4** | Keepalive v3 (heartbeat + rotación + `ram_free_mb`) + timer/servicio + instalador | ~1,5 h |
| **T5** | Vigilancia nueva (incl. `df` del agente) + guardarraíles + `registrar_tareas` | ~2 h |
| **T6** | Extracción: `exportar_denominador.sh` + `contar_denominador.py` (+ tests) | ~1 h |
| **T7** | **DT0–DT13** + snapshot `v2` + verificación post-snapshot | ~3,5 h |
| **T8** | Documentación (README/B10/sha256sums/vmrun/resultado) + cierre limpio + gate final | ~1,5 h |

**Total ≈ 16,5 h** (15 h de v2 + **90 min** del navegador) repartibles entre el 21 y el 25/10 (5 días). Si
DT-B pasara y hubiera que regenerar la receta con el bloque de navegador, **+1 h**. **No** se arma nada hasta
que T8 esté cerrado.

---

## 17. Trazabilidad

| Afirmación | Fuente verificable |
|---|---|
| Causa raíz, cronología y evidencia | `Soporte/Laboratorio/legitimo_72h/diagnostico_fallo.md` §1–§2 |
| Log de consola a `Trace` y lanzador sin tope | `D:\TFG-VMs\material-ghosts\client-linux\nlog.config` (línea 23) · `client_ctl.sh:15` · `tfg_keepalive.sh:20` |
| `Command` de Linux guarda stdout en `history_timeline.result` | `src/ghosts.client.linux/Handlers/Bash.cs` (`Report(... Result)`) |
| `Result` **se acumula** (H-C) | `Bash.cs`: `private string Result` + `Result += p.ReadToEnd()` |
| Azar **sin semilla** en la actividad | `BaseHandler.cs:15` · `Jitter.cs:13` · `DelayExtensions.cs:10` · `Bash.cs:69-90` · `TimelineBuilder.cs:82` |
| `Curl` inyecta **UA aleatoria** | `Curl.cs:33,105` · `UserAgentManager.Get()` (`PickRandom()`) |
| Solo hay semilla en el Animator y **sin llamadores** | `src/Ghosts.Animator/AnimatorRandom.cs:11-14` · `grep -rn '\.Seed\(' src` → 0 |
| `NpcSystem` = encender/apagar | `docs/core/handlers/npc_system.md` · `src/ghosts.client.linux/Handlers/NpcSystem.cs` |
| **Hay handlers de navegador** (`BrowserFirefox`, `BrowserChrome`) con Selenium | `src/ghosts.client.linux/Handlers/Browser{Firefox,Chrome}.cs` · `Orchestrator.cs:164-169` · `docs/core/handlers/browser.md` |
| **Chrome abre en la ventana; Firefox, al arrancar el cliente** | `BrowserChrome.cs:20-26` + `BaseHandler.cs:17-20` · `BrowserFirefox.cs:24-30,103,120` |
| **Firefox reintenta en bucle caliente si el driver falla** | `BrowserFirefox.cs:28-30,149` (`while (!hasRunSuccessfully)`, `_log.Debug(e)`) |
| **`random`/`stickiness`/placeholders añaden azar** | `BaseBrowserHandler.cs:386,396,490,496` · `RequestBuilder.cs:24-44` |
| **El cliente no trae driver; sí `selenium-manager`** | listado de `material-ghosts/client-linux/` · `ghosts.client.linux.csproj:29-30` |
| **Los args deben ser strings (`"true"`)** | `Ghosts.Domain/Code/Helpers/DictionaryExtensions.cs:9-12` |
| **`auditd` captura todo `execve` y toda escritura, sin filtro de ruta** | `Soporte/Wazuh/Reglas/auditd_tfg.rules:20-25` |
| **Ningún ATA del corpus usa navegador** | `grep -ri 'firefox\|chrome\|chromium\|navegador\|browser' Dataset/Ataques/Comandos/` → **0** |
| NPC = identidades sintéticas | `docs/animator/index.md` · `src/Ghosts.Animator/Npc.cs` |
| Update `Timeline` solo escribe el fichero | `src/ghosts.client.linux/Comms/Updates.cs:98-99` · `README.md` §3 (recarga en caliente mata al cliente) |
| **El agente ya reporta `df -P` cada 360 s** | `wazuh` rama 4.14 (`v4.14.0/etc/ossec-agent.conf`: `<localfile><log_format>command…>df -P`) + agente del laboratorio **4.14.7** (`runbook_agente_linux.md` §2) · **220 muestras** del agente `001` en `%TEMP%\tfg-legit-72h-fallo\ossec-archive-19.json.gz` |
| **100 % a las 14:03:39Z** y tasa ≈ 1,1 GB/h | serie `df -P` del 19/10 (13:03 = 1.165.972 KB · 14:03:39 = 0 KB) |
| `syscollector` **no** recoge disco | docs Wazuh *System inventory* (hardware: CPU/RAM/placa) · *Disk space utilization* (command monitoring) |
| El agente es **4.14.7-1** | `Soporte/Wazuh/Configuracion/runbook_agente_linux.md` §2 |
| `archives.json` es hardlink y rota a `.gz` | `diagnostico_fallo.md` §3 y §5 |
| `logall_json_ctl.sh off` **borra** `archives.json` | `Soporte/Laboratorio/ghosts/logall_json_ctl.sh:23` |
| `systemctl restart` del manager puede fallar | `diagnostico_fallo.md` §4.6 y §5.3 |
| 209 acciones en 180 s (bucle viejo) | `Dataset/Legitimo/legitimo_72h/ventana_meta.md` §5 |
| `WorkingHours` no soporta franjas que cruzan medianoche | `legitimo_72h/README.md` §3 · `src/Ghosts.Domain/Code/WorkingHours.cs` |
| Unidad del legítimo, `M`, fallback `L11` | `Soporte/Metrica/metrica_hids.md` §2 y §9.2 |
| DST europeo 2026 = 25/10 | regla europea (último domingo de octubre) |
| Reloj del host: 20/10 (CEST +02:00); tras el 25/10, **+01:00** | `Get-TimeZone` / `Get-Date` |

---

## 18. Lo que no cuadra y decisiones abiertas

### 18.1 Decisiones que **tomo yo** (y el humano ratifica en el gate)

1. **Log**: `Warn` + tope **40 MB** + `app.log` a 21 MB. **No** `/dev/null`, **no** `Info`.
2. **Actividad**: **receta determinista** de 3 días (111/117/105), jornada 08:00–17:00Z, pausas café/comida,
   **sin actividad nocturna**. Un solo stream (`Command`), sin `random`, sin UA aleatoria.
3. **NPC+semilla**: **descartado** con la evidencia de §4 (+ DT0).
4. **`df`**: **del agente** (0 cambios); **se elimina** la sonda de v1 en la timeline.
5. **Keepalive**: reinicia (2 recuperaciones, 2 confirmaciones, 30 min, ≥ 1 GB libre) + **rotación diaria**.
6. **Vigilancia**: cada **30 min**, 8 señales **en vivo** + **RAM post-hoc**, 3 niveles, con **calendario** (no juzga la noche).
7. **Snapshot**: **`lab-listo-legit-v2`** + **`fallo-…-NO-USAR`**; `lab-listo-legit` **se conserva**.
8. **Extracción**: `.gz` por día + vivo, dedupe `sha256`, `[t0,t1]` inclusivo, `--estricto`.
9. **Repetición**: bloque `legitimo-72h-v2`; **`t0 = 2026-10-26T00:00:00Z`** (propuesta abierta, §11.3).
10. **Navegador**: **descartado** (§4.8) por fragilidad, huella de eventos no acotable, **inflación de `M`**
    y coste (RAM/disco/driver), con **DT-B (90 min)** como prueba de falsación; en su lugar, **sesión web
    *browser-like* con `curl`** (§5.7) **sin cambiar el recuento**.
11. **RAM**: presupuesto declarado (§4.9), **G-12** en `prep` y lectura **post-hoc** en el keepalive (§4.10).
    **No** se añade vigilancia en tiempo real de RAM (no hay señal pasiva sin tocar la víctima).

### 18.2 Decisiones **abiertas** (para el humano)

1. **`M` titular**: `endpoint` (propuesta) vs `total` — sigue abierta desde L1 §14.1.
2. **`boveda_version`**: ¿bump a 2? (recomiendo sí; lo decide el humano/orquestador).
3. **La ficha inválida** en `Dataset/Legitimo/legitimo_72h/ventana_meta.md`: este bloque **no la toca**;
   **debe** archivarse al empezar `legitimo-72h-v2`, **antes** de escribir la nueva.
4. **Horario local**: he elegido **09:00–18:00** (España, jornada partida con comida a las 14:00). Si el
   humano prefiere **08:00–15:00** (intensiva), se regenera la receta (1 h de trabajo) **antes** del dry test.

### 18.3 Lo que **no cuadra** (declarado, sin adornos)

1. **El `M` va a bajar mucho y el FPR no será comparable con nada anterior.** Con 333 acciones (frente a
   ~5,9 k) la mayor parte de los eventos pasa a ser **ruido de fondo** del endpoint (~4,2 MB/h medidos en L0).
   La proyección de v1 (≈ 90 MB gz / 5,1 M eventos) **se queda grande**; el presupuesto real se mide en DT11
   y se declara. **Consecuencia honesta**: menos acciones ⇒ menos alertas `80792` ⇒ **FPR más bajo**. El TFG
   debe informar **siempre** de `acciones/hora` y `M` junto al FPR. **No se oculta**: es efecto directo de la
   decisión de realismo.
2. **La variedad de días depende de un reinicio diario** (rotación). Es actividad del banco, declarada y
   acotada (2 en la ventana), pero es **intrusión**. Si el humano prefiere **cero reinicios**, la alternativa
   es **un solo día repetido 3 veces** (peor realismo) o **ampliar el bloque** para que el cliente reciba la
   timeline por el API (riesgo de recarga en caliente, descartado).
3. **`history_timeline.result` acumula** (H-C): con 333 acciones la BD crecerá ~55 MB (estimación
   cuadrática), muy por debajo de los 66 MB del intento fallido, pero **crece**. **No se parchea**: se vigila.
4. **Los reinicios podrían duplicar la máquina** en GHOSTS (H-J). Se mitiga consultando **todos** los ids y se
   prueba en DT5b. Si aun así cambiara, la vigilancia seguiría viendo las acciones (consulta por unión).
5. **La prueba en seco no puede probar la rotación real del manager a `t1`** sin esperar a medianoche: se
   prueba la **hipótesis** (G-9) y la **tolerancia** (reintentos + plano).
6. **No hay garantía de que el cliente aguante 72 h**: por eso hay autocuración **y** una regla de validez
   que puede **invalidar** la ventana. No se finge lo contrario.
7. **El `Warn` podría seguir generando avisos** (p. ej. si “internet local” parpadea): el tope lo acota.
8. **`Dataset/` queda con una ficha de una ventana inválida** hasta que la archive el bloque siguiente.
9. **21/10 no es viable** y no se finge que sí: la alternativa realista es **26/10** (§11.3).
10. **La receta es «una persona, un escritorio»**: no simula dos aplicaciones a la vez (un solo stream). Es
    una simplificación **declarada**; el ruido de fondo multitarea lo pone el propio sistema (auditd,
    syscheck, SCA, agente), no GHOSTS. Además, **las interacciones web no usan navegador**: GHOSTS **tiene**
    handlers de navegador (`BrowserFirefox`, `BrowserChrome`), pero **no hay navegador instalado** en la
    víctima y **se ha decidido no instalarlo** (§4.8). La sesión web se hace con `curl` **dentro** del
    handler `Command` (UA **fija y honesta**, cookies, `Referer`, requisitos), que es lo que ya funcionaba en
    L1 (el handler `Curl` también ejecuta el binario `curl`: `Curl.cs` → `ProcessInfo.FileName = "curl"`).
11. **El navegador no se ha podido "probar a lo grande"**: DT-B es **acotado** (6 páginas, 90 min). Es
    suficiente para decidir (**secuencia, recursos, `M`, orfandades, fallo**) pero **no** es una sesión de
    navegación real de 9 h. Se dice así: la decisión es **proporcionada**, no exhaustiva.
12. **El FPR no es comparable si cambia `M`**: por eso el navegador se descarta (diluiría el denominador) y
    por eso el TFG debe informar de **acciones/h y `M`** junto a cualquier FPR (§18.3-1).
13. **La RAM no se vigila en tiempo real**: `syscollector` no da memoria libre y no se toca la config de
    Wazuh. Se mide en `prep` (G-12) y **post-hoc** en el keepalive (§4.10). Si hubiera OOM, se vería al
    cerrar; **no** se finge una vigilancia que no existe.
14. **El `df -P` del agente está en `M`** (240 eventos/día) y **siempre lo estuvo**: no es instrumentación
    nueva, pero **se declara** para que nadie lo cuente como «actividad del usuario».
15. **Incidente de continente (ya resuelto en v1).** El plan de **L1** vivía en la **raíz** (`plan.md`) porque
    L1 nunca se archivó; se **reconstruyó** en `Soporte/Laboratorio/legitimo_72h/plan_L1_2026-10-18_reconstruido.md`.
    **Acción para el orquestador**: al aprobar **este** plan, guardarlo en git **y** archivar la v1 de este
    bloque en `_fases/legitimo-fix/` (**gate Q7**, CA-24).
