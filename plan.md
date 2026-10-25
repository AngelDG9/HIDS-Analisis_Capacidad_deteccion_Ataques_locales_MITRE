---
bloque: legitimo-72h-v2
nombre: L1-v2 — ventana de 72 h de actividad legítima (Wazuh Linux virgen) desde lab-listo-legit-v2, extracción y sellado B10
version: 1
status: draft
fecha: 2026-10-25
autor: tfg-planner
depende_de: legitimo-fix (cerrado 2026-10-21, PASA) · legitimo-infra (L0, cerrado) · reencuadre-metrica (métrica congelada v1) · legitimo-72h (L1, EJECUTADO y FALLIDO · ventana INVÁLIDA)
ventana_objetivo: t0 = 2026-10-26T00:00:00Z → t1 = 2026-10-29T00:00:00Z (72 h exactas; **propuesta** — la ratifica el humano en el gate Q1)
gate: |
  **PENDIENTE DE APROBACIÓN (gate humano).** Este bloque **sí ejecuta** las 72 h. Nada se arma
  hasta que el humano firme Q1–Q8 de §11 y el plan quede **en git**.
  Decisiones que debe ratificar: (1) la **fecha** (§2.2, con condición de viabilidad y alternativa);
  (2) el **compromiso de 3 días** con el PC encendido y sin tocar la víctima; (3) el **ensayo E0**
  de armado (§4.3) antes de `t0`; (4) el **orden nuevo de cierre** (cosecha de logs del invitado
  en `t1+2` y parada después, §6.2); (5) `boveda_version` → **2** y **quién** lo aplica (§8);
  (6) el **micro-cambio MC-1** en `exportar_acciones.sh` (§10, 1 línea + `pytest`);
  (7) que si la ventana sale **inválida se repite entera** (no se parchea);
  (8) que los datos se promocionan a `Dataset/` **solo si es VÁLIDA** (§6.5).
---

# plan.md — Bloque `legitimo-72h-v2` (v1, borrador)

> **Qué es.** El bloque que **ejecuta una única ventana de 72 h** de actividad legítima sobre
> `victima-linux` con **Wazuh virgen** (`C1 = {RS1,RS2}`), desde el snapshot **`lab-listo-legit-v2`**,
> con **arranque y parada automáticos**, **cero acceso a la víctima** dentro de `[t0,t1]`, y que
> después **extrae** las tres cosas que la métrica necesita —**alertas** (ficheros diarios),
> **denominador `M`** (`.gz` por día + vivo, con dedupe) y **acciones GHOSTS**—, **sella B10** y
> **dictamina la validez**.
>
> **Qué NO es.** **No arregla** nada: el laboratorio se cerró arreglado y probado en `legitimo-fix`
> (`lab-listo-legit-v2`). **No analiza** (`T3`/`T4`, FPR, catálogo de ruido: es `L2`
> `legitimo-analisis`). **No toca** el ruleset, la métrica congelada, el corpus, `Hojas/`,
> `_recursos/` ni `Dataset/` (salvo la promoción declarada de §6.5, y solo si la ventana es válida).
> **No monta** Windows ni Velociraptor. **No inventa** una segunda oportunidad: una ventana; si es
> inválida, se repite entera.
>
> **Frase que resume el bloque:** *encender, no tocar, mirar que hace (no que está), copiar antes
> de apagar, contar, sellar y decir la verdad sobre si vale.*

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [La ventana: fechas, por qué y qué hace el humano](#2-la-ventana-fechas-por-qué-y-qué-hace-el-humano)
3. [Estado de partida verificado (2026-10-25)](#3-estado-de-partida-verificado-2026-10-25)
4. [Preparación (antes de `t0`)](#4-preparación-antes-de-t0)
5. [Ejecución: arranque, vigilancia y disciplina](#5-ejecución-arranque-vigilancia-y-disciplina)
6. [Extracción (después de `t1`)](#6-extracción-después-de-t1)
7. [Validez: V1–V8 y qué invalida la ventana](#7-validez-v1v8-y-qué-invalida-la-ventana)
8. [Sellado de la bóveda B10 (versiones y huellas)](#8-sellado-de-la-bóveda-b10-versiones-y-huellas)
9. [Riesgos y mitigaciones](#9-riesgos-y-mitigaciones)
10. [Criterios de aceptación (verificables)](#10-criterios-de-aceptación-verificables)
11. [Gate humano (lenguaje sencillo)](#11-gate-humano-lenguaje-sencillo)
12. [Ficheros que se tocarán](#12-ficheros-que-se-tocarán)
13. [Trazabilidad](#13-trazabilidad)
14. [Lecciones del fallo de L1, aplicadas una por una](#14-lecciones-del-fallo-de-l1-aplicadas-una-por-una)
15. [Lo que no cuadra y decisiones abiertas](#15-lo-que-no-cuadra-y-decisiones-abiertas)

---

## 0. Resumen ejecutivo

`legitimo-fix` dejó el laboratorio **arreglado y probado** (DT0–DT13 + DT-B, `pytest` 189,
snapshot `lab-listo-legit-v2`, receta de **111/117/105** acciones/día, vigilancia de 9 señales que
ya lee el `df` del agente). Lo que **falta** es lo único que no se puede simular: **72 h de reloj**.

Este bloque hace **seis cosas**:

1. **Arma** el laboratorio desde `lab-listo-legit-v2`: `prep` (revierte, despliega, enciende
   manager + GHOSTS + "internet local", `logall_json` ON, G-1…G-12) y `arm` (timer del invitado a
   `t0−5`, cliente arriba, checklist).
2. **Ejecuta** 72 h **sin tocar la víctima**: lo único que actúa dentro es el **keepalive v3**
   (≤2 rotaciones de receta + ≤2 recuperaciones + ≤3 arranques), **declarado** en `recovery.log`.
3. **Vigila** cada **30 min** con 9 señales **host-side** (7 en vivo + 2 post-hoc): «¿está
   haciendo?», agente dentro, daemons, entrada de eventos, **disco de la víctima leído del agente
   (valor y tasa)**, disco del host, BD de GHOSTS, recuperaciones y RAM post-hoc.
4. **Extrae**, en este orden estricto: **cosecha de logs del invitado** (`t1+2`) → **parada** de la
   víctima → **copia del denominador** (3 `.gz` + vivo + `MANIFEST` + dedupe `sha256`) → **conteo
   `M`** (`--estricto`) → **`logall_json off`** (que **borra** `archives.json`). Después: alertas
   de los **3 ficheros diarios** y **acciones** de `history_timeline`.
5. **Dictamina** V1–V8 con evidencia y **firma el humano**.
6. **Sella B10** con valores **medidos** (no proyectados), `boveda_version` → **2**, y deja el
   laboratorio **cerrado**.

**Lo que cambia respecto de L1 (el intento fallido) no es la intención, es el método:** se mide
«hacer» y no «estar», el disco se lee de la señal que **ya existía**, el log tiene **tope duro**,
el denominador se copia **antes** de apagarlo, y **ningún paso se estrena la noche de `t0`**.

**Estado hoy (verificado, §3):** 0 VMs · 5 snapshots (incluido `lab-listo-legit-v2`) · **53/53**
huellas de `sha256sums.txt` correctas · `TFG_GUEST_PW` en el entorno · **Windows Update NO está
pausado** (`wuauserv` = `Manual`/`Running`, aunque la política `NoAutoUpdate=1` sigue puesta) ·
`D:` 183 GB libres · `prep` ya se ejecutó con éxito el 21/10 (EXIT=0, tres veces) · **`arm` nunca se
ha ejecutado de principio a fin**.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

Producir, con **una sola ejecución**, el **dataset legítimo de 72 h** de `victima-linux` con Wazuh
virgen —**alertas** + **denominador `M`** + **acciones GHOSTS**—, **sellar B10** con los valores
reales y **emitir un veredicto de validez** con criterios escritos de antemano.

### 1.2 Entra

- **Armar** desde `lab-listo-legit-v2` (`prep` + `arm`), con `logall_json` ON **solo** en `[t0,t1]`.
- **Ejecutar** las 72 h con tareas del host y timer del invitado; **cero** acceso a la víctima.
- **Vigilar** cada 30 min (9 señales), con aviso visible y umbrales ya probados.
- **Cosechar** la evidencia del invitado al cerrar (`recovery.log`, `keepalive.log`, `client.out`,
  `id.json`, `rotacion.estado`, `ip route`, `df`).
- **Copiar y contar `M`** con rotación diaria, dedupe y manifiesto; **antes** de `logall_json off`.
- **Extraer alertas** (3 diarios, agente `001`) y **acciones** (`history_timeline`).
- **Evaluar V1–V8**, escribir la ficha de la ventana y **sellar B10** (sidecar + `sha256sums`).
- **Cerrar limpio** (0 VMs, 0 tareas, firewall retirado, `logall_json=no`, Windows Update restaurado).

### 1.3 NO entra (fuera de alcance)

- **Analizar** (`T3`/`T4`, FPR/TNR, catálogo de ruido, pruning): es `L2`.
- **Cambiar el laboratorio**: la receta, el keepalive, la vigilancia, el `nlog.config`, el ruleset y
  `ossec.conf` (salvo `logall_json`) están **congelados** en `v2`. Único cambio admitido: **MC-1**
  (§10) en `exportar_acciones.sh`, 1 línea, con `pytest`.
- **Tocar** `Soporte/Metrica/**` (lo aplica el humano/orquestador), `_recursos/**`, el corpus
  (`Soporte/Ataques/**`, `Dataset/Ataques/**`, `Bitacora/**`), `Hojas/**`, `Dataset/**` (salvo §6.5).
- **Reparar o parchear la ventana**: si es inválida, **se repite entera** con snapshot limpio.
- **Medir dos configuraciones** (A/B) ni añadir reglas/HIDS: `C1 = {RS1,RS2}` y nada más.
- **Windows legítimo, Velociraptor, coste computacional**: otros bloques.
- **Commits/push**: los hace el orquestador/humano (**el plan sí se guarda en git al aprobarse**).

---

## 2. La ventana: fechas, por qué y qué hace el humano

### 2.1 Propuesta (la ratifica el humano)

| Parámetro | Valor |
|---|---|
| **`t0`** | **2026-10-26T00:00:00Z** = lunes 26/10 **01:00** local (CET, UTC+1) |
| **`t1`** | **2026-10-29T00:00:00Z** = jueves 29/10 **01:00** local |
| Duración | **72 h exactas** (`t1 = t0 + 259 200 s`) |
| Días de actividad | **lunes 26 · martes 27 · miércoles 28** → recetas `d1` · `d2` · `d3` |
| Jornada | **08:00–17:00 Z** = 09:00–18:00 local (café 10:00–10:20Z, comida 13:00–14:00Z) |
| Corte diario | a **medianoche UTC** ⇒ **3 `.gz` + 1 vivo** (regla de borde §6.3) |
| `prep` | 26/10 **00:15** local (`t0−45`) · `arm` 00:40 local (`t0−20`) · timer 00:55 local (`t0−5`) |
| `stop` | 29/10 **01:05** local (`t1+5`) |

### 2.2 Por qué esta fecha (y su condición)

| Motivo | Detalle |
|---|---|
| **No cruza el cambio de hora** | El DST europeo termina el **25/10/2026**; la ventana empieza **después** ⇒ `08:00Z = 09:00 local` los tres días, sin saltos |
| **Días laborables** | lunes → miércoles: 3 jornadas de oficina consecutivas |
| **Cortes diarios exactos** | `t0`/`t1` a medianoche UTC ⇒ 3 días de calendario ⇒ 3 `.gz` (L1 midió que la rotación ocurre a las **00:04Z**) |
| **Ya está todo hecho** | `lab-listo-legit-v2`, la receta y las pruebas en seco están cerradas desde el 21/10: **no hay trabajo previo pendiente** |

> **Condición de viabilidad (honesta, con reloj).** Al escribir este plan son las **2026-10-25
> ~20:00Z**: quedan **~4 h** para `t0`. Cabe **solo** si se cumplen las tres cosas:
> **(a)** gate firmado y plan **en git** antes de las **21:00Z**; **(b)** ensayo **E0** (§4.3,
> ~45 min) entre 21:00–22:15Z; **(c)** Windows Update **re-pausado** antes de las 23:00Z.
> Si a las **21:00Z** no se ha cerrado el gate, **la propuesta pasa a `27/10 00:00Z → 30/10 00:00Z`**
> (martes→viernes, mismas condiciones, sin DST), con **E0 la mañana del 26**. *No se arranca sin E0.*

> **Coste de cambiar de fecha (verificado, no estimado).** `MAPA_DIAS` está **hardcodeado** en
> `_artefactos/scripts/construir_receta_legitima.py:86` (`2026-10-26/27/28`) y se replica en
> `recetas/calendario.json` y `recetas/bloques.env:13`. Cambiar de fecha exige: **editar esa
> constante (1 línea) → regenerar recetas → `--check` → actualizar `sha256sums.txt`** (~20 min).
> Los **contenidos de `d1/d2/d3` no cambian** (los comandos calculan la fecha en ejecución), así que
> sus `sha256` se mantienen; **lo que cambia es el calendario**. `prep` (G-4) valida el mapa contra
> `--check`, y el keepalive calcula el día desde `T0`: **no hay más acoplamientos**.

### 2.3 Qué hace el humano (y qué no)

**Sí:**

1. **Dejar el PC encendido, enchufado, sin suspensión ni hibernación, 3 días.** (Verificado hoy:
   `STANDBYIDLE` AC = 0 y `HIBERNATEIDLE` AC = 0.) La pantalla se puede **bloquear**; **no cerrar
   sesión** (las tareas son `Interactive`).
2. **No tocar la víctima** (`victima-linux`) durante `[t0,t1]`: ni consola, ni SSH, ni
   `runProgramInGuest`, ni snapshots. *(El manager sí se consulta: solo lectura, por SSH, y solo lo
   hace el `watch`.)*
3. **Mirar el aviso** una vez al día (burbuja `msg.exe`) y **leer 3 líneas** del log de vigilancia
   (§5.4). Si hay `ALARMA`, avisar al orquestador; **no** actuar sobre el invitado.
4. **No instalar/actualizar nada** en el host esos días, y **no apagar/reiniciar**.
5. **No limpiar `%TEMP%\opencode`** (ahí vive el estado del `watch`; si se borra, el primer chequeo
   da una falsa alarma).
6. **Estar disponible al cierre** (`t1+5`) o, como muy tarde, la mañana del jueves 29, para la
   extracción (la copia del denominador se hace en `t1+30…+90`; **si se apaga `logall_json` antes,
   el denominador se pierde**).

**No:**

- No ejecutar tareas pesadas (compilaciones, juegos, edición de vídeo) que puedan dormir/hundir el
  host. El host corre PostgreSQL + API GHOSTS + 3 servicios Python.
- No "echar un vistazo" a la víctima «por si acaso»: **un solo acceso contamina la ventana** (V4) y
  **no se resta**.
- No cambiar la fecha a mitad, ni "probar" el timer del invitado dentro de la ventana.

---

## 3. Estado de partida verificado (2026-10-25)

Todo lo de esta tabla se ha **leído** (no se ha tocado nada) al escribir el plan:

| Elemento | Estado real | Cómo |
|---|---|---|
| **VMs** | **0 en marcha** | `vmrun -T ws list` → `Total running VMs: 0` |
| **Snapshots `victima-linux`** | **5**: `base-limpia`, `lab-listo`, `lab-listo-legit`, `fallo-2026-10-19-disco-lleno-NO-USAR`, **`lab-listo-legit-v2`** | `vmrun listSnapshots` |
| **Snapshots `wazuh-server`** | `base-limpia`, `lab-listo` | idem |
| **Huellas del laboratorio** | **53/53** entradas de `sha256sums.txt` coinciden con el árbol | recálculo `sha256` |
| **Receta** | `--check` PASS en `legitimo-fix` (DT10): 111/117/105, 0 `random`, 0 pipes, 0 `Browser*` | `prueba_en_seco.md` |
| **Windows Update** | ⚠️ **`wuauserv` = `Running` / `Manual`**; política `NoAutoUpdate=1` y `NoAutoRebootWithLoggedOnUsers=1` **presentes** | `Get-Service`, registro |
| **Energía** | `STANDBYIDLE` AC = **0**, `HIBERNATEIDLE` AC = **0** | `powercfg /query` |
| **Disco del host** | `D:` **183 GB** libres | `Get-PSDrive D` |
| **Tareas del host** | 4 `TFG-Baseline-*` (preexistentes); **0** `TFG-Legit-*` | `Get-ScheduledTask` |
| **Reglas de firewall** | **0** `TFG-*` | `Get-NetFirewallRule` |
| **Puertos 5000/8080/9090/9092** | **cerrados** (laboratorio parado) | `Test-NetConnection` |
| **`TFG_GUEST_PW`** | presente (usuario + sesión); `TFG_MANAGER_PW` no definida ⇒ se usa la misma | `[Environment]::GetEnvironmentVariable(...,'User')` |
| **`prep` (extremo a extremo)** | **probado el 21/10**: `prep5`/`prep6` **EXIT=0**; `legitimo_host_control.log:2316-2530` | logs de la sesión |
| **`arm` (extremo a extremo)** | ❌ **nunca ejecutado**: no hay ni una línea `[arm]` en `legitimo_host_control.log` | `Select-String '\[arm\]'` → 0 |

> **Consecuencia directa:** el eslabón **no probado** es `arm` (instalación del timer del invitado,
> arranque del cliente desde el host, checklist) y el **encadenado real de tareas** del Programador
> de Windows con `T0/T1`. Por eso **E0 es obligatorio** (§4.3) y no es burocracia.

---

## 4. Preparación (antes de `t0`)

> **Regla de oro (heredada):** si un guardarraíl falla, **no se arma nada**; se arregla y se repite
> `prep`. Nada de «seguir y ya veremos».

### 4.1 `prep` (`t0−45`, tarea `TFG-Legit-Prep`) — lo que ya hace

`legitimo_host_control.ps1 -Phase prep` (`:249-400`), en este orden: **G-1** snapshot v2 existe →
**G-10** host (`D:` ≥ 60 GB, **`wuauserv` = `Disabled`**, sesión) → **G-4** receta `--check` PASS +
`sha256` == repo → **revert a `lab-listo-legit-v2`** + arranque de las 2 VMs → **G-12** RAM libre
≥ 1500 MB (swap se declara) → `deploy_client.ps1` (nlog, receta, `client_ctl.sh`, keepalive) →
**G-2** ≥ 4 GB y ≥ 20 % inodos → **G-3** `verificar_arreglos.sh` = PASS → manager arriba +
**`logall_json on`** + **G-7** `yes`/daemons → "internet local" + GHOSTS + **G-8** sin ruta por
defecto → **G-5** agente `Active` → **G-11** `machineid`(s) → `timeline.json` = **d1** +
`rotacion.estado` = fecha de `t0` → **G-9** sonda de rotación (informativo) → **G-6** llegan
muestras `df -P` del agente (`≤ 7 min`).

**Códigos de aborto:** 41 (sin v2), 42 (disco/inodos), 40 (arreglos), 20 (receta), 43 (agente),
46 (`df -P`), 44 (`logall_json`/daemons), 45 (NAT), 47 (host), 48 (RAM), 30 (sin contraseña).

### 4.2 Precondiciones que **el host** debe cumplir antes (P-1…P-6)

> No son cambios en el código (el laboratorio está congelado): son **comprobaciones/acciones del
> host**, fuera de `[t0,t1]`, hechas por el humano/orquestador y **registradas** en el log.

| # | Precondición | Cómo | Si falla |
|---|---|---|---|
| **P-1** | **Windows Update re-pausado** (se auto-repara, verificado hoy) | `pausar_windows_update.ps1 pausar` → `wuauserv` **Disabled** + política 1/1 | G-10 aborta (47) |
| **P-2** | **`TFG_GUEST_PW`** disponible para las tareas | `[Environment]::GetEnvironmentVariable('TFG_GUEST_PW','User')` ≠ vacío | `prep`/`arm` salen con 30 |
| **P-3** | **Disco del manager** ≥ **10 GB** libres (denominador + alertas + copia) | por SSH al manager (arrancado en `prep`): `df -h /` | retrasar/limpiar **antes** de `t0` |
| **P-4** | **Energía**: sin suspensión/hibernación | `powercfg /query` (ya verificado: 0/0) | ajustar antes de `t0` |
| **P-5** | **Sin restos**: 0 VMs, 0 `TFG-Legit-*`, 0 reglas `TFG-*` | §3 | limpiar antes de `prep` |
| **P-6** | **Estado del `watch` limpio** (si no, falsa alarma en el 1er chequeo) | borrar `%TEMP%\opencode\tfg_watch_estado.json` (**solo ese fichero**) | — |

### 4.3 **E0 — ensayo de armado (obligatorio, fuera de ventana, ~45 min)**

> **Qué cubre:** el único tramo nunca ejecutado: **`arm` + timer del invitado + keepalive + tareas
> del host**. **Qué no repite:** `prep` (3× con EXIT=0), la receta (DT9/DT11), la vigilancia
> (DT4/DT6/DT7), la extracción (DT8), el snapshot (DT12).

| Paso | Qué se hace | Pasa si |
|---|---|---|
| **E0-1** | `prep -T0 <T0_real>` (deja el laboratorio listo, cliente parado) | termina sin código ≠ 0; G-1…G-12 en `OK` |
| **E0-2** | `arm -T0 <T0_falso = ahora+25 min>` | `instalar_tarea_invitado.sh` rc=0; `systemctl list-timers` con `NEXT` = `T0_falso−5 min` (**en UTC**); cliente vivo (1 proceso) |
| **E0-3** | Esperar al disparo del timer | `systemctl status tfg-ghosts-legit` activo; `keepalive.log` con `inicio (...)`; `recovery.log` **vacío**; 1 solo proceso del cliente |
| **E0-4** | `stop` del invitado + `cleanup` del host | 0 procesos del cliente/keepalive; `logall_json=no`; `CONFIG_IDENTICA`; VMs apagadas |
| **E0-5** | `registrar_tareas.ps1 -T0 <T0_real>` + `-Verificar` | 4 tareas `Ready`; `NextRun_UTC` = `t0−45`, `t0−20`, `t0`, `t1+5` (±1 min) |
| **E0-6** | Revertir a **`lab-listo-legit-v2`** y dejarlo apagado | `vmrun listSnapshots` intacto; 0 VMs |

- **Registro:** `Soporte/Laboratorio/legitimo_72h/ensayo_E0.md` (salida literal recortada + horas
  UTC + veredicto PASS/FAIL). Si E0 falla: **se corrige y se repite E0**; **no** se arma la ventana.
- **Coste:** ~45 min y **no ensucia** (todo se revierte a `v2`).
- **Efecto secundario declarado:** el `id.json`/`machineid` puede cambiar con el revert; `prep`
  vuelve a sembrar `rotacion.estado` y `G-11` registra los ids; el `watch` consulta **todos** los
  ids de `victima-linux` (hallazgo H-J).

### 4.4 Después de E0: armar de verdad

1. `pausar_windows_update.ps1 pausar` (**re-pausar**; P-1) y comprobar `Disabled`.
2. Borrar el estado del `watch` (P-6).
3. Dejar las **4 tareas** registradas con el `T0/T1` **reales** y `NextRun` **en UTC** verificado.
4. **No** armar `prep` a mano salvo que falle la tarea: el camino que se mide es el automático.

---

## 5. Ejecución: arranque, vigilancia y disciplina

### 5.1 Las tareas (nada en segundo plano a mano)

| Tarea | Ámbito | Cuándo (local) | Qué hace |
|---|---|---|---|
| **`TFG-Legit-Prep`** | host | 26/10 00:15 | §4.1 (revierte, enciende, despliega, `logall_json` ON) |
| **`TFG-Legit-Arm`** | host | 26/10 00:40 | instala timer (`t0−5`), arranca el cliente, checklist, purga `machine_updates` |
| **`TFG-Ghosts-Legit`** | **invitado** | 26/10 00:55 | keepalive v3 durante **74 h** (muere con la VM) |
| **`TFG-Legit-Watch`** | host | cada **30 min** desde `t0` | vigilancia de 9 señales (**no toca la víctima**) |
| **`TFG-Legit-Stop`** | host | 29/10 01:05 | **parada** (soft) de la víctima; el manager **sigue** |

- `registrar_tareas.ps1` imprime `NextRun_local` **y** `NextRun_UTC` (`:66-82`) — se comprueba el UTC.
- El **timer** del invitado es `Persistent=false`: no se dispara «al arrancar» si llega tarde.
- El **cliente** lo arranca `arm` a `t0−20`; **no ejecuta nada** hasta las `08:00Z` (la primera
  ventana de `d1` es `08:00:00–08:12:00`).

### 5.2 Disciplina dentro de `[t0,t1]` (regla dura)

1. **CERO** acceso a `victima-linux` (SSH, consola, `vmrun`, snapshots). Los únicos eventos
   atribuibles al banco dentro del invitado son los del **keepalive** (declarados y contados).
2. **El manager** se consulta **solo lectura** por el `watch` (SSH + `sudo -S` para `agent_control`
   y `stat`), y **solo** para leer.
3. **No** se cambia ninguna configuración (Wazuh, GHOSTS, "internet local", host) dentro de la
   ventana. *Excepción declarada y única:* si Windows Update «se auto-repara» **antes** de `t0`, se
   re-pausa **antes** de `t0`; **dentro** de la ventana **no se toca** (la política `NoAutoUpdate=1`
   es la protección; se comprueba en el chequeo diario y se declara si hubo que tocar algo).
4. El **PC** no se apaga, no se suspende y **no se cierra sesión**.

### 5.3 Qué se vigila (9 señales, cada 30 min, sin tocar la víctima)

| # | Señal | Fuente | Umbral |
|---|---|---|---|
| 1 | **¿está haciendo?** | `max(createdutc)` de `history_timeline` (todos los ids) + **calendario** | bloque: ≤15 min OK · 15–30 **AVISO** · **>30 ALARMA**; pausa/noche **no se juzga** |
| 2 | ¿agente dentro? | `agent_control -i 001` → `Last keep alive` | ≤60 s OK · ≤10 min AVISO · **>10 min ALARMA** |
| 3 | daemons | `is-active wazuh-manager` + `pgrep remoted/analysisd` | unit `active` y ≥2 ⇒ OK |
| 4 | ¿entran eventos? | Δ`archives.json` + Δ diario de alertas | 0 en **2** chequeos dentro de bloque ⇒ **ALARMA** |
| 5 | **disco de la víctima** | líneas `df -P` del agente `001` en `archives.json`, offset incremental | ≥3 GB OK · 2–3 AVISO · **<2 GB ALARMA**; tasa < **−1 GB/h** ALARMA |
| 6 | disco del host | `Get-PSDrive D` | ≥60 GB OK · 20–60 AVISO · <20 **ALARMA** |
| 7 | BD de GHOSTS | `pg_database_size('ghosts')` | <4 GB OK · 4–10 AVISO · >10 **ALARMA** |
| 8 | recuperaciones/rotaciones | `recovery.log` (se lee **al cerrar**, post-hoc) | informativo; se juzga con §7.2 |
| 9 | RAM | `ram_free_mb` del keepalive (post-hoc) | mín. ≥512 MB; `<256 MB` ⇒ revisión |

- **Formato de línea** (una por chequeo, UTC): `[watch] estado=… doing_age=… bloque=… hb=… ag=…
  mgr=…/… arch=…B dia=…B df=…G tasa=…MB/h db=…MB host=…G ram=post-hoc rec=post-hoc rot=post-hoc notas=…`.
- **Aviso al humano:** línea `[ALARMA]` + fichero `ALARMA_<UTC>.txt` + `msg.exe`. Dos `ALARMA`
  seguidas de la misma señal ⇒ `PERSISTENTE`.
- **La vigilancia NUNCA actúa** (no reinicia, no para, no arranca, no entra en el invitado).

### 5.4 Chequeo diario del host (manual, solo lectura, 1×/día)

> Lo hace el humano/orquestador **desde el host**, sin tocar la víctima, y **lo apunta** en
> `legitimo_host_control.log` con una línea `check-dia-N`.

1. Últimas **3** líneas de `vigilancia_legitimo.log` (¿`OK`? ¿qué señal dispara?).
2. **Uptime del host**: `(Get-CimInstance Win32_OperatingSystem).LastBootUpTime` debe ser **anterior
   a `t0`**; y en el registro de Sistema, **0** eventos `Kernel-Power` 42/107 dentro de la ventana.
3. `wuauserv` sigue `Disabled` y la política 1/1; `vmrun list` sigue mostrando **2** VMs.
4. `Get-PSDrive D` (disco del host) y, si se quiere, `df -h /` por SSH al **manager** (P-3).
5. **No** se hace nada más. Si hay `ALARMA`: se avisa y **se decide**; el `watch` no arregla.

### 5.5 Aborto temprano (si procede)

Si en las **primeras 24 h** aparece una condición **invalidante** de §7.3 (agente caído > 60 min,
manager caído > 30 min, fichero diario ausente, un bloque entero sin acciones), el humano puede
**abortar** para no gastar 2 días: `registrar_tareas -Eliminar` + `cleanup` (**host-side**, sin
entrar en la víctima) y se reprograma. **Se registra el motivo** (no se «arregla» la ventana).

---

## 6. Extracción (después de `t1`)

> **Orden crítico** (aprendido del fallo y del ensayo de L1): **cosechar → parar → copiar → contar →
> apagar `logall_json`**. `logall_json_ctl.sh off` hace `rm -f archives.json`
> (`logall_json_ctl.sh:53`) ⇒ **si se apaga antes de copiar, `M` se pierde**.

### 6.1 Cambio de orden respecto de L1 (declarado y necesario)

En L1 se paraba la víctima a `t1+5` y **después** se extraía. Pero la evidencia que decide V2/§7.2
(`recovery.log`, `keepalive.log`, `client.out`, `rotacion.estado`, `ip route`) **vive dentro del
invitado**. Con la VM apagada **no se puede leer**, y encenderla después sería peor.

⇒ **`t1+2` (fuera de la ventana, declarado):** una **única** sesión SSH al invitado para
**congelar y cosechar** (parar `tfg-ghosts-legit.timer/service` + `client_ctl.sh stop` + `scp` de
6 ficheros + `ip route` + `df`). **`t1+5`: parada** (`vmrun stop soft`). Esto **no** contamina la
medida: ocurre **después** de `t1`, y la ventana es `[t0,t1]`.

### 6.2 Secuencia (con horas)

| Hora | Paso | Quién | Producto |
|---|---|---|---|
| **`t1+2`** | **Cosecha**: para timer+cliente; `scp` de `recovery.log`, `keepalive.log`, `client.out`, `instance/id.json`, `rotacion.estado`, `config/timeline.json`; `ip route` y `df -h /` | orquestador (host) | `Soporte/.../ventana_*/evidencia/` |
| **`t1+5`** | **Parada** de la víctima (soft). **El manager sigue encendido** | tarea `TFG-Legit-Stop` | — |
| **`t1+10`** | `exportar_denominador.sh info` (ver rotación y `.gz`) | host → manager | salida en log |
| **`t1+30`** | **Copia de la ventana**: `copiar-ventana t0 t1` (3 `.gz` + `.sum` + planos + vivo) + `MANIFEST.tsv` + **dedupe `sha256`**; `scp` a **fuera del repo**. Reintentos: **3 × 10 min** si falta el `.gz` del día 28 | host | `D:\TFG-VMs\legitimo-2026-10-26\denominador\` |
| **`t1+45`** | **Puerta obligatoria antes de apagar nada**: el `MANIFEST.tsv` existe, el **vivo** está copiado y los `sha256` cuadran. **Si no: NO se apaga `logall_json`** | host | checklist en el log |
| **`t1+45…+55`** | **Conteo `M`**: `contar_denominador.py --desde t0 --hasta t1 --estricto --manifest --boveda-version 2 --out denominador_M.csv` | host | `denominador_M.csv` |
| **`t1+60`** | **`logall_json off`** (solo tras la puerta de `t1+45`) + `status` + `diff` `CONFIG_IDENTICA` | host → manager | `logall_json=<logall_json>no</logall_json>` |
| **`t1+70`** | **Alertas**: `cat` de los 3 diarios → `/tmp/alertas_ventana.jsonl`; `extraer_alertas.py --desde --hasta --detail --out` (sha del script verificado) | manager | `alertas_detalle.csv`, `ruleids_legitimos.csv` |
| **`t1+80`** | **Acciones**: `exportar_acciones.sh t0 t1 <staging>/ghosts_acciones.csv` | host | `ghosts_acciones.csv` |
| **`t1+90`** | **Disco del manager** y cierre de la copia (`sha256` de cada producto) | host | `MANIFEST.md` |

### 6.3 Regla de borde y dedupe (escrita)

- Ventana **`[t0,t1]` con ambos extremos inclusivos**.
- Los **3 `.gz`** (`26`, `27`, `28` de octubre) cubren `[t0, t1)`.
- El **vivo** (`archives.json` del día 29) solo puede aportar eventos con `timestamp` **exactamente
  `t1`** (se comprueba: si aporta más, **se investiga**, no se suma a ciegas).
- **`archives.json` es hardlink** del fichero del día ⇒ **dedupe por `sha256`** (se cuenta una vez).
- **`--estricto`**: si dos ficheros **únicos** solapan en tiempo ⇒ **exit 3** y **no** se publica `M`.
- Si el `.gz` del día 28 **no** está a `t1+30`: 3 reintentos de 10 min; si sigue sin estar, se usa el
  **plano** y **se declara** (el fichero plano existe mientras no rote otra vez).

### 6.4 Productos y presupuesto

| Producto | Ruta | Notas |
|---|---|---|
| Alertas por alerta (agente `001`) | `Dataset/Legitimo/legitimo_72h/alertas_detalle.csv` | solo si VÁLIDA (§6.5) |
| Catálogo por `rule.id` (+ por día) | `…/ruleids_legitimos.csv` (+ `_DD.csv`) | idem |
| Denominador `M` | `…/denominador_M.csv` | `endpoint` (001) + `total` |
| Acciones | `…/ghosts_acciones.csv` | total + por `handler` + por hora |
| Copia cruda del denominador + alertas | `D:\TFG-VMs\legitimo-2026-10-26\` (**fuera del repo**) | `MANIFEST.tsv` + `sha256` |
| Evidencia operativa | `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/evidencia/*.txt` | logs copiados como `.txt` (los `.log` están en `.gitignore`) |

- **Presupuesto medido en DT11:** **6,65 MB/h** de `archives.json` en régimen de fondo ⇒ **≈ 480 MB
  a 72 h** (con actividad, **500–700 MB**). **Muy por debajo** del disparador de fallback (**5 GB**).
  Se **mide** lo real y se **declara**; si superara 5 GB, se activa el fallback `FP/acción`+`FP/hora`
  (`L11`) y **la ventana sigue siendo válida** (es una decisión de métrica, no un fallo).
- **Disco del manager:** 21 GB libres al cierre de `legitimo-fix`; con alertas + `M` + copias se
  estima **< 2 GB**. P-3 exige ≥ 10 GB antes de armar.

### 6.5 Promoción a `Dataset/` (solo si la ventana es VÁLIDA)

1. **Archivar la ficha inválida**: `Dataset/Legitimo/legitimo_72h/ventana_meta.md` (estado
   «PREPARADA», ventana 19–22/10) se **mueve** a
   `Soporte/Laboratorio/legitimo_72h/fallo_2026-10-19/ventana_meta_INVALIDA_2026-10-19.md`
   (si el `sha256` coincide con la copia ya archivada, el movimiento es un no-op verificado; **no se
   borra nada sin huella**).
2. **Escribir** los CSV y la ficha nueva **en la misma carpeta** (`legitimo_72h/`), con cabecera
   `metrica_version=1`, `boveda_version=2`, `t0/t1` y `sha256` de las entradas.
3. **Si la ventana es INVÁLIDA:** **no** se escribe nada en `Dataset/` salvo el archivado de la
   ficha vieja; los productos van a `Soporte/.../ventana_*/` como **evidencia**, marcados
   `INVALIDA`, y **no** se sella B10 con ellos.

---

## 7. Validez: V1–V8 y qué invalida la ventana

### 7.1 Criterios (se cumplen **todos** para VÁLIDA)

| # | Criterio | Cómo se comprueba (objetivo) |
|---|---|---|
| **V1 — Cobertura de alertas** | Primera alerta del `001` ≤ **`t0+10 min`**; última ≥ **`t1−10 min`**; **ningún hueco > 30 min** entre alertas consecutivas del `001` | `alertas_detalle.csv` (columna `timestamp_utc`), diferencia entre consecutivas |
| **V2 — Actividad** | Cada día ≥ **90 %** de su receta (**≥100 / ≥105 / ≥95** sobre 111/117/105) y **0 acciones** fuera de **`[07:55, 17:10]Z`**, salvo las **explicadas** por una recuperación declarada | `ghosts_acciones.csv` por hora + `recovery.log` |
| **V3 — Manager y diarios** | Manager `active` en **todos** los chequeos; los **3 diarios** existen y **crecen**; los daemons presentes | `vigilancia_legitimo.log` + tamaños de los 3 ficheros |
| **V4 — 0 contaminación** | **0** filas con `srcip = 192.168.65.1` en `[t0,t1]` y **0** sesiones del operador en el `001` | `alertas_detalle.csv` (`srcip`, `srcuser`) + log host (sin fases en la ventana) |
| **V5 — Aislamiento** | NAT **off**; la víctima solo habló con la "internet local" | `ip route` cosechado a `t1+2` **sin** `default` + log de accesos web sin destinos externos |
| **V6 — `M` obtenido** | Copiado **antes** de `off`; `--estricto` sin solapes; `exit 0`; `MANIFEST` con `sha256` | `denominador_M.csv` + `MANIFEST.tsv` + salida literal |
| **V7 — Sin cambios a mitad** | `sha256sums.txt` 53/53 antes y después (salvo MC-1 declarado); `ossec.conf` `CONFIG_IDENTICA`; ruleset con la misma huella; `git status` solo rutas permitidas | recálculo + `diff` + `git status` |
| **V8 — Host sin reinicio/suspensión** | `LastBootUpTime` **< `t0`** y **0** eventos `Kernel-Power` 42/107 en `[t0,t1]` | `Get-CimInstance Win32_OperatingSystem` + `Get-WinEvent` (System) |
| **V2bis — Actividad del banco (declarada)** | Recuperaciones ≤ **2**, rotaciones ≤ **2** (día 1 se salta), arranques ≤ **3**, todas en `recovery.log` | `recovery.log` cosechado |

### 7.2 Válida **con incidencia** (no se repite, se declara)

- **1 o 2 recuperaciones** del cliente (sin huecos > 30 min sin explicar) ⇒ **VÁLIDA**; la incidencia
  se escribe en `ventana_meta.md` con hora, motivo y acciones duplicadas.
- **Una rotación fallida** (p. ej. `d2` no se pudo copiar) ⇒ **VÁLIDA** si el resto está bien: se
  repite el día con la receta que quedó y **se declara** (el día deja de ser «distinto»).
- **Duplicados de acciones** por recuperación dentro de bloque ⇒ **VÁLIDA**, contados y explicados
  (el exceso se documenta; no se «resta»).
- **Fallo de la herramienta** de extracción con el dato fuente íntegro ⇒ se **re-extrae**
  (idempotente) y sigue **VÁLIDA**.

### 7.3 Qué **invalida** la ventana (⇒ se repite **entera**)

1. **Acceso del operador a la víctima** dentro de `[t0,t1]` (la contaminación **no se resta**).
2. **Agente `001` caído o con un hueco > 60 min** dentro de `[t0,t1]` (o caído al cierre).
3. **Manager caído > 30 min**, o **falta un fichero diario** de alertas de los 3.
4. **`M` no recuperable**: no se copió a tiempo, o `--estricto` detecta solape **no** explicable por
   hardlink, o el fichero está truncado.
5. **Un bloque de trabajo entero sin acciones** (regla ya escrita en `legitimo-fix` §6.3.4).
6. **El PC se reinicia, se suspende o se cierra sesión** dentro de `[t0,t1]`.
7. **Cambio de configuración** a mitad (Wazuh, GHOSTS, internet local, host) que el bloque no pueda
   declarar como preexistente.
8. **Más de 2 recuperaciones** (el keepalive topa en 2 ⇒ algo externo actuó), o **una recuperación
   fallida que deje un bloque sin acciones**, o **cualquier** `ALARMA` de disco (`<2 GB`) o de agente
   que no se explique.

> **Regla:** una ventana **parcial o dudosa no vale**. Se repite **desde `v2`** (snapshot limpio +
   72 h nuevas). El **veredicto lo firma el humano** con la evidencia delante; el bloque **no** se
   autovalida.

---

## 8. Sellado de la bóveda B10 (versiones y huellas)

### 8.1 Qué se sella (valores **medidos**, no proyectados)

Se actualiza `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` a **v3** con:

| Elemento | Qué se añade respecto de v2 |
|---|---|
| **Ventana ejecutada** | `t0`/`t1` **firmados**, 72 h, 3 días, `t0`/`t1` a medianoche UTC |
| **Versiones** | GHOSTS **v8.3.1** commit `4d2e160…`; **`sha256` del binario del cliente** (⚠️ **hueco de v2**: no estaba sellado y `prep` lo **redespliega** en cada arranque); Wazuh **4.14.7-1**; PostgreSQL; .NET 8 |
| **Receta ejecutada** | `sha256` de `d1/d2/d3` + calendario + **mapeo real fecha→receta** |
| **"Internet local"** | `sha256` de `serve_site.py` + `site/**` (ya estaban) + **puertos** |
| **Instrumentación `M`** | `logall_json` ON solo `[t0,t1]`; rotación diaria a `ossec-archive-DD.json.gz`; `exportar_denominador.sh copiar-ventana` + `contar_denominador.py --estricto` |
| **Lo que actúa dentro** | **recuperaciones** (n), **rotaciones** (n), **arranques** (n) **reales** + eventos estimados |
| **Medida** | **`M` (endpoint/total)**, MB, eventos/h, **acciones/día** (reales), nº de alertas, nº de `rule.id` |
| **Volumen** | `M` < 5 GB ⇒ **sin fallback** (o declarado si se activó) |
| **Navegador** | `receptor_navegador=none` (decisión de `legitimo-fix`, DT-B0 FAIL) |
| **`metrica_version` / `boveda_version`** | **1 / 2** |

### 8.2 `boveda_version` → 2 (quién y cómo)

Decisión **ya aprobada** (`legitimo-fix`, gate Q8). Para que sea **coherente** hay que tocar **tres**
cosas a la vez (lo aplica el **humano/orquestador**, no el ejecutor de este bloque):

1. `Soporte/Metrica/boveda_congelacion.md` → **B10** con los valores de §8.1 y `version: 2`;
2. recalcular `Soporte/Metrica/boveda_congelacion.sha256`;
3. `_artefactos/scripts/metrica_hids.py` → `VERSION_BOVEDA = 2` + `pytest -q` (**189** en verde).

> **Coherencia de los CSV:** `contar_denominador.py` acepta `--boveda-version 2`; `exportar_acciones.sh`
> **no** (cabecera hardcodeada) ⇒ **MC-1** (§10). Sin eso, los productos saldrían con `boveda_version=1`
> y la cifra sería inconsistente con la bóveda.

### 8.3 Huellas

- `sha256sums.txt` (**laboratorio**): se **regeneran** todas las entradas y se **añaden** los
  artefactos nuevos del bloque (`ensayo_E0.md`, `b10_sellado.md` actualizado, `exportar_acciones.sh`
  tras MC-1).
- Los **productos de la medida** (`denominador_M.csv`, `alertas_detalle.csv`, `ruleids_legitimos.csv`,
  `ghosts_acciones.csv`, `ventana_meta.md`) llevan su `sha256` en el `MANIFEST.md` de la ventana y en
  la cabecera de la ficha (no se mezclan con las huellas del laboratorio).
- **Ningún fichero se borra**: lo que se sustituye queda archivado y con su `sha256` citado.

---

## 9. Riesgos y mitigaciones

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| **R1** | **La fecha es hoy a 4 h** y el gate se retrasa | Se pierde el arranque | **Corte a las 21:00Z** → fecha alternativa **27/10** (§2.2). *No se arranca sin E0* |
| **R2** | **Windows Update se auto-repara** (verificado hoy) y reinicia el host | Ventana perdida (V8) | Re-pausar en P-1 + política 1/1 + chequeo diario (§5.4) + `LastBootUpTime` |
| **R3** | **El agente `001` se cae** (el fallo de L1, por otra vía) | Sin denominador ni alertas | Tope de log 40 MB, disco del agente con valor **y tasa**, alarma `hb>10 min`, `ALARMA_DISCO` en el keepalive |
| **R4** | **Disco de la víctima** | Repite L1 | G-2 (≥4 GB), tope duro, señal 5 (3/2 GB y −1 GB/h) |
| **R5** | **`arm`/timer fallan** (nunca probados) | No hay ventana | **E0** obligatorio; aborta si falla |
| **R6** | **Una recuperación duplica acciones** del bloque | V2 con exceso | Se **cuenta y se declara**; V2 tolera con explicación; `recovery.log` |
| **R7** | **Rotación diaria falla** (día repetido) | Menos variedad | `rotacion.estado` + huella de comandos (DT5b); **se declara**, no invalida |
| **R8** | **Copia del denominador incompleta** (`.gz` de D+2 tarde) | `M` incompleto | 3 reintentos + plano + `--estricto` + manifiesto; P-3 (disco manager) |
| **R9** | **`logall_json off` antes de copiar** | **`M` perdido** (borra `archives.json`) | Orden §6.2 fijado y **verificado** (`archives.json` presente antes de `off`) |
| **R10** | **Doble conteo** por hardlink | `M` inflado | Dedupe `sha256` + `--estricto` + `MANIFEST` |
| **R11** | **El humano toca la víctima** | Contaminación (V4) | Regla dura + gate Q + V4 (0 filas con `srcip` del host) |
| **R12** | **Host se suspende / se cierra sesión** | Tareas no corren | P-4 + sesión `Interactive` + chequeo diario (uptime) |
| **R13** | **La BD de GHOSTS crece** (bug `Bash.cs`) | Disco | 333 acciones (no 5,9 k) ⇒ ~55 MB; señal 7 + `D:` 183 GB |
| **R14** | **Los servicios de "internet local" mueren** | Acciones web con error (pero **se ejecutan**) | El `execve` cuenta igual (V2 no cambia); se declara incidencia; **no** invalida salvo que afecte a todo un bloque |
| **R15** | **`~/.cache/tfg-web` o `~/Documentos` no existen** | Comandos fallan (redirect) | `prep` los crea (`deploy_client.ps1:70`); si faltan, se ve en `client.out` y se declara |
| **R16** | **Estado del `watch` obsoleto** | Falsa alarma en el 1er chequeo | P-6 (borrar `%TEMP%\opencode\tfg_watch_estado.json`) |
| **R17** | **Ventana inválida** | 3 días perdidos | Criterios **escritos antes** (§7) + aborto temprano si es evidente (§5.5) |
| **R18** | **`M` baja y el FPR no es comparable** | Interpretación | Se **declara** y se informa **siempre** de `M` y `acciones/h` junto al FPR (efecto directo del realismo) |

---

## 10. Criterios de aceptación (verificables)

| # | Criterio | Verificación |
|---|---|---|
| **CA-01** | **Ventana ejecutada**: `prep`/`arm`/`stop` corrieron en sus horas (±5 min) y la duración fue **72 h ± 1 min** | `legitimo_host_control.log` + `NextRun` + `keepalive.log` |
| **CA-02** | **E0 PASS** antes de armar (arm + timer + keepalive + tareas) | `ensayo_E0.md` |
| **CA-03** | **Cero acceso a la víctima** en `[t0,t1]`: en el log no hay fases `prep/arm/stop` ni SSH al invitado dentro del intervalo; **0** filas `srcip=192.168.65.1` | log + `alertas_detalle.csv` |
| **CA-04** | **144 chequeos** de vigilancia (±2), sin `ALARMA` no explicada | `vigilancia_legitimo.log` |
| **CA-05** | **3 diarios** de alertas presentes y crecientes; V1 (cobertura y huecos ≤ 30 min) | ficheros + CSV |
| **CA-06** | **Acciones**: 111/117/105 **medidas**, ≥90 % y **0** fuera de `[07:55,17:10]Z` sin explicar | `ghosts_acciones.csv` + `recovery.log` |
| **CA-07** | **`M` contado** con `.gz`+vivo, dedupe y `--estricto` (exit 0), **antes** de `off` | `denominador_M.csv` + `MANIFEST` + log |
| **CA-08** | **`logall_json=no`** y `ossec.conf` `CONFIG_IDENTICA` tras el cierre; ruleset con la misma huella | `diff` + huella |
| **CA-09** | **Copia cruda fuera del repo** con `sha256` de cada fichero y totales que **cuadran** con `M` | `MANIFEST.tsv` |
| **CA-10** | **Fallback**: no se activa (`M` < 5 GB) o, si se activa, está declarado con la decisión | `denominador_M.csv` (tamaño) |
| **CA-11** | **Evidencia del invitado** cosechada y versionada como `.txt` con `sha256` | `evidencia/` + `MANIFEST.md` |
| **CA-12** | **V1–V8 escritos** con la evidencia y **firmados** por el humano | `ventana_meta.md` + `veredicto_validez.md` |
| **CA-13** | **B10 v3** con `M`, acciones, recuperaciones/rotaciones reales, **`sha256` del binario del cliente** y `boveda_version=2` | `b10_sellado.md` |
| **CA-14** | **Cero daño colateral**: `git status` solo rutas permitidas; `git diff --stat` **vacío** en `Soporte/Metrica/`, `Hojas/`, `_recursos/`, corpus y `Dataset/` (salvo §6.5) | `git status`/`git diff` |
| **CA-15** | **Sin secretos**: 0 coincidencias de la contraseña en ficheros nuevos | `git grep`/`Select-String` |
| **CA-16** | **Laboratorio cerrado**: 0 VMs, 0 tareas `TFG-Legit-*`, 0 reglas `TFG-*`, GHOSTS/internet local parados, `logall_json=no`, **Windows Update restaurado** | `vmrun list`, `Get-ScheduledTask`, `Get-NetFirewallRule`, `wuauserv` |
| **CA-17** | **Huellas**: `sha256sums.txt` recalculado y coherente (53 + nuevos, MC-1 incluido) | `sha256sum -c` |
| **CA-18** | **`pytest -q` verde** (189 + los que toque MC-1) | salida literal |
| **CA-19** | **MC-1 declarado**: diff de **1 línea** en `exportar_acciones.sh` (versión de bóveda por parámetro), sin cambio de semántica | `git diff` |
| **CA-20** | **El plan está en git** desde la aprobación | `git log -- plan.md` |

### MC-1 (micro-cambio declarado, el único del bloque)

`exportar_acciones.sh:28` escribe `boveda_version=1` **hardcodeado** en la cabecera. Con la bóveda
en **2**, la cabecera mentiría. Cambio mínimo: aceptar un **4º argumento opcional** (o
`TFG_BOVEDA_VERSION`) con defecto **1** y usarlo en la cabecera; **no** cambia consultas ni formato.
Se actualiza `sha256sums.txt` y se re-ejecuta `pytest -q`. *Alternativa si el humano prefiere
«cero cambios»: **no** bumpear la bóveda (queda `1` + B10 sellado) y se declara.*

---

## 11. Gate humano (lenguaje sencillo)

> **Qué te pido.** Que dejemos el ordenador encendido **tres días** sin tocar la máquina que vigila
> Wazuh, mientras un programa hace **actividad de oficina** (correo, documentos, copias, web local)
> y Wazuh graba **todo** lo que pasa. Después contamos: **cuántas alertas** saltaron sin que hubiera
> ataque (falsos positivos) y **cuántos eventos** hubo (el denominador). Con eso el TFG puede decir
> «este HIDS, en una jornada normal, se equivoca X veces de cada Y».

1. **Qué se va a hacer.** Arrancar el laboratorio desde el snapshot bueno (`lab-listo-legit-v2`),
   dejarlo correr 72 h con arranque y parada automáticos, vigilarlo cada media hora **sin entrar en
   la víctima**, y al final copiar los datos **antes** de apagar la instrumentación.
2. **Qué necesito de ti.**
   - **Q1. ¿Firmas la fecha `lunes 26/10 00:00Z → jueves 29/10 00:00Z`?** Son las **01:00 local**.
     **Ojo:** hoy es 25/10 y quedan ~4 h. Si el gate no está cerrado a las **21:00Z**, propongo
     **`27/10 → 30/10`** (mismas condiciones, un día más de margen). Cambiar la fecha son ~20 min
     (una línea del generador + regenerar + huellas).
   - **Q2. ¿Te comprometes a los 3 días** con el PC **encendido, enchufado, sin suspensión**, sesión
     iniciada (puedes bloquear la pantalla) y **sin tocar `victima-linux`**? Un solo acceso
     **invalida** la ventana y hay que repetirla entera.
   - **Q3. ¿Apruebas que, antes de arrancar, hagamos un ensayo de ~45 min (E0)** que prueba lo único
     que nunca se ha probado de punta a punta (el "armado" automático)? Sin E0, no arranco.
   - **Q4. ¿Apruebas el orden de cierre?** A las 72 h **primero** copio los registros de dentro de la
     víctima (2 minutos después del final, ya fuera de la ventana), **luego** la apago, **después**
     copio el denominador y **solo al final** apago la instrumentación (apagarla **borra** el
     fichero del denominador: es la trampa que ya nos costó una ventana).
   - **Q5. ¿Apruebas `boveda_version` → 2** y que lo aplique el humano/orquestador en los **tres**
     sitios (bóveda + su huella + constante del módulo de métrica)? Si prefieres no tocar el módulo,
     dímelo y **no** se bumpea.
   - **Q6. ¿Apruebas un micro-cambio de 1 línea** (`exportar_acciones.sh`) para que la cabecera del
     CSV diga la versión de bóveda correcta, con `pytest`?
   - **Q7. ¿Apruebas que los datos se publiquen en `Dataset/` solo si la ventana es VÁLIDA**, y que
     si es inválida queden como evidencia marcada `INVALIDA` sin sellar B10?
   - **Q8. ¿Apruebas que el plan se guarde en git al aprobarse** (para no repetir la pérdida del plan
     de L1)?
3. **Qué NO vas a ver.** No habrá análisis ni FPR todavía (eso es el bloque siguiente). No habrá dos
   configuraciones: **una** ventana, **una** actividad, **un** HIDS. Si sale mal, **se repite
   entera** — no se "arregla" a posteriori.
4. **Qué puede salir mal (y qué haremos).** (a) Windows Update se reactive y reinicie el PC: se
   re-pausa antes de arrancar, la política está puesta y lo comprobamos a diario; (b) el agente se
   caiga: la vigilancia avisa a los 10 minutos (y a los 30 por actividad), y si el hueco pasa de
   60 min la ventana **no vale**; (c) el disco se llene: el log tiene tope duro de 40 MB y el disco
   del agente se lee **cada 6 min** con valor y tasa; (d) el "armado" falle: por eso E0.

---

## 12. Ficheros que se tocarán

### 12.1 Nuevos

| Ruta | Qué |
|---|---|
| `_fases/legitimo-72h-v2/plan.md` | Este plan (archivado al cerrar; en la **raíz** mientras el bloque corre) |
| `_fases/legitimo-72h-v2/{reviews.md,change-doc.md}` | Verificación y cierre |
| `Soporte/Laboratorio/legitimo_72h/ensayo_E0.md` | Salida literal del ensayo de armado + veredicto |
| `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/ventana_meta.md` | Ficha de la ventana (t0/t1, config, incidencias, V1–V8, veredicto) |
| `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/veredicto_validez.md` | Cálculo literal de V1–V8 (comandos y salidas) |
| `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/MANIFEST.md` | Tamaño/`sha256` de cada producto y de la copia cruda |
| `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/{denominador_M.csv,ghosts_acciones.csv}` | Copia de trabajo (la canónica irá a `Dataset/` si VÁLIDA) |
| `Soporte/Laboratorio/legitimo_72h/ventana_2026-10-26/evidencia/*.txt` | `recovery`, `keepalive`, `client.out` (extracto), `id.json`, `rotacion.estado`, `ip route`, `df`, extracto de `web_access.log`, `vigilancia` y `host_control` |
| `Dataset/Legitimo/legitimo_72h/{alertas_detalle.csv,ruleids_legitimos.csv,denominador_M.csv,ghosts_acciones.csv,ventana_meta.md}` | **Solo si VÁLIDA** (§6.5): la ficha de `Soporte/…/ventana_*/` es el **borrador/evidencia**; esta es la **canónica** |

### 12.2 Modificados

| Ruta | Cambio | Motivo |
|---|---|---|
| `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` | → **v3** con valores medidos + `sha256` del binario del cliente + `boveda_version=2` | §8 |
| `Soporte/Laboratorio/legitimo_72h/sha256sums.txt` | Regenerado | §8.3 |
| `Soporte/Laboratorio/legitimo_72h/exportar_acciones.sh` | **MC-1**: versión de bóveda por parámetro (defecto 1) | §10 |
| `Soporte/Laboratorio/legitimo_72h/resultado.md` | Sección «ventana ejecutada» (72 h reales) | evidencia |
| `Soporte/Laboratorio/legitimo_72h/README.md` | Orden de cierre nuevo (§6.1) + E0 | docs |
| `Soporte/Laboratorio/legitimo_72h/legitimo_host_control.log` · `vigilancia_legitimo.log` | Crecen (no se versionan: `*.log`) | ejecución |
| `Soporte/Metrica/boveda_congelacion.md` + `.sha256` + `_artefactos/scripts/metrica_hids.py` | `boveda_version=2` | **humano/orquestador**, no el ejecutor |
| `state.md`, `roadmap.md` | Estado del bloque | **orquestador** |

### 12.3 Prohibido tocar

`_recursos/**` · corpus (`Soporte/Ataques/**`, `Dataset/Ataques/**`, `Bitacora/**`) · `Hojas/**` ·
`Soporte/Metrica/**` (ejecutor) · `Dataset/**` (salvo §6.5) · `_artefactos/scripts/extraer_alertas.py`
· `_artefactos/scripts/filtrar_ruido.py` · la receta (`recetas/**`) · `Soporte/Wazuh/**` (ruleset y
`ossec.conf` salvo `logall_json`) · los snapshots `base-limpia`, `lab-listo`, `lab-listo-legit`,
`fallo-2026-10-19-disco-lleno-NO-USAR` y **`lab-listo-legit-v2`** (que es el que se usa).

### 12.4 Tandas (orden de ejecución)

| Tanda | Contenido | Estimación |
|---|---|---|
| **T0** | Gate + **commit del plan** + P-1 (pausar WU) | 30 min |
| **T1** | **E0** (prep + arm + timer + stop + cleanup) + revert a `v2` | 45 min |
| **T2** | `registrar_tareas -T0 real` + verificación `NextRun` UTC + P-3/P-6 | 20 min |
| **T3** | **Ventana** `[t0,t1]` (automática) + chequeo diario | **72 h** (humano) |
| **T4** | Cosecha + stop + copia + `M` + `off` + alertas + acciones | 90 min |
| **T5** | V1–V8 + ficha + B10 v3 + `sha256sums` + promoción (si VÁLIDA) | 3 h |
| **T6** | `cleanup` + restauración WU + `-ClearSecret` + cierre limpio | 45 min |

---

## 13. Trazabilidad

| Afirmación | Fuente verificable |
|---|---|
| La causa del fallo de L1 y su cronología | `Soporte/Laboratorio/legitimo_72h/diagnostico_fallo.md` §1–§2 |
| El log sin tope y su arreglo (40 MB) | `Soporte/Laboratorio/ghosts/client_ctl.sh` (`rotar`, `MAX_MB`) · `client_config/nlog.config` (`Warn`, `maxArchiveFiles="20"`) |
| La receta (111/117/105, jornada 08–17Z, café/comida) | `recetas/{d1,d2,d3}.json`, `recetas/{calendario.json,bloques.env}` · `prueba_en_seco.md` DT9/DT10/DT11 |
| `MAPA_DIAS` hardcodeado (y su duplicado) | `_artefactos/scripts/construir_receta_legitima.py:86`, `:550` · `recetas/bloques.env:13` |
| `prep` completo y con EXIT=0 (3 veces) | `legitimo_host_control.log:1877-2530` · `%TEMP%\opencode\prep{5,6}.out` (`EXIT=0`) |
| **`arm` nunca ejecutado** | `legitimo_host_control.log` sin ninguna línea `[arm]` |
| Guardarraíles G-1…G-12 y sus códigos | `legitimo_host_control.ps1:249-400` |
| `arm`: timer a `t0−5`, cliente y checklist | `legitimo_host_control.ps1:403-432` · `guest/instalar_tarea_invitado.sh:30-32,35` |
| Keepalive v3 (heartbeat por `lastReportedUtc`, 2 recup., rotación) | `guest/tfg_keepalive.sh:33-48,97-130,153-193,226-260` · `b10_sellado.md` |
| Vigilancia de 9 señales y umbrales | `legitimo_host_control.ps1:435-552` · `watch_manager.py:81-126,186-202` |
| Disco de la víctima **desde el agente** (`df -P` cada 360 s) | `watch_manager.py:81-126` · `fallo_2026-10-19/evidencia/df_series_agente_001.tsv` (220 muestras, 100 % a las 14:03:39Z) |
| `logall_json off` **borra** `archives.json` | `Soporte/Laboratorio/ghosts/logall_json_ctl.sh:53` |
| Extracción con `.gz` por día + dedupe + `--estricto` | `exportar_denominador.sh:50-105` · `_artefactos/scripts/contar_denominador.py:283-329` |
| Presupuesto real de `archives.json` (6,65 MB/h de fondo) | `prueba_en_seco.md` §DT11 |
| Alertas del **fichero diario** (no `alerts.json`) | `state.md` (regla operativa de Fase 3) · `_artefactos/scripts/extraer_alertas.py:59-61,441-473` |
| V1–V8 originales de L1 | `_fases/legitimo-72h/plan.md` §8 |
| B10 y `boveda_version` | `Soporte/Metrica/boveda_congelacion.md` (B10 «pendiente») · `Soporte/Laboratorio/legitimo_72h/b10_sellado.md` (v2) · gate Q8 de `legitimo-fix` |
| Estado del host hoy (WU `Manual`, 0 VMs, 5 snapshots, 53/53 huellas, 183 GB) | medición de este plan (§3) |

---

## 14. Lecciones del fallo de L1, aplicadas una por una

| Lección | Cómo se aplica aquí |
|---|---|
| **Nada de logs sin tope** | `client.out` con tope **duro 20 MB × 2** y `app.log` 1 MB × 20 (medido en DT2/DT3: **~0,001 MB/30 min**) |
| **La vigilancia debe medir «hacer», no «estar»** | Señal 1 = `max(createdutc)` de `history_timeline`; el heartbeat del keepalive es `lastReportedUtc` (se descubrió que `app.log` engañaba) |
| **La señal del disco ya existía: faltaba leerla** | Señal 5 lee el `df -P` **del agente** (valor **y** tasa), sin tocar la timeline ni Wazuh |
| **`systemctl is-active` miente** | Señal 2 usa `Last keep alive` de `agent_control`; DT6 reproduce el engaño |
| **Copiar el denominador antes de apagarlo** | Orden §6.2 cerrado y comprobado (`archives.json` presente antes del `off`) |
| **Una ventana parcial no vale** | §7.3 y «se repite entera»; criterios escritos **antes** |
| **El plan se perdió una vez** | Se guarda **en git** al aprobarse (Q8, CA-20) |
| **Un paso no probado revienta de noche** | **E0** obligatorio (el `arm` nunca se había ejecutado) |
| **No se parchea a mitad** | `watch` solo avisa; ninguna acción sobre el invitado dentro de la ventana |
| **Los datos se declaran, no se maquillan** | Recuperaciones, rotaciones, duplicados, `M` bajo... todo con su línea en la ficha y en B10 |

---

## 15. Lo que no cuadra y decisiones abiertas

1. **La fecha propuesta deja ~4 h de margen.** No es un problema de diseño sino de reloj: si el gate
   se cierra a las 21:00Z, cabe (E0 45 min + prep 45 min antes de `t0`). Si no, **27/10**. **La
   decisión es del humano** (Q1); el plan **no** la cambia por su cuenta.
2. **`arm` es el único eslabón sin probar de punta a punta.** Se cubre con **E0**; aun así es el
   punto con más probabilidad de fallo la primera vez. Se declara.
3. **Windows Update se ha auto-reparado** (`wuauserv` `Running`/`Manual` hoy, pese al cierre de
   `legitimo-fix` que lo daba por pausado). La política `NoAutoUpdate=1` **sí** persiste. Se re-pausa
   antes de `t0` y se comprueba a diario; **no** se toca dentro de la ventana.
4. **La cosecha de logs del invitado se hace a `t1+2`**, es decir, **fuera** de `[t0,t1]` pero
   **antes** de la parada. Es un cambio de orden respecto de L1, **declarado**; sin él, V2 y §7.2 no
   se pueden juzgar (los logs se quedan dentro de una VM apagada).
5. **`boveda_version=2` exige tres cambios coherentes** (bóveda, su `.sha256` y `metrica_hids.py`).
   Si el humano no quiere tocar el módulo congelado, la alternativa honesta es **no** bumpear y
   sellar B10 dentro de `v1`; **el bloque no decide**.
6. **`exportar_acciones.sh` escribe `boveda_version=1` a mano** ⇒ **MC-1** (1 línea) o cabecera
   incoherente. Declarado y con `pytest`.
7. **El binario del cliente no estaba sellado en B10 v2** y `prep` lo **redespliega** desde
   `D:\TFG-VMs\material-ghosts\client-linux` en cada arranque. Se añade su `sha256` a B10 v3; si el
   binario hubiera cambiado desde `v2`, **la medida sería de otro banco** ⇒ se compara antes de `t0`.
8. **El `M` va a ser bajo** (333 acciones/ventana). El FPR resultante **no es comparable** con nada
   anterior; se informará siempre con `M` y `acciones/h` al lado. Es consecuencia directa del
   realismo decidido, no un defecto oculto.
9. **Una recuperación puede duplicar acciones** del bloque (el cliente reinicia la timeline desde el
   principio de la ventana). V2 lo tolera **con declaración**; no se «resta».
10. **La RAM no se vigila en vivo** (no hay señal pasiva sin tocar la víctima): G-12 antes y
    `ram_free_mb` post-hoc. Si hubiera OOM, se vería al cerrar. **No se finge** una vigilancia que no
    existe.
11. **El `watch` no arregla nada**: si el agente muere a las 03:00, la alarma se lee por la mañana.
    Es una decisión de diseño (no tocar la víctima), no un olvido.
12. **`Dataset/Legitimo/legitimo_72h/` conserva hoy la ficha de la ventana inválida** de L1
    («PREPARADA», 19–22/10). Este bloque la **archiva** antes de escribir la nueva (§6.5) y **no**
    borra nada sin huella.
