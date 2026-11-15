---
bloque: windows-legit
nombre: Ventana legítima Windows de 72 h — captura, cierre, análisis y M1b-W
version: 2
status: pending_human
fecha: 2026-11-13
autor: claude (auditoría a fondo sobre el plan v1 de tfg-planner)
t0: 2026-11-23T00:00:00Z
t1: 2026-11-26T00:00:00Z
depende_de: >-
  `windows-legit-prep` **W3-bis CERRADO** (commit `474e18e`) · snapshot
  `lab-listo-windows-legit-v2` (294 ficheros, `MANIFEST_SHA256=4621046f…`) · cliente GHOSTS
  **8.3.1** · sello `sha256sums.txt` **200** entradas (`sha256sum -c` **0 fallos**, 13-nov) ·
  **527 tests** en verde (487 + 40 nuevos de esta auditoría) · Linux `legitimo-v3` cerrada
  (`M`=342.966, FPR=0,857963) · B1/B2 Windows (54 casos) · `Soporte/Metrica/metrica_hids.md` v1
no_toca: >-
  `_recursos/` · `Hojas/` · `Dataset/` · `Soporte/Metrica/` · corpus · ruleset · config de Sysmon
  · config del agente `002` · recetas `w1/w2/w3` · `campana_windows.csv` · `casos_windows.md` ·
  snapshot v2 y los 7 previos · ficheros del invitado sellados en `manifiesto_esperado.json`
  (`tfg_keepalive_windows.ps1`, `verificar_windows.ps1`, `instalar_tareas_windows.ps1`…)
ejecuta_ahora: >-
  NADA de la ventana. Este documento es diseño. Los cambios de código de la §0.2 YA están hechos
  en el árbol de trabajo (sin commit) y probados; la ventana no se lanza hasta que el ensayo
  WE0 (§3.2) pase y el humano firme.
---

# plan.md — bloque `windows-legit` (ventana de 72 h) · v2

> **Convención:** **[H]** hecho comprobado (con fuente) · **[D]** decisión de este plan ·
> **[S]** suposición que hay que medir. **La contraseña de las VMs nunca se escribe en ningún
> fichero, log ni commit**: vive solo en la sesión (`$env:TFG_MANAGER_PW`).

---

## 0. Resumen y auditoría del 13-nov

### 0.1 La ventana en diez líneas

1. **`t0` = lunes 2026-11-23T00:00Z**, **`t1` = jueves 2026-11-26T00:00Z** (movida una semana
   por la auditoría: las piezas nuevas necesitan ensayo real). Mapa de días: 23→`d1`, 24→`d2`,
   25→`d3`. (`t0` = 01:00 hora local; la receta corre 08:00–17:00Z y la campaña 17:05–17:50Z).
2. **Base:** `lab-listo-windows-legit-v2` (cliente 8.3.1, Defender OFF, sesión `angel` por
   autologon). **`prep` ahora revierte de verdad al v2** (antes iba al v1, §0.2-H1).
3. **Durante:** GHOSTS **504** acciones, `logall_json=yes`, chivato `:9095`, keepalive de 1
   proceso, **`watch_loop.ps1`** cada 30 min (144 chequeos, **10 guardarraíles**: añade G-W15,
   la pila del host) y **pila del host viva** (GHOSTS API, PostgreSQL, "internet local").
4. **Cierre (orden duro):** `cosecha` del invitado → `crudo` del manager → análisis →
   `cleanup` (VM encendida) → snapshot final. `stop`/`cleanup` quedan **bloqueados** sin las dos
   puertas (`exit 70/84/87`).
5. **Lo que se guarda (prioridad del humano: todos los eventos):** `archives` + `alerts` del
   manager **+ `ossec.log`/contadores de descartes del manager** + del invitado los **`.evtx`
   completos** (Security, Sysmon, PowerShell, System, Application), su **conteo por EventID**,
   `ossec.log` del agente, estado del operador y las 22 marcas de la campaña.
6. **Nuevo: ensayo WE0 extendido** (viernes 20 noche → sábado 21 mañana, ~9 h): mide la **noche**
   (criterio V1), la **huella real del operador** sin tocar nada, la **completitud**
   `.evtx` ↔ `archives` y prueba **todo el código nuevo** en real.
7. **V1 NO se rebaja a ciegas:** se mide primero (§5). En Linux V1 pasó porque auditd genera
   alertas toda la noche (hueco máx. 62 s); un Windows en reposo tuvo **36 min** sin alertas.
8. **Coste:** ~1 día de ensayo + 72 h + 5–7 días de análisis. **Plazo del TFG: enero** ⇒ hay
   margen de sobra; **no se lanza nada con incertidumbre**.
9. Windows se estudia **por defecto (virgen)**; lo que ahora se guarda (todos los eventos)
   permite evaluar más escenarios después (`+propias`, `+externas`).
10. **Fichero de salida:** este `plan.md` (raíz).

### 0.2 Hallazgos de la auditoría (todo comprobado en disco, en las VMs o con los datos)

| # | Hallazgo | Evidencia | Estado |
|---|---|---|---|
| **H1** | **`prep` revertía al snapshot v1**, no al v2: habría fallado con *«manifiesto DIFIERE»* (`exit 46`) en pleno domingo. El último `prep` real (12-nov 09:34) ya falló así; el v2 se creó a mano después y **nunca se probó `prep` contra él** | `windows_legit_host_control.ps1` `$Snap` (antes l.159); `windows_legit_host_control.log` 12-nov 09:38 | **CORREGIDO** (`$Snap='…-v2'`, v1 sigue exigido en G-W2) + test |
| **H2** | **La pausa de Windows Update del PC no está aplicada** (se restauró tras la ventana de Linux). Hoy: sin política `NoAutoUpdate`, `wuauserv` Manual, `UsoSvc` en marcha. El controlador solo miraba que `wuauserv` no estuviera *Running* | `Get-ItemProperty …\WindowsUpdate\AU` vacío (13-nov) | **G-W12 ahora EXIGE la política** (`prep` aborta sin ella). **El humano debe ejecutar la pausa** (§3.1): no puedo tocar la config del sistema del PC |
| **H3** | **Logs de eventos del invitado pequeños y circulares**: Security 20 MB (ya al 17 MB, 21.888 reg.), PowerShell 15 MB (lleno). En 72 h se sobrescribirían; el `.evtx` copiado quedaría truncado | `wevtutil gl` en la VM (13-nov) | **CORREGIDO**: `prep` fija Security 512 MB / Sysmon 256 MB / PowerShell 128 MB y lo verifica (`exit 49`). Probado por SSH (la sesión es *High*). Solo capacidad, no cambia qué se registra |
| **H4** | **El etiquetador de operador dejaba escapar ~39 de 352 alertas (11 %)** del crudo de 2 h: `sshd.exe`, hijos de `sshd`, `schtasks … TFG-WinLegit-*`, `type …keepalive.log` | análisis del crudo `legitimo-windows-2026-11-12` | **CORREGIDO**: 3 reglas nuevas; sobre el mismo crudo escapan **0**; ninguna acción de `w1/w2/w3` las dispara (test) |
| **H5** | **`prep` NO arrancaba la pila del host** (GHOSTS API, PostgreSQL, "internet local" 8080/9090/9092) y nada comprobaba que siguiera viva. **La receta y la campaña tienen ~50 `curl` a `intranet.local:8080`: en la prueba de 2 h hubo 32 `curl` y 0 conexiones al 8080** ⇒ esas descargas **fallaron**, distinto de Linux | 17+15+18 menciones en `w1/w2/w3`; `archives` 2 h: Sysmon 3 solo al 9095 (25) | **CORREGIDO**: `prep` arranca la pila (idempotente) y prueba `curl` HTTP 200 **desde el invitado** (`exit 40`); **G-W15** la vigila en `arm`/`watch`/`status`; `cleanup` la para. Verificado: con la pila arriba el invitado descarga el PDF (HTTP 200, 633 B) |
| **H6** | **R-01/R-02 del plan v1 eran reales**: no existía `watch_loop` ni fase `cosecha` | `ValidateSet` del controlador | **CORREGIDOS**: `watch_loop.ps1` (probado con controlador falso: ticks, alarma, saltados, mutex) y fase `cosecha` + `cosecha_invitado.ps1` (**probada contra la VM real**: 28/28 ficheros verificados por hash, 5 `.evtx`, reloj 0,34 s) |
| **H7** | **Faltaba la evidencia de pérdidas**: sin `ossec.log` no se puede probar que `archives` esté completo. El manager registró **1 «Package dropped»** el 08-nov (día de ataques B1) | `/var/ossec/logs/ossec.log` del manager | **CORREGIDO**: `crudo` copia `ossec.log` + `wazuh-analysisd/remoted.state` del manager; `cosecha` el `ossec.log` del agente y el **conteo de eventos por (log, EventID)** del invitado |
| **H8** | **El criterio V1 del plan v1 se rebajaba sin medir** («incompatible con t0=00:00»). Linux tenía el mismo horario y pasó V1 | `ventana_meta.md` Linux (hueco 62 s); baseline Windows 8-oct (hueco **36 min**) | **PENDIENTE DE MEDIR en WE0** (§5, V1) |
| **H9** | **El agente excluye por defecto 13 EventID de Security** (5145, 5156, 5447, 4656, 4658, 4663, 4660, 4670, 4690, 4703, 4907, 5152, 5157) y tiene un buffer de **5.000 eventos / 500 por s** | `ossec.conf` del agente 002 | **DECLARAR** en la memoria (es la config virgen). El buffer sobra para la ventana legítima; **vigilar en los ataques masivos** (ransomware) con `ossec.log` |
| **H10** | **Los «3 tests que fallan» eran el PATH de Git Bash** (`tar` de Git en vez del de Windows), no un fallo | `test_ejecucion_windows.py` en bash vs PowerShell | **No es bug.** Con `System32` primero: **527 pasan** |
| **H11** | Manager sano: **18 GB** libres, reloj sincronizado (NTP), `events_dropped=0`; ficheros diarios por día **UTC** (comprobado en los de Linux) ⇒ el `crudo` por día UTC es correcto | `date`, `df`, `wazuh-analysisd.state`, timestamps de `ossec-archive-03.json.gz` | OK |
| **H13** | **El primer `prep` real del 15-nov falló en el `deploy`**: el paquete salió con `payload\campana` como un **fichero** (el CSV) en vez de una carpeta, y `robocopy campana` falló en el invitado (rc=16). En aislado el mismo código funciona (probable: el borrado del stage viejo de 15 MB aún en curso con el antivirus del host escaneando) | log `prep` 10:05Z; `payload\campana` = 19.291 B (el CSV) | **CORREGIDO**: espera a que el stage desaparezca, crea carpetas con .NET, copia a rutas de fichero explícitas y **verifica la estructura antes de comprimir** (falla pronto y claro). Resellado (200 entradas) |
| **H14** | **G-W12 (RAM) paró el `prep`**: con 2 VMs (8,3 GB) + pila + Notion/WARP/Defender solo quedaban **1,2 GB** disponibles (mínimo 1,5 GB). El guardarraíl funcionó | `AvailableMBytes`=1163 | **P4 es obligatorio**: cerrar Notion, WARP, navegadores… antes del `prep`. En el ensayo se usó `-RamMinMb 1000` solo para completar la prueba |
| **H15** | **`prep` completo PASA contra el v2** (15-nov 10:12Z): pila viva en 73 s, revert, logs 512/256/128 MB verificados, deploy, `DEFENDER_OFF=1`, `SESION_ANGEL=1`, lista negra 0 residuos, **curl HTTP 200 desde el invitado**, **manifiesto `4621046f` OK** | `prep_trial3_20261115.txt` | OK (deshecho después; evidencia restaurada) |
| **H12** | **Reloj del invitado**: ~0,3–0,5 s respecto al host (criterio ≤2 s) | `cosecha` real (`delta_reloj_s=0.34`) | OK |

> **Lo que sigue bien (comprobado):** sello 200 entradas y `sha256sum -c` 0 fallos; 8 snapshots
> de Windows (v2 incluido) y 2 del manager; el host nunca se suspende (todos los tiempos de
> energía a 0), arrancado desde el 5-nov, sin reinicio pendiente; 9,8 GB de RAM libres (5 GB con
> la pila); Sysmon 15.22 + agente 4.14.7 + Defender parado en la VM; `cleanup` sin `crudo.done`
> ⇒ `exit 84`, sin `cosecha.done` ⇒ `exit 87`, `stop` sin ellas ⇒ `exit 70` (probados).

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

**Medir el FPR de Windows** en una ventana legítima de 72 h con la **misma unidad** que Linux
(`FP/acción`, `FP/hora`, `FP_uni/M`), publicar el **FPR canónico y `sin_operador`**, **guardar
todos los eventos** y **re-cortar los 54 ataques Windows** con el catálogo de ruido de la
ventana (**M1b-W**).

### 1.2 Entra

- **Ensayo WE0 extendido** (§3.2) y **preparación** (`prep`, `arm`).
- **Ventana de 72 h**: GHOSTS 504 acciones, vigilancia, pila del host.
- **Cierre**: `cosecha`, `crudo`, análisis mecánico, `cleanup`, snapshot final.
- **Análisis**: T3-W, T4-W, T5-W, M1b-W (54 casos), comparación con Linux.

### 1.3 NO entra

- **Velociraptor**, **memoria**, nuevos ataques B1/B2.
- **Repetir los ataques con `logall_json=yes`** (decidido: «más adelante»). Hoy los 54 ataques
  Windows tienen `alerts` pero **no `archives`**; el re-corte M1b-W es *alerts-only* y se declara.
- Cambiar la **métrica**, el ruleset, Sysmon, la config del agente, las recetas o la campaña.
- **Commits** (los hace el orquestador). **Sin secretos** en ficheros ni logs.

---

## 2. Calendario (UTC)

| Momento | Qué | Quién | Evidencia |
|---|---|---|---|
| **Vie 13 → Jue 19** | Revisión de este plan; **pausa de Windows Update del PC** (§3.1); firmar `comparabilidad_windows.md` (CA-W3b-19) | humano | ficha firmada, `G-W12` OK |
| **Vie 20 23:00** | **`prep` del WE0** (revert v2, pila, logs ampliados, gates) | ejecutor | `windows_legit_host_control.log` |
| **Vie 20 23:40** | **`arm` del WE0**: `-T0 2026-11-21T00:00:00Z -T1 2026-11-21T09:00:00Z`; lanzar `watch_loop.ps1` | ejecutor | `ventana_actual.json` |
| **Vie 20 23:40 → Sáb 21 09:00** | **El ensayo corre SIN tocar nada** (noche + B1 de `d1`) | automático | latido, `watch_loop.log` |
| **Sáb 21 09:05** | `cosecha` → `crudo` → **`analizar_ensayo_windows.py`** → `cleanup` → revert | ejecutor | informe A1–A11 |
| **Sáb 21 – Dom 22** | Decidir **V1** y umbrales con los datos del WE0; ajustar y **resellar** si hace falta; firma | humano + ejecutor | `ensayo_WE0.md` |
| **Dom 22 23:00** | **`prep` real** | ejecutor | log |
| **Dom 22 23:40** | **`arm` real** `-T0 2026-11-23T00:00:00Z -T1 2026-11-26T00:00:00Z` | ejecutor | `ventana_actual.json` |
| **Dom 22 23:50** | lanzar **`watch_loop.ps1`** (espera hasta `t0`) | ejecutor | `watch_loop.log` |
| **Lun 23 00:00** | **`t0`** | — | — |
| **Lun 23 – Mié 25** | Receta 08:00–17:00; campaña 17:05–17:50; vigilancia 30 min; latido 5 min | automático | `heartbeat.jsonl` |
| **Jue 26 00:00** | **`t1`** | — | — |
| **Jue 26 00:02** | **`cosecha`** (VM encendida) | ejecutor | `cosecha\cosecha.done` |
| **Jue 26 00:15** | **`crudo`** + **`analizar_ensayo_windows.py`** | ejecutor | `crudo.done`, informe |
| **Jue 26 00:45** | **`cleanup`** (VM encendida) + snapshot final + **restaurar** la pausa de Windows Update | ejecutor | log |
| **Jue 26 → Mié 2-dic** | T3-W/T4-W/T5-W, M1b-W, comparación | analista | `Hojas/T*_windows_legit.csv` |

> **El PC no se apaga, no se suspende y no se cierra la sesión** desde el viernes 20 hasta el
> jueves 26 (compromiso; el WE0 es la primera prueba de ello).

---

## 3. Preparación

### 3.1 Prerrequisitos del humano (lo único que no puede hacer el agente)

| # | Qué | Cómo |
|---|---|---|
| **P1** | **PowerShell elevado** (administrador) para `prep`, `arm`, `cleanup` y `watch_loop` (firewall `TFG-hb-9095`, puertos, `wevtutil`) | abrir *Windows PowerShell (administrador)* |
| **P2** | **Pausa de Windows Update del PC** (**YA APLICADA el 15-nov**; sigue activa hasta el `restaurar` del jueves 26) (evita que se actualice/reinicie solo). Sin ella `G-W12` falla y `prep` aborta | `powershell -NoProfile -ExecutionPolicy Bypass -File Soporte\Laboratorio\legitimo_72h\pausar_windows_update.ps1 pausar` (y `restaurar` **después** del `cleanup` del jueves 26) |
| **P3** | **Contraseña del manager en la sesión**, nunca a fichero | `$env:TFG_MANAGER_PW = Read-Host` en la misma ventana donde lances `prep`/`arm`/`watch_loop`/`cleanup` |
| **P4** | **RAM disponible ≥ 1,5 GB con las VMs y la pila arriba** (**el 15-nov solo había 1,2 GB** con Notion/WARP/etc. abiertos: `prep` aborta) | cerrar navegador, juegos, Discord… durante el WE0 y la ventana |
| **P5** | **No cerrar sesión, no suspender, no apagar** el PC | — |

### 3.2 Ensayo WE0 **extendido** (viernes 20 noche → sábado 21 mañana)

Una sola pasada continua de **~9 h** con el **código real y sin ninguna intervención**:

| Qué prueba | Cómo se mide |
|---|---|
| `prep` completo contra el **v2** (revert, pila, logs 512/256/128 MB, curl 200, gates) | `prep OK` |
| **La noche** (00:00–08:00Z: solo keepalive + latido + ruido de Windows) | `analizar_ensayo_windows.py` A2/A3 + tabla por hora |
| **1 h de receta real** (`d1`, 08:00–09:00: B1 + inicio de B2) con los `curl` ya funcionando | `M`, alertas, errores 10/día |
| **Huella del operador sin tocar nada** | A5 (≤ 5 %, 0 sin etiquetar) |
| **Latido** cada 5 min durante 9 h | A4 |
| **Completitud `.evtx` ↔ `archives`** | A6 |
| **Pérdidas** del agente y del manager | A7/A8 |
| **`watch_loop`** (19 chequeos) + G-W15 + suspensión del PC bloqueada | `watch_loop_resumen.json` |
| **`cosecha`/`crudo`/`cleanup`** con puertas (`exit 87`/`84`) | logs |
| **Rotación de día a las 00:00** (`dia_aplicado`) — reinicia el cliente en `t0` | `recovery.log` / `keepalive.log` |
| **Reloj** invitado↔host | A11 |

**Pasa si** `analizar_ensayo_windows.py` da **0 FAIL** (los `ND` se justifican) **y** el
`prep`/`arm`/`cleanup` no dan error. Salida: `ensayo_WE0.md` + `informe_WE0.md` + decisión de V1.

### 3.3 `prep` real (domingo 22, 23:00)

Elevado y con `TFG_MANAGER_PW` en la sesión:

1. Gate de sellos (`exit 56`) · manifiesto 294/`4621046f` (`exit 46`).
2. **Pila del host** (GHOSTS API 5000, PostgreSQL 5432, web 8080, sink 9090, WebDAV 9092) `exit 40`.
3. **Revert a `lab-listo-windows-legit-v2`** + arranque; **logs ampliados** (`exit 49`);
   `deploy` idempotente; `DEFENDER_OFF=1`; `SESION_ANGEL=1`; lista negra 11/11.
4. **`curl` HTTP 200 desde el invitado** a `http://intranet.local:8080/` (`exit 40`).
5. Sink `:9095` + firewall `TFG-hb-9095`; `heartbeat.jsonl`/`.seq` anteriores archivados.
6. G-W12 con **pausa de WU del PC** (`exit 41` si falta).

### 3.4 `arm` real (domingo 22, 23:40)

`-Phase arm -T0 2026-11-23T00:00:00Z -T1 2026-11-26T00:00:00Z`: mapa de días 23/24/25,
`logall_json=yes` **verificado** (no se re-ejecuta `on` si ya está), `armado.flag`, cliente,
`ventana_actual.json`; evalúa también **G-W15**. Después `watch_loop.ps1` (esperará hasta `t0`).

---

## 4. Durante la ventana (72 h)

### 4.1 GHOSTS, `logall_json` y pila del host

| Elemento | Valor |
|---|---|
| Acciones | **504** (d1 163, d2 178, d3 163; jornada 147/153/141 + campaña 16/25/22) |
| Cliente | 8.3.1, tarea `Interactive` (IL Medium), `WorkingDirectory=C:\Users\angel` |
| `logall_json` | `yes` desde `arm` hasta `cleanup`; `M` del endpoint `002` |
| **Pila del host** | GHOSTS API :5000 + PostgreSQL :5432 (**de ahí sale el conteo de acciones**) + internet local :8080/:9090/:9092 (**~50 `curl`/web de la receta**) — **G-W15** la vigila |
| Rotación | `d1→d2→d3` a las 00:00 (24 y 25) por `dia_aplicado.txt`; **a las 00:00 de `t0` también reinicia el cliente** (esperado) |

### 4.2 Chivato y keepalive

Chivato `POST http://192.168.65.1:9095/heartbeat` cada 5 min (JSON ≤1 KB, `seq` +
`sha256_prev`); keepalive de **1 proceso** (+`conhost`), mutex `Global\TFG-WinLegit-Keepalive`.
Frescura `G-W13` (≤12 min). **El latido deja una huella** en `archives` (1 evento Sysmon 3 cada
5 min ⇒ ~864 en 72 h) y se etiqueta como operador; el ruido operador objetivo es **≤5 %**.

### 4.3 Vigilancia `watch_loop.ps1` (cada 30 min, 144 chequeos)

`powershell -File Soporte\Laboratorio\windows\legit\watch_loop.ps1` (elevado, con
`TFG_MANAGER_PW`, **sesión que no se cierra**). Un solo proceso (mutex), **bloquea la suspensión
del PC** mientras corre, **no abre SSH al invitado**, anota ticks **SALTADOS** (PC dormido) sin
ráfagas, y deja `ALARMA_<ts>.txt` visible si un chequeo falla.

| Guardarraíl | Qué |
|---|---|
| **G-W5** | manager `active` + daemons + agente `002` `Active` |
| **G-W7** | `logall_json` según `[t0,t1]` + disco del manager ≥ 5 GB |
| **G-W8** | 0 hijos de `vmtoolsd.exe` (latido) |
| **G-W9** | `powercfg` 0/0/0 (latido) |
| **G-W10** | disco del invitado ≥ 4 GB (latido) |
| **G-W11** | exactamente 1 `ghosts.exe` de `angel` (latido) |
| **G-W12** | RAM del host ≥ 1.500 MB + `wuauserv` parado + **política de pausa de WU** |
| **G-W13** | latido ≤12 min + `seq` monótono + `ka_instancias=1` |
| **G-W14** | Defender del invitado `off` (latido) |
| **G-W15** *(nuevo)* | **pila del host viva**: GHOSTS API, PostgreSQL, web, sink, WebDAV |

> G-W6 (aislamiento) se verifica en `prep`/`status`. **15 guardarraíles en total; 10 en `watch`.**

---

## 5. Criterios de validez (W-V1…W-V9)

| # | Criterio | Cómo se comprueba |
|---|---|---|
| **W-V1 — Registro continuo** *(redefinido, ver abajo)* | **hueco máximo entre EVENTOS de `archives` del endpoint ≤ 10 min** (el latido garantiza uno cada 5 min). Además se **informa** el hueco máximo entre ALERTAS y se compara con Linux (62 s). | `analizar_ensayo_windows.py` A2/A3 |
| **W-V1b — Cobertura de la receta** | primera acción de `d1` a 08:00±10 min; última de la campaña ≥17:50; `--check` 147/153/141; 0 acciones fuera de bloque (salvo recuperaciones) | `ghosts_acciones.csv` + `bloques_windows.env` |
| **W-V2 — Actividad** | cada día ≥ 90 % de su receta | `history_timeline` |
| **W-V3 — Manager/diarios** | manager `active` en todos los chequeos; los 3 diarios existen y crecen | `watch_loop.log` + `crudo` |
| **W-V4 — 0 contaminación** | **0** sesiones SSH del host al invitado en `[t0,t1]`; **0** hijos de `vmtoolsd`; **0** `4624` desde `192.168.65.1`; **A5 ≤ 5 %** y 0 sin etiquetar | `alertas_detalle.csv` + A5 |
| **W-V5 — Aislamiento** | sin ruta por defecto; solo VMnet1 | `heartbeat.jsonl` |
| **W-V6 — `M`** | copiado **antes** del `off`; `--estricto` `exit 0`; **un solo `M`** `--agent-id 002 --boveda-version 3` | `denominador_M.csv` |
| **W-V7 — Sin cambios** | `sha256` de Sysmon, `ossec.conf` 002, receta y campaña tras `arm` y en cosecha; `CONFIG_IDENTICA`; excepciones: `campana\*`, 1 `eventcreate`, `web_access.log`, **tamaño de los logs de eventos (declarado)** | `diff` + `sha256` |
| **W-V8 — Host/invitado estables** | host `LastBootUpTime < t0`; 0 `Kernel-Power 42/107`; invitado 0 reinicios (`A10`) | WMI + `reinicios.txt` |
| **W-V9 — Reloj** | |Δ| ≤ 2 s en `prep` y cosecha (`A11`); >5 s sostenido ⇒ inválida | `heartbeat.jsonl` + `cosecha.done` |
| **W-V10 — Completitud** *(nuevo)* | `A6` (evtx↔archives), `A7` (manager sin descartes), `A8` (agente sin buffer lleno) | informe |

**Sobre W-V1 (decisión pendiente del WE0):** el W0 pedía *primera alerta ≤t0+10 y hueco de
alertas ≤30 min*. Linux pasó con 62 s porque auditd genera alertas toda la noche. **No se asume
que Windows no pueda:** el WE0 mide la noche. Si en Windows hay alertas toda la noche, V1 se
mantiene **tal cual** (comparable con Linux). Si no, V1 pasa a medirse sobre **eventos** (como
arriba) y la divergencia con Linux se **declara** (M-3). La tabla por hora lo dejará a la vista.

**Válida con incidencia:** 1–2 recuperaciones del cliente; 1 ciclo de sink caído ≤30 min;
**`watch_loop` con 130–143 chequeos o ticks saltados si el latido y `archives` son continuos**;
un `NO` de campaña. **Invalida:** >2 recuperaciones; cliente caído >60 min; manager caído >30 min;
reinicio/suspensión/logoff; cambio de config no declarado; `M` no recuperable; Δ>5 s;
**`archives` con huecos >30 min**; **pila del host caída >30 min** (se pierde el conteo).

---

## 6. `t1` y cierre (orden **no negociable**)

```
t1 00:00  ── fin de la ventana (watch_loop termina; el cliente sigue hasta la cosecha)
t1+02     ── COSECHA   (VM encendida, SSH solo lectura) → cosecha\cosecha.done
t1+15     ── CRUDO     (manager: archives + alerts + ossec.log + estados) → crudo.done
t1+30     ── ANALISIS  analizar_ensayo_windows.py → informe A1..A11 (ya se ve si es VALIDA)
t1+45     ── CLEANUP   (VM encendida) exige crudo.done (84) y cosecha.done (87):
             stop.flag → bucle fuera → tareas fuera → sink fuera → actividad fuera →
             firewall fuera → VM off → logall_json off → CONFIG_IDENTICA →
             GHOSTS/PostgreSQL/internet local parados
t1+60     ── snapshot final `lab-listo-windows-legit-post72h` (VM apagada) + manifiesto
t1+90     ── restaurar la pausa de Windows Update (humano)
```

- **No se usa `stop` antes de `cleanup`.** `stop` exige ahora **las dos puertas**.
- `cosecha` copia: `keepalive.log`, `recovery.log`, `estado.json`, `client.out`, `heartbeat.seq`,
  `dia_aplicado.txt`, `errores.log`, `ghosts-client\logs\*`, las 22 marcas de campaña, **`ossec.log`
  y `ossec.conf` del agente**, **los 5 `.evtx` completos**, `conteo_por_evento.csv`,
  `reinicios.txt`, `reg query`/`schtasks`/`ipconfig`/`systeminfo`; y **verifica en el host el
  `sha256` de cada fichero** contra el manifiesto del invitado.
- `crudo` copia además **`ossec.log` y los `*.state` del manager** (pruebas de que no hubo descartes).

---

## 7. Análisis

### 7.1 T3-W — FPR de la ventana

| Producto | Contenido |
|---|---|
| `analizar_legitimo_windows.py` (nuevo) | índice de `archives` (unidad = línea), `alertas` del `002`, catálogo, `T3_detalle` |
| `catalogo_ruido_windows.csv` | reglas de la ventana |
| `Hojas/T3_legitimo_windows.csv` | C0/C1 × N=0/3/7/10/12: `M`, `FP_uni`, `TNR`, `FPR`, `A_FP`; **canónico** y **`sin_operador`** |
| `estabilidad_dia/hora/campana_windows.csv` | 3/72/11 filas |

- **Unidad:** `FP_uni` = línea de `archives` con ≥1 alerta; `M` = líneas del endpoint `002`;
  `FPR = FP_uni/M`; `FP/acción = A_FP/504`; `FP/hora = A_FP/72`.
- **El titular NO es el FPR a N=0/3** (casi cualquier evento dispara una regla de nivel 3: en
  Linux 0,86): **lo comparable es N≥7 y `FP/hora`**. Se publican las dos cifras.

### 7.2 T4-W y T5-W · 7.3 M1b-W · 7.4 Comparación con Linux

Como en el plan v1: T4-W con la misma fórmula (Precisión/F1 mezclan planos); T5-W con la
fórmula de Linux; **M1b-W** re-corta los **54** ataques (catálogo = reglas de la ventana ∪ reglas
de operador ∪ artefactos `92213/91823`), **alerts-only** (los ataques no tenían `logall`),
publicando los deltas vs M1a y una sensibilidad con catálogo puro. Comparación Linux↔Windows:
`M` per-plataforma, `sin_operador` Windows frente al canónico de Linux (≈ sin operador: no se ve
con auditd; **«no se observa operador», no «se demuestra que no hay»**), TPR 54/54 vs 53/55.

### 7.5 Sellado B10-W

`b10_windows_sellado.md` + `boveda_windows.sha256` (telemetría, agente, cliente, receta,
campaña, `M`/`crudo`/`cosecha`, `T3/T4/T5`, `metrica_version=1`, **`boveda_version=3`**).
**No** se recalcula Linux.

---

## 8. Riesgos y puntos de parada

| # | Riesgo | Mitigación / parada |
|---|---|---|
| **R1** | Defender se reactiva | `prep` `exit 47`; G-W14; si cuarentena o cliente muerto ⇒ parar e invalidar |
| **R2** | Cliente caído | keepalive relanza ≤2; >2 o hueco >60 min ⇒ invalidar |
| **R3** | **El PC se duerme/reinicia** | P2 (pausa WU), `watch_loop` bloquea la suspensión; ticks saltados ⇒ incidencia si el latido es continuo; **reinicio ⇒ invalidar** |
| **R4** | Sink caído >30 min | `hb=FAIL`; >30 min ⇒ incidencia; si el cliente también cae ⇒ invalidar |
| **R5** | Autologon/sesión perdida | `SESION_ANGEL=1`; `sin_sesion` en el latido; no se reabre sin reiniciar ⇒ invalidar |
| **R6** | **La pila del host cae** (API/PostgreSQL/internet local) | G-W15 ⇒ ALARMA; relanzar `start_ghosts.ps1`/`start_internet_local.ps1`; >30 min ⇒ invalidar |
| **R7** | Reloj | |Δ|≤2 s; >5 s ⇒ invalidar |
| **R8** | Disco del invitado | guarda 500 MB; <4 GB ALARMA; <300 MB parar |
| **R9** | `M` > 5 GB | no esperable (2 h = ~6 MB); disco del manager 18 GB |
| **R10** | `cosecha`/`crudo` fallan | `cleanup` bloqueado (`exit 87/84`); reintento documentado |
| **R11** | Logs de eventos se sobrescriben | `prep` los amplía (verificado, `exit 49`) |
| **R12** | **El etiquetador deja escapar operador** | probado sobre crudo real (0 escapan) + A5 en el ensayo |
| **R13** | **Pérdida de eventos del agente** | A6/A7/A8; buffer 5000/500 sobra para la ventana legítima |
| **R14** | `eventcreate` a Medium falla | tarea elevada pre-creada (declarada) |
| **R15** | `logall_json` residual / snapshot final con residuos | `arm` idempotente; `cleanup` verifica `no`; manifiesto + lista negra |
| **R16** | **RAM justa** (con la pila ~1,9 GB libres) | P4: cerrar apps; G-W12 ≥ 1.500 MB |

---

## 9. Criterios de aceptación (tester)

| # | CA | Verificación |
|---|---|---|
| **CA-WL-01** | **WE0 extendido PASA** (`analizar_ensayo_windows.py` 0 FAIL) y ≤7 días antes de `t0` | `informe_WE0.md` |
| **CA-WL-02** | `prep`/`arm` a su hora (±5 min); revert al **v2**; pila del host viva; curl 200; logs ampliados; `logall_json=yes` verificado; 1 cliente; `SESION_ANGEL=1`; `DEFENDER_OFF=1` | log |
| **CA-WL-03** | `watch_loop` 144±4 chequeos, 0 `ALARMA` no explicada, **0 SSH al invitado**, `HB_EDAD_MIN≤12`, `ka_instancias=1`, **G-W15 OK** | `watch_loop.log` |
| **CA-WL-04** | `M` de la copia (`--estricto --agent-id 002 --boveda-version 3`); FPR canónico y `sin_operador`; `FP/acción`/`FP/hora` | `denominador_M.csv` + `T3` |
| **CA-WL-05** | **`cosecha` y `crudo` ANTES de `cleanup`**; hashes verificados; `.evtx` ×5; `ossec.log` agente y manager; `cosecha.done`+`crudo.done` | `MANIFEST.tsv` |
| **CA-WL-06** | **Validez W-V1…W-V10** (A1–A11); noche declarada | `veredicto_validez.md` |
| **CA-WL-07** | Campaña 11/11 (o ≥9/11) con `n_acciones` vs esperado (0 `REPORTE_INCOMPLETO`); `W-07` canónico NO + sensibilidad SI | `campana_fp_windows.csv` |
| **CA-WL-08** | T3-W/T4-W/T5-W y M1b-W 54 casos; deltas publicados | `Hojas/T*_windows_legit.csv` |
| **CA-WL-09** | Comparación Linux↔Windows firmada | `comparacion_linux_windows.md` |
| **CA-WL-10** | Cierre limpio: 0 VMs de medida, 0 `TFG-*`, **GHOSTS/PostgreSQL/internet local parados**, firewall ausente, `logall_json=no`+`CONFIG_IDENTICA`, variables borradas, **pausa de WU restaurada** | logs |
| **CA-WL-11** | Snapshot final `…-post72h`; v2 y 7 previos intactos | `vmrun listSnapshots` |
| **CA-WL-12** | Higiene: **0 secretos** en repo/logs; `git status` acotado; prohibidos sin tocar | repo |
| **CA-WL-13** | B10-W sellado; `boveda_version=3` | `b10_windows_sellado.md` |
| **CA-WL-14** | **Completitud**: A6/A7/A8 sin FAIL; los `ND` justificados | informe |

---

## 10. Qué se declara en la memoria

| # | Declaración |
|---|---|
| **M-1** | FPR Windows canónico y `sin_operador` con `M`, `FP_uni`, `FP/acción`, `FP/hora`; `M` per-plataforma y no comparable en crudo con Linux; el titular comparable es **N≥7 y `FP/hora`** |
| **M-2** | `watch_loop` 10 guardarraíles / 15 totales, 144 chequeos, **0 SSH al invitado** |
| **M-3** | **V1**: criterio y resultado de la noche (medido en WE0); si se midió por eventos, la **divergencia con Linux** (que usó alertas) |
| **M-4** | Keepalive de 1 proceso; kill duro no se auto-reinicia (se detecta ≤12 min) |
| **M-5** | **Latido por red**: 1 evento Sysmon 3 cada 5 min en `archives` (huella declarada y etiquetada) |
| **M-6** | Campaña 11 casos; `W-07` canónico 90/15/NO y sensibilidad 87/6/SI; `92213` es artefacto |
| **M-7** | M1b-W alerts-only; deltas vs M1a; sensibilidad con catálogo puro |
| **M-8** | T4-W: Precisión/F1 mezclan planos (convención del profesor) |
| **M-9** | 2 casos parciales (C-05, C-06); TPR Windows 54/54 |
| **M-10** | Tarea `Interactive` (IL Medium) depende de la sesión de `angel` |
| **M-11** | **Defender OFF como control ambiental: se mide Wazuh, no Defender** (un ataque bloqueado no generaría la actividad que Wazuh debe detectar) |
| **M-12** | `eventcreate` elevado si hace falta; nunca sustituido por lectura |
| **M-13** | Snapshot final; v2 y los 7 previos intactos |
| **M-14** | B10-W bóveda v3; no se recalcula Linux |
| **M-15** | **Configuración virgen del agente**: excluye por defecto 13 EventID de Security y tiene buffer 5.000/500; no se tocó |
| **M-16** | **Tamaño de los logs de eventos ampliado** (512/256/128 MB) para no sobrescribir en 72 h: solo capacidad |
| **M-17** | **Hallazgo metodológico**: en la prueba de 2 h las descargas `curl` a `intranet.local` **fallaron** porque no se había arrancado la "internet local"; corregido (`prep` la arranca, G-W15 la vigila, `curl` 200 desde el invitado). La prueba de 2 h **no es representativa de esas acciones** |
| **M-18** | **Linux «sin operador» = canónico por falta de visibilidad** (auditd no ve VMware Tools): «no se observa», no «se demuestra que no hay» |
| **M-19** | **`archives` = lo que el agente envió**; la completitud se comprueba contra los `.evtx` del invitado (A6) y las pruebas de descartes (A7/A8). **Linux no tiene esta comprobación** (no se cosechó `audit.log`) |
| **M-20** | Los 54 ataques Windows y los de Linux **no tienen `archives`** (`logall=no`): límite declarado; se repetirán más adelante con `logall_json=yes` para evaluar `+propias`/`+externas` |
| **M-21** | El manager registró 1 «Package dropped» el 08-nov (ataques B1): evidencia de que el buffer puede saturarse en ataques masivos |

---

## 11. Ficheros

### 11.1 Cambiados / nuevos por esta auditoría (YA hechos, sin commit)

| Ruta | Qué |
|---|---|
| `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` | **v5**: `$Snap=v2`; fases `cosecha`; puertas `exit 87/70`; `prep` amplía logs (`49`), arranca la pila (`40`) y prueba el `curl`; **G-W15**; G-W12 exige la pausa de WU; `crudo` guarda `ossec.log` del manager; `cleanup` para la internet local; `LogC` |
| `Soporte/Laboratorio/windows/legit/watch_loop.ps1` | **nuevo**: vigilante cada 30 min |
| `Soporte/Laboratorio/windows/legit/cosecha_invitado.ps1` | **nuevo**: cosecha dentro del invitado (+ conteo por EventID) |
| `_artefactos/scripts/etiquetar_operador_legit.py` | +`ssh_operador`, +`tareas_operador`, +`logs_operador` por línea de comandos |
| `_artefactos/scripts/analizar_ensayo_windows.py` | **nuevo**: informe mecánico A1–A11 |
| `_artefactos/scripts/verificar_sellos_windows.py` | lista blanca ampliada |
| `_artefactos/scripts/tests/test_watch_cosecha_windows.py`, `test_analizar_ensayo_windows.py`, `test_etiquetar_operador_legit.py` | **+40 tests** (527 en total) |
| `Soporte/Laboratorio/legitimo_72h/sha256sums.txt` | resellado: **200** entradas, `sha256sum -c` 0 fallos |

### 11.2 Por crear en la ventana

`Soporte/Laboratorio/windows/legit/ventana_2026-11-23/` (`ventana_meta.md`, `veredicto_validez.md`,
`informe_WE0.md`, `ensayo_WE0.md`), `D:\TFG-VMs\legitimo-windows-2026-11-23\{cosecha,crudo}\`,
`snapshot_windows_legit_post72h.md`, `b10_windows_sellado.md` + `boveda_windows.sha256`,
`analizar_legitimo_windows.py`, `recortar_ataques_m1b_windows.py`, `Hojas/T*_windows_legit.csv`.

### 11.3 No se toca

`_recursos/`, `Hojas/` existentes, `Dataset/` existente, `Soporte/Metrica/`, corpus, ruleset,
Sysmon, recetas, campaña, snapshot v2 y los 7 previos, ficheros del invitado sellados en el
manifiesto 294 (**no se modificó ninguno**: por eso el snapshot v2 sigue siendo válido).

---

## 12. Lo que el humano debe decidir / hacer

| # | Pregunta / acción | Recomendación |
|---|---|---|
| **Q1** | ¿Se aprueba el **WE0 extendido** (viernes 20 noche → sábado 21 mañana, ~9 h, el PC encendido) en lugar de 1 h de día? | **Sí**: es la única forma de medir la noche y probar el código nuevo antes de las 72 h |
| **Q2** | **Aplicar la pausa de Windows Update** (P2) antes del viernes 20 | **Sí**; el agente no puede (el sistema bloquea cambiar la config del PC). Sin ella `prep` aborta a propósito |
| **Q3** | ¿Se aprueba que **V1 se decida con los datos del WE0** (mantener si hay alertas de noche; si no, pasar a eventos y declararlo)? | **Sí** |
| **Q4** | ¿`watch_loop` con menos de 140 chequeos = **incidencia** (no invalidación) si el latido y `archives` son continuos? | **Sí** |
| **Q5** | ¿Se aprueba el catálogo M1b-W (ventana ∪ operador ∪ artefactos) con sensibilidad pura? | **Sí** |
| **Q6** | ¿Se aprueba el snapshot final `…-post72h` y la promoción a `Dataset/` solo si VÁLIDA? | **Sí** |
| **Q7** | **Commit** de los cambios de esta auditoría (los hace el orquestador/tú) | Antes del WE0, para que el sello apunte a un commit |

**Nada de la ventana se ejecuta hasta que apruebes y el WE0 pase.**
