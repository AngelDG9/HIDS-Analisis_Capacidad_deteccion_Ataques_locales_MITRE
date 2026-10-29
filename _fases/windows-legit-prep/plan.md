---
bloque: windows-legit-prep
nombre: W0 — preparación del espejo Windows de la ventana legítima (sin ejecutarla)
version: 2
status: approved_by_human
fecha: 2026-10-29
fecha_aprobacion: 2026-10-29
aprobado_por: humano
correcciones: "2026-10-29 · W1+W2: rutas/nombres reales y cambios ejecutados (W-04->AES, W-05->PowerShell, W-09->cmd /c copy, W-11 sin certutil -urlcache, rm_inexistente->type). Ver §16.4. Sin cambio de fondo."
autor: tfg-planner
depende_de: legitimo-v3 (Linux, plan v5 APROBADO y PAUSADO hasta el 2026-11-05) · legitimo-fix (cerrado, PASA) · legitimo-72h-v2 (abortado, lecciones) · fase-02b-baseline (cerrado, PASA) · reencuadre-metrica (métrica v1 CONGELADA)
no_toca: plan.md (raíz, bloque Linux) · _recursos/ · Hojas/ · Dataset/ · Soporte/Metrica/ · laboratorio · corpus
ejecuta_ahora: NADA. Las VMs siguen apagadas. Este documento es de preparación; la ejecución se decide después.
ventana_ejecucion: sin fecha. Se fija al cerrar WE0 (§8), con la misma regla que Linux (≥ 48 h de margen, primer lunes→jueves), y **solo después** de que cierre la ventana Linux (2–5/11).
gate: |
  **APROBADO (2026-10-29) — OK del humano a las 4 decisiones de fondo:** (1) usar el **cliente GHOSTS de
  Windows** y **trasladar la receta por ranuras** (mismos tiempos y conteos que Linux); (2) **los 11 casos**,
  con los 2 difíciles escritos a mano en PowerShell, **declarado**; (3) **aislar el denominador**
  (`--agent-id 002` + VM Linux apagada); (4) **construir ahora** (papel y scripts) y **ejecutar después**
  del 2026-11-05. **Excepción a §16.3 declarada** para `construir_receta_legitima.py` (fix L-1).
  Se mantiene: nada de VMs hasta cerrar Linux, y WE0 obligatorio antes de armar.
---

# plan.md — Bloque `windows-legit-prep` (W0)

> **Qué es este documento.** El **espejo Windows** de la ventana legítima de Linux. **No ejecuta
> nada**: define qué hay que construir, cómo se prueba, qué se sella y qué **no** se puede replicar.
> El plan aprobado del bloque Linux está en `plan.md` (raíz, `legitimo-v3` v5, `approved_by_human`) y
> **no se toca**.
>
> **Convención de rigor usada en todo el documento:**
> **[H]** hecho comprobado hoy (con fuente `fichero:línea` o comando leído) · **[D]** decisión de este
> plan (con coste y alternativa) · **[S]** suposición declarada (a confirmar en WE0, §8).

---

## Índice

0. [Resumen ejecutivo, **lo que NO es trasladable** y **tabla de espejo**](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Estado de partida verificado (2026-10-29)](#2-estado-de-partida-verificado-2026-10-29)
3. [Decisiones con coste/beneficio](#3-decisiones-con-costebeneficio)
4. [La receta Windows (qué se construye)](#4-la-receta-windows-qué-se-construye)
5. [La campaña Windows (11 casos espejo)](#5-la-campaña-windows-11-casos-espejo)
6. [El denominador `M` en Windows](#6-el-denominador-m-en-windows)
7. [Tandas W1–W4](#7-tandas-w1w4-qué-se-construye-y-cómo-se-prueba)
8. [WE0 — ensayo de armado](#8-we0--ensayo-de-armado-obligatorio)
9. [Criterios de validez](#9-criterios-de-validez-w-v1w-v9)
10. [Extracción](#10-extracción)
11. [Bóveda B10-W y versionado](#11-bóveda-b10-w-y-versionado)
12. [Riesgos](#12-riesgos)
13. [Criterios de aceptación verificables](#13-criterios-de-aceptación-verificables)
14. [Cómo se verifica (tester)](#14-cómo-se-verifica-tester)
15. [Gate humano (lenguaje sencillo)](#15-gate-humano-lenguaje-sencillo)
16. [Ficheros](#16-ficheros)
17. [Trazabilidad](#17-trazabilidad)
18. [Lo que no cuadra](#18-lo-que-no-cuadra)
19. [Veredicto del planificador](#19-veredicto-del-planificador)

---

## 0. Resumen ejecutivo

**Principio rector (encargo del humano).** *Todo lo que se hizo en Linux se replica en Windows, igual o
adaptado. Si algo no se puede replicar, se declara y se explica por qué.*

### 0.1 Lo que **NO** es trasladable (arriba y claro)

| # | Qué no se traslada | Por qué (comprobado) | Qué se hace en su lugar |
|---|---|---|---|
| **N-1** | **La campaña derivada del corpus de ataques** | En Linux las 11 fichas se reconstruyeron **desde el corpus** (4 107 detecciones `80792` con `audit_exe`; `plan.md:620-653`). **No existe corpus de ataques Windows**: `Dataset/Ataques/Resultados/Wazuh/` solo tiene `linux/`, `Auditado/`, `CSV/`, `Logs/`, `Perf/` **[H]**, y el bloque **B1 (`fase-03b`) no ha empezado** (`roadmap.md:83`) | La lista se deriva del **ruleset congelado** (`active_ruleset.txt:144-191`) + el **inventario P1-Windows** (89 técnicas, 77 aplicables, 75 factibles, 38 con ART; `Hojas/inventario_p1_windows.csv`) + la **baseline Windows de 2×4 h**. Se etiqueta como **[S] predicción**, no como medida, hasta que exista B1 |
| **N-2** | **`auditd` y el par `execve`/`audit_cwd`** | Windows no tiene `auditd`. La telemetría es **eventos de registro** (4688, Sysmon 1, 4104) + FIM (`telemetria_windows.md:11-25`) | El ancla equivalente es `win_image ∧ win_command_line ∧ win_cwd` (`telemetria_windows.md:60-67`). **`cwd` solo existe en Sysmon EID 1**: 4688 no lo lleva **[H, doc. del propio proyecto]** ⇒ el ancla `cwd` depende de Sysmon |
| **N-3** | **El extractor de alertas congelado** | `extraer_alertas.py` solo lee `data.audit.*` y `syscheck.path` (`extraer_alertas.py:337-340`); en Windows `audit_exe`/`audit_cwd` salen **vacíos** — ya ocurrió: `Dataset/Legitimo/windows/baseline_detalle_v1.csv` tiene esas columnas en blanco **[H]** | **Extractor nuevo** `extraer_alertas_windows.py` (no se toca el congelado: está en la lista de prohibidos, `plan.md:1305`) |
| **N-4** | **Cifrado con contraseña de un fichero (`openssl enc`)** | Windows 10 Pro **no trae** ninguna herramienta nativa de cifrado simétrico con contraseña por línea de comandos (sin instalar) **[S]** | **AES en PowerShell** (clave fija, sin contraseña) + `certutil -hashfile` ⇒ el caso **C-05 baja a parcial**: se pierde la variante con contraseña de T1486-legítimo (W-04, ya ejecutado; §16.4) |
| **N-5** | **Borrado seguro (`shred`)** | El equivalente (`cipher /w:<dir>`) **reescribe el espacio libre 3 veces**: GB escritos y horas de disco en una VM de 12 GB **[S]** | Solo borrado (`del`, `rd`). El caso **C-06 baja a parcial**: se pierde T1561-legítimo |
| **N-6** | **Persistencia benigna (crear+borrar tarea programada)** | Ya se retiró en Linux (**C-04**, `plan.md:695-700`): la campaña es **no mutante** | Se mantiene fuera en Windows **por la misma decisión**, aunque aquí la tentación es mayor (T1053.005 es la técnica de persistencia por excelencia en Windows) |
| **N-7** | **1 acción = 1 `execve`** | En Windows **sí se mantiene la unidad**, pero por otra razón: GHOSTS `Cmd` arranca **`cmd /c <comando>` por acción** (`Cmd.cs:106`) ⇒ 1 acción = 1 `cmd.exe` (+ hijos). **No** es un problema; se documenta porque el *baseline* histórico **no** lo hacía: su script usaba cmdlets dentro de un único `powershell.exe` y produjo **68 eventos de proceso en 4 h** (`baseline_resultado.md:§11-12`) | Regla de la receta: **una entrada = un `cmd /c`**; nada de scripts internos que agrupen N acciones |
| **N-8** | **Ofimática real (Word/Excel/Outlook)** | Los handlers existen (`Ghosts.Client/Handlers/Word.cs`, `Excel.cs`, `Outlook.cs`) pero **exigen Office instalado** (`Ghosts.Client.csproj:464` y ss., `Microsoft.Office.Interop.*`) **[H]**, y la decisión de Linux fue **no instalar** (`plan.md:245, 293`) | CSV/TXT planos + `tar`/`findstr`/`more`. Se declara hueco (igual que Linux declaró LibreOffice fuera) |
| **N-9** | **Navegador real** | Igual que Linux: `browser_eval.md` DT-B0 FAIL (12 librerías, 3,4 GB) y aquí exigiría Chrome+driver Selenium (`Ghosts.Client.csproj`, `Selenium.WebDriver.*`) **[H]** | `curl.exe` (incluido en Windows 10 ≥ 1803) con UA fija, como el "browser-like" de Linux |
| **N-10** | **Comparabilidad en crudo del FPR** | La métrica ya lo dice **entre HIDS** (`metrica_hids.md:66-68, 254-268`); aquí se añade la dimensión **entre plataformas**: los "eventos" de Windows (registro) y de Linux (`audit`) son cosas distintas | Se compara con la **unidad común** (`FP/acción`, `FP/hora`) y **por técnica**, nunca `FPR` crudo Windows vs Linux |

### 0.2 Tabla de espejo

> **Cómo leerla.** «Cambia» describe la diferencia técnica; «por qué» justifica que la comparación
> siga siendo legítima.

| # | Elemento en Linux (fuente) | Equivalente en Windows | Qué cambia | Por qué sigue siendo espejo |
|---|---|---|---|---|
| **1** | Generador: cliente **GHOSTS Linux** con `HandlerType=Command` → `Bash.cs` (`bash -c`) (`plan.md:307-309`; `ghosts.client.linux/.../Orchestrator.cs:193`) | **GHOSTS `Ghosts.Client`** (Windows, .NET 4.6.2) con **el mismo** `HandlerType=Command` → `Cmd.cs` (`cmd /c`) (`Orchestrator.cs:330`; `Cmd.cs:106`) | cambia el binario del cliente y el *shell*; **no cambia el formato del timeline** (el `d1.json` de Linux ya usa `"HandlerType": "Command"`) **[H]** | mismo API, misma base de datos (`history_timeline`), mismos campos, misma versión 8.3.1 ⇒ la unidad «acción» es la misma |
| **2** | **Receta**: `d1/d2/d3` con B1–B6, P1 café, P2 comida, jornada **08:00–17:00Z**, jitter literal, **147/153/141 acciones** (`plan.md:472-504`; `bloques.env`; `state.md:10`) | mismos días, **mismos bloques y mismas horas UTC**, **mismo vector de `DelayAfter`** (traslado **por ranuras**: `n` eventos y `DelayAfter` idénticos por bloque) | cambian los **comandos** (POSIX → `cmd`/PowerShell), no el **ritmo** | elimina una variable (el tiempo) y deja una sola (la plataforma); el validador comprueba la igualdad de ranuras |
| **3** | **`cwd` realista** `/home/angel` (mejora 1, `plan.md:574-577, §1.9.2`) | `WorkingDirectory` de la tarea = `C:\Users\angel` + `cd /d` explícito por comando; se mide `win_cwd` en **Sysmon EID 1** | en Windows el `cwd` **no viaja en 4688**; depende de Sysmon | mismo objetivo: quitar el artefacto «cwd de bot» (aquí el riesgo es `C:\Windows\System32`, que es el `cwd` de una tarea SYSTEM) |
| **4** | **Errores con reintento**, ~10/día, con `errores.log` de 5-6 campos (`plan.md:583-585`; CA-03) | `if errorlevel N (...)` + reintento correcto + `errores.log` (TSV) | sintaxis y **trampa real**: `%ERRORLEVEL%` se expande **antes** de ejecutar ⇒ hay que usar `if errorlevel` o `call` (§4.4) | misma familia de eventos (`rc≠0` + reintento) y mismo producto sellable |
| **5** | **Herramientas de doble uso elegidas por el corpus** (12: `xargs`, `sed`, `openssl`, `ip`, `rsync`…) (`plan.md:601-609`) | `certutil`, `curl.exe`, `bitsadmin`, `schtasks`, `reg`, `sc`, `net`, `whoami`, `tasklist`, `ipconfig`, `route`, `netsh`, `wevtutil`, `robocopy`, `tar`, `makecab`, `findstr`, `icacls`, `eventcreate`, `powershell` | **la selección no puede venir del corpus** (N-1): viene del **ruleset** y del **inventario P1-Windows** | misma lógica (herramientas que atacan y se usan a diario), distinta fuente de evidencia: se declara |
| **6** | **Campaña B6**: 11 casos **no mutantes**, 3/4/4, `17:05–17:50Z`, inicios **17:06/17:17/17:11**, marcas `inicio/fin/hecho` (`plan.md:501-504, 666-678`) | **11 casos espejo** en `C:\lab-legit\campana\W-XX\`, mismo reparto, mismas horas, mismas marcas | 2 casos **parciales** (N-4, N-5); 1 cambia de mecanismo (`xargs` → `for /L` + `cmd /c copy`, tras corregir `xcopy` en W1); el resto se reescribe en `cmd` | la estructura (bloque declarado, marcas, esperado por umbral, publicación aparte, no mutación) es **idéntica** |
| **7** | **Denominador `M`**: `logall_json` en el manager + `contar_denominador.py`, filtrado al agente **`001`** (`plan.md:1049-1053`; `contar_denominador.py:288` por defecto `001`) | mismo `logall_json`, **`--agent-id 002 --agent-name victima-windows`**; agente `001` **apagado** (VM Linux off) | el volumen es **desconocido** y probablemente **mucho mayor** (Sysmon + Security). Se mide en WE0 (§6.3) | `M` es por plataforma (la métrica ya lo declara per-HIDS, `metrica_hids.md:66-68`); el método de conteo es el mismo script |
| **8** | **Extracción**: cosecha SSH → `cosecha.done` → `stop` → `M` → `logall_json off` → alertas → acciones → campaña (`plan.md:1029-1046`) | mismo orden, pero la cosecha es **`vmrun copyFileFromGuestToHost`** (Windows no tiene SSH) y las alertas se extraen con **extractor nuevo** (N-3) | transporte y extractor | mismo orden crítico (`off` borra `archives.json`) y mismos productos |
| **9** | **Validez V1–V8** (`plan.md:1066-1075`) | **W-V1…W-V9** con umbrales propios (§9) | el fondo Windows es **intermitente**: la baseline histórica midió **hueco máximo 40,8 min** (`baseline_meta.md:145`) ⇒ «ningún hueco > 30 min» **fallaría por diseño** | mismos criterios, umbrales **pre-registrados con evidencia** en vez de copiados |
| **10** | **Bóveda B10** (`plan.md:1114-1129`) | **B10-W**: Sysmon 15.22 + `sha256` de su config + canales + política 4688/4104 + `ossec.conf` del 002 + cliente Windows + receta + campaña | **otra telemetría** ⇒ **otra bóveda** y **`boveda_version=3`** con `plataforma=windows` | la bóveda congela *qué se mide*; cambiar de plataforma cambia la telemetría, no la métrica |
| **11** | **E0** de 10 pasos (`plan.md:945-956`) | **WE0** de 13 pasos (§8, incluye **2b**: herramientas) | 4 pasos nuevos: Sysmon config, **`where` de herramientas**, WU/Defender y **medición de `M`** | «ningún artefacto se estrena la noche de `t0`» |
| **12** | **Keepalive del invitado** (`guest/tfg_keepalive.sh`, tarea `systemd`) | `tfg_keepalive_windows.ps1` como **tarea programada SYSTEM**, cada 5 min | `systemd` → Programador de tareas | misma función: latido, recuperación del cliente y guarda de disco (**sin acceso del host al invitado**, §9) |
| **13** | **Vigilancia `watch`** cada 30 min, host + manager, 9 señales (`plan.md:995-1015`) | mismas señales adaptadas; **el disco del invitado se lee antes/después, no en vivo** (§9, W-L1) | en Linux el `df` venía del agente; en Windows no hay equivalente pasivo | se sustituye por **guarda local** + presupuesto de escritura declarado |
| **14** | **Secuencialidad**: una plataforma a la vez, host de 16 GB (`roadmap.md:110`) | **la ventana Windows no convive con la de Linux**: manager compartido y RAM | — | evita contaminar `M` y evita el tercer aborto por recursos |

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

Dejar **construida y probada** —sin ejecutarla— la ventana legítima de **`victima-windows`**:
una **receta** de jornada de oficina con la **misma estructura** que la de Linux, una **campaña de 11
casos benignos que parecen ataque**, la **instrumentación del denominador `M`** para el agente `002`,
los **criterios de validez**, el **plan de extracción**, el **sello B10-W** y un **ensayo WE0**. Al
terminar, la ventana se podrá armar en un solo día, con la fecha fijada por regla.

### 1.2 Entra

- **Estudiar** (hecho: §2) y **decidir** (§3).
- **Construir**: generador de receta Windows, campaña, validador, extractor de alertas Windows,
  controlador del host (prep/arm/watch/stop/cleanup), keepalive del invitado, deploy idempotente.
- **Probar en seco dos veces** y **ensayar WE0** en un revert desechable.
- **Sellar B10-W** y dejar la ventana lista para fijar fecha.

### 1.3 NO entra

- **Ejecutar la ventana** (72 h). Se decide **después** de que cierre la de Linux (2–5/11).
- **Modificar** `plan.md` (raíz), `_recursos/`, `Hojas/`, `Dataset/`, `Soporte/Metrica/`, el corpus,
  el ruleset, la config de Sysmon ni el laboratorio existente.
- **Tocar** los artefactos del bloque Linux: `construir_receta_legitima.py`, `campana.py`,
  `extraer_campana.py`, `construir_receta_legitima`'s `BINARIOS_OK`, `legitimo_host_control.ps1`,
  `exportar_acciones.sh`, `contar_denominador.py`, `extraer_alertas.py` (**se reutilizan tal cual o
  se envuelven; nunca se editan**).
- **Ejecutar ataques Windows** (eso es `B1 fase-03b`) y **analizar** (eso es `L2`).
- **Instalar** Office, navegador, ni software en la víctima.
- **Campaña mutante**: ni `schtasks /create`, ni `reg add`, ni `sc create/config`, ni `net user /add`.
- **Commits** (los hace el orquestador). Sin secretos en ficheros.

---

## 2. Estado de partida verificado (2026-10-29)

| Elemento | Estado real **[H]** | Cómo se comprobó |
|---|---|---|
| **VMs en marcha** | **0** | `vmrun -T ws list` → `Total running VMs: 0` |
| **Snapshots `victima-windows`** | **3**: `base-limpia`, `lab-listo-windows`, `lab-listo-windows-baseline` | `vmrun listSnapshots` |
| **Snapshots `wazuh-server`** | **2**: `base-limpia`, `lab-listo` | `vmrun listSnapshots` |
| **Snapshots `victima-linux`** | **6**, incluido `lab-listo-legit-v3` (la ventana Linux está lista y pausada) | `vmrun listSnapshots` |
| **Tareas `TFG-*` del host** | **4 `TFG-Baseline-*` en `Ready`**, con `StartWhenAvailable=True` y disparadores del **2026-10-08** (pasados). Una de ellas (`...-Afternoon-Stop`) **apaga el manager** | `Get-ScheduledTask` + `Get-ScheduledTaskInfo` |
| **`TFG_GUEST_PW`** | **presente** (valor no mostrado); `TFG_GUEST_USER` ausente ⇒ el script usa `angel` | entorno de usuario |
| **`wuauserv` (host)** | `Stopped` / `Manual` | `Get-Service` |
| **Disco `D:`** | **181,0 GB** libres | `Get-PSDrive D` |
| **RAM del host** | 15,9 GB totales / **11,5 GB** libres | `Win32_OperatingSystem` |
| **Uptime del host** | arranque **2026-10-22 14:31** local | ídem |
| **Repositorio** | **limpio**; `HEAD = f150dca` | `git status --short` (vacío), `git log` |
| **GHOSTS (host)** | API y PostgreSQL **parados**; fuente `D:\TFG-VMs\material-ghosts\GHOSTS` (*tag* `v8.3.1`, commit `4d2e160`) | `Get-Process`, `prestaging_material.md:14` |
| **Cliente GHOSTS de Windows** | **NO existe** ni descargado ni compilado | `D:\TFG-VMs\material-ghosts\` no lo contiene; no hay `ghosts.client.windows` en `src/` |
| **Toolchain para compilarlo** | **NO**: sin VS Build Tools, sin *targeting pack* de .NET Framework 4.6.2, solo `MSBuild.exe` **4.0** (no soporta `PackageReference`) | `Test-Path` del targeting pack = `False`; `Get-ChildItem` de MSBuild |
| **Inventario P1-Windows** | **89** técnicas · **77** aplicables a Windows · **75** factibles · **38** con prueba ART Windows · 13 no factibles | recuento reproducible sobre `Hojas/inventario_p1_windows.csv` |
| **Corpus de ataques Windows** | **NO existe** (`Dataset/Ataques/Resultados/Wazuh/` = `Auditado`, `CSV`, `linux`, `Logs`, `Perf`) | `Get-ChildItem` |
| **Baseline Windows (2×4 h, 08/10)** | **159 alertas**, **7 `rule.id`**, 4 estables / 3 variables; `67027` = **132 (83 %)**; **hueco máximo 40,8 min** | `Dataset/Legitimo/windows/{ruleids_legitimos.csv,estabilidad_windows.csv,baseline_meta.md:138-176}` |
| **Agente `002`** | última evidencia documentada: `active`, Wazuh 4.14.7, Sysmon **v15.22** (SwiftOnSecurity, `sysmonconfig-export.xml`, 123 257 B, *source v74*) | `state.md:29`, `baseline_resultado.md:§1-4`, `construccion_resultado.md:26-27` |
| **`logall_json`** | **`no`** (se activa solo en `[t0,t1]`) | `_fases/legitimo-72h-v2/change-doc.md:59` |

> **Lo que este estado obliga a cambiar respecto de lo que se supone:** la **ausencia de toolchain**
> (§3, D1) y la **existencia de 4 tareas vivas** que revierten/pagan la VM (§12, R-W1) **no estaban
> previstas** en ningún documento previo. Van en «lo que no cuadra» (§18).

---

## 3. Decisiones con coste/beneficio

### D1 — Quién ejecuta la actividad

| Opción | Qué es | Coste | Ventaja | Inconveniente / riesgo | Veredicto |
|---|---|---|---|---|---|
| **A. `Ghosts.Client` (Windows) publicado por CMU, `v8.3.1`** | Descargar el ZIP «Windows x64» del *release* `v8.3.1` (55 MB, enlazado desde el propio *release*), fijar `sha256` propio, desplegar | **~2-3 h** (descarga + huella + despliegue + prueba) | **misma versión, mismo API, misma tabla `history_timeline`** ⇒ la unidad «acción» y el `FP/acción` son comparables al 100 % | **no hay `sha256` publicado**: el pin es *nuestro*; procedencia declarada `[S]`; el binario es .NET 4.6.2 (Windows 10 trae 4.8: OK) | **RECOMENDADA** |
| **B. Compilar `Ghosts.Client` en local** | Instalar VS Build Tools + targeting pack 4.6.2, `nuget restore`, `msbuild` | **~5-7 h** + **2-4 GB** de instalación en el host | reproducibilidad desde el commit `4d2e160` (mejor procedencia) | *csproj* **legacy** con `PackageReference` (necesita MSBuild ≥ 15) y ~150 paquetes: riesgo real de fallar | **Plan B** (si A no arranca) |
| **C. Adaptar el script PowerShell existente** | Reutilizar `baseline_actividad_windows.ps1` (sha `EB60DF9D…`) | **~1-2 h** | cero dependencias nuevas | **rompe el espejo**: sin GHOSTS no hay tabla de acciones ⇒ **no hay `FP/acción`**; y **el precedente histórico ya falló como unidad**: 68 eventos de proceso en 4 h porque todo eran cmdlets en un único `powershell.exe` **[H]** | **Solo si A y B fallan** ⇒ el bloque cambia de naturaleza y se declara («legítimo guionizado, no NPC», igual que el plan B de `L0`, `decision_gonogo.md:44-48`) |

> **D1 = A.** Criterio aplicado: la comparabilidad manda (misma filosofía, misma estructura, **misma
> unidad**), y A es la única opción que la da a coste razonable.
>
> **Verificación previa obligatoria (WE0-2):** el timeline de Windows **acepta el mismo JSON** que el
> de Linux (el `d1.json` ya usa `"HandlerType": "Command"` **[H]**) y **reporta** las acciones. Si no
> reporta (bug análogo al `|` de `Bash.cs`, `state.md:10` H-1), se cae a B **antes** de seguir.

### D2 — Qué es «receta» en Windows

**[D] Traslado por ranuras.** La receta Windows **no se inventa**: se **porta** de la de Linux.

1. Se toma `recetas/d1|d2|d3.json` (**147/153/141 acciones**) y se extrae, **por bloque** (B1–B5, B6),
   el vector `(nº de eventos, DelayAfter de cada uno)`.
2. Se escribe una lista de comandos Windows **de la misma longitud** por bloque (`B1w…B5w`), con la
   misma semántica de mini-tarea.
3. El validador **falla** si `n` o los `DelayAfter` difieren en un solo elemento ⇒ el ritmo es
   **idéntico**, no «parecido».
4. Los comandos se reescriben en `cmd`/PowerShell con **una entrada = un `cmd /c`** (N-7).

Coste: **~6-8 h** (incluye la traducción de las ~150 mini-tareas y el validador). Alternativa
descartada: escribir una receta Windows independiente con su propio jitter (**+2 h y pierde la
igualdad 1:1**; además el humano pidió espejo).

Reglas duras del validador Windows (CA-W3):

- **0 pipes** en la cadena de `cmd` (la lección de `Bash.cs` se mantiene por prudencia; los pipes
  **dentro** de un argumento `powershell -Command` **sí** se permiten y se declaran, §4.5).
- **0 comandos mutantes de sistema**: `schtasks /create|/delete|/change`, `reg add|delete|import`,
  `sc create|delete|config`, `net user … /add|/delete`, `bcdedit`, `vssadmin`, `cipher /w`,
  `format`, `diskpart`, `icacls … /grant|/deny`.
- **0 aleatoriedad**: ni `%RANDOM%` ni `Get-Random`.
- **0 evasión**: nada de `-EncodedCommand`, `-WindowStyle Hidden`, `-ExecutionPolicy Bypass` fuera de
  la tarea del invitado.
- **Rutas** dentro de `C:\Users\angel` y `C:\lab-legit` (más `%TEMP%` del usuario).
- **`cd` explícito** por comando cuando el `cwd` importe (espejo del plan B de Linux, `plan.md:320`).

### D3 — El denominador `M`: aislamiento y volumen

| Aspecto | Linux | Windows | Decisión |
|---|---|---|---|
| Quién cuenta | `contar_denominador.py`, `--agent-id 001` (defecto) | `--agent-id 002 --agent-name victima-windows` | **[D]** pasar los argumentos explícitos y **dejarlos escritos** en el sello (un `001` por defecto es una bomba silenciosa) |
| Contaminación por el otro agente | — | el `001` seguiría reportando `503/504` al manager | **[H]** esos eventos llevan `agent.id = 000` (manager) ⇒ **no entran en `endpoint`**; el script ya distingue `endpoint` de `total` (`contar_denominador.py:13-16`) |
| Aislamiento físico | — | **[D]** la VM Linux se queda **apagada** durante toda la ventana Windows (RAM: 6 + 4 = 10 GB de 16; y el `watch` no debe ver dos agentes) | secuencialidad de `roadmap.md:110` |
| Volumen | **≈4,17 MB/h** (≈300 MB/72 h) medido en `L0` (`decision_gonogo.md:59-62`) | **desconocido**. Sysmon (config SwiftOnSecurity) + `Security` + `4104` pueden ser **5-20×** Linux **[S]** | **[D]** **se mide** en WE0 con 60 min instrumentados (§8, WE0-9) y se aplica un **disparador pre-registrado**: proyección **> 5 GB** ⇒ fallback de la métrica (`metrica_hids.md:61-64`, caso L11: se publica `FP/acción` + `FP/hora` y `M` queda declarado); proyección **2-5 GB** ⇒ adelante con el manager con **≥ 3× la proyección libre** |

### D4 (secundaria) — Con qué **usuario** corre la actividad: **`angel`, no `SYSTEM`**

**[H]** El *baseline* histórico corrió como **`SYSTEM`** (`S-1-5-18`, `baseline_resultado.md:62-63`).
**[D]** La ventana Windows corre como **`angel`** (usuario estándar), tarea «ejecutar tanto si el
usuario inició sesión como si no».

- **Por qué:** en Linux toda la actividad corre como `angel` **no root**, y eso es la mitad del
  argumento de T5 (`plan.md:353-355, 1367-1370`). Un `SYSTEM` hace que **cada** acción legítima se
  parezca a un atacante con privilegios: `IntegrityLevel=System`, `win_user=SYSTEM`, escrituras en
  rutas de sistema. Sería un artefacto **peor** que el `cwd` de bot que arreglamos en Linux.
- **Coste:** ~30 min (credencial guardada en la tarea; si el perfil no se carga, se corrige con
  `AutoAdminLogon` dentro de la imagen, declarado). **Riesgo:** alguna herramienta exige elevación
  (`wevtutil qe Security`, `eventcreate`) ⇒ se sustituye y se declara (§5, W-03/W-10).
- **Trampa que hay que cerrar:** el **keepalive** corre como `SYSTEM` (para poder reiniciar servicios),
  así que **no puede lanzar el cliente directamente** — lo haría como `SYSTEM` y rompería D4 en
  silencio. Se reinicia **relanzando la tarea `TFG-WinLegit-Actividad`** (`schtasks /run`), que conserva
  **su** principal (`angel`). Comprobación: CA-W5 (`win_user=angel`) **también después de una
  recuperación** (W3).
- **Efecto medible:** se espera **menos** ruido de nivel alto que como `SYSTEM` (hipótesis **H-W2**,
  falsable, §9.4).

### D5 (secundaria) — Snapshot nuevo: **sí**, uno

**[D]** `lab-listo-windows-legit` (hijo de `lab-listo-windows`), con cliente + receta + campaña +
keepalive + `hosts` ya dentro. Los 3 snapshots actuales **intactos** (3 → 4).
**Por qué:** `prep` **revierte** a un snapshot; si el material no está dentro, la reversión lo borra
(la lección está escrita en `baseline_resultado.md:77-95`). La decisión de Linux «sin snapshot nuevo»
era sobre **no añadir otro tras un fallo** (`plan.md:912-918`), no sobre no tener uno de trabajo.
Coste: ~1,5 GB de disco (hay 181 GB).

### D6 (secundaria) — Orden respecto de B1 y versionado de la bóveda

- **[D]** La ventana Windows **no** espera a B1 (los ataques Windows). Consecuencia declarada: el
  `FPR` de Windows nacerá **sin pareja de `TPR`**; se publica igual (es una medida válida de `M` y de
  FP), y la comparación se hace con `FP/acción` y `FP/hora`.
  *Alternativa (si el humano prefiere):* hacer B1 primero; cuesta **+2-3 semanas** de reloj y no
  cambia nada de lo que se construye aquí (§15, Q5).
- **[D]** `boveda_version = 3` para la ventana Windows (2 = Linux). La bóveda congela la telemetría;
  Sysmon + registro es **otra** telemetría ⇒ otro número. Se aplica en el sello y en la cabecera de
  cada CSV de la ventana Windows, **sin tocar** la bóveda de Linux.

---

## 4. La receta Windows (qué se construye)

### 4.1 Estructura (idéntica a Linux)

| Bloque | UTC | Qué | Nota |
|---|---|---|---|
| **B1** | 08:00–08:12 | llegada: abrir carpetas, leer correo guardado, crear la agenda del día | espejo de `bloques.env` |
| **B2** | 08:12–10:00 | mañana: documentos, CSV, búsquedas, web interna | |
| **P1** | 10:00–10:20 | café (**sin actividad**) | |
| **B3** | 10:20–13:00 | documentos largos, compresión, copias | |
| **P2** | 13:00–14:00 | comida (**sin actividad**) | |
| **B4** | 14:00–16:15 | tarde: informes, sincronización, incidencias | |
| **B5** | 16:15–17:00 | cierre del día | |
| **B6** | 17:05–17:50 | **campaña** (declarada, no es jornada) | 3/4/4, inicios 17:06/17:17/17:11 |

**[D]** Mismas horas **UTC** que Linux (08:00-17:00Z). No se adapta a «horario español»: la
comparación con Linux exige el mismo reloj, y el desfase local ya está declarado en el plan de Linux
(`plan.md:482-485`).

### 4.2 Vocabulario (derivado del ruleset y del inventario, **no del corpus**)

| **Familia** | **Herramientas** | **Reglas que puede tocar (fuente)** |
|---|---|---|
| **Descubrimiento** | `whoami`, `hostname`, `systeminfo`, `tasklist`, `ipconfig`, `route`, `getmac`, `arp`, `nslookup` | `67027` L3 (proceso), `92xxx` (Sysmon 1) |
| **Ficheros / ofimática de consola** | `dir`, `type`, `more`, `findstr`, `fc`, `copy`, `move`, `robocopy`, `tar` **[S]**, `makecab`, `certutil -hashfile`, `attrib`, `icacls` (lectura) | `67027`, `92xxx`, `92200-92227` (Sysmon 11) |
| **Sistema / registro (lectura)** | `reg query`, `sc query`, `schtasks /query`, `wevtutil qe`, `netsh advfirewall show`, `net start`, `net user` (lectura) | `67027`, `60xxx`, `60100-60232` |
| **Red** | `curl.exe` **[S]**, `ping`, `tracert`, `bitsadmin /list` **[S]** | `67027`, `92101-92110` (Sysmon 3) |
| **Scripting** | `powershell -NoProfile -Command …` (CSV, JSON, fechas, hashes) | `91801-91846` (**4104**), `67027` |
| **Compresión / empaquetado** | `tar -czf` / `tar -xzf` **[S]**, `makecab`, `expand` | `67027`, `92200-92227` |

> **[S]** `curl.exe` (desde Windows 10 1803), `tar.exe`/bsdtar y `bitsadmin` (obsoleto pero presente)
> **se suponen** en la imagen. **WE0-2b** lo comprueba con `where`, que es el espejo de `command -v` de
> Linux. **Si falta una, se cae esa herramienta; no se instala** (`plan.md:246`, P-2).

Coste: **~2 h** de traducción + validación. Regla: **cada entrada es una orden que un oficinista
escribiría**; nada de rutas de laboratorio en el texto del comando más allá de `C:\lab-legit`.

### 4.3 `cwd` y sesión

- `WorkingDirectory` de la tarea = **`C:\Users\angel`**; `cd /d C:\Users\angel\...` explícito en las
  entradas que lo necesiten.
- **Se mide** `win_cwd` en Sysmon EID 1 (N-2). CA-W5: **0** acciones con `win_cwd` en
  `C:\Windows\System32` o en el directorio del cliente.

### 4.4 Errores con reintento (la trampa de `cmd`)

**[H, técnico]** En `cmd`, `%ERRORLEVEL%` se expande **al analizar la línea**, no al ejecutar ⇒
`cmd /c "dir X & echo %ERRORLEVEL%"` imprime el valor **anterior**. Patrones admitidos:

```bat
cmd /c "dir C:\Users\angel\Documents\informe 2>nul & if errorlevel 1 (>>C:\lab-legit\errores.log echo 2026-11-09T09:12:03Z	ruta_mal	dir ...\informe	rc=ge1	reintento=dir ...\informes) & dir C:\Users\angel\Documents\informes"
cmd /c "certutil -hashfile x.txt MD6 >nul 2>&1 & if errorlevel 1 (>>C:\lab-legit\errores.log echo ...	opcion_invalida	MD6	rc=ge1	reintento=SHA256) & certutil -hashfile x.txt SHA256"
```

> **`call :log` no vale**: en una línea de `cmd /c` no hay etiquetas (`:log` solo existe dentro de un
> `.bat`). Si se necesita el **rc numérico exacto**, se obtiene con **una acción aparte** de
> `powershell -Command "'rc='+$LASTEXITCODE"` (declarada, +1 proceso) — y **solo** en los casos donde el
> número aporta (los 3 que se declaran en T1).

**[D]** `errores.log` (TSV, misma función que Linux) con: `ts · familia · comando · rc (exacto o
`ge<N>`) · reintento · rc_reintento`. **10/día** repartidos, y **cada error seguido del reintento
correcto**. Familias (espejo de las de Linux, `plan.md:583`):

1. Ruta mal escrita → `dir` de `…\informe` (rc 1) → `dir …\informes`.
2. `copy` a carpeta inexistente (rc 1) → `md` → `copy`.
3. `type` de un directorio (rc 1).
4. Opción inválida → `certutil -hashfile x MD6` (rc 1) → `SHA256`.
5. **`type` de un temporal ausente** (rc 1; **en Windows `del` de un fichero inexistente devuelve 0**, así que el «error» se materializa con `type` y el reintento con `del /f /q`; se declara).
6. `robocopy` con origen inexistente (**rc 16**, es una máscara: se compara `if errorlevel 8`).
7. `curl.exe` a puerto cerrado (**rc 7**) → reintento al 8080.
8. `findstr` sin coincidencias (**rc 1 legítimo, no es error**): se declara para no inflar el conteo.
9. `tar` de un fichero inexistente (rc 2).
10. `powershell` con ruta inexistente (rc 1) → reintento.

**Coste:** 2 h. **Riesgo:** que el patrón `if errorlevel` no escriba el log ⇒ **WE0-6** lo prueba con
los 10 casos en 5 minutos.

### 4.5 PowerShell: excepción del pipe

**[D]** Los pipes **dentro** de un argumento `powershell -NoProfile -Command "…"` **se permiten**.
**Por qué:** el bug de GHOSTS (`Bash.cs` pierde el reporte con `|`, `state.md:10` H-1) atañe a la
cadena que ejecuta el handler, no al interior de un intérprete; aquí el proceso es **uno**
(`powershell.exe`) y su salida se captura entera. **Se verifica en WE0-2** (si el reporte se pierde,
se prohíbe también y se declara). **Ventaja:** ejercita **4104** (`91801-91846`), canal que Linux no
tiene y que es superficie real de Windows.

---

## 5. La campaña Windows (11 casos espejo)

> **Estado de la evidencia:** **[S] predicción**. No hay corpus Windows (N-1). El «esperado» se
> pre-registra **por umbral**, no por `rule_id` exacto (salvo `67027`, que es la regla de ejecución y
> **debe** aparecer si el caso se ejecutó).

### 5.1 Hipótesis pre-registradas (antes de ejecutar nada)

- **H-W1.** A `N ≤ 3`, **cada proceso creado es un FP** por **`67027`** (L3, «A process was created»,
  `0955-WEF-baseline_rules.xml` 67011-67029, `active_ruleset.txt:191`) — el análogo funcional de
  `80792`. **[H parcial]** es la única regla L3 de creación de proceso observada en la baseline
  (132 de 159 alertas, `ruleids_legitimos.csv`); su mapeo evento→regla se confirma en **WE0-3**.
- **H-W2.** Como usuario **estándar** (D4), a `N ≥ 7` la actividad benigna queda **casi vacía**.
  La baseline histórica solo produjo **1 alerta L9 por ventana** (`92201`, `powershell.exe` creando
  un fichero de scripting en `Temp`, `estabilidad_windows.csv:8`) — y esa, como `SYSTEM`, sería
  **peor**. Se espera **≤ 2 alertas L≥7 en 72 h**; si hay más, **es un hallazgo**, no un fallo.
- **H-W3.** El techo de ruido de régimen es **menor** que en Linux (7 reglas vs 12; el propio
  proyecto ya lo anotó, `state.md:33`), pero **más intermitente** (hueco máx. 40,8 min).

### 5.2 Tabla maestra (11 casos · `d1` 3 · `d2` 4 · `d3` 4 · B6 17:05–17:50Z)

> **Convención de severidad:** la misma que Linux (`P4 = nivel 0-3`, `P3 = 4-6`, `P2 = 7-11`,
> `P1 ≥ 12`), para poder comparar con el TFM hermano (`plan.md:657-659`).
> **«Se confunde con»:** técnica MITRE del inventario P1-Windows + el `ATA` de Linux con el **mismo
> mecanismo** (analogía declarada, **no** evidencia Windows).

| # | Caso (espejo de) | Qué hace | Ejecutables | Se confunde con | Esperado `N≥3` | Esperado `N≥7` | ¿Muta? | Dónde |
|---|---|---|---|---|---|---|---|---|
| **W-01** | El equipo va lento (C-01) | `tasklist /svc`; `systeminfo`; `sc query state= all` | `tasklist`, `systeminfo`, `sc` | T1057 · T1082 (ATA004/045 Linux) | `67027` L3 ×3 | **0** | No | `C:\lab-legit\campana\W-01\` |
| **W-02** | No me va la intranet (C-02) | `ipconfig /all`; `route print`; `findstr /c:"192.168.65."` sobre la salida (evidencia) | `ipconfig`, `route` | T1016 · T1018 (ATA054/055) | `67027` L3 ×2 | **0** | No | idem |
| **W-03** | ¿Está la copia programada? (C-03) | `schtasks /query /fo LIST`; `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `schtasks`, `reg` | T1053.005 (lectura) · T1547.001 (lectura) (ATA021) | `67027` L3 ×2 | **0** (solo lectura) | No | idem |
| **W-04** | Protejo el informe (C-05, **parcial**) | `powershell` AES cifra/descifra con clave fija; `certutil -hashfile informe.txt SHA256`; `certutil -hashfile informe.txt.rec SHA256` | `powershell`, `certutil` | T1486 (ATA001/019/041) | `67027` L3 ×3 + `91801-91846` (4104) | **0** | Transitorio (se borra) | idem |
| **W-05** | Limpio temporales (C-06, **parcial**) | `rd /s /q tmp`; `powershell` sobrescribe `borrador.txt` (**2 sobrescrituras: ceros + patrón**) **+ borrado** | `powershell` (builtin `rd` ⇒ 1 `cmd.exe`/acción) | T1070.004 · T1485 (ATA003/005) | `67027` L3 ×2 + `91801-91846` | **0** | Solo lo suyo | idem |
| **W-06** | Sincronizo informes (C-07) | `robocopy C:\lab-legit\campana\W-06\origen C:\lab-legit\campana\W-06\destino /MIR` | `robocopy` | T1039 · T1074.001 (ATA039/040) | `67027` L3 ×1 + `92200-92227` por fichero creado | **0** **[S]** | Transitorio | idem |
| **W-07** | Normalizo el CSV (C-08) | `powershell -NoProfile -Command "(Get-Content …\export.csv) -replace ';',',' \| Set-Content …\export2.csv"` | `powershell` | T1565.001 (ATA006/032/026) | `67027` L3 ×1 + **`91801-91846` (4104)** | **0** **[S]** | Transitorio | idem |
| **W-08** | La intranet no responde (C-09) | `curl.exe -sS --max-time 3 -o intranet.html -w "%{http_code}" http://intranet.local:8080/`; `curl.exe -sS --max-time 2 http://intranet.local:8081/`; `curl.exe -sS -o reintento.html http://intranet.local:8080/` | `curl` | T1496.001 · T1048 (ATA025/009/050) | `67027` L3 ×3 comandos (≈6 procesos) | **0** | No | idem |
| **W-09** | Preparo el lote (C-10) | `for /L %i in (1,1,12) do @cmd /c copy /y plantilla.txt lote_%i.txt` | `cmd /c copy` (12 procesos, **espejo de `xargs`**) | T1499.002/.003 (ATA046/047) | `67027` L3 ×13 (1 `cmd` + 12 `cmd /c`) | **0** | Transitorio | idem |
| **W-10** | Dejo constancia (C-11) | `eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO ofimatica /D "…"` | `eventcreate` | T1056.001-adyacente (ATA018); **escritura benigna en registro** | `67027` L3 ×1 + `60600-61072` (app log) **[S]** | **0** **[S]** | **1 evento** (declarado, no se borra) | idem |
| **W-11** | Descargo el manual (C-12) | `curl.exe -o manual.pdf http://intranet.local:8080/descargas/manual_empleado.pdf` | `curl` | **T1105** (ATA008/043) | `67027` L3 ×1 | **0** (`certutil -urlcache` **retirado**: era una hipótesis y un patrón clásico de detección) | Transitorio | idem |

**Cuentas:** 11 casos · **22 marcas** (`inicio`/`fin`) · **63 acciones** y **75 procesos** (cota
inferior: 63 `cmd.exe` + 12 hijos de W-09), medidos en el pre-registro (W2; antes el plan
estimaba ~40/~55). El número exacto lo fija `campana_windows.csv` y se sella (CA-W2).

> **Cómo leer «Esperado `N≥3`».** Cada acción es un `cmd /c` ⇒ **~2 procesos por comando** (el `cmd.exe`
> y la herramienta). El recuento de `67027` es por tanto **≥ el número de comandos**, y el número exacto
> **se mide** (los recuentos de la tabla son cotas inferiores, no promesas). Lo que **sí** se
> pre-registra es lo falsable: **`67027` debe aparecer** (si no, el caso no se ejecutó) y **ninguna regla
> `≥ 7`** salvo la hipótesis declarada de W-11.

### 5.3 Diferencias declaradas con la lista de Linux

| Cambio | Motivo | Coste asumido |
|---|---|---|
| **C-05 y C-06 pasan a parciales** | sin cifrado con contraseña ni borrado seguro nativos (N-4, N-5) | se pierde la medición legítima de T1486 y T1561 **en Windows**; se declara |
| **C-10 usa `for /L` + `cmd /c copy`** | Windows no tiene `xargs`; el `copy` del `cmd` hijo conserva el **abanico de 12 procesos** (W1 descartó `xcopy`: no creaba los 12 ficheros) | misma intención y mismo fan-out; se valida en WE0-6 |
| **C-11 usa `eventcreate`** | `logger` no existe; es el «escribir en el registro de eventos» | **riesgo:** `eventcreate` puede exigir elevación. **[D]** Si en WE0 falla como `angel`, el caso se convierte en **lectura** (`wevtutil qe Application /c:5 /rd:true /f:text`) y se declara la pérdida |
| **C-04 sigue fuera** | no mutación (N-6) | se pierde la única vía benigna a una regla de persistencia; **se declara** |
| **No hay `systemctl`/`crontab`** | no existen | `sc`/`schtasks` cubren el mecanismo (en **lectura**) |

### 5.4 Pre-registro y ejecución

- **`casos_windows.md`** (esta tabla + H-W1..H-W3) y **`campana_windows.csv`** (11 filas, comandos
  literales), con **`sha256` y fecha anterior a `t0`** (CA-W2).
- **Marcas:** `inicio.txt` → comandos → `hecho.txt` (evidencia de efecto) → `fin.txt`. **2 marcas por
  caso** (22), declaradas como acciones.
- **Atribución:** alertas del agente `002` en `[ini−10 s, fin+60 s]`; ventanas **sin solape**
  (separación ≥ 3 min, 3/4/4 en 45 min).
- **No mutación:** 0 escrituras fuera de `C:\lab-legit\campana\W-XX\`; 0 `schtasks`/`reg`/`sc` de
  escritura; comprobación `reg query` + `schtasks /query` **idénticos** antes/después (espejo de
  `crontab -l`, CA-W8).
- **Honestidad:** si un caso alerta a `N ≥ 7`, **se publica** con su `level` y su `P`; **no se
  re-ejecuta**. Si un caso **no** produce `67027`, **no se ejecutó** (no es «0 alertas»).

---

## 6. El denominador `M` en Windows

### 6.1 Instrumentación

Idéntica a Linux: `<logall_json>yes</logall_json>` en el manager **solo en `[t0,t1]`**; rotación
`ossec-archive-<DD>.json[.gz]`; **un solo `M`** sobre la ventana completa; `--estricto`; `MANIFEST`
con `sha256` y dedupe (la métrica exige cabecera con versiones y hashes, `metrica_hids.md:180-181`).

### 6.2 Aislamiento (respuesta a «si el agente `001` está activo, contamina»)

| Riesgo | Verdad comprobada | Mitigación |
|---|---|---|
| `M` incluye al agente `001` | **No**, si se filtran los argumentos: el script separa `endpoint` (agente medido) de `total` (`contar_denominador.py:13-16, 159-162`) | **[D]** `--agent-id 002 --agent-name victima-windows` **explícitos** y escritos en la cabecera del CSV |
| `logall_json` capta al manager (`000`) | Sí | fuera del `endpoint`; se reporta `total` como dato de contexto |
| Volumen duplicado / RAM | Sí si Linux estuviera encendido | **[D]** VM Linux **apagada** durante la ventana |
| Acciones de otro cliente en `history_timeline` | `exportar_acciones.sh` **no filtra por máquina** (`exportar_acciones.sh:30-33`) **[H]** | **[D]** ventana con **un solo cliente vivo** + **CA-W6**: el rango contiene **exactamente 1 `machineid`** |

### 6.3 Volumen: no se estima, se mide

**[D]** En WE0 se instrumenta **60 min** con la receta real y se calcula:

```
proyeccion_72h = bytes(archives en 60 min) × 72
```

- **< 2 GB** ⇒ adelante.
- **2–5 GB** ⇒ adelante con **≥ 3×** de disco libre en el manager (verificar en `prep`).
- **> 5 GB** ⇒ **disparador de la métrica** (`metrica_hids.md:61-64`): se publica `M = n/a` y el
  titular cae a `FP/acción` + `FP/hora`, **declarado como limitación** (caso L11). **No** se cambia la
  métrica.
- **Fuera de banda de plausibilidad** (`M_W` < 5 000 o > 200 000 eventos/hora) ⇒ **no invalida**, pero
  dispara revisión manual antes de `t0` (puede ser agente mal configurado).

---

## 7. Tandas W1–W4: qué se construye y cómo se prueba

> **Regla de oro (la misma de Linux):** ningún artefacto se estrena la noche de `t0`; **dos
> generaciones idénticas y dos ejecuciones completas** sobre un revert desechable.
> **Cuándo:** después de que cierre la ventana Linux (2–5/11) y su extracción. **Sin fechas** dentro de
> cada tanda.

### W1 — Generador y receta · ~8 h

| Se construye | Cómo se prueba |
|---|---|
| `construir_receta_legitima_windows.py`: traslado por ranuras desde `recetas/d1-d3.json`; `--check`; `bloques.env` compatible; escribe `Soporte/Laboratorio/windows/recetas/{w1,w2,w3}.json`, `calendario_windows.json`, `bloques_windows.env`, `receta_windows_resumen.md`; `verificar_espejo.py` comprueba 504=504 y los `DelayAfter` | **dos generaciones byte-idénticas** (`sha256`); **0** `random`/`Get-Random`; 0 pipes; 0 comandos mutantes; **igualdad de ranuras** con Linux (CA-W1, CA-W3) |
| Traducción de las ~150 mini-tareas a `cmd`/PowerShell + documento de trazado por bloque | revisión humana de la tabla «tarea Linux → tarea Windows» (no se automatiza el juicio) |
| Familias de error (§4.4) + `errores.log` | prueba en seco de los 10 patrones: 10 líneas con rc, 10 reintentos correctos |

**Salida:** `Soporte/Laboratorio/windows/recetas/` + `receta_windows_resumen.md`.

### W2 — Campaña, validador y extractores · ~8 h

| Se construye | Cómo se prueba |
|---|---|
| `campana_windows.csv` (11 casos, comandos literales) + `casos_windows.md` (pre-registro) | `sha256` + fecha; 11 filas; 22 marcas; 0 mutaciones; set de `rule_id` esperado por umbral |
| `campana_windows.py` (constantes Windows: `RULE_EXEC="67027"`, `UMBRAL_N7=7`, `B6`) y generación del bloque B6 en `d*.json` | misma estructura que `campana.py` (que **no se edita**); el runner de Linux se reutiliza con `--agente victima-windows --agente-id 002` |
| `extraer_alertas_windows.py` (columnas actuales + `win_image`, `win_command_line`, `win_cwd`, `win_user`, `event_id`) | prueba con las **159 alertas históricas** de `Dataset/Legitimo/windows/` (debe reproducir los 7 `rule_id` y los recuentos 72/87) |
| `cobertura_herramientas_windows.py` (mismo **procedimiento** de conteo que `cobertura_exes.py`; **no** cobertura comparable) | salida literal: `cobertura_herramientas_windows = n/50` + línea `NOTA:` que declara que mide **solape de `basename`** con el corpus **Linux** y **no** es comparable con el 23/50 de Linux (3/50; solo **2/50** —`curl`, `tar`— estrictamente comparables; `find` de Windows es un filtro de texto, no el `find` GNU). La lectura «contra ruleset + inventario» queda declarada para `B1`/`L2`, no simulada |

**Salida:** `Soporte/Laboratorio/windows/campana/{casos_windows.md,campana_windows.csv}` + `_artefactos/scripts/extraer_alertas_windows.py` y `cobertura_herramientas_windows.py` (+ tests).

### W3 — Despliegue, controlador y snapshot · ~5 h

| Se construye | Cómo se prueba |
|---|---|
| `deploy_windows.ps1` **idempotente y reversible**: cliente GHOSTS, `recetas/`, `campana/`, `hosts` (`intranet.local`), tarea del invitado como **`angel`** con `WorkingDirectory`, keepalive, `errores.log`, tope de `client.out` | 2 aplicaciones = **mismo `sha256`**; revert limpio |
| `windows_legit_host_control.ps1` (fases `prep/arm/watch/stop/cleanup/status/drytest`) con **G-W1…G-W12** | prueba en seco de cada fase con `drytest` (sin ventana) |
| `tfg_keepalive_windows.ps1` (tarea **SYSTEM** cada 5 min: latido, **guarda de disco ≥ 500 MB**, **guarda de WU**; **reinicia la actividad con `schtasks /run /tn TFG-WinLegit-Actividad`**, nunca lanzando el cliente desde SYSTEM) | 2 h de funcionamiento; 1 muerte provocada del cliente ⇒ recuperación en ≤ 2 ciclos **y `win_user` sigue siendo `angel`** |
| **Snapshot** `lab-listo-windows-legit` con todo dentro | revert + arranque: tarea `Ready`, cliente presente, `Sysmon64`/`WazuhSvc` `Running`, `powercfg STANDBYIDLE=0`, sin residuos |

**Salida:** `deploy_windows.ps1`, `windows_legit_host_control.ps1`, snapshot nuevo documentado en
`snapshot_windows_legit.md`.

### W4 — WE0, `M` y fecha · ~3 h

Ejecuta §8 completo, mide el volumen (§6.3), fija `t0` por regla y registra las tareas.
**Salida:** `ensayo_WE0.md` + `ventana_meta.md` + `sha256sums.txt`.

---

## 8. WE0 — ensayo de armado (obligatorio)

| Paso | Qué se hace | Pasa si |
|---|---|---|
| **WE0-1** | Estado de la imagen: `agent_control -l` (`002` **Active**), `WazuhSvc`/`Sysmon64` `Running`, `Sysmon -c` (versión + config) | los tres OK y **`sha256` de la config** guardado |
| **WE0-2** | **Motor**: un timeline de 5 acciones con `HandlerType=Command` → `cmd /c` **reportadas** en `history_timeline`; incluye una con `|` dentro de `powershell -Command` | **5/5 reportadas**; si < 5/5 ⇒ se prohíben los pipes internos y se declara |
| **WE0-2b** | **Herramientas presentes**: `where` de **cada** ejecutable de la receta y de la campaña (espejo de E0-2 de Linux, `plan.md:948`) | todas presentes; **si falta una ⇒ se cae ESA herramienta** (con nota), **no se instala** |
| **WE0-3** | **Ancla**: leer en el manager `win_image`, `win_command_line`, `win_cwd`, `win_user`, `event_id` de esas 5 acciones | `win_image=cmd.exe`, `win_command_line` con el comando, **`win_cwd=C:\Users\angel`**, `win_user=angel` |
| **WE0-4** | `67027` como regla de ejecución: confirmar que cada proceso creado produce `67027` L3 | **nº de `67027` ≥ nº de procesos** de la prueba (H-W1 confirmada) |
| **WE0-5** | **Errores**: los 10 patrones del §4.4 | 10/10 con `rc`, 10 reintentos correctos, `0` falsos (el `findstr` rc 1 **no** se cuenta como error) |
| **WE0-6** | **Un día comprimido**: `d1` recortado (B1 completo + 3 casos de campaña) | acciones según lo previsto; **6/6 marcas**; `campana_windows.csv` generable; **0 mutación** (§WE0-10) |
| **WE0-7** | **`eventcreate` como `angel`** | si funciona ⇒ caso W-10 completo; si no ⇒ **se sustituye por lectura** y se anota |
| **WE0-8** | **WU y Defender dentro del invitado**: `wuauserv` estado, política `NoAutoUpdate`, `TamperProtection`, servicio `WinDefend` | WU **no** puede instalar/reiniciar; Defender **no** vuelve a estar activo; se registra el estado |
| **WE0-9** | **`M`**: 60 min instrumentados con la receta real ⇒ proyección 72 h | proyección calculada y **decisión §6.3 tomada y escrita** |
| **WE0-10** | **No mutación de la campaña**: `reg query` de las claves vigiladas y `schtasks /query` **idénticos** antes/después; 0 ficheros fuera de `campana\` | `diff` = 0 |
| **WE0-11** | **Vigilancia**: 2 chequeos del `watch` + primer chequeo (sin `AVISO` falso) + borde de bloque | 0 falsas alarmas |
| **WE0-12** | **Cierre**: `stop` + `cleanup` con la VM apagada (sin intentos de acceso), `logall_json=no`, `CONFIG_IDENTICA`, revert a `lab-listo-windows-legit` y **0 VMs** | todo OK; `0` residuos |

- **Registro:** `ensayo_WE0.md` (salida literal, horas UTC, veredicto) + evidencias en
  `ensayo_WE0/`.
- **Antigüedad:** WE0 **≤ 7 días** antes de `t0`; si no, **se repite** (~90 min).
- **Coste:** ~90-120 min (más que los 60-75 min de Linux por WE0-8/WE0-9).

---

## 9. Criterios de validez (W-V1…W-V9)

> Pre-registrados **antes** de ejecutar. Un fallo **objetivo** invalida y se repite; el juicio de
> «podría ser más realista» **no** invalida (cláusula anti-aborto, `plan.md:538-545`).

### 9.1 La ventana

| # | Criterio | Cómo se comprueba |
|---|---|---|
| **W-V1 — Cobertura** | primera alerta del `002` ≤ `t0+10 min`; última ≥ `t1−10 min`; **hueco máximo dentro de bloques ≤ 30 min**; **hueco absoluto ≤ 90 min** (P2 = 60 min + margen) | `alertas_detalle.csv` |
| **W-V2 — Actividad** | cada día ≥ **90 %** de su receta (contra `--check`); **0 acciones fuera de los bloques congelados** (salvo recuperaciones declaradas) | `ghosts_acciones.csv` + `bloques_windows.env` |
| **W-V3 — Manager y diarios** | manager `active` en todos los chequeos; los **3 diarios** existen y crecen | log de vigilancia |
| **W-V4 — 0 contaminación** | **0** `4624/4625/4672` desde `192.168.65.1`; **0** procesos con padre **`vmtoolsd.exe`** dentro de `[t0,t1]`; **0** sesiones RDP/consola del operador | `alertas_detalle.csv` + Sysmon (padre) |
| **W-V5 — Aislamiento** | NAT desconectado; `ipconfig` sin puerta de enlace externa; solo VMnet1 | evidencia del invitado (cosecha) |
| **W-V6 — `M`** | copiado **antes** del `off`; `--estricto` `exit 0`; `MANIFEST` con `sha256`; **un solo `M`** con `--agent-id 002` | `denominador_M.csv` |
| **W-V7 — Sin cambios a mitad** | `sha256` de `sysmonconfig-export.xml`, `ossec.conf` del `002`, `bloques_windows.env`, receta y campaña **antes/después**; `CONFIG_IDENTICA`. *Excepciones declaradas:* ficheros de `campana\`, **1 evento** de `eventcreate`, `web_access.log` de la intranet (host) | recálculo + `diff` |
| **W-V8 — Host y invitado estables** | host: `LastBootUpTime < t0`, 0 `Kernel-Power` 42/107. **invitado: 0 reinicios** (eventos `1074/6005/6006/41`), `wuauserv` sin instalación | WMI + `Get-WinEvent` + log del keepalive |
| **W-V9 — Reloj** | Δ(host, invitado) ≤ **2 s** en `prep` y en la cosecha | `w32time` está **apagado** (`state.md:34`) ⇒ depende de **VMware Tools** (`tools.syncTime="TRUE"` **[H]**, en el `.vmx`). Se mide, no se supone |

### 9.2 Válida **con incidencia**

1–2 recuperaciones del cliente (sin huecos > 30 min **dentro de bloque** sin explicar) · una rotación
fallida · duplicados por recuperación (contados) · fallo de herramienta de extracción con fuente
íntegra (se re-extrae) · `eventcreate` que exige elevación (se sustituye y se declara).

### 9.3 Qué **invalida la ventana**

1. Acceso del operador al invitado en `[t0,t1]` (incluido `vmrun runProgramInGuest`).
2. Agente `002` caído o hueco > 60 min.
3. Manager caído > 30 min o falta un diario.
4. `M` no recuperable.
5. Un bloque de trabajo entero sin acciones.
6. **Reinicio del invitado** (Windows Update, crash, `shutdown`), suspensión o cierre de sesión.
7. Cambio de configuración no declarado (**incluida la config de Sysmon**: cambiarla cambia `M`).
8. Más de 2 recuperaciones o alarma de disco/agente sin explicar.
9. **Δreloj > 5 s** medida en la cosecha.

> **Lo que NO invalida:** ningún fallo de la campaña (casos no ejecutados, `hecho.txt` ausente, solape,
> alerta inesperada a `N ≥ 7`). La campaña tiene su propia escala (§9.4), igual que en Linux
> (`plan.md:1061-1062`).

### 9.4 Validez de la campaña

| # | Criterio | Si falla |
|---|---|---|
| **CW1 — Ejecución** | ≥ 9/11 con `inicio`, `fin` y `hecho.txt` | campaña **parcial**; sin marcas ⇒ `NO_EJECUTADO`; marcas sin `hecho.txt` ⇒ `NO_EVALUABLE` |
| **CW2 — Atribución** | ventanas `[ini−10 s, fin+60 s]` sin solape | campaña **no concluyente** |
| **CW3 — Esperado** | cada caso con `esperado_cumplido`; un `NO` a `N≥3` ⇒ **caso no ejecutado** | se reclasifica; **no** se re-ejecuta |
| **CW4 — No mutación** | `reg query` + `schtasks /query` idénticos; 0 ficheros fuera de `campana\` | campaña inválida como campaña; **la ventana sigue** |

### 9.5 Titular

**Un solo `M`** (ventana completa, agente `002`) + **tabla de campaña aparte** con sus recuentos por
caso (`extraer_campana_windows.py --agente victima-windows --agente-id 002`). **No** se publica un FPR
alternativo. Misma decisión que Linux (`plan.md:1106-1110`).

### 9.6 Limitaciones declaradas (para la memoria)

| # | Limitación | Por qué | Qué se hace |
|---|---|---|---|
| **W-L1** | **El disco del invitado no se vigila en vivo** | en Linux el `df` venía del agente; en Windows leerlo desde el host exigiría `runProgramInGuest`, que **mete procesos y rompe W-V4** | guarda local (≥ 500 MB) + presupuesto de escritura + comprobación **antes/después** de la ventana |
| **W-L2** | **`M` y `FPR` no son comparables en crudo con Linux** | son «eventos» de telemetrías distintas (registro vs `auditd`) | se reporta `M` per-plataforma y se compara con `FP/acción` y `FP/hora` (unidad común, `metrica_hids.md:254-268`) |
| **W-L3** | **El `FPR` de Windows no tiene `TPR` de Windows hasta `B1`** | no hay corpus de ataques Windows | se publica el `FPR` con la etiqueta «sin pareja de `TPR`» (D6) |
| **W-L4** | **2 de 11 casos son parciales** (cifrado con contraseña, borrado seguro) | no existen sin instalar | se declara; el hueco de T1486/T1561 legítimo en Windows queda abierto |
| **W-L5** | **La actividad no es una sesión interactiva real** | la tarea corre con «ejecutar tanto si el usuario inició sesión como si no» | se declara; es el mismo límite que Linux declaró (sin PAM, `plan.md:1367-1370`) |

---

## 10. Extracción

> **Orden crítico (idéntico):** cosechar → `cosecha.done` → **parar** → copiar → **`M`** →
> **`logall_json off`** (el `off` **borra** `archives.json`).

| Momento | Paso | Producto |
|---|---|---|
| `t1+2 min` | **Cosecha** (única interacción con el invitado, ya fuera de ventana): `vmrun copyFileFromGuestToHost` de `C:\lab-legit\` (log del cliente, `errores.log`, `keepalive.log`, `estado.json`, `campana\**\{inicio,fin,hecho}.txt`) + `reg query` de las claves vigiladas + `schtasks /query` + `ipconfig /all` + `systeminfo` de cierre. Al terminar, **crear `cosecha.done` en el host** | `ventana_*/evidencia/*.txt` |
| `t1+5` | Ventanas de campaña: `extraer_campana_windows.py --solo-ventanas` | `campana_ventanas_windows.tsv` |
| `t1+10` | **Parada** suave del invitado (**solo si `cosecha.done` existe**; tope `t1+15`) | — |
| `t1+15` | `exportar_denominador.sh info` | log |
| `t1+30` | Copia de los diarios + `MANIFEST.tsv` + **dedupe `sha256`** (fuera del repo) | `D:\TFG-VMs\legitimo-windows-<t0>\denominador\` |
| `t1+45` | Puerta: `MANIFEST` existe, `sha256` cuadran; **si no, NO se apaga `logall_json`** | checklist |
| `t1+45…+55` | **`M` único**: `contar_denominador.py --estricto --manifest --boveda-version 3 --agent-id 002 --agent-name victima-windows` | `denominador_M.csv` |
| `t1+60` | `logall_json off` + `status` + `diff` `CONFIG_IDENTICA` | — |
| `t1+70` | **Alertas**: `extraer_alertas_windows.py` sobre los 3 diarios | `alertas_detalle.csv`, `ruleids_legitimos.csv` |
| `t1+80` | **Acciones**: `exportar_acciones.sh` (**sin editar**; se le pasa la salida) + verificación **1 sola `machineid`** | `ghosts_acciones.csv` |
| `t1+90` | **Tabla de campaña** (`extraer_campana_windows.py --agente … --agente-id 002`) | `campana_fp_windows.csv` |
| `t1+100` | `sha256` de cada producto + `MANIFEST.md` | — |

---

## 11. Bóveda B10-W y versionado

| Elemento | Qué se sella (medido) |
|---|---|
| Ventana | `t0`/`t1` firmados, 72 h, 3 días, medianoche UTC |
| **Telemetría Windows** | Sysmon **v15.22** + **`sha256` de `sysmonconfig-export.xml`** (*source v74*) + **EIDs** que llegan; canales `Security`, `Microsoft-Windows-Sysmon/Operational`, `PowerShell/Operational`; política **4688 con línea de comandos**; **ScriptBlockLogging 4104**; FIM (rutas y claves) |
| **Agente** | `ossec.conf` del `002` (`sha256`) + versión 4.14.7 + **usuario con el que corre** |
| **Cliente** | GHOSTS **v8.3.1** + **`sha256` del binario Windows** + origen (CMU Box o build local, **declarado**) |
| **Receta** | `sha256` de `d1/d2/d3` + calendario + `bloques_windows.env` + conteos de `--check` + **igualdad de ranuras con Linux** (n y `DelayAfter`) |
| **Campaña** | `sha256` de `casos_windows.md` (fecha anterior a `t0`) + `campana_windows.csv` (11 filas) + ventanas |
| **`errores.log`** | `sha256` + conteo de `rc≠0` y reintentos + muestra |
| **Deploy** | `sha256` de `deploy_windows.ps1` + ficheros desplegados + **idempotencia** (2 aplicaciones = mismo hash) |
| **Método** | `logall_json` ON solo `[t0,t1]`; `--estricto`; **un `M`**; `--agent-id 002` **explícito** |
| **Discriminante** | **`win_user=angel`**, `IntegrityLevel=Medium`, `win_cwd` ≠ `System32` |
| **Versiones de medida** | `metrica_version=1`, **`boveda_version=3`**, `plataforma=windows` |
| **Instrumentación declarada** | keepalive (~288 `powershell.exe`/día), tarea del invitado, `logs/*.log` con tope |

**Versionado respecto de Linux:** `boveda_version` es **monótono y global**: Linux sellará **2**;
Windows, **3**. La cabecera de **cada** CSV de esta ventana llevará
`metrica_version=1 boveda_version=3 plataforma=windows` y los `sha256` de sus entradas. **No se
recalcula nada de Linux** y **no se reescribe** `boveda_congelacion.md` de Linux: Windows añade
**su** sidecar `b10_windows_sellado.md` + `boveda_windows.sha256`, y el índice
`boveda_congelacion.md` gana **una fila** (declarada) que apunta a él.

---

## 12. Riesgos

| # | Riesgo | Impacto | Mitigación |
|---|---|---|---|
| **R-W1** | **Las 4 tareas `TFG-Baseline-*` siguen vivas** con `StartWhenAvailable=True`; una **apaga el manager** y las de `*-Start` **revierten la VM** | ventana destruida | **[D]** desactivarlas (no borrarlas) antes de `prep`, con evidencia, y **verificarlo en `prep`** (G-W1). Es el hallazgo más urgente de este plan (§18.1) |
| **R-W2** | El **cliente GHOSTS de Windows no existe** y no hay toolchain | W1 no arranca | D1 opción A; B como plan B; C como último recurso (con cambio de naturaleza declarado) |
| **R-W3** | **Volumen de `M`** desborda (> 5 GB) | fallback de la métrica | WE0-9 mide **antes**; disco verificado en `prep` |
| **R-W4** | **Windows Update reinicia** el invitado (el `wuauserv` «se auto-repara»: `state.md:30`) | W-V8 | política + **guarda en el keepalive** (cada 5 min, dentro del invitado) + comprobación en `prep`/`watch` **sin tocar la VM** |
| **R-W5** | **Defender** se reactiva y pone en cuarentena ficheros de la actividad | acciones perdidas + FP falsos | `TamperProtection=0` ya aplicado (`state.md:30`); se verifica en `prep` y en la cosecha; se declara |
| **R-W6** | **Reloj**: `w32time` apagado, depende de VMware Tools | invalidez por tiempos | W-V9 (≤ 2 s en `prep` y en cosecha) |
| **R-W7** | **`eventcreate` exige elevación** | un caso se degrada | WE0-7; se sustituye por lectura y se declara |
| **R-W8** | **El perfil `C:\Users\angel` está bajo FIM** | FIM dispara en cada escritura ⇒ el numerador se dispara | WE0-1 lo comprueba; si está vigilado, la actividad va a `C:\lab-legit` (como la baseline) y se declara (sin tocar el FIM) |
| **R-W9** | **`cmd /c` pierde el reporte** con ciertas comillas (`"…"` anidadas) | acciones no contadas | WE0-2 con comillas dobles y `%`; regla: comillas simples internas y sin `^` |
| **R-W10** | **`%ERRORLEVEL%` expandido en tiempo de análisis** | `errores.log` sin rc | patrón `if errorlevel` (§4.4) + WE0-5 |
| **R-W11** | **La campaña dispara `N ≥ 7`** | «sorpresa» | **es el objetivo**; esperado pre-registrado (H-W2), se publica como hallazgo |
| **R-W12** | **Tercer aborto** (el de Linux sería el segundo) | calendario | cláusula anti-aborto (§9) + criterio fijado antes |
| **R-W13** | **`exportar_acciones.sh` mezcla clientes** | `FP/acción` mal | CA-W6 (1 sola `machineid` en el rango) + VM Linux apagada |
| **R-W14** | **`extraer_alertas_windows.py` no cuadra con el histórico** | pérdida de trazabilidad | prueba de regresión contra las **159 alertas** del 08/10 (W2) |
| **R-W15** | **Disco del invitado** (12 GB de VM) | repite L1 | presupuesto: campaña ≤ 40 MB, logs con tope ~15 MB, guarda ≥ 500 MB en el keepalive; verificación **antes/después** (W-L1) |
| **R-W16** | **Deploy no idempotente** | `prep` deja la VM a medias | WE0-12 + 2 aplicaciones = mismo `sha256`; si falla dos veces, snapshot nuevo con OK humano |

---

## 13. Criterios de aceptación verificables

| # | Criterio | Verificación |
|---|---|---|
| **CA-W1** | Receta Windows: `--check` PASS; **0** `Get-Random`/`%RANDOM%`; 0 pipes de `cmd`; 0 comandos mutantes; **dos generaciones byte-idénticas** | `--check` + `sha256` ×2 |
| **CA-W2** | **Igualdad de ranuras** con Linux: por bloque, mismo `n` y mismo `DelayAfter` (441 eventos en total: 147/153/141) | validador + salida literal |
| **CA-W3** | Campaña pre-registrada **antes de `t0`**: 11 casos, 22 marcas, comandos literales, `sha256` con fecha | `git log`/`sha256` |
| **CA-W4** | **`errores.log`**: ≥ 8/día con `rc` y **reintento correcto** posterior; `sha256` y conteo | receta + WE0-5 |
| **CA-W5** | **`cwd` realista**: 100 % de las acciones con `win_cwd` ≠ `C:\Windows\System32` ni el directorio del cliente; valor declarado en B10-W | `alertas_detalle.csv` / WE0-3 |
| **CA-W6** | **`M` único** con `--agent-id 002`, `--estricto` `exit 0`, `MANIFEST` con `sha256`, copiado **antes** del `off`; **1 sola `machineid`** en las acciones | `denominador_M.csv` + `ghosts_acciones.csv` |
| **CA-W7** | **Volumen decidido con dato**: proyección de WE0-9 escrita y regla §6.3 aplicada | `ensayo_WE0.md` |
| **CA-W8** | **No mutación**: `reg query` + `schtasks /query` idénticos antes/después; 0 ficheros fuera de `campana\` | WE0-10 |
| **CA-W9** | **Vigilancia**: 144 chequeos (±2), 0 `ALARMA` no explicada, 0 falsas alarmas de borde, 0 `AVISO` en el primero | log |
| **CA-W10** | **WE0 PASS** completo (WE0-1…WE0-12 **+ WE0-2b**) y **≤ 7 días** antes de `t0` | `ensayo_WE0.md` |
| **CA-W11** | **Snapshot** `lab-listo-windows-legit` con los 3 originales intactos (**4**); deploy idempotente y reversible | `vmrun listSnapshots` + `sha256` ×2 |
| **CA-W12** | **Ventana**: `prep`/`arm` a su hora (±5 min); `stop` a `t1+10` tras `cosecha.done`; **72 h ± 1 min** | log + `cosecha.done` |
| **CA-W13** | **Cero acceso** al invitado en `[t0,t1]`: 0 `4624` desde `192.168.65.1`, **0** procesos con padre `vmtoolsd.exe` | CSV + Sysmon |
| **CA-W14** | **Campaña**: 11/11 (o ≥ 9/11) con `hecho.txt` y `esperado_cumplido`; tabla por caso **y por umbral** `{0,3,7,10,12}` + severidad `P` | `campana_fp_windows.csv` |
| **CA-W15** | **Tabla de campaña separable**: el titular es la ventana completa; **no** hay FPR alternativo | `campana_fp_windows.csv` + `denominador_M.csv` |
| **CA-W16** | **`logall_json=no`** y `CONFIG_IDENTICA` al cerrar; `sha256` de Sysmon igual antes/después | `diff` + huella |
| **CA-W17** | **B10-W** sellado con telemetría, `sha256` de Sysmon y de la config, cliente, receta, campaña, `errores.log`, `boveda_version=3`, `plataforma=windows` | `b10_windows_sellado.md` |
| **CA-W18** | **Cero daño colateral**: `git diff --stat` vacío en `Soporte/Metrica/`, `Hojas/`, `_recursos/`, corpus y `Dataset/` (salvo promoción declarada) | `git status` |
| **CA-W19** | **Las 4 `TFG-Baseline-*` desactivadas** y verificadas en `prep`; **0** `TFG-WinLegit-*` huérfanas al cerrar | `Get-ScheduledTask` |
| **CA-W20** | **Sin secretos**; `TFG_GUEST_PW` fuera de ficheros y de logs | `Select-String` |
| **CA-W21** | **Laboratorio cerrado**: 0 VMs, 0 tareas `TFG-WinLegit-*`, 0 reglas `TFG-*`, GHOSTS/PostgreSQL/intranet parados | `vmrun`, tareas, `Get-Process` |
| **CA-W22** | **Promoción a `Dataset/Legitimo/windows/legitimo_72h/` solo si VÁLIDA** | `git status` + ficha |
| **CA-W23** | **Extractor Windows** reproduce las **159 alertas** y los **7 `rule_id`** del 08/10 | prueba de regresión |
| **CA-W24** | **`plan.md` de la raíz intacto** (`sha256` antes/después) | `sha256` |
| **CA-W25** | **Herramientas**: `where` de **todas** las de receta + campaña; las que falten, **declaradas y retiradas** (nunca instaladas) | WE0-2b (salida literal) |

---

## 14. Cómo se verifica (tester)

1. **Determinismo**: dos generaciones y `sha256`; `--check`; igualdad de ranuras con Linux.
2. **Unidad**: WE0-2 (5/5 reportadas) y WE0-4 (`67027` ≥ nº procesos).
3. **Ancla**: `Select-String` de `win_cwd`/`win_user`/`win_image` sobre una muestra; 0 filas con
   `System32` o `SYSTEM`.
4. **Campaña**: 11 filas con umbral; `sha256` previo; `campana_fp_windows.csv` con 9 columnas; **0 `N ≥ 7`**
   salvo hallazgo declarado; 0 mutación.
5. **`M`**: `--estricto` `exit 0`; `MANIFEST` cuadra; `--agent-id 002` en la cabecera; 1 `machineid`.
6. **Validez**: recalcular W-V1…W-V9; **0** falsas alarmas de borde y **0** `ALARMA` sin explicar.
7. **Regresión**: el extractor Windows reproduce el histórico (CA-W23); `plan.md` de la raíz intacto.
8. **Higiene**: `git status` acotado; 0 secretos; 4 tareas desactivadas; laboratorio cerrado.

---

## 15. Gate humano (lenguaje sencillo)

> **Qué te pido.** Antes de tocar nada quiero dejar por escrito **qué copiamos de Linux a Windows y qué
> no**, porque hay cuatro cosas que en Windows **no existen** y no voy a disimularlas: el cifrado de un
> fichero con contraseña, el borrado seguro, el corpus de ataques de Windows (todavía no lo tenemos) y
> el extractor de alertas (el de Linux no lee los campos de Windows).
>
> **Lo que se va a construir** (sin encender nada todavía): la misma jornada de oficina, con **los mismos
> horarios, el mismo número de acciones y el mismo ritmo** que Linux; los mismos **11 casos benignos que
> parecen ataque**, con dos de ellos «a medias» por lo dicho arriba; el contador de eventos de Windows;
> y un ensayo general.

**Preguntas (solo lo que no está decidido):**

- **Q1. ¿Apruebas que el ejecutor sea el cliente de GHOSTS para Windows publicado por la universidad
  (CMU) en su versión 8.3.1, en vez de instalar Visual Studio para compilarlo?** Son 55 MB; **no
  publican la huella**, así que la calculo yo y lo dejo escrito.
- **Q2. ¿Apruebas que la actividad corra como el usuario `angel` y no como `SYSTEM`?** El ensayo
  antiguo corría como `SYSTEM`; así cada acción parecía cosa de un administrador. Cuesta media hora y
  hace la comparación con Linux honesta.
- **Q3. ¿Apruebas crear un snapshot nuevo (`lab-listo-windows-legit`) y dejar los tres actuales
  intactos?** Es el sitio del que arranca la ventana; sin él, el material se borra al revertir.
- **Q4. ¿Apruebas desactivar las cuatro tareas `TFG-Baseline-*` que siguen vivas?** Las de arranque
  **devuelven la máquina a un estado anterior** y las de parada **la apagan** (una de ellas, también el
  servidor): si se disparan durante la ventana, la destruyen.
- **Q5. ¿La ventana de Windows va antes o después de los ataques de Windows (`B1`)?** Mi recomendación:
  **antes** (así cerramos la parte legítima y no esperamos dos semanas), aceptando que hasta que exista
  `B1` el «error por evento» de Windows estará sin pareja de detección. Si prefieres lo contrario, se
  planifica igual, solo cambia el orden.
- **Q6. ¿Apruebas que la bóveda de Windows sea la versión 3** (Linux será la 2) y que se guarde en un
  sello aparte? Es la forma de no mezclar dos telemetrías distintas en el mismo número.

**Lo que NO vas a ver:** ni análisis, ni FPR, ni comparación con Linux todavía. Y **no se enciende
ninguna máquina** hasta que cierre la ventana de Linux (2–5/11).

---

## 16. Ficheros

### 16.1 Nuevos

| Ruta | Qué |
|---|---|
| `_fases/windows-legit-prep/plan.md` | Este plan |
| `Soporte/Laboratorio/windows/` | Directorio del bloque (**no** `windows_legit/`): conviven el histórico de `fase-02b-baseline` y los subdirectorios nuevos `recetas/`, `campana/`, `guest/` |
| `Soporte/Laboratorio/windows/recetas/{w1,w2,w3}.json`, `calendario_windows.json`, `bloques_windows.env`, `receta_windows_resumen.md` | Receta Windows (W1, ya generada) |
| `Soporte/Laboratorio/windows/campana/{casos_windows.md,campana_windows.csv,campana_fp_windows.csv,campana_ventanas_windows.tsv}` | Pre-registro y resultado de la campaña (W2). `casos_windows.md` es el `campana_windows.md` que decía este plan |
| `Soporte/Laboratorio/windows/{deploy_windows.ps1,windows_legit_host_control.ps1,pausar_wu_invitado.ps1,verificar_arreglos_windows.ps1}` | Despliegue, control y garantías (W3) |
| `Soporte/Laboratorio/windows/guest/{tfg_keepalive_windows.ps1,verificar_windows.ps1}` | Guardián del invitado (W3) |
| `Soporte/Laboratorio/windows/{snapshot_windows_legit.md,ensayo_WE0.md,b10_windows_sellado.md,boveda_windows.sha256,resultado.md,README.md}` | Documentación y sellado. **No** hay `sha256sums.txt` propio: el del bloque es el **compartido** `Soporte/Laboratorio/legitimo_72h/sha256sums.txt`, que ya incluye las entradas Windows |
| `Soporte/Laboratorio/windows/ventana_<t0>/{ventana_meta.md,veredicto_validez.md,MANIFEST.md,evidencia/*}` | Ficha y evidencia |
| `_artefactos/scripts/{construir_receta_legitima_windows.py,verificar_espejo.py,campana_windows.py,extraer_campana_windows.py,extraer_alertas_windows.py,cobertura_herramientas_windows.py}` + `tests/` | Herramientas (deterministas, con tests) |
| `Dataset/Legitimo/windows/legitimo_72h/ventana_<t0>/…` | **Solo si VÁLIDA** |

### 16.2 Modificados (mínimo indispensable)

| Ruta | Cambio |
|---|---|
| `state.md`, `roadmap.md` | Estado del bloque (**orquestador**) |
| `Soporte/Metrica/boveda_congelacion.md` | **Una fila** que apunta a la bóveda de Windows (**orquestador/humano**; las 10 entradas existentes no se tocan) |

### 16.3 Prohibido tocar

`plan.md` (raíz) · `_recursos/**` · `Hojas/**` · `Dataset/**` (salvo §16.1) · `Soporte/Metrica/**` (salvo
la fila) · el corpus · el ruleset · la config de Sysmon · `construir_receta_legitima.py` · `campana.py`
· `extraer_campana.py` · `extraer_alertas.py` · `contar_denominador.py` · `exportar_acciones.sh` ·
`legitimo_host_control.ps1` · los **3** snapshots de `victima-windows` y los **6** de `victima-linux` ·
`Soporte/Laboratorio/windows/*` (baseline histórico, se conserva como **histórico**).

> **Excepción declarada (2026-10-29, W1).** `construir_receta_legitima.py` **se ha modificado** (48 líneas):
> la acción `B5#1` hacía `sha256sum X` **sin redirección** ⇒ el fichero `.sha256` no se creaba y `B5#2`
> (`cat …sha256`) **fallaba todos los días** en **Linux** (defecto heredado, detectado al ejecutar la
> receta de Windows). Se añade `> X.sha256` y un **auditor** que falla si una huella se lee sin haberse
> escrito. **Consecuencia:** el hash de `d1/d2/d3` cambia (1 acción/día) ⇒ **hay que repetir P1 antes de
> la ventana**. Detalle: `Soporte/Laboratorio/legitimo_72h/fix_receta_v3.md`. El resto de la lista sigue
> vigente.

### 16.4 Nota de corrección factual (2026-10-29, W1+W2) — **sin cambio de fondo**

> Corrección posterior a la aprobación (v2) de **nombres y rutas reales** y de lo **ya
> ejecutado** al construir W1/W2. No cambia ninguna decisión (D1–D6), ningún criterio
> (W-V*, CA-W*) ni el alcance: sustituye lo que el plan describía **antes** de tener el
> árbol construido. Donde haya conflicto, manda esta nota.

**Rutas y nombres reales** (los de §16.1 y §7):

| El plan decía | Real |
|---|---|
| `Soporte/Laboratorio/windows_legit/` | `Soporte/Laboratorio/windows/` (**no existe** `windows_legit/`) |
| `recetas_windows/{d1,d2,d3}.json`, `calendario.json`, `receta_resumen.md` | `recetas/{w1,w2,w3}.json`, `calendario_windows.json`, `receta_windows_resumen.md` (+ `bloques_windows.env`) |
| `campana_windows/{campana_windows.md,campana_fp.csv,campana_ventanas.tsv}` | `campana/{casos_windows.md,campana_fp_windows.csv,campana_ventanas_windows.tsv}` (+ `campana_windows.csv`) |
| `construir_receta_windows.py` | `construir_receta_legitima_windows.py` (+ `verificar_espejo.py`, 504 = 504) |
| (extractor de campaña no listado en §16.1) | `extraer_campana_windows.py` |
| `sha256sums.txt` propio de `windows_legit/` | el **compartido** `Soporte/Laboratorio/legitimo_72h/sha256sums.txt`, con las entradas Windows |
| `campana_windows.md` (§11) | `casos_windows.md` |
| `campana_fp.csv` (§14) | `campana_fp_windows.csv` |

**Cambios ya ejecutados al construir (declarados, no silenciosos):**

| Caso / familia | El plan decía | Ejecutado | Motivo |
|---|---|---|---|
| **W-04** | `tar -a -c -f` + `certutil` | **AES en PowerShell** + `certutil -hashfile` | `tar -a` no cifra: no era T1486 |
| **W-05** | `del /f /q` + `rd /s /q` | **`powershell`** sobrescribe y borra + `rd /s /q` | `del` de un fichero ausente devuelve rc=0; no produce error ni borrado mínimamente seguro |
| **W-09** | `for /L` + `xcopy` | **`for /L` + `cmd /c copy`** | `xcopy` no creaba los 12 ficheros; `copy` conserva el fan-out de 12 procesos |
| **W-11** | `certutil -urlcache` + `curl.exe` | **solo `curl.exe`** | `certutil -urlcache` era una hipótesis abierta y un patrón clásico de detección; se retira |
| **`rm_inexistente`** (§4.4) | `del` de inexistente (rc≠0) | **`type` del temporal (rc=1)** + `del` de reintento | en Windows `del` de un fichero ausente devuelve **rc=0**: el fallo no se registraba |

> **Otras correcciones de §5.2 (2026-10-29).** **W-02** no usa `ping`: son `ipconfig /all` +
> `route print`, y la evidencia se extrae con `findstr` (2 comandos, no 3). **W-03** usa
> `schtasks /query /fo LIST` (sin `/v`). Las cuentas reales del pre-registro son **63 acciones /
> 75 procesos** (cota inferior, D-W5), no «~40 / ~55».

> **Lectura del `3/50` (2026-10-29).** `cobertura_herramientas_windows.py` mide **solape de
> `basename`** con el corpus **Linux**; **no** es cobertura equivalente ni comparable con el
> **23/50** de Linux (el corpus es Linux-específico). El 3/50 incluye `find` como solape
> **nominal** (el `find` de Windows es un filtro de texto, **no** el `find` GNU) ⇒
> estrictamente comparables: **2/50** (`curl`, `tar`). El script lo imprime en una línea
> `NOTA:`; «mismo corpus y criterio» (§7) nunca significó «mismo número».

> **CA-W23 — alcance de la prueba (declarado).** El JSON crudo del manager del 08/10 **no**
> está en el repositorio (solo se conservaron los productos `baseline_detalle_v{1,2}.csv`).
> La regresión reproduce **72 + 87 = 159** alertas y **7 `rule_id`** sobre esos productos
> congelados; el mapeo JSON→`win_*` se prueba con **fixtures sintéticos**, no con datos
> históricos. No se maquilla: si los recuentos no cuadran, la regresión falla.

Detalle: `Soporte/Laboratorio/windows/recetas/receta_windows_resumen.md` y
`casos_windows.md` (tabla «Desviaciones respecto del plan», D-W1…D-W7).

---

## 17. Trazabilidad

| Afirmación | Fuente verificable |
|---|---|
| Jornada 08:00–17:00Z, B6 17:05–17:50, inicios 17:06/17:17/17:11 | `plan.md:472-504`; `recetas/bloques.env` |
| 147/153/141 acciones; 11 casos, 63 acciones, 22 marcas | `state.md:10`; `campana/campana_casos.csv` (cabecera) |
| Receta Linux escrita con `HandlerType=Command` (⇒ portable) | `recetas/d1.json:5` |
| `Command` → `Bash.cs` en Linux | `ghosts.client.linux/TimelineManager/Orchestrator.cs:193` |
| `Command` → `Cmd.cs` (`cmd /c`) en Windows | `Ghosts.Client/TimelineManager/Orchestrator.cs:330`; `Handlers/Cmd.cs:106` |
| El handler PowerShell lanza `powershell.exe` **sin argumentos** y escribe por *stdin* (⇒ `4688` sin línea de comandos) | `Handlers/PowerShell.cs:117-124` |
| Cliente Windows = **.NET Framework 4.6.2** + Office Interop + Selenium | `Ghosts.Client/Ghosts.Client.csproj:11, 464…` |
| `Ghosts.Client.Lite` (net8.0) **no tiene** handler de comandos | `Ghosts.Client.Lite/src/Infrastructure/Handlers/` (solo `FileHandler`, `HttpHandler`, `MemoryCleanUpHandler`) |
| No hay toolchain para compilarlo en el host (sin targeting pack 4.6.2, sin Build Tools) | `Test-Path` = `False`; MSBuild solo `v4.0.30319` |
| Release `v8.3.1` **sin assets** en GitHub; binarios Windows en Box | `api.github.com/repos/cmu-sei/GHOSTS/releases` |
| `67027` («A process was created», L3) en `0955-WEF-baseline_rules.xml` (67011-67029) | `active_ruleset.txt:191` |
| Baseline Windows: 159 alertas, 7 `rule.id`, `67027`=132, hueco 40,8 min | `Dataset/Legitimo/windows/{ruleids_legitimos.csv,estabilidad_windows.csv}`, `baseline_meta.md:138-176` |
| `92201` (L9) disparada por `powershell.exe` benigno | `estabilidad_windows.csv:8` |
| Baseline corrió como **SYSTEM** | `baseline_resultado.md:62-63` |
| El script de baseline hacía cmdlets en **un** proceso (68 eventos/4 h) | `Soporte/Wazuh/Scripts/baseline_actividad_windows.ps1:62-107` |
| `extraer_alertas.py` solo lee campos Linux | `extraer_alertas.py:337-340` |
| `contar_denominador.py` filtra `endpoint` por agente; defecto `001` | `contar_denominador.py:13-16, 288` |
| `exportar_acciones.sh` no filtra por máquina | `exportar_acciones.sh:30-33` |
| `extraer_campana.py` parametriza agente y `RULE_EXEC` | `extraer_campana.py:585-586`; `campana.py:73` |
| Sysmon v15.22 + `sysmonconfig-export.xml` (SwiftOnSecurity, *source v74*, 123 257 B) | `construccion_resultado.md:21,26`; `baseline_resultado.md:91-95` |
| Reloj: `w32time` apagado, depende de VMware Tools | `state.md:34`; `victima-windows.vmx` (`tools.syncTime="TRUE"`) |
| 4 tareas `TFG-Baseline-*` vivas con `StartWhenAvailable=True` | `Get-ScheduledTask` (2026-10-29) |
| 0 VMs; 3/2/6 snapshots | `vmrun list`, `listSnapshots` (2026-10-29) |
| Inventario: 89/77/75/38 | recuento sobre `Hojas/inventario_p1_windows.csv` |
| No hay corpus de ataques Windows | `Dataset/Ataques/Resultados/Wazuh/` (solo `linux/`) |
| Secuencialidad y una plataforma a la vez | `roadmap.md:106-110` |
| `M` es per-HIDS y no comparable en crudo | `metrica_hids.md:66-68, 254-268` |
| Fallback de `M` (> 5 GB) y caso L11 | `metrica_hids.md:61-64, 250` |
| Lecciones de v2 (WU se auto-repara, `off` borra `archives`) | `_fases/legitimo-72h-v2/change-doc.md:47-55` |
| Metodología de la campaña (umbral, ventanas, marcas, publicación aparte) | `plan.md:660-678, 783-870, 1093-1110` |
| Cláusula anti-aborto | `plan.md:538-545` |

---

## 18. Lo que no cuadra

1. **Cuatro tareas del host siguen armadas y son una trampa.** `TFG-Baseline-Night-Start`,
   `TFG-Baseline-Night-Stop`, `TFG-Baseline-Afternoon-Start` y `TFG-Baseline-Afternoon-Stop` están en
   `Ready`, con `StartWhenAvailable=True`. **Una apaga el servidor** (`…-Afternoon-Stop`), **otra apaga
   la víctima** (`…-Night-Stop`) y las **dos de arranque** hacen `revertToSnapshot` de
   `victima-windows` a `lab-listo-windows-baseline`. Cualquier re-armado accidental
   destruye la ventana. **No estaba registrado como riesgo en ningún documento**; aquí es R-W1 y
   CA-W19. Ya se había visto el mismo patrón con un disparador pasado que **se ejecutó** al arrancar
   (`baseline_resultado.md:262-265`).
2. **El «espejo» no puede ser completo, y el motivo es de fondo**: en Linux la campaña y las
   herramientas se eligieron **desde el corpus de ataques**; en Windows ese corpus **no existe**. Por
   eso la campaña de Windows es una **predicción** y no una medida, y el «esperado» solo puede
   fijarse por **umbral** (no por `rule_id` exacto). Si el humano quiere la simetría completa, hay que
   hacer **B1 primero**: eso retrasa el bloque ~2-3 semanas y no cambia nada de lo que se construye
   aquí.
3. **El ensayo histórico de Windows no sirve como precedente metodológico** (sí como suelo de ruido):
   corrió como `SYSTEM`, no instrumentó `logall_json` (nunca hubo `M` de Windows) y su actividad no
   producía un evento por acción. Se conserva como **histórico declarado**, no como catálogo
   (coherente con `metrica_hids.md:228-229`, que ya invalida baselines antiguos para el juicio final).
4. **`extraer_alertas.py` no puede leer Windows y está en la lista de prohibidos**: hay que **duplicar**
   el extractor. Es deuda técnica heredada: el catálogo histórico tiene `audit_exe`/`audit_cwd` vacíos,
   así que **no** se puede auditar con él qué comando disparó cada alerta.
5. **`exportar_acciones.sh` no filtra por máquina.** Con un cliente vivo no hay problema, pero es una
   bomba si algún día conviven dos. Se mitiga con CA-W6 (1 `machineid`) en vez de editar el script.
6. **`67027` viene de un fichero de «baseline» (`0955-WEF-baseline_rules.xml`)**: es el equivalente
   funcional de `80792`, pero conviene decirlo con precisión — **no es** una regla de detección, es una
   regla que **registra** a nivel 3. Si la analogía se vende como «detección», el hallazgo se pierde.
7. **`cwd` en Windows depende de Sysmon.** Si alguien cambia la config de Sysmon (o su versión), se
   pierde el ancla y cambia `M`. Por eso la config entra en la bóveda con `sha256` y **prohibido
   tocarla** (CA-W16).
8. **`M` de Windows es una incógnita de tamaño.** Es el único parámetro del bloque que puede cambiar el
   titular (por el fallback de 5 GB) y no hay ni una medida previa. Se resuelve **midiendo en WE0**, no
   estimando.
9. **El disco del invitado no se puede vigilar en vivo sin contaminar.** Cualquier lectura desde el host
   (`runProgramInGuest`) mete procesos en la ventana y rompe W-V4. Se sustituye por guarda local, y eso
   es **peor** que Linux (que leía el `df` del agente). Declarado (W-L1).
10. **La ventana Windows nacerá sin `TPR` de Windows.** El `FPR` es válido, pero la fila «Windows» de la
    tabla de resultados quedará coja hasta `B1`. Es una decisión de orden, no un defecto; se declara
    (D6, Q5).
11. **Riesgo de sobreingeniería**: este bloque construye **4 scripts nuevos de análisis** y **1
    generador**. Se justifica porque el espejo exige la misma unidad y los mismos productos; si el
    humano prefiere recortar, el mínimo defendible es **receta + campaña + extractor de alertas**
    (W1+W2) y dejar la vigilancia en su versión más simple.

---

## 19. Veredicto del planificador

> **SÓLIDO CON TRES RESERVAS, y una de ellas es de fondo.**
>
> **Lo que está bien:** el espejo es **estructuralmente posible** porque el timeline de GHOSTS es el
> mismo en las dos plataformas (`HandlerType=Command` → `bash`/`cmd`), y eso permite copiar **ritmo,
> bloques, número de acciones y unidad de conteo** sin inventar nada. La métrica no se toca: se aplica
> con `--agent-id 002` y con la unidad común (`FP/acción`, `FP/hora`).
>
> **Reservas:**
> 1. **La campaña de Windows es una predicción, no una medida** (no hay corpus Windows). Se publica
>    como tal; la simetría completa exige `B1`.
> 2. **Dos casos quedan parciales** (cifrado con contraseña y borrado seguro no existen sin instalar) y
>    uno puede degradarse (`eventcreate` con privilegios). Se declara y no se maquilla.
> 3. **El volumen de `M` es la única incógnita que puede cambiar el titular.** Se resuelve con una
>    medida en WE0 y un disparador escrito **antes**; si se descubre tarde, se pierde la ventana.
>
> **Condiciones para que el veredicto se mantenga:** (a) las 4 tareas `TFG-Baseline-*` **desactivadas y
> verificadas** antes de `prep`; (b) WE0 completo y **≤ 7 días** antes de `t0`; (c) la campaña
> pre-registrada con `sha256` y fecha anterior a `t0`; (d) el `M` medido en WE0 con la decisión §6.3
> escrita. Si (a) o (d) fallan, el bloque **no se arma**: es preferible no tener datos de Windows a
> tener datos contaminados.
