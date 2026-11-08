---
bloque: B1
nombre: Ataques Windows (fase-03b) — corpus B1 v3, canal SSH y medición T2/T4-W
version: 3
status: approved_by_human
fecha: 2026-11-08
fecha_aprobacion: 2026-11-08
aprobado_por: humano
autor: tfg-planner
nota_gate: >-
  **APROBADO (2026-11-08).** El humano autoriza: (1) B1.0-SSH.0 (viabilidad) y, si es viable,
  B1.0-SSH.1 (instalar/configurar + snapshot + bóveda v3); (2) si no hay payload offline,
  Win32-OpenSSH pre-staged con URL+sha256, con fallback a vmrun + predicado; (3) predicado
  OPERADOR_WIN + sensibilidad sin predicado; (4) interactivos S1 (autologon + InteractiveToken),
  con S2 como fallback declarado; (5) extractor aditivo con doble regresión; (6) los 5 artefactos
  B-2/B-3 antes de B1.1. Corpus 32 sin cambios.
aprobado_v2: f0b99c4
b1_0: "PASA (2026-11-08): snapshot lab-listo-windows-ataques, C0 de clases, servicios del host y pre-staging verificados. Bloqueante del tester: huella del canal 67022/67023/67028."
correccion: >-
  v3 (2026-11-08, enmienda del humano + tutor): el canal del operador pasa a **SSH primero**
  (como Linux) porque `vmrun runProgramInGuest` genera 3 alertas de logon por invocación
  (`67022/67023/67028`, nivel 3) que no están en el catálogo v1 y, con `auto_ruido` vacío,
  contarían como `novel` ⇒ TPR artificial 32/32 a N=3. Si SSH no es viable offline, fallback
  declarado a `vmrun` + catálogo/predicado de canal (o WinRM). Se resuelve la contradicción del
  extractor (`win_target`) con extensión **aditiva** y doble regresión. Corpus 32 sin cambios.
depende_de: >-
  plan.md v2 (aprobado, f0b99c4) · B1.0 (PASA, Soporte/Laboratorio/windows/ataques/B1.0_infra.md) ·
  fase-02b-construccion (laboratorio Windows; **sin SSH**, construccion_resultado.md:4) ·
  fase-02b-baseline (159 alertas / 7 rule_id) · legitimo-infra ("internet local" del host) ·
  windows-legit-prep W0/W1/W2 (W3 pendiente) · Soporte/Metrica/metrica_hids.md v1 (congelada) ·
  Soporte/Ataques/{criterio_ataques,criterio_doble_iteracion,plantilla_esperado}.md ·
  Hojas/{inventario_p1_windows,ATA_index}.csv · estado Linux cerrado (55/128/53, commit 850248c)
no_toca: >-
  _recursos/ · Hojas/ATA_index.csv · Hojas/{T2,T4,T5}*.csv · Dataset/Legitimo/ ·
  Dataset/Ataques/Resultados/Wazuh/linux/ · Soporte/Metrica/ ·
  _artefactos/scripts/extraer_alertas.py (congelado) · laboratorio Linux (victima-linux) ·
  corpus Linux (55 casos) · reglas RS3/RS4
gate: humano
ejecuta_ahora: NADA. Este documento es de diseño; no se arranca ninguna VM ni se instala SSH.
---

# plan.md — bloque `B1` (ataques Windows, `fase-03b`) — v3

> **Resumen en 12 líneas.** El corpus sigue en **32 ataques** (ATA056–ATA087; 30 técnicas Linux +
> 2 Windows-only). **B1.0 está ejecutado y PASA**, pero el tester encontró un **bloqueante**: el
> canal `vmrun runProgramInGuest` deja **3 alertas de logon por invocación** (`67022/67023/67028`,
> nivel 3) que **no están en el catálogo v1**; con `auto_ruido` vacío y el `esperado` declarando
> `67027`, una fila `67022` saldría **`deteccion/novel`** ⇒ **TPR artificial 32/32 a N=3**. Decisión
> del humano (con su tutor): **probar SSH primero**, como en Linux; si no es viable offline,
> **fallback** a `vmrun` + **catálogo/predicado de canal** (o WinRM). Este plan diseña la
> **viabilidad SSH (B1.0-SSH.0)**, la **instalación/configuración (B1.0-SSH.1)**, el **predicado de
> operador** (nunca detección), la **sensibilidad sin predicado**, la **extensión aditiva del
> extractor** (`win_target`, `srcip`, `logon_type`, `win_parent_image`) y la **solución/limitación
> de los 3 casos interactivos**. Método, métrica v1, `C0≡C1`, catálogo provisional v1, `FPR`
> pendiente y re-juicio posterior: **sin cambios**.

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Estado de partida verificado (incluye B1.0)](#2-estado-de-partida-verificado-incluye-b10)
3. [Decisiones](#3-decisiones)
4. [Corpus B1: 32 casos](#4-corpus-b1-32-casos)
5. [Método por caso, canal y extractor](#5-método-por-caso-canal-y-extractor)
6. [Laboratorio: SSH, snapshot y bóveda v3](#6-laboratorio-ssh-snapshot-y-bóveda-v3)
7. [Medición](#7-medición)
8. [Productos y ficheros](#8-productos-y-ficheros)
9. [Tandas y paradas humanas](#9-tandas-y-paradas-humanas)
10. [Criterios de aceptación](#10-criterios-de-aceptación)
11. [Verificación del tester](#11-verificación-del-tester)
12. [Riesgos](#12-riesgos)
13. [Trazabilidad](#13-trazabilidad)
14. [Lo que no cuadra y predicciones declaradas](#14-lo-que-no-cuadra-y-predicciones-declaradas)
15. [Gate humano](#15-gate-humano)
16. [Veredicto del planificador](#16-veredicto-del-planificador)

---

## 0. Resumen ejecutivo

### 0.1 Qué sale de B1 (sin cambios de fondo)

| # | Producto | Estado tras B1 |
|---|---|---|
| 1 | **32 casos** Windows con 2 iteraciones | 64 ventanas `[t0,t1]` + 32 planes `C0` |
| 2 | `T2_ataques_windows.csv` (TPR, FN, `rule_id`, primera evidencia) | **completo** (config × umbral) |
| 3 | `T4_rendimiento_windows.csv` | **TPR + `FP/hora`**; `FPR/TNR/F1/GM/Precisión` **pendientes de `M`** |
| 4 | Comparación **por técnica** Linux↔Windows | **30 técnicas** |
| 5 | Cobertura ART Windows | **21/32** disponibles, **18** aprovechables |
| 6 | Filtro Windows + **predicado de canal** | nuevo, con regresión Linux byte a byte |
| 7 | Re-juicio con catálogo definitivo | **bloqueado** hasta la ventana legítima Windows |

### 0.2 Lo que cambia en v3 (el bloqueante)

| # | Hecho verificado | Consecuencia |
|---|---|---|
| **B-1** | `vmrun runProgramInGuest` deja **`67022` (4624), `67023` (4634), `67028` (4672)**, nivel 3, **fuera del catálogo v1** | Con `auto_ruido` vacío y `esperado` con `67027`, una fila `67022` → **`deteccion/novel`** ⇒ **TPR 32/32 a N=3** artificial. **T2-W se invalidaría** |
| **B-3** | `extraer_alertas_windows.py` **no emite** `win_target` (y `srcip` sale vacío en Windows) | La señal `win_target` queda **no evaluable**; el predicado de operador **no puede demostrarse por IP** |
| **B-2** | Faltan `procedimiento_ventana.md`, `servicios_host.md`, `arrancar_servicios_host.py`; `c0_detalle.csv`/`c0_agregado.csv` **no archivados** | Se crean **antes de B1.1** (no se dejan cabos) |
| **B-4** | **No hay sesión interactiva** (`-interactive` falla): ATA071/072/073 (pantalla, portapapeles, teclado) | Solución **S1** (autologon + `InteractiveToken`) o **limitación S2**, declarada |
| **B-5** | `Sysmon 3` base = **nivel 0** (`185001`): **H-B1-5 falsada** | Las técnicas de red **no** tienen capa de red; se detectan por **proceso** (`4688`/`Sysmon 1`/`4104`) |
| **B-6** | Puntos ciegos medidos: `Sysmon 23` (no se genera), `7036` (0 eventos), `4698/106` (no se generan), FIM de registro **no realtime** | Se ajustan las capas esperadas de ATA062/064/079/063 |

### 0.3 Las tres cifras que el humano debe tener claras

1. **`N = 32`** (sin cambios): 30/32 técnicas Linux; **55 %** del corpus Linux.
2. **`C0 ≡ C1`** (RS2 vacía) y **catálogo provisional v1** (4 reglas). El **canal** no entra en el
   catálogo: se resuelve con **predicado de operador** + **sensibilidad**.
3. **`FPR` no se calcula en B1** (sin `M`). Se entrega `TPR` + `FP/hora` y se declara el hueco.

### 0.4 Hipótesis (actualizadas con B1.0)

- **H-B1-1.** `67027` (nivel 3) sostendrá la detección; caída fuerte a `N=7`.
- **H-B1-2.** `67027` será **de doble uso**.
- **H-B1-3.** `Sysmon 23` sin reglas ⇒ T1485 por **FIM 553** + proceso. **(Confirmada en C0.)**
- **H-B1-4.** La **implementación** cambia el resultado (utilidad vs PowerShell/.NET).
- **H-B1-5. FALSADA por B1.0**: `Sysmon 3` base es **nivel 0** (`185001`). Las técnicas de red **no**
  tendrán capa de red; la detección será el **proceso**. Se sustituye por **H-B1-5′**: *"las 10
  técnicas de exfiltración se detectarán (si se detectan) por `4688`/`Sysmon 1`/`4104`, no por red;
  el `sink.log` es prueba de efecto, no detección"*.
- **H-B1-6.** **Sin predicado de canal**, el TPR a `N=3` será **32/32** (artefacto); **con**
  predicado, el TPR medirá el ataque. La diferencia entre ambos es la **sensibilidad de canal**.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

1. **Medir 32 ataques locales en Windows** con el método de Linux (doble iteración, `esperado`
   pre-registrado, C0, prueba de efecto, validación manual).
2. **Resolver el canal** (SSH primero) para que la huella del operador **no** cuente como detección.
3. **Producir T2-W** (métrica v1, catálogo provisional) y **T4-W** en lo calculable.
4. **Comparar por técnica** Linux↔Windows en 30 técnicas (RF-08).
5. Dejar el laboratorio cerrado y la cadena Linux intacta (byte a byte).

### 1.2 Entra

- **32 casos** (§4), **sin cambios respecto de v2**.
- **Canal SSH** (si viable) o **fallback `vmrun` + predicado de canal**.
- **Extensión aditiva** del extractor de Windows.
- **Arreglos B-2/B-3** antes de B1.1.

### 1.3 NO entra

- **13 no factibles** del inventario (SaaS/Exchange/cuenta cloud/lifecycle/dispositivo de red), con
  su motivo literal: **T1213.001–.005, T1485.001, T1496.003/.004, T1530, T1537, T1557.004,
  T1602.001/.002**. **No se excluye por categoría.**
- **5 adaptables diferidas a B1.6** (T1496.002, T1499.003, T1498.002, T1557.001, T1557.003), con
  motivo técnico (solape o requisito de red). **43 de los 75 factibles no medidos**, con código
  (`parent_de_medida`, `hardware`, `solape_mecanismo`, `coste`, `coste_destructivo`, `sin_servicio`,
  `requiere_*`).
- **Reglas propias RS3/RS4** (se mide virgen), **Defender ON**, **evasión**, **Velociraptor**,
  **P2**, **ventana legítima (W3)** y **cierre de P1-Windows**.
- **`extraer_alertas.py` (Linux)**: congelado, **no se toca**.

---

## 2. Estado de partida verificado (incluye B1.0)

### 2.1 Hechos previos

| Hecho | Fuente |
|---|---|
| Linux cerrado: **55 / 128 / 53**; FN = ATA013, ATA034 | `state.md` |
| VM `victima-windows` W10 Pro, `192.168.65.130`, agente **`002`** | `construccion_resultado.md:27` |
| Telemetría: Sysmon 15.22, 4688, 4104, FIM (incl. `C:\lab-attack` realtime) | ídem `:26-27` |
| **La VM se construyó SIN SSH** | `construccion_resultado.md:4`; `README.md` |
| Baseline 2×4 h: **159 / 7**; v1 = **72 / 4** | `Dataset/Legitimo/windows/` |
| RS2 **vacía**; RS1 incluye Sysmon/Security/PowerShell/FIM | `README.md:196-201`; `active_ruleset.txt` |
| "Internet local": 8080, 9090, **9091**, 9092; firewall `/24` | `internet_local/README.md:11-15, 24-26` |
| Inventario: 89 / 77 / **75 factibles** / 13 no factibles | `Hojas/inventario_p1_windows.csv` |
| `extraer_alertas_windows.py` emite 23 columnas (sin `win_target`) | `extraer_alertas_windows.py:70-77` |
| `extraer_alertas.py` (Linux) emite `srcip/srcuser/dstuser` | `extraer_alertas.py` (`DETAIL_HEADER`) |
| `filtrar_ruido.py` no conoce `win_*` | grep |
| `tabla2_ataques.py:219` hardcodea la ficha Linux | ídem |
| La ventana legítima Windows está preparada (W3 pendiente) | `_fases/windows-legit-prep/plan.md` |

### 2.2 B1.0 — ejecutado y **PASA** (2026-11-08)

| Punto | Resultado |
|---|---|
| Snapshot `lab-listo-windows-ataques` | **creado**; los 3 anteriores intactos |
| `C:\lab-attack` vacío + FIM realtime | **PASA** |
| Defender OFF / `NoAutoUpdate=1` / sin suspensión / hora Δ ≤ 2 s | **PASA** |
| `Sysmon64`/`WazuhSvc` Running; agente `002` Active | **PASA** |
| Pre-staging rclone / PortableGit / sqlite3 (URL+`sha256`) | **PASA** |
| Servicios del host 8080/9090/9091/9092 (prueba y apagado) | **PASA** |
| C0 de clases (dry run) | **PASA**, con puntos ciegos |
| Pre-flight del canal `vmrun` (no interactivo) | **PASA**, con huella no catalogada |
| Cierre: 0 VMs, 0 tareas `TFG-*`, puertos cerrados | **PASA** |

### 2.3 C0 real (B1.0) — lo que el plan debe respetar

| Clase | `event_id` | ¿Alerta? | `rule_id` (nivel) |
|---|---|---|---|
| Sysmon 1 | 1 | **SÍ** | `92029`(6), `92033`(3), `92039`(3), `92004`(4), `92027`(4), `92052`(4) |
| **Sysmon 3** | 3 | **NO** | `185001`(0) — evento generado, **sin alerta** |
| Sysmon 11 | 11 | **SÍ** | `92213`(15), `92200`(6) |
| **Sysmon 23** | 23 | **NO** | **no se genera** con la config actual |
| 4688 | 4688 | **SÍ** | `67027`(3) |
| 4104 | 4104 | **SÍ** | `91818`(4) |
| FIM fichero | — | **SÍ** | `554`(5), `553`(7) |
| FIM registro | — | **SÍ** (solo barrido) | `598`/`752`/`594`/`750`(5) + `91844`(12) |
| 7045 | 7045 | **SÍ** | `61138`(5) |
| **7036** | 7036 | **NO** | 0 eventos en System |
| **4698/106** | 4698/106 | **NO** | no se generan (política de auditoría) |
| 4720/4726 | 4720/4726 | **SÍ** | `60109`(8), `60111`(8) |
| 1074 | 1074 | **SÍ** | `67018`(3) |
| Extra | 7040 / 13 | **SÍ** | `61104`(3) / `92307`(3) |
| **Huella del canal** | **4624/4634/4672** | **SÍ** | **`67022`/`67023`/`67028` (3)** |

> **Puntos ciegos declarados**: Sysmon 3 genérico, Sysmon 23, 7036, 4698/106 y FIM de registro no
> realtime. **No se inventan capas**: cada caso se apoya en la capa que el C0 demostró.

### 2.4 El bloqueante (reproducido por el tester)

- Cada `vmrun runProgramInGuest` genera **3 alertas** de logon/logoff/privilegios.
- **No están en el catálogo v1** y `auto_ruido` está **vacío**.
- El `esperado` de cada caso declara `rule_id=67027` (D6b), así que el filtro **sí evalúa** señales
  de campo y una fila `67022` cae en el paso 4 (`novel`) ⇒ **`deteccion`**.
- Resultado: **32/32 casos "detectados" a `N=3`** por el **canal**, no por el ataque. **T2-W se
  invalida** si no se resuelve.

---

## 3. Decisiones

> Se mantienen **D1–D14** del v2. Se **corrige D8** y se añaden **D15–D19**.

| # | Decisión | Por qué | Coste / alternativa |
|---|---|---|---|
| **D8′** | **Canal = SSH primero**; `vmrun` solo como **fallback** | SSH es el canal estándar, comparable con Linux, y su logon es **atribuible por IP** (`192.168.65.1`) | Si SSH no es viable: fallback `vmrun` + predicado por `win_user`/`event_id` |
| **D15** | **B1.0-SSH.0 (viabilidad)** + **B1.0-SSH.1 (instalar/configurar)** antes de B1.1 | No se ataca sin canal resuelto | ~0,5 d + ~1 d |
| **D16** | **Predicado `OPERADOR_WIN`** (logon del canal) + **`auto_ruido` del servicio** (`sshd.exe`/`vmtoolsd.exe`), **nunca detección**; **sensibilidad sin predicado** | El canal no es ataque; el catálogo v1 no debe contaminarse | 1 regla de filtro + 1 variante de T2 |
| **D17** | **Extensión aditiva** de `extraer_alertas_windows.py`: `win_target`, `srcip` (de `ipAddress`), `logon_type`, `win_parent_image`; **`extraer_alertas.py` no se toca** | Resuelve B-3 y hace el predicado **demostrable por IP** | 2 regresiones: Linux byte a byte + CA-W23 |
| **D18** | **Casos interactivos**: **S1** autologon + tarea `InteractiveToken` (snapshot `-gui`) o **S2** limitación declarada | SSH no da escritorio; no se inventa | S1: +1 snapshot y ruido de sesión; S2: efecto parcial |
| **D19** | **Arreglos B-2/B-3 antes de B1.1**: `procedimiento_ventana.md`, `servicios_host.md`, `arrancar_servicios_host.py`, archivar `c0_detalle.csv`/`c0_agregado.csv`, `criterio_ataques.md §D.2` | No dejar cabos del tester | ~0,5 d |

**Decisiones que NO cambian** (requisito del humano): corpus 32, método, métrica v1, `C0≡C1`,
catálogo provisional v1, `FPR` pendiente, re-juicio posterior, filtro Windows nuevo, `Hojas/ATA_index.csv`
intacto.

---

## 4. Corpus B1: 32 casos

> **El corpus no cambia.** Se actualiza la columna **Capa** con lo que el C0 demostró (puntos ciegos)
> y se añade la **vía de canal** (SSH / tarea).

| ATA | Técnica | Táctica | Linux | Vía | Servicio / capa (C0 real) | Acción | Prueba de efecto |
|---|---|---|---|---|---|---|---|
| **ATA056** | T1020 Automated Exfiltration | Exfil | ATA020 | ART tal cual (`9c780d3d`) | sink `9090` (PUT) | bucle de PUT | `sink.log`: N líneas + `sha256` |
| **ATA057** | T1567.004 Webhook | Exfil | ATA043 | ART tal cual (`f0057c81`) | sink `9090` `/hook` | POST JSON | `sink.log` + JSON |
| **ATA058** | T1567.002 Cloud Storage | Exfil | ATA049 | ART adaptado (`8529ee44`) | WebDAV `9092` | `rclone` al remote local | fichero + `sha256` |
| **ATA059** | T1567.003 Text Storage | Exfil | ATA050 | ART adaptado (`c2e8ab6e`) | sink `9090` `/paste` | POST del dato | `sink.log` + contenido |
| **ATA060** | T1496.001 Compute Hijacking | Impact | ATA025 | manual | CPU local | 4 jobs 30 s | `CPU %` antes/durante |
| **ATA061** | T1486 Data Encrypted | Impact | ATA001 | manual (AES .NET) | ficheros (FIM `554`) | AES-256 | `sha256` ≠ + descifrado |
| **ATA062** | T1485 Data Destruction | Impact | ATA002 | ART adaptado | **FIM `553`** + proceso (Sysmon 23 **ciego**) | sobrescribir + borrar | no existen |
| **ATA063** | T1490 Inhibit Recovery | Impact | ATA003 | ART adaptado | Sysmon 13 (`92307`) + **FIM registro forzado** | `vssadmin`+`bcdedit` | `bcdedit` = `No` |
| **ATA064** | T1489 Service Stop | Impact | ATA004 | ART adaptado | `7045`(`61138`)/`7040`(`61104`) + 4688 (**7036 ciego**) | servicio de juguete | `sc query` |
| **ATA065** | T1531 Account Access Removal | Impact | ATA024 | ART adaptado | `60109`/`60111` + 4688 | usuario de juguete | `net user` |
| **ATA066** | T1491.001 Internal Defacement | Impact | ATA033 | ART adaptado | FIM `554`/`550` + Sysmon 11 | sobrescribir `index.html` | `sha256` ≠ |
| **ATA067** | T1529 Shutdown/Reboot | Impact | ATA038 | ART adaptado | `67018` + estado del agente | `shutdown /r` | `boot time` |
| **ATA068** | T1005 Data from Local System | Coll | ATA029 | ART adaptado | 4688/Sysmon 1/4104 | `dir`/`findstr` | `inventario.txt` |
| **ATA069** | T1560.001 Archive via Utility | Coll | ATA030 | ART adaptado | FIM `554` + 4104 | `Compress-Archive` | `.zip` N entradas |
| **ATA070** | T1074.001 Local Data Staging | Coll | ATA011 | ART adaptado | 4688 + FIM `554` | `robocopy` | N ficheros |
| **ATA071** | T1113 Screen Capture | Coll | ATA051 | ART adaptado | 4104 + FIM `554` | `CopyFromScreen` | PNG real (**S1**) |
| **ATA072** | T1115 Clipboard Data | Coll | ATA052 | ART adaptado | 4104 + FIM `554` | `Get-Clipboard` | cadena sembrada (**S1**) |
| **ATA073** | T1056.001 Keylogging | Coll | ATA018 | ART adaptado | 4104 + 4688 | `GetAsyncKeyState` | cadena inyectada (**S1**) |
| **ATA074** | T1041 C2 Channel | Exfil | ATA010 | ART tal cual (`d1253f6e`) | 4688/Sysmon 1 (**Sysmon 3 ciego**) | `curl.exe` POST | `sink.log` `sha256` |
| **ATA075** | T1048.001 Symmetric | Exfil | ATA019 | manual | 4688/Sysmon 1 | AES + `TcpClient` | `sink.log` TCP |
| **ATA076** | T1048.002 Asymmetric | Exfil | ATA041 | manual (mismatch ART) | 4688/Sysmon 1 | RSA + POST | `sink.log` + descifrado |
| **ATA077** | T1048.003 Unencrypted | Exfil | ATA042 | manual (mismatch ART) | 4688/Sysmon 1 | texto plano TCP | `sink.log` TCP |
| **ATA078** | T1567.001 Code Repository | Exfil | ATA022 | manual | 4688 + FIM | `git push` local | `git log` |
| **ATA079** | T1029 Scheduled Transfer | Exfil | ATA021 | manual | **4688/Sysmon 1 (`schtasks.exe`)**; 4698/106 **ciego** | `schtasks` + POST | `sink.log` + `LastRunTime` |
| **ATA080** | T1213.006 Databases | Coll | ATA016 | manual | 4688 + FIM | `sqlite3 .dump` | `dump.sql` N filas |
| **ATA081** | T1114.001 Local Email | Coll | — | ART adaptado | 4688 + FIM | copiar `.pst`/`.eml` | N ficheros |
| **ATA082** | T1185 Browser Session | Coll | — | manual | 4688 + FIM | copiar `Cookies` | SQLite header |
| **ATA083** | T1667 Email Bombing | Impact | ATA031 | manual | 4688 + FIM | 25 `.eml` | 25 ficheros |
| **ATA084** | T1657 Financial Theft | Impact | ATA017 | manual | 4688 + FIM | transferencia | saldo alterado |
| **ATA085** | T1498.001 Direct Flood | Impact | ATA048 | manual | 4688/Sysmon 1 | 8×8 MiB a `9091` | 8 líneas, 64 MiB |
| **ATA086** | T1499.001 OS Exhaustion | Impact | ATA045 | manual | 4688/Sysmon 1 | 512 MiB / 15 s | `Available MBytes` |
| **ATA087** | T1499.002 Service Exhaustion | Impact | ATA047 | manual | 4688/Sysmon 1 | 200 req loopback | servicio no responde |

> **Predicción declarada.** Solo `67027`(3), `92201`(9), `60642`(3), `60702`(5) están **probados**;
> el C0 añade `92029/92033/92039/92004/92027/92052`, `92213/92200`, `91818`, `554/553`, `61138/61104`,
> `60109/60111`, `67018`, `92307` **como evidencia de clase** (no de caso). Todo `rule_id` no visto en
> el C0 ni en el catálogo va marcado **`prediccion`**.

### 4.1 Cambios respecto de v2

| Cambio | Detalle |
|---|---|
| **Corpus** | **32, sin cambios** (0 añadidos, 0 quitados) |
| **Capa esperada** | Actualizada con los **puntos ciegos** del C0 (Sysmon 3, Sysmon 23, 7036, 4698/106, FIM registro) |
| **Canal** | `vmrun` → **SSH primero** (D8′/D15); `vmrun` = fallback |
| **Bloqueante** | **Predicado de operador** + **sensibilidad** (D16) |
| **Extractor** | **Aditivo** (D17); se corrige el v2 "no se toca" |
| **Interactivos** | **S1/S2** declarados (D18) |
| **B-2/B-3** | 5 artefactos antes de B1.1 (D19) |
| **H-B1-5** | **Falsada** por B1.0; sustituida por H-B1-5′ |

---

## 5. Método por caso, canal y extractor

### 5.1 Señal esperada (sin cambios de esquema)

`ATA<NNN>_esperado.csv` v5, **field-first**, ancla **H4-W** (`win_image` ∧ (`win_cwd` ∨
`win_command_line` ∨ `win_target`/`syscheck_path`) ∧ evento de ejecución). Lo que falla → `dudosa`.
`rule_id` solo si está probado; si no, `nota=prediccion`.

### 5.2 Canal: predicado de operador (el arreglo del bloqueante)

**Principio.** El canal **no es ataque**. Se clasifica como **`ruido_conocido`/`operador`** (o
`auto_ruido` para el **servicio**), **nunca** `deteccion`. La evidencia es el **C0 del canal**
(`canal_ssh.csv`): una invocación real, con sus `rule_id`, `event_id`, `srcip`, `win_user` y
`logon_type`.

**Predicado propuesto (`OPERADOR_WIN`)** — se ratifica con la evidencia, no se supone:

| `rule_id` | `event_id` | Condición | Categoría | Motivo |
|---|---|---|---|---|
| `67022` | 4624 | **`srcip = 192.168.65.1`** (host del operador) | `ruido_conocido` | `operador:67022` |
| `67023` | 4634 | **`srcip = 192.168.65.1`** | `ruido_conocido` | `operador:67023` |
| `67028` | 4672 | **`win_user = angel`** (sin IP en 4672) | `ruido_conocido` | `operador:67028` |
| `sshd.exe` (proceso) | — | **solo la imagen del servicio**, no sus hijos | `auto_ruido` | `auto_ruido:canal-ssh` |
| `vmtoolsd.exe` (proceso) | — | **solo en fallback `vmrun`** | `auto_ruido` | `auto_ruido:canal-vmrun` |

**Reglas duras:**
1. **Nunca** se marca `deteccion` una fila del canal. Si una fila no es atribuible (sin IP y sin
   usuario), va a **`dudosa`** y se declara (no se descarta).
2. **Los hijos de `sshd.exe` no son canal**: el ataque corre **dentro** de esa sesión. Solo la
   **imagen del servicio** (`sshd.exe`) es `auto_ruido`; `cmd.exe`/`powershell.exe` del ataque se
   atribuyen por carpeta (`C:\lab-attack\ATA<NNN>`) como siempre.
3. **El predicado no sustituye al catálogo**: el catálogo v1 sigue con **4 reglas**. El canal es una
   **capa aparte** (como `OPERADOR` en Linux), y se publica **con y sin** él.
4. **Sensibilidad obligatoria** (`--sin-operador`): T2-W se calcula **también** sin el predicado. La
   diferencia mide **cuánto TPR era artefacto del canal** (el tester ya vio 32/32 a `N=3`). Ambas
   cifras se publican; la **canónica** es **con** predicado.
5. **Evidencia**: `Soporte/Ataques/c0/windows/canal_ssh.csv` (o `canal_vmrun.csv`) con `sha256`, y
   una fila por invocación del dry run.

> **Si SSH no es viable** (fallback `vmrun`): el mismo predicado, pero **sin `srcip`** (el detalle de
> Windows no lo traía; con D17 sí lo traerá para 4624/4635). Si aun así no hay IP, la condición es
> `win_user = angel ∧ event_id ∈ {4624,4634,4672}` y se **declara** que **no es demostrable por IP**
> (limitación aceptada porque ningún caso de ataque inicia sesión como `angel`).

### 5.3 Casos interactivos (ATA071/072/073)

SSH abre una sesión **no interactiva** (session 0): `CopyFromScreen`, `Get-Clipboard` y
`GetAsyncKeyState` **no ven el escritorio**. Dos soluciones, **el humano elige**:

| Opción | Qué se hace | Efecto | Coste / límite |
|---|---|---|---|
| **S1 (recomendada)** | Snapshot **`lab-listo-windows-ataques-gui`** con **autologon** de `angel` (sesión 1) + tarea pre-creada `TFG-Attack-<ATA>` con **`InteractiveToken`** y disparo a `t0+30 s` | **Real** (pantalla, portapapeles, teclas) | +1 snapshot; el autologon añade ruido de sesión **al arranque** (fuera de `[t0,t1]` si `t0` ≥ 90 s tras `Active`); se mide en el C0 |
| **S2 (fallback)** | Solo SSH; se mide **proceso + 4104** | **Parcial**: el PNG/cadena pueden salir vacíos | Se declara `efecto_parcial` en la ficha; **no se inventa** la captura |

**Regla:** los 3 casos **no se cierran** sin declarar `S1` o `S2` **antes de `t0`** (en el README y
en la bitácora). Si S1: la tarea se crea **antes de `t0`** y el único proceso del canal dentro de la
ventana es el del ataque. Si S2: el `esperado` no declara `win_target` de la captura (no evaluable) y
la prueba de efecto se marca **parcial**.

### 5.4 Extractor: extensión aditiva (resuelve B-3)

**Hecho.** `extraer_alertas_windows.py` emite 23 columnas; **no** emite `win_target`, y `srcip`
sale **vacío** en Windows (el campo real es `data.win.eventdata.ipAddress`). El plan v2 decía "no se
toca": **se corrige** — el congelado es `extraer_alertas.py` (Linux), **no** el de Windows.

**Cambio (aditivo, solo columnas nuevas al final):**

| Columna | Origen JSON (orden de prueba) | Uso |
|---|---|---|
| `win_target` | `data.win.eventdata.targetFilename` → `destinationIp:destinationPort` | ancla H4-W (Sysmon 11/3) |
| `srcip` (ya existe) | **se rellena** con `data.win.eventdata.ipAddress` | predicado `OPERADOR_WIN` |
| `logon_type` (nueva) | `data.win.eventdata.logonType` | distinguir 2/3/5/10 |
| `win_parent_image` (nueva) | `data.win.eventdata.parentImage` | canal (`sshd.exe` → `cmd.exe`) |

**Doble regresión obligatoria:**
1. **Linux byte a byte**: `extraer_alertas.py` **no se toca**; se re-extrae una ventana Linux y se
   compara `sha256` con la actual.
2. **CA-W23**: `extraer_alertas_windows.py --regresion` sigue dando **159 / 7**, y las **23 columnas
   anteriores no cambian** (solo se **añaden** al final).

**Consecuencia**: `filtrar_ruido_windows.py` puede evaluar `win_target` y `srcip`; el `esperado` de
ATA074/075/076/077/085 deja de tener señales **no evaluables**.

### 5.5 C0 (sin cambios de método)

C0 **empírico por tanda** con la tabla real de B1.0 (§2.3). Cada caso referencia las clases que usa.
**No se usa `wazuh-logtest`** con `eventchannel` (no probado). Si una clase no alerta, se declara
punto ciego y el caso se apoya en otra capa.

### 5.6 Doble iteración y validación manual (sin cambios)

2 iteraciones desde el mismo snapshot; `t0` ≥ 90 s tras `Active`; criterio v2 (C1′/C2′/C3′); las
`dudosa` se resuelven **antes** de T2; nada del ataque se llama `ruido`.

---

## 6. Laboratorio: SSH, snapshot y bóveda v3

### 6.1 Árbol de decisión del canal

```
B1.0-SSH.0 (viabilidad; solo lectura + 1 dry run; se revierte si no vale)
│
├─ ¿`sshd.exe` ya instalado?  (Get-WindowsCapability / Test-Path)
│   ├─ SÍ ──────────────────────────────► configurar (B1.0-SSH.1)
│   └─ NO
│       ├─ ¿FoD ISO / payload offline disponible? (`Add-WindowsCapability -Source`)
│       │   ├─ SÍ ──────────────────────► instalar offline ──► configurar
│       │   └─ NO
│       │       ├─ ¿Win32-OpenSSH pre-staged (URL+sha256)? 
│       │       │   ├─ SÍ ──────────────► instalar manual ───► configurar
│       │       │   └─ NO ──────────────► FALLBACK
│       └─ (si el servicio no arranca o la auth falla) ──► FALLBACK
│
└─ FALLBACK (declarado):
    A. `vmrun runProgramInGuest` + predicado de canal (sin IP si no hay) + sensibilidad
    B. WinRM (5985/5986) — NO probado; solo si A falla
```

**Criterio de "SSH viable" (los 5 a la vez):**
1. `sshd` **arranca** y queda `Running` tras el arranque del snapshot.
2. El **host** conecta a `192.168.65.130:22` (firewall `/24`).
3. **Auth** por **clave** (preferida) o contraseña; `angel` entra.
4. El **dry run** devuelve `SSH-OK` y el manager alerta la huella **con `srcip=192.168.65.1`**.
5. **Cero** dependencia de internet (NAT off; payload local).

Si falla **cualquiera** → **FALLBACK A** (no se fuerza SSH).

### 6.2 B1.0-SSH.0 — viabilidad (pasos concretos, **no ejecutados**)

> Se hace sobre `lab-listo-windows-ataques`; si no es viable, **revert** y no queda cambio.

1. Revert + start; esperar agente `002` `Active` + 90 s.
2. `Get-WindowsCapability -Online -Name OpenSSH.Server*` → anotar `State`.
3. `Test-Path C:\Windows\System32\OpenSSH\sshd.exe`; `Get-Service sshd -ErrorAction SilentlyContinue`.
4. Si `NotPresent`: comprobar si hay **FoD ISO** montada (`Add-WindowsCapability -Online -Name
   OpenSSH.Server~~~~0.0.1.0 -Source <ISO>\sources\sxs`). **Sin ISO no se intenta** (NAT off).
5. **Cliente del host**: `Test-Path C:\Windows\System32\OpenSSH\ssh.exe`; `ssh -V`.
6. **Clave** (si se opta por clave): `ssh-keygen -t ed25519 -f <fuera del repo>`; copiar la **pública**
   a `C:\Users\angel\.ssh\authorized_keys` con ACLs (`icacls`: solo `angel` y `SYSTEM`).
7. **Firewall** (invitado): `New-NetFirewallRule -DisplayName TFG-ssh-22 -Direction Inbound -Protocol
   TCP -LocalPort 22 -RemoteAddress 192.168.65.0/24 -Action Allow`.
8. **Servicio**: `Set-Service sshd -StartupType Automatic`; `Start-Service sshd`; `Get-Service sshd`.
9. **Conectividad**: desde el host `Test-NetConnection 192.168.65.130 -Port 22`.
10. **Dry run** (2 min): `ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new angel@192.168.65.130
    "cmd /c echo SSH-OK"` → extraer alertas del manager y rellenar `canal_ssh.csv`
    (`rule_id, rule_level, event_id, srcip, win_user, logon_type, win_parent_image`).
11. **Decisión**: si los 5 criterios → **B1.0-SSH.1**; si no → **FALLBACK A** y se documenta el motivo.

### 6.3 B1.0-SSH.1 — instalación/configuración (si viable)

1. **Instalar** (una de las tres, en este orden):
   - capability **ya presente** → no instalar;
   - **FoD ISO** → `Add-WindowsCapability ... -Source <ISO>\sources\sxs`;
   - **Win32-OpenSSH** pre-staged (`OpenSSH-Win64.zip`, URL+`sha256`) → expandir en
     `C:\Program Files\OpenSSH` y `powershell -File Install-sshd.ps1`.
2. **`sshd_config` mínimo** (declarado y con `sha256`): `Port 22`, `PubkeyAuthentication yes`,
   `PasswordAuthentication no` (si clave), `AllowUsers angel`, `LogLevel INFO`.
3. **Servicio**: `Automatic` + `Running`; host key generada (`ssh-keygen -A`/`Install-sshd.ps1`).
4. **Firewall**: regla `TFG-ssh-22` acotada a `192.168.65.0/24`.
5. **C0 del canal**: **3 invocaciones** (whoami, cmd, powershell) en 2 min → `canal_ssh.csv` +
   `sha256`. Se ratifica el **predicado** (§5.2) con la evidencia (¿`4624` trae `ipAddress`? ¿`4672`
   trae usuario? ¿hay reglas `sshd` propias?).
6. **Sensibilidad**: `filtrar_ruido_windows.py --sin-operador` sobre el dry run → documentar cuántas
   filas serían `novel` sin predicado.
7. **Snapshot `lab-listo-windows-ataques-ssh`** (VM **apagada**). Si **S1**: habilitar autologon y
   crear `lab-listo-windows-ataques-gui` (también apagada).
8. **Bóveda v3**: `Soporte/Laboratorio/windows/ataques/boveda_v3.md` con versión de OpenSSH, `sha256`
   del zip/config, huella de la host key (**pública**), puerto, regla de firewall, cuenta de servicio,
   y `boveda_version=3`.

> **Si S1**: el autologon se configura **antes** del snapshot `-gui`; la sesión se crea **al arrancar**
> (fuera de `[t0,t1]`). Se mide en el C0 y se declara.

### 6.4 Lanzamiento del ataque

| Canal | Comando | Notas |
|---|---|---|
| **SSH (principal)** | `ssh -i <clave> -o BatchMode=yes angel@192.168.65.130 "cmd /c C:\lab-attack\ATA<NNN>\run.cmd"` | No interactivo; `t0`/`t1` los sella el guion; cosecha con `scp` |
| **Tarea (S1)** | tarea pre-creada `TFG-Attack-<ATA>` (`InteractiveToken`, disparo `t0+30 s`) | Solo ATA071/072/073 |
| **`vmrun` (fallback)** | `vmrun -gu angel -gp <env> runProgramInGuest ...` | Solo si SSH no es viable |

- **Cosecha**: `scp -r angel@...:C:/lab-attack/ATA<NNN>/evidencias ./Logs/ATA<NNN>_iterN/` (o
  `vmrun copyFileFromGuestToHost` en fallback).
- **Sin secretos**: la clave privada y la contraseña viven **fuera del repo**; la pública en el
  invitado.

### 6.5 Orden de una iteración

```
revert <snapshot del canal>            (ssh o gui)
start + agente Active + 90 s
[servicio local pre-staged, si aplica]  ← fuera de [t0,t1]
copiar C:\lab-attack\ATA<NNN>\          ← fuera de [t0,t1]
t0  ← marca UTC (invitado + host)
lanzar (ssh / tarea)                    ← 1 proceso de canal declarado
[t0,t1] ataque (≤ 120 s)
t1  ← marca UTC; cosechar (scp) y forzar FIM si el caso lo necesita
stop soft / revert
```

### 6.6 Aislamiento y no contaminación (sin cambios)

`victima-linux` apagada; manager encendido; NAT off; servicios del host acotados a `/24`; sin
artefactos (revert); sin secretos; manager intacto.

---

## 7. Medición

### 7.1 Unidad, ventana, rejilla (sin cambios)

`N = 32`; ventana canónica `_iter1`; umbrales `{0,3,7,10,12}`; titular `C1 × N=0` (= `C0 × N=0`);
doble conteo.

### 7.2 Config Windows (sin cambios)

`C0 = {RS1}`; `C1 = {RS1, RS2}` con RS2 vacía ⇒ `C0 ≡ C1`; `C2 = C3 = C1`. Límites declarados.

### 7.3 Catálogo de ruido (sin cambios)

**Provisional canónico = v1** (4 reglas); sensibilidad v1+v2; definitivo = ventana legítima (72 h).
**El canal NO entra en el catálogo** (es predicado). `auto_ruido` = servicio del canal (`sshd.exe`),
no sus hijos.

### 7.4 Qué se calcula en B1 y qué no

| Métrica | ¿B1? | Fuente |
|---|---|---|
| **TPR** (`TP/32`) **con predicado** | **sí (canónica)** | T2 |
| **TPR sin predicado** | **sí (sensibilidad)** | T2 `--sin-operador` |
| `#Alertas`, `#rule.id`, `A_TP`, `A_TP^c` | **sí** | T2 |
| **`FP/hora`** | **sí, descriptivo** | 159 / 8 h = 19,875 |
| **`FPR`/`TNR`/`Precisión`/`F1`/`GM`/`Usabilidad`** | **no** | Necesitan `M` ⇒ tras W3 |
| **T5 doble uso** | **provisional** | `67027` |
| **Sensibilidad "sin `67027`"** | **sí** | variante |
| **Sensibilidad "sin operador"** | **sí** | variante |

> **La cifra canónica es con predicado.** La sensibilidad sin predicado **no** se publica como
> resultado: se publica como **prueba del sesgo** (32/32 a `N=3`).

### 7.5 Extracción y atribución

- **Extractor**: `extraer_alertas_windows.py` **extendido aditivamente** (§5.4); `--detail` por
  iteración; `--agent-id 002`.
- **Atribución**: `filtrar_ruido_windows.py` con **`OPERADOR_WIN`** + `auto_ruido` de canal; regresión
  baseline v1/v2 → 0; guardarraíl "nada del ataque en `ruido`".

---

## 8. Productos y ficheros

### 8.1 Nuevos (v3)

| Ruta | Contenido |
|---|---|
| `Soporte/Laboratorio/windows/ataques/B1.0-SSH.md` | viabilidad + decisión (SSH / fallback) |
| `Soporte/Laboratorio/windows/ataques/boveda_v3.md` | OpenSSH, config, puerto, firewall, host key (pública), `boveda_version=3` |
| `Soporte/Ataques/c0/windows/canal_ssh.csv` | huella del canal (rule_id, level, event_id, srcip, win_user, logon_type, win_parent_image) |
| `Soporte/Ataques/c0/windows/c0_detalle.csv` + `c0_agregado.csv` | **archivados** (B-2) con `sha256` |
| `Soporte/Laboratorio/windows/ataques/procedimiento_ventana.md` | runbook por ventana (B-2) |
| `Soporte/Laboratorio/windows/ataques/servicios_host.md` | servicios del host, puertos, start/stop (B-2) |
| `_artefactos/scripts/arrancar_servicios_host.py` | start/stop idempotente + verificación de puertos (B-2) |
| `Hojas/ATA_index_windows.csv` | 32 filas ATA056–ATA087 |
| `Hojas/T2_ataques_windows.csv` + `_sens_67027` + `_sens_catalogo` + **`_sens_sin_operador`** | T2-W y sensibilidades |
| `Hojas/T4_rendimiento_windows.csv` | T4-W (ataque; legítimo `n/a`) |
| `Hojas/auditoria_origen_windows.csv` | ART vs propia |
| `Dataset/Ataques/Comandos/windows/T<id>-<desc>/` | ataque, `run.cmd`, `esperado`, `README`, `prestaging.ps1` |
| `Dataset/Ataques/Resultados/Wazuh/windows/` | fichas, `Auditado/`, `CSV/`, `Logs/`, `README` |
| `Bitacora/ATA056..087.json` | esquema Linux + `sistema: "windows"`, `canal`, `c0` |
| `_fases/fase-03b-b1/{plan,change-doc}.md` | archivo del bloque |

### 8.2 Modificados (aditivo + regresión)

| Fichero | Cambio | Regresión |
|---|---|---|
| `_artefactos/scripts/extraer_alertas_windows.py` | **+`win_target`, `srcip` (ipAddress), `logon_type`, `win_parent_image`** | **CA-W23 159/7** + columnas previas intactas + **Linux byte a byte** |
| `_artefactos/scripts/tabla2_ataques.py` | `--ficha-dir` | T2 Linux byte a byte |
| `Soporte/Ataques/plantilla_esperado.md` | §7.3: `win_target` **evaluable** (ya no pendiente) | — |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | §9.6: `OPERADOR_WIN` + `auto_ruido` de canal + sensibilidad | — |
| `Soporte/Ataques/criterio_ataques.md §D.2` | canal SSH, red/nube local, puntos ciegos | — |

### 8.3 Scripts nuevos

`filtrar_ruido_windows.py` (con `--sin-operador`), `verificar_ventana_windows.py`,
`resumen_windows.py`, `arrancar_servicios_host.py`.

### 8.4 Hashes

Cada producto con `sha256`; cabecera de CSV con `metrica_version=1`, `boveda_version=3`,
`catalogo=provisional_v1`, `canal=ssh|vmrun` y `sha256` de entradas.

---

## 9. Tandas y paradas humanas

| Tanda | Qué | Salida | Parada |
|---|---|---|---|
| **B1.0 — infra** | **HECHA (PASA)** | snapshot `lab-listo-windows-ataques`, C0, servicios, pre-staging | — |
| **B1.0-SSH.0 — viabilidad** (~0,5 d) | árbol §6.1, dry run, `canal_ssh.csv`, decisión | **SSH sí/no** documentado | **G-SSH.0** |
| **B1.0-SSH.1 — instalación** (~1 d) | instalar/configurar, snapshot, bóveda v3, predicado, sensibilidad | canal resuelto | **G-SSH.1** |
| **B1.1 — piloto mixto** (~3 d) | ATA056–ATA061 (2 tal cual, 2 adaptado, 2 manual) | pipeline validado | **G-B1.1** |
| **B1.2 — Impact** (~2,5 d) | ATA062–ATA067 | T2 parcial | **G-B1.2** |
| **B1.3 — Collection** (~2,5 d) | ATA068–ATA073 (071/072/073 con S1/S2) | T2 parcial | **G-B1.3** |
| **B1.4 — Exfiltración local** (~3,5 d) | ATA074–ATA080 | T2 parcial | **G-B1.4** |
| **B1.5 — Windows-only + datos + recursos** (~3 d) | ATA081–ATA087 | T2-W completo | **G-B1.5** |
| **B1.6 — cierre** (~1 d) | T2/T4, sensibilidades, hashes, cadena, README | bloque cerrado | **G-B1-final** |

**Coste total**: ~18 días efectivos (**≈ 105 h**), 4–5 semanas. **Recorte ofrecido**: 25 casos (sin
B1.5) ≈ 12 días.

**Salida del piloto (G-B1.1)**: 6/6 efecto, 0 `dudosas`, filtro OK, T2 reproducible, **y el canal no
aporta ninguna detección** (con predicado). Si falla → no se escala.

---

## 10. Criterios de aceptación

> Se mantienen **CA-B1-01…17** del v2: índice con **32 filas**; `esperado` firmado antes de `t0`;
> 2 iteraciones con `-Audited`/`-Revision`; `iguales`/`review` declarado; **0 filas del ataque en
> `ruido_conocido`**; prueba de efecto en los 32; C0 con evidencia real; replay baseline 0;
> T2 determinista; **regresión Linux byte a byte**; T4 legítimo `n/a`; piloto mixto; red/nube local
> y acotada; laboratorio cerrado; 0 secretos; `pytest` verde; `rule_id` predicho marcado
> `prediccion`. Se añaden:

| # | Criterio | Verificación |
|---|---|---|
| **CA-B1-18** | **Canal resuelto y declarado**: SSH viable (5 criterios) **o** fallback documentado con motivo | `B1.0-SSH.md` |
| **CA-B1-19** | **Predicado `OPERADOR_WIN`**: una invocación del canal **no** produce ninguna fila `deteccion`; las no atribuibles → `dudosa` | dry run + filtro |
| **CA-B1-20** | **Sensibilidad de canal** publicada: T2-W con y sin predicado; la diferencia documentada | `_sens_sin_operador` |
| **CA-B1-21** | **Extractor aditivo**: CA-W23 159/7, 23 columnas previas intactas, **Linux byte a byte** | 2 regresiones |
| **CA-B1-22** | **B-2/B-3 cerrados**: `procedimiento_ventana.md`, `servicios_host.md`, `arrancar_servicios_host.py`, `c0_detalle.csv`/`c0_agregado.csv` archivados, `criterio_ataques §D.2` | inspección |
| **CA-B1-23** | **Interactivos**: ATA071/072/073 con **S1 o S2 declarado antes de `t0`**; si S2, `efecto_parcial` en la ficha | fichas |
| **CA-B1-24** | **Bóveda v3** con OpenSSH (versión, `sha256`, config, puerto, firewall, host key pública) | `boveda_v3.md` |
| **CA-B1-25** | **Sin secretos**: clave privada fuera del repo; `authorized_keys` solo pública | grep |

---

## 11. Verificación del tester

1. **Canal**: reproducir una invocación y comprobar **0 `deteccion`** (con predicado) y **≥1** sin
   predicado (prueba del sesgo).
2. **Extractor**: CA-W23 159/7 + columnas previas intactas + Linux byte a byte.
3. **Predicado**: que **no** exime a los hijos de `sshd.exe` ni a un logon de ataque.
4. **Interactivos**: que S1/S2 está declarado **antes** de `t0` y que el efecto es real o parcial.
5. **B-2/B-3**: los 5 artefactos existen y están enlazados.
6. **Resto**: TPR re-derivado, cadena de huellas, `esperado` no re-escrito, baseline replay 0,
   laboratorio cerrado, 0 secretos, `pytest` verde.

---

## 12. Riesgos

> Se mantienen R1–R20. Se añaden:

| # | Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|---|
| **R21** | SSH no viable offline (payload FoD no disponible) | **alta** | alto | Árbol §6.1 → Win32-OpenSSH pre-staged → fallback `vmrun` + predicado |
| **R22** | El predicado es **demasiado ancho** y oculta una detección real | media | **crítico** | Condición estrecha (regla+IP/usuario); nunca hijos; sensibilidad publicada; revisión humana |
| **R23** | El predicado es **demasiado estrecho** y deja filas `novel` | media | alto | `dudosa` (no `deteccion`); C0 del canal con evidencia real |
| **R24** | La extensión del extractor rompe la cadena Linux | baja | **crítico** | `extraer_alertas.py` intacto; doble regresión |
| **R25** | S1 (autologon) cambia el ruido de fondo | media | medio | Autologon al arranque (fuera de `[t0,t1]`); C0 lo mide; se declara |
| **R26** | El canal SSH añade ruido propio (sshd, 7045, 4624) no catalogado | **alta** | alto | C0 del canal + predicado + sensibilidad; **nunca** al catálogo v1 |
| **R27** | S2 deja efectos parciales y se confunde con FN | media | medio | `efecto_parcial` explícito; no se cuenta como detección del efecto |

---

## 13. Trazabilidad

| Afirmación | Cita verificable |
|---|---|
| B1.0 PASA y huella del canal | `Soporte/Laboratorio/windows/ataques/B1.0_infra.md:43-60, 119-134` |
| C0 real y puntos ciegos | `Soporte/Ataques/c0/windows/clases_evento.csv`; `README.md:27-40` |
| VM **sin SSH** | `Soporte/Laboratorio/windows/construccion_resultado.md:4` |
| `extraer_alertas_windows.py` sin `win_target` | `_artefactos/scripts/extraer_alertas_windows.py:70-77` |
| `extraer_alertas.py` con `srcip` | `_artefactos/scripts/extraer_alertas.py` (`DETAIL_HEADER`) |
| Política §9 (perfil Windows) y §9.1 (OPERADOR no implementado) | `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md:307-323` |
| `win_target` pendiente | `Soporte/Ataques/plantilla_esperado.md:177-180` |
| Servicios del host y puertos | `Soporte/Laboratorio/internet_local/README.md:11-15, 24-26` |
| Baseline 159/7 y v1 72/4 | `Dataset/Legitimo/windows/` |
| Configs C0..C3 y umbrales | `Soporte/Metrica/metrica_hids.md:167-168`; `metrica_hids.py:58-64` |
| Ventana canónica y C1′/C2′/C3′ | `metrica_hids.md:204-213`; `criterio_doble_iteracion.md:29-33` |
| `t0` ≥ 60–90 s | `criterio_doble_iteracion.md:57-67` |
| Criterio ART/pre-staging y §D.2 | `Soporte/Ataques/criterio_ataques.md:16-46, 102-167` |
| 13 no factibles | `Hojas/inventario_p1_windows.csv` |
| `tabla2` hardcodea la ficha Linux | `_artefactos/scripts/tabla2_ataques.py:219` |
| Reglas Sysmon 3 (`92101-92110`) y ausencia EID 23 | `active_ruleset.txt`; C0 real |

---

## 14. Lo que no cuadra y predicciones declaradas

### 14.1 Bloqueantes y contradicciones (resueltos o declarados)

1. **Bloqueante B-1 (canal)**: resuelto con **SSH primero** y **predicado**; si SSH falla, fallback
   con predicado por usuario (no demostrable por IP) + sensibilidad.
2. **Contradicción B-3 (extractor)**: el v2 decía "no se toca"; **se corrige** — `extraer_alertas.py`
   (Linux) es el congelado; el de Windows es **aditivo** con doble regresión.
3. **B-2 (artefactos)**: faltan 3 documentos/script y 2 CSV sin archivar; se crean **antes de B1.1**.
4. **B-4 (interactivos)**: sin sesión interactiva; **S1** o **S2**, declarado antes de `t0`.
5. **B-5 (H-B1-5 falsada)**: `Sysmon 3` es nivel 0; las técnicas de red **no** tienen capa de red.
6. **B-6 (puntos ciegos)**: `Sysmon 23`, `7036`, `4698/106`, FIM registro no realtime; las capas
   esperadas se ajustan y **no se inventan**.
7. **`67027` en el catálogo**: D6b uniforme + sensibilidad sin `67027`.
8. **Sin `M`**: `FPR` no calculable en B1.
9. **`T1048.002/.003`**: el test ART usa HTTPS a `file.io` (no coincide con RSA/texto plano) ⇒ propio.
10. **`T1486`**: ART exige GPG4Win/DiskCryptor o solo `.akira` ⇒ AES .NET propio.
11. **`T1213.006`/`T1567.001`/`T1567.002`**: necesitan `sqlite3`/`git`/`rclone` pre-staged.
12. **`T1657`/`T1667`**: datos locales (libro/mailbox), no red; se incluyen porque son baratas y
    Linux-measured.
13. **El host es parte del laboratorio**: sink/WebDAV/web en `192.168.65.1`; no es internet.
14. **SSH cambia el entorno**: la baseline v1 se midió **sin** SSH; el catálogo provisional es
    **aún más provisional**; el re-juicio con 72 h decidirá.
15. **FIM de registro no realtime**: ATA063 necesita **barrido forzado** (`agent_control -r -u 002`)
    antes de `t1` o esperar el ciclo; se declara en el procedimiento de ventana.

### 14.2 Predicciones

- Solo `67027`, `92201`, `60642`, `60702` están probados; el C0 añade evidencia **de clase** (no de
  caso). Todo lo demás es **predicción**.
- **H-B1-1..4, H-B1-5′ y H-B1-6** (§0.4). Si fallan, se declara.
- **Volumen de alertas por ventana**: desconocido.

### 14.3 Lo que no se puede replicar

- `auditd`/`execve`/`audit_cwd`; `cwd` en 4688 (solo Sysmon 1).
- **SaaS/Exchange/cuenta cloud/lifecycle/dispositivo de red** (13 no factibles).
- **Ofimática real, navegador real, SMTP real, USB/audio/vídeo**.
- **Falsificación de origen** (T1498.002) y **segmento aislado** (T1557.003).
- **`FPR` en B1** y comparación en crudo Linux↔Windows.
- **Escritorio real por SSH** (S1 lo resuelve con autologon; S2 lo declara).

---

## 15. Gate humano

**Lo que se pide aprobar (6 puntos).**

1. **SSH primero**: ¿se autoriza **B1.0-SSH.0** (viabilidad, sin instalar) y, si es viable,
   **B1.0-SSH.1** (instalar/configurar + snapshot + bóveda v3)?
2. **Payload**: si no está offline, ¿se aprueba **Win32-OpenSSH pre-staged** (URL+`sha256`) o se
   prefiere el **fallback `vmrun` + predicado** (sin IP)?
3. **Predicado `OPERADOR_WIN`** propuesto (`67022/67023` por `srcip=192.168.65.1`; `67028` por
   `win_user=angel`; `sshd.exe` como `auto_ruido`) y **sensibilidad sin predicado**. ¿OK?
4. **Interactivos**: **S1** (autologon + `InteractiveToken` en snapshot `-gui`) o **S2** (limitación
   declarada, efecto parcial)?
5. **Extractor aditivo** (`win_target`, `srcip`, `logon_type`, `win_parent_image`) con doble
   regresión (Linux byte a byte + CA-W23). ¿OK?
6. **B-2/B-3 antes de B1.1**: `procedimiento_ventana.md`, `servicios_host.md`,
   `arrancar_servicios_host.py`, archivar `c0_detalle.csv`/`c0_agregado.csv`, `criterio_ataques §D.2`.

**Se mantiene**: corpus 32, método, métrica v1, `C0≡C1`, catálogo provisional v1, `FPR` pendiente,
re-juicio posterior, `Hojas/ATA_index.csv` intacto.

**No se ejecuta nada hasta que el humano responda y el orquestador marque este plan como
`approved_by_human`.** `git push` prohibido. Las fechas las fija el humano.

---

## 16. Veredicto del planificador

**GO condicionado al gate.** El bloqueante es real y el tester tiene razón: con el canal sin
catalogar, **T2-W sería un 32/32 de escaparate**. La solución correcta es la que pide el humano:
**SSH primero** (canal estándar, comparable con Linux, logon **atribuible por IP**) y, si no es
viable offline, **fallback declarado** con predicado y sensibilidad. La extensión **aditiva** del
extractor resuelve B-3 sin tocar el congelado de Linux. Los 3 interactivos tienen **solución o
limitación**, no invención.

Lo que **no** prometo: que los 32 se detecten. Prometo que **cada cifra será reproducible**, que el
canal **no** contará como detección, y que la diferencia entre "con" y "sin" predicado quedará
publicada. Si el TPR sale 32/32 a `N=3` **sin** predicado y 9/32 **con** él, ese será el resultado.

**Riesgo principal**: R21 (SSH no viable) y **R22** (predicado mal calibrado). Ambos se cierran en
**B1.0-SSH.0/1**, antes de B1.1, o no se empieza.
