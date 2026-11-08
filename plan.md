---
bloque: B1
nombre: Ataques Windows (fase-03b) — corpus B1 v2 con red/nube local y medición T2/T4-W
version: 2
status: approved_by_human
fecha: 2026-11-08
fecha_aprobacion: 2026-11-08
aprobado_por: humano
autor: tfg-planner
nota_gate: >-
  **APROBADO (2026-11-08).** El humano acepta: (1) 32 casos (ATA056–ATA087); (2) piloto mixto
  B1.1 de 6 (2 ART tal cual + 2 ART adaptados + 2 manual); (3) un plan con 7 tandas y paradas
  humanas; (4) segunda oleada posterior para ampliar más allá de 30; (5) servicios locales del
  host y pre-staging (rclone/PortableGit/sqlite3) con URL+sha256; (6) C0≡C1, catálogo
  provisional v1, FPR pendiente y re-juicio posterior; (7) snapshot nuevo + desactivar
  TFG-Baseline-* + vmrun con fallback + victima-linux apagada. **Condición expresa: los ataques
  deben estar bien diseñados.** Se autoriza arrancar SOLO B1.0 (infraestructura); los ataques
  requieren el gate G-B1.0.
correccion: >-
  v2 (2026-11-08, corrección del humano): NO se excluye ninguna técnica por ser de red/nube.
  Se incorporan las adaptables a la "internet local" del host (8080/9090/9091/9092, git bare,
  loopback, SQLite, mailbox/libro locales). Corpus 18 → 32. Primera tanda = piloto mixto
  (ART tal cual + ART adaptado + manual). Se mantienen método, métrica v1, filtro Windows,
  catálogo provisional v1, C0≡C1, FPR pendiente y re-juicio posterior.
depende_de: >-
  fase-02b-construccion (cerrado, laboratorio Windows operativo) ·
  fase-02b-baseline (cerrado, 159 alertas / 7 rule_id) ·
  legitimo-infra (cerrado, "internet local" del host) ·
  windows-legit-prep W0/W1/W2 (aprobado; W3 pendiente) ·
  Soporte/Metrica/metrica_hids.md v1 (congelada) ·
  Soporte/Ataques/{criterio_ataques,criterio_doble_iteracion,plantilla_esperado}.md ·
  Hojas/{inventario_p1_windows,ATA_index}.csv · estado Linux cerrado (55/128/53, commit 850248c)
no_toca: >-
  _recursos/ · Hojas/ATA_index.csv · Hojas/{T2,T4,T5}*.csv · Dataset/Legitimo/ ·
  Dataset/Ataques/Resultados/Wazuh/linux/ · Soporte/Metrica/ ·
  _artefactos/scripts/{filtrar_ruido.py,extraer_alertas.py,metrica_hids.py} ·
  laboratorio Linux (victima-linux) · corpus Linux (55 casos) · reglas RS3/RS4
gate: humano
ejecuta_ahora: NADA. Este documento es de diseño; no se arranca ninguna VM ni se lanza ningún ataque.
---

# plan.md — bloque `B1` (ataques Windows, `fase-03b`) — v2

> **Resumen en 10 líneas.** B1 mide **32 ataques locales en `victima-windows`** (ATA056–ATA087):
> **30 técnicas ya medidas en Linux** (comparación por técnica, RF-08) y **2 Windows-only**. La
> corrección del humano se incorpora: **las técnicas de red/nube no se excluyen**, se adaptan con la
> **"internet local" del host** (`192.168.65.1`: web 8080, sink HTTP 9090, TCP crudo 9091, WebDAV
> 9092), **git bare local**, servicios de loopback y **BD/mailbox/libro locales**, igual que en Linux
> (ATA016–ATA023, ATA041–ATA050, ATA044–ATA055). La **primera tanda es un piloto mixto de 6** (2 ART
> tal cual, 2 ART adaptado, 2 manual) para probar el pipeline antes de escalar. Se mantiene la
> **métrica v1**, el **catálogo provisional v1**, **`C0 ≡ C1`** (RS2 vacía) y **`FPR` pendiente** de
> `M`; todo B1 se **re-juzga** con el catálogo de la ventana legítima Windows (M1b-W).

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Estado de partida verificado](#2-estado-de-partida-verificado)
3. [Decisiones (con coste y alternativa)](#3-decisiones-con-coste-y-alternativa)
4. [Corpus B1: 32 casos](#4-corpus-b1-32-casos)
5. [Método por caso](#5-método-por-caso)
6. [Laboratorio](#6-laboratorio)
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

### 0.1 Qué sale de B1

| # | Producto | Estado tras B1 |
|---|---|---|
| 1 | **32 casos** Windows con 2 iteraciones | 64 ventanas `[t0,t1]` + 32 planes `C0` (5 *dry runs* de clase por tanda) |
| 2 | `T2_ataques_windows.csv` (TPR, FN, `rule_id`, primera evidencia) | **completo** (config × umbral) |
| 3 | `T4_rendimiento_windows.csv` | **TPR + `FP/hora`**; `FPR/TNR/F1/GM/Precisión` **pendientes de `M`** |
| 4 | Comparación **por técnica** Linux↔Windows | **30 técnicas** (la más amplia del TFG) |
| 5 | Cobertura ART Windows (guid + fichero + commit) | **21/32** con prueba disponible (**18** aprovechables); vía por caso |
| 6 | Filtro Windows y política v8 | nuevo, con regresión Linux byte a byte |
| 7 | Re-juicio con catálogo definitivo | **bloqueado** hasta la ventana legítima Windows |

### 0.2 Las tres cifras que el humano debe tener claras **antes** de aprobar

1. **`N = 32`** (18 del plan v1 + **14 nuevas**), no 55 ni 75. **30/32 son técnicas Linux**:
   la comparación por técnica cubre el **55 %** del corpus Linux.
2. **En Windows `C0 ≡ C1`** (RS2 vacía: `Soporte/Laboratorio/windows/README.md:196-201`).
   La rejilla pierde un eje; el eje útil pasa a ser el **umbral** y la **capa de origen**.
3. **`FPR` de Windows no se puede calcular en B1**: no hay `M` (la baseline 2×4 h **no** instrumentó
   `logall_json`). Se entrega `TPR` + `FP/hora` y se declara el hueco.

### 0.3 Hipótesis pre-registradas (predicciones, **no** resultados)

- **H-B1-1.** La detección la sostendrá la regla genérica de creación de proceso (`67027`, nivel 3),
  como `80792` en Linux: TPR alto a `N=3` y **caída fuerte a `N=7`**.
- **H-B1-2.** `67027` será **de doble uso** (ruido legítimo + detección), como `80792`.
- **H-B1-3.** `Sysmon EID 23` (borrado) **no tiene reglas** en el ruleset activo ⇒ T1485 se verá por
  **FIM** y por el **proceso**.
- **H-B1-4.** La **misma técnica** cambiará de resultado según la **implementación**
  (utilidad nativa vs PowerShell/.NET), replicando ATA013/ATA030/ATA034.
- **H-B1-5.** En Windows las técnicas de red **sí pueden tener capa de red** (`Sysmon EID 3`,
  reglas `92101-92110`), a diferencia de Linux (donde solo se vio el `execve`). Si se cumple, es una
  **ventaja medida** de Windows, no una suposición.

> Se escriben **antes** de medir y se contrastan en el cierre. Si fallan, se declara el fallo.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

1. **Medir 32 ataques locales en Windows** con el método de Linux (corpus por caso, doble iteración,
   `esperado` pre-registrado, C0, prueba de efecto, validación manual).
2. **Producir T2-W** con la métrica v1 y el catálogo provisional.
3. **Producir T4-W en lo calculable** (`TPR`, `FP/hora`) y **declarar** lo que no (todo lo que usa `M`).
4. **Comparar por técnica** Linux↔Windows en **30 técnicas** (RF-08), sin comparar `FPR` en crudo.
5. Dejar el laboratorio cerrado y la cadena Linux intacta (byte a byte).

### 1.2 Entra

- **32 casos** (§4), incluidos **10 de exfiltración** y **4 de recursos/DoS acotado** adaptados a la
  infraestructura local del host, **1 BD local**, **1 mailbox local** y **1 libro de cuentas local**.
- Diseño de señales, C0, guardarraíles, medición, productos y tandas.

### 1.3 NO entra: **solo lo no factible** (13) y lo no medido con motivo (43)

> **Regla de la corrección.** **No se excluye ninguna técnica por ser de red/nube.** Las 13 que
> quedan fuera lo son porque **no hay servicio real** (SaaS/Exchange/cuenta cloud/lifecycle/dispositivo
> de red), no por su categoría. Todo lo demás tiene un **motivo de solape, coste o hardware**, y
> queda listado para que el humano pueda promoverlo.

**1.3.1 No factibles (13, del inventario — no se atacan)**

| Técnica | Motivo (literal del inventario) |
|---|---|
| T1213.001 Confluence | SaaS (no hay servicio real) |
| T1213.002 SharePoint | SaaS/SharePoint (no hay servicio real) |
| T1213.003 Code Repositories (SaaS) | SaaS (no hay servicio real) — **distinto** de T1567.001 (repo **local**, sí se mide) |
| T1213.004 CRM | SaaS (no hay servicio real) |
| T1213.005 Messaging | Office/SaaS (no hay servicio real) |
| T1485.001 Lifecycle-Triggered Deletion | nube/IaaS (no hay servicio real) |
| T1496.003 SMS Pumping | SaaS (no hay servicio real) |
| T1496.004 Cloud Service Hijacking | SaaS (no hay servicio real) |
| T1530 Data from Cloud Storage | nube/IaaS (no hay servicio real) |
| T1537 Transfer Data to Cloud Account | nube/IaaS (no hay servicio real) |
| T1557.004 Evil Twin | dispositivo de red (no está en el laboratorio) |
| T1602.001 SNMP (MIB Dump) | dispositivo de red (no está en el laboratorio) |
| T1602.002 Network Device Configuration Dump | dispositivo de red (no está en el laboratorio) |

**1.3.2 Adaptables pero diferidas a `B1.6` (5, con motivo técnico — no por categoría)**

| Técnica | Por qué se difiere | Qué haría falta |
|---|---|---|
| **T1496.002** Bandwidth Hijacking | Su capa (volumen al sink `9091`) es la **misma** que T1498.001, que **sí se mide** (`criterio_ataques.md §C.3`: un modo por capa) | — (se mide la otra) |
| **T1499.003** Application Exhaustion | Solapa con T1499.002 (misma familia, misma capa, mismo efecto observable) | — (se mide .002) |
| **T1498.002** Reflection Amplification | Exige **falsificación de origen**; en Windows los raw sockets están restringidos y no hay `netns` para un reflector aislado | Tercer host o `netns` (Linux) |
| **T1557.001** LLMNR/NBT-NS | Exige un **tercer host que resuelva** y material externo (Inveigh); el host es **infraestructura**, no objetivo | Segunda VM Windows o host sacrificable |
| **T1557.003** DHCP Spoofing | En Linux se hizo con **veth+netns** aislado; Windows no tiene ese aislamiento y un DHCP en VMnet1 **colisiona** con el de VMware (mismo rango `.128-.254`) | Interfaz virtual aislada |

> **T1657 y T1667 sí entran** (§4): son adaptables a **libro de cuentas** y **mailbox** locales, como
> en Linux (ATA017/ATA031), y no necesitan servicio externo.

**1.3.3 No medidos en B1 (43 de los 75 factibles) — por código**

| Código | N | Técnicas | Significado |
|---|---|---|---|
| `parent_de_medida` | 11 | T1048, T1056, T1074, T1114, T1213, T1491, T1496, T1498, T1499, T1560, T1567 | El padre está cubierto por una subtécnica medida |
| `hardware` | 8 | T1011, T1011.001, T1025, T1052, T1052.001, T1123, T1125, T1495 | Sin USB/Bluetooth/audio/vídeo/firmware; un VHD montado no es "extraíble" |
| `solape_mecanismo` | 8 | T1119, T1056.003, T1560.002, T1560.003, T1565, T1565.001, T1496.002*, T1499.003* | Misma capa y mismo efecto que un caso medido |
| `coste` | 6 | T1039, T1056.002, T1056.004, T1499.004, T1565.002, T1565.003 | SMB/GUI/hooking/DLL/exploit/proxy: coste alto, capa ya cubierta |
| `coste_destructivo` | 3 | T1561, T1561.001, T1561.002 | Wipe de disco: destructivo y sin capa nueva frente a T1485/T1486 |
| `sin_servicio` | 2 | T1114.003, T1491.002 | Sin servidor de correo / sin web publicada |
| `requiere_segundo_host` | 1 | T1074.002 | Remote staging: no hay segundo host |
| `requiere_tercer_host` | 2 | T1557, T1557.001* | Ver §1.3.2 |
| `requiere_segmento_aislado` | 1 | T1557.003* | Ver §1.3.2 |
| `requiere_spoofing` | 1 | T1498.002* | Ver §1.3.2 |

`*` = adaptable diferida a B1.6. **Ninguna se excluye por ser de red/nube.**

---

## 2. Estado de partida verificado

| Hecho | Fuente |
|---|---|
| Linux cerrado: **55 casos / 128 ventanas / 53 de 55**; FN = ATA013, ATA034 | `state.md` (bloque `legitimo-analisis`) |
| VM `victima-windows` W10 Pro, `192.168.65.130`, agente **`002`** | `Soporte/Laboratorio/windows/construccion_resultado.md:27` |
| Telemetría: **Sysmon v15.22**, **4688 con cmdline**, **4104**, **FIM** (incl. `C:\lab-attack` realtime) | ídem `:26-27`; `telemetria_windows.md:15-25` |
| Snapshots: `base-limpia`, `lab-listo-windows`, `lab-listo-windows-baseline` | `state.md` (fase-02b) |
| Baseline 2×4 h: **159 alertas / 7 `rule_id`**; v1 = **72 / 4** | `Dataset/Legitimo/windows/{estabilidad_windows.csv,ruleids_legitimos_v1.csv}` |
| Catálogo v1 = `60642`(3), `60702`(5), `67027`(3), `92201`(9) | `ruleids_legitimos_v1.csv` |
| v2 añade `594`/`598`/`750` **por un FIM forzado** | `baseline_resultado.md:363-364` |
| RS2 **vacía**; RS1 incluye todo el ruleset Windows (Sysmon `1/3/7/8/10/11/13/20`, Security, PowerShell, FIM) | `README.md:196-201`; `active_ruleset.txt` |
| **No hay reglas de Sysmon EID 23**; **sí** de EID 3 (`92101-92110`) | `active_ruleset.txt` (detalle por fichero) |
| **"Internet local" del host**: web **8080**, sink HTTP **9090**, TCP crudo **9091**, WebDAV **9092**; firewall acotado a `192.168.65.0/24`; alias `intranet.local`/`nube.local` | `Soporte/Laboratorio/internet_local/README.md:11-15, 24-26, 41-49` |
| Linux ya adaptó red/nube así: ATA019 (.001, TCP 9091), ATA020 (9090), ATA022 (git bare local), ATA041 (.002, 9090), ATA042 (.003, 9091), ATA043 (/hook), ATA049 (WebDAV), ATA050 (/paste) | `Dataset/Ataques/Comandos/T*/README.md` |
| Linux ya adaptó recursos: ATA045 (512 MiB, `timeout`), ATA046 (app en `127.0.0.1:9093`), ATA047 (servicio en `127.0.0.1:9094`), ATA048 (flood TCP acotado), ATA054 (veth+netns) | ídem |
| Linux ya adaptó datos locales: ATA016 (SQLite real), ATA017 (libro de cuentas), ATA031 (Maildir, 25 mensajes) | ídem |
| Inventario: **89 / 77 aplicables / 75 factibles / 13 no factibles** | `Hojas/inventario_p1_windows.csv` |
| `filtrar_ruido.py` **no conoce** campos `win_*` | grep sobre `_artefactos/scripts/filtrar_ruido.py` |
| `extraer_alertas_windows.py` pasó **CA-W23** (159/7) | cabecera del script, `:37-43` |
| `tabla2_ataques.py` **hardcodea** la ficha Linux | `tabla2_ataques.py:219` |
| La ventana legítima Windows está **preparada pero no ejecutada** (W3) | `_fases/windows-legit-prep/plan.md` |

---

## 3. Decisiones (con coste y alternativa)

| # | Decisión | Por qué | Coste / alternativa |
|---|---|---|---|
| **D1** | **Corpus = 32 casos** (ATA056–ATA087): 18 del v1 + 14 de red/nube/recursos/datos locales | 30/32 son técnicas Linux ⇒ comparación por técnica máxima; la corrección pide no excluir red/nube | 64 ventanas. **Recorte ofrecido: 25** (sin B1.5) |
| **D2** | Índice nuevo **`Hojas/ATA_index_windows.csv`**; **no se toca** `Hojas/ATA_index.csv` | Añadir filas a `ATA_index.csv` **rompe** el `ata_index_sha256` de `Hojas/T2_ataques.csv` | 1 fichero nuevo; `tabla2` ya acepta `--ata-index` |
| **D3** | **Esquema de señales v5** (`win_image, win_command_line, win_cwd, win_target, win_user, event_id`) + **ancla H4-W** | En Windows no hay `audit_exe/cwd`; el ancla debe ser explícita | Aditivo en `plantilla_esperado.md` |
| **D4** | **Módulo nuevo `filtrar_ruido_windows.py`**; **no se toca** `filtrar_ruido.py` | Proteger la cadena de 128 `-Audited.csv` Linux | **Desviación declarada** de D6 (`README.md:174-181`): seguridad de la cadena |
| **D5** | **`C0 = {RS1}`, `C1 = {RS1}` (RS2 vacía) ⇒ `C0 ≡ C1`** | Hecho del ruleset, no elección | 2 columnas idénticas + complemento por capa |
| **D6** | **Catálogo provisional = v1 (4 reglas)**; sensibilidad v1+v2 | Las 3 de FIM de v2 son **ruido provocado** (FIM forzado) y borrarían detecciones FIM | 2 T2-W (canónico + sensibilidad) |
| **D6b** | **Los 32 declaran `67027` como señal anclada** + sensibilidad "sin `67027`" | Si unos sí y otros no, el TPR se sesga | 1 columna más |
| **D7** | Snapshot **`lab-listo-windows-ataques`** + **desactivar `TFG-Baseline-*`** | `StartWhenAvailable` puede dispararse al revertir | ~20 min; snapshots originales intactos |
| **D8** | Canal del operador = **`vmrun runProgramInGuest`** (pre-flight) con **fallback** a tarea | Patrón no probado; fallback ya probado en baseline | +1 h en B1.0 si falla |
| **D9** | **T2-W ahora; T4-W parcial** (`TPR` + `FP/hora`); **`FPR` pendiente de `M`** | No hay `M` de Windows; inventarlo invalidaría | Hueco declarado; se rellena tras W3 |
| **D10** | **ART: 21/32 disponibles, 18 aprovechables** (3 descartadas: 2 por mecanismo y 1 por material externo); se extrae el comando literal y se cita `guid`+fichero+`commit`; harness propio ⇒ `ART_adaptado` | Evita `Invoke-AtomicTest` y dependencias | Reparto distinto a Linux (5/43); declarado |
| **D11** | **B1 no cierra P1-Windows** (32/75) | No es un cierre | Declarado en este plan + índice |
| **D12** | **Red/nube = "internet local" del host** (8080/9090/9091/9092), **git bare**, **loopback**, **SQLite**, **mailbox/libro** | Es la adaptación ya validada en Linux; el host es parte del laboratorio | Servicios del host encendidos durante B1; se apagan al cerrar |
| **D13** | **Pre-staging declarado** de 3 herramientas: `rclone.exe` (T1567.002), PortableGit (T1567.001), `sqlite3.exe` (T1213.006), con **URL+`sha256`** | Sin ellas el mecanismo no es fiel; son pequeñas y fijables (`criterio_ataques.md §C.2`) | +3 sidecars en la bóveda; entran **antes de `t0`** |
| **D14** | **Primera tanda = piloto mixto de 6** (2 ART tal cual, 2 ART adaptado, 2 manual) | Probar el pipeline completo antes de escalar | 3 días; si falla, se para |

---

## 4. Corpus B1: 32 casos

### 4.1 Criterio de selección (20/80)

1. **Comparabilidad**: 30/32 son técnicas **ya medidas en Linux** ⇒ comparación por técnica (RF-08).
2. **Red/nube adaptables**: **no se excluye ninguna**; se llevan a la infraestructura local (§4.4).
3. **Cobertura de capas**: proceso, fichero (crear/borrar/modificar), registro, PowerShell, **red**,
   servicio, cuentas, **tarea programada**, **estado del agente**, **CPU/memoria/disco**.
4. **Prueba ART Windows** cuando el mecanismo coincide (**21/32 disponibles; 18 aprovechables**).
5. **Factibilidad offline** con servicios del host y material fijado (URL+`sha256`).
6. **Un modo por técnica** (`criterio_ataques.md §C.3`).

### 4.2 Tabla del corpus

> `Linux` = ATA de la misma técnica. `Vía` = provisional (se ratifica por caso con `guid`+`commit`).
> `Servicio` = infraestructura local usada. La señal exacta se **pre-registra por caso** (§5.1).

| ATA | Técnica | Táctica | Linux | Vía | Servicio / capa | Acción | Prueba de efecto |
|---|---|---|---|---|---|---|---|
| **ATA056** | T1020 Automated Exfiltration | Exfil | ATA020 | **ART tal cual** (`9c780d3d`) | sink `9090` (PUT) | bucle de PUT de N ficheros | `sink.log`: N líneas + `sha256` |
| **ATA057** | T1567.004 Exfil. Over Webhook | Exfil | ATA043 | **ART tal cual** (`f0057c81`) | sink `9090` `/hook` | POST JSON del botín | `sink.log` `/hook` + JSON |
| **ATA058** | T1567.002 Exfil. to Cloud Storage | Exfil | ATA049 | **ART adaptado** (`8529ee44`) | WebDAV `9092` | `rclone` al remote local | fichero en WebDAV + `sha256` |
| **ATA059** | T1567.003 Text Storage Sites | Exfil | ATA050 | **ART adaptado** (`c2e8ab6e`) | sink `9090` `/paste` | POST del dato | `sink.log` `/paste` + contenido |
| **ATA060** | T1496.001 Compute Hijacking | Impact | ATA025 | **manual** | CPU local | 4 jobs de CPU 30 s | `CPU %` antes/durante/después |
| **ATA061** | T1486 Data Encrypted for Impact | Impact | ATA001 | **manual** (AES .NET) | ficheros | AES-256 sobre `datos\` | `sha256` antes ≠ después; descifrado = original |
| **ATA062** | T1485 Data Destruction | Impact | ATA002 | ART adaptado | ficheros | sobrescribir + borrar `datos\` | los ficheros no existen |
| **ATA063** | T1490 Inhibit System Recovery | Impact | ATA003 | ART adaptado | registro/VSS | `vssadmin` + `bcdedit` + `reagentc` | `bcdedit /enum` = `No` |
| **ATA064** | T1489 Service Stop | Impact | ATA004 | ART adaptado | servicio | servicio **de juguete** stop/delete | `sc query` → STOPPED / no existe |
| **ATA065** | T1531 Account Access Removal | Impact | ATA024 | ART adaptado | cuentas | usuario **de juguete** delete | `net user` → no existe |
| **ATA066** | T1491.001 Internal Defacement | Impact | ATA033 | ART adaptado | ficheros | sobrescribir `web\index.html` | `sha256` ≠ |
| **ATA067** | T1529 System Shutdown/Reboot | Impact | ATA038 | ART adaptado | estado del agente | `shutdown /r /t 5 /f` (última acción) | `boot time` + reconexión |
| **ATA068** | T1005 Data from Local System | Coll | ATA029 | ART adaptado | proceso | `dir /s`, `findstr /s`, `Get-ChildItem` | `inventario.txt` con N líneas |
| **ATA069** | T1560.001 Archive via Utility | Coll | ATA030 | ART adaptado | ficheros | `Compress-Archive` | `.zip` N entradas; extraído = `sha256` |
| **ATA070** | T1074.001 Local Data Staging | Coll | ATA011 | ART adaptado | ficheros | `robocopy` a `staging\` | N ficheros, `sha256` iguales |
| **ATA071** | T1113 Screen Capture | Coll | ATA051 | ART adaptado | pantalla | `CopyFromScreen` → PNG | PNG con dimensiones y tamaño > 0 |
| **ATA072** | T1115 Clipboard Data | Coll | ATA052 | ART adaptado | portapapeles | `Set-Clipboard` → `Get-Clipboard` | fichero con la cadena sembrada |
| **ATA073** | T1056.001 Keylogging | Coll | ATA018 | ART adaptado | teclado | `GetAsyncKeyState` + `SendKeys` | log con la cadena inyectada |
| **ATA074** | T1041 Exfil. Over C2 Channel | Exfil | ATA010 | **ART tal cual** (`d1253f6e`) | sink `9090` `/c2` | `curl.exe` POST | `sink.log` con el `sha256` |
| **ATA075** | T1048.001 Symmetric Encrypted Non-C2 | Exfil | ATA019 | **manual** | TCP crudo `9091` | AES + `TcpClient` | `sink.log` TCP `len`+`sha256`; descifrado |
| **ATA076** | T1048.002 Asymmetric Encrypted Non-C2 | Exfil | ATA041 | **manual** (mismatch ART) | sink `9090` | RSA + POST | `sink.log` + descifrado con la privada |
| **ATA077** | T1048.003 Unencrypted Non-C2 | Exfil | ATA042 | **manual** (mismatch ART) | TCP crudo `9091` | texto plano + `TcpClient` | `sink.log` TCP `len`+`sha256` |
| **ATA078** | T1567.001 Exfil. to Code Repository | Exfil | ATA022 | **manual** | **git bare local** | `git push` al repo local | `git log` con el commit |
| **ATA079** | T1029 Scheduled Transfer | Exfil | ATA021 | **manual** | sink `9090` | `schtasks` + POST programado | `sink.log` + `LastRunTime` |
| **ATA080** | T1213.006 Databases | Coll | ATA016 | **manual** | **SQLite local** | `.dump` de la BD de juguete | `dump.sql` con N filas |
| **ATA081** | T1114.001 Local Email Collection | Coll | — | ART adaptado | perfil de correo | copiar `.pst`/`.eml` sintéticos | N ficheros de correo |
| **ATA082** | T1185 Browser Session Hijacking | Coll | — | **manual** | perfil de navegador | copiar `Cookies`/`Login Data` | ficheros + cabecera `SQLite format 3` |
| **ATA083** | T1667 Email Bombing | Impact | ATA031 | **manual** | **mailbox local** | 25 `.eml` en el buzón | 25 ficheros |
| **ATA084** | T1657 Financial Theft | Impact | ATA017 | **manual** | **libro de cuentas local** | transferencia fraudulenta | saldo alterado + fila nueva |
| **ATA085** | T1498.001 Direct Network Flood | Impact | ATA048 | **manual** | TCP crudo `9091` | 8 conexiones × 8 MiB | `sink.log`: 8 líneas, 64 MiB |
| **ATA086** | T1499.001 OS Exhaustion Flood | Impact | ATA045 | **manual** | memoria | 512 MiB, retenidos 15 s | `Available MBytes` antes/durante |
| **ATA087** | T1499.002 Service Exhaustion Flood | Impact | ATA047 | **manual** | loopback `9094` | 200 peticiones / 10 s | el servicio deja de responder |

> **Predicción declarada.** Los `rule_id` de FIM (`550/553/554`), Sysmon (`92xxx`) y Seguridad
> (`1074`, `4720/4726/4732`, `7045/7036`, `4698/106`) que aparecen en las fichas **son predicción**:
> solo `67027`, `92201`, `60642` y `60702` están **probados**. La tabla es **hipótesis de capa**.

### 4.3 Representatividad y límites

- **30/32** técnicas Linux ⇒ **55 %** del corpus Linux, elegido por riqueza de telemetría.
- **32/75** factibles = **43 %**; **no es un cierre**.
- **Por táctica**: Impact **13** (41 %), Exfiltration **10** (31 %), Collection **9** (28 %).
  Linux: Impact 35 %, Exfil 18 %, Coll 25 %. **Exfiltration va sobre-representada** a propósito:
  es lo que la corrección pide medir con la "internet local".
- **ART**: 21/32 con prueba Windows disponible, **18 aprovechables** (2 `art_mecanismo_no_coincide`:
  T1048.002/.003; 1 por material externo: T1486). La **vía** (tal cual/adaptado/propio) se decide por
  **mecanismo**, no por disponibilidad. En Linux fue 5/43: el reparto **cambia**, el criterio no.

### 4.4 Cómo se adapta cada técnica de red/nube (y las de datos locales)

> **Principio.** El host (`192.168.65.1`) es **parte del laboratorio**; **nada sale** de VMnet1.
> El destino es **fijo** y el guion **aborta** si no coincide. El log del servicio es la **prueba de
> efecto**, no la detección: la detección la da el **proceso** (y, si H-B1-5 se cumple, `Sysmon 3`).

| Técnica | Servicio local (host) | Cliente Windows | Prueba de efecto | Guardarraíl |
|---|---|---|---|---|
| T1020 | sink HTTP `9090` (PUT) | `Invoke-WebRequest -Method Put` (ART) | `sink.log`: `PUT /... len= sha256=` | destino `http://192.168.65.1:9090`; N ≤ 5 ficheros |
| T1041 | sink `9090` `/c2/beacon` | `Invoke-WebRequest -Method Post` (ART) | `sink.log` con el `sha256` del botín | destino fijo; 1 POST |
| T1048.001 | sink TCP crudo `9091` (`--tcp-port`) | `TcpClient` + AES-256 | `sink.log`: `TCP len= sha256=` + descifrado local | destino fijo; 1 conexión |
| T1048.002 | sink `9090` `/exfil` | RSA-2048 + `Invoke-WebRequest` | `sink.log` + descifrado con la clave privada | destino fijo; 1 POST |
| T1048.003 | sink TCP crudo `9091` | `TcpClient` texto plano | `sink.log`: `TCP len= sha256=` | destino fijo; 1 conexión |
| T1029 | sink `9090` `/api/scheduled` | `schtasks /create` + `curl.exe` | `sink.log` a `t0+30 s` + `LastRunTime` | tarea **de juguete**, se borra al cerrar |
| T1567.001 | **git bare** en `C:\lab-attack\ATA078\repo.git` | `git push` (PortableGit) | `git log --stat` con el dato | repo **local**; nunca remoto real |
| T1567.002 | WebDAV `9092` (`/nube/`) | `rclone copy` (remote WebDAV) | fichero en el WebDAV + `sha256` | destino fijo; 1 fichero |
| T1567.003 | sink `9090` `/paste` | `Invoke-RestMethod -Method Post` | `sink.log` `/paste` + contenido | destino fijo; 1 POST |
| T1567.004 | sink `9090` `/hook` | `Invoke-RestMethod` JSON (ART) | `sink.log` `/hook` + JSON | destino fijo; 1 POST |
| T1496.001 | — (CPU local) | `Start-Job` × 4 | `CPU %` antes/durante/después | ≤ 4 jobs, ≤ 30 s, `Stop-Job` por `trap` |
| T1496.002* | sink TCP `9091` | `TcpClient` × 1 | `sink.log` 32 MiB | **diferida** (solape con T1498.001) |
| T1498.001 | sink TCP `9091` | 8 `TcpClient` concurrentes | `sink.log`: 8 líneas, 64 MiB | `CONN=8`, 8 MiB/conn, ≤ 15 s |
| T1499.001 | — (memoria) | `[byte[]]::new(512MB)` retenido | `Available MBytes` antes/durante | ≤ 512 MiB, `HOLD=15 s`, liberar |
| T1499.002 | loopback `127.0.0.1:9094` (servicio desechable, **pre-staged**) | `TcpClient` × 200 | el servicio deja de responder / cola llena | ≤ 200 peticiones, ≤ 10 s, solo loopback |
| T1213.006 | **SQLite local** (`db.sqlite`, pre-staged) | `sqlite3.exe db ".dump"` | `dump.sql` con N filas | solo el fichero de juguete |
| T1667 | **mailbox local** (`C:\lab-attack\ATA083\mailbox\`) | `Set-Content` × 25 `.eml` | 25 ficheros | 25 mensajes, datos de juguete |
| T1657 | **libro de cuentas local** (`libro.csv`) | PowerShell: añade transferencia | saldo alterado + fila nueva | solo el libro de juguete |

`*` = diferida. **Todas las direcciones son fijas y el guion aborta si no coinciden.**

### 4.5 Cambios respecto de v1

| Cambio | Detalle | Por qué |
|---|---|---|
| **Corpus 18 → 32** | +14 casos | Corrección del humano: no excluir red/nube |
| **Añadidos (14)** | T1020, T1567.004, T1567.003, T1496.001, T1048.001, T1048.002, T1567.001, T1029, T1213.006, T1667, T1657, T1498.001, T1499.001, T1499.002 | Todas **ya medidas en Linux**; adaptadas a la infraestructura local |
| **Quitados** | **0** | Los 18 del v1 se mantienen |
| **§1.3 reescrita** | Antes: "nube/SaaS fuera". Ahora: **solo las 13 no factibles** + 43 no medidas con motivo | La exclusión por categoría era incorrecta |
| **Tandas 4 → 7** | B1.0 + B1.1 (piloto mixto) + B1.2 + B1.3 + B1.4 + B1.5 + B1.6 (cierre) | Probar el pipeline antes de escalar |
| **Piloto** | 6 casos: 2 ART tal cual + 2 ART adaptado + 2 manual | Requisito de la corrección |
| **Infra nueva** | Servicios del host + 3 herramientas pre-staged (rclone, PortableGit, sqlite3) | Sin ellas la red/nube no es fiel |
| **C0 nuevo** | Clases `Sysmon 3`, `4698/106`, `7045/7036` | Capas nuevas del corpus |
| **N** | 18 → 32 (TPR sobre 32) | Corpus ampliado |
| **Sin cambios** | Método, métrica v1, filtro Windows, catálogo v1, `C0≡C1`, `FPR` pendiente, re-juicio | Requisito de la corrección |

---

## 5. Método por caso

### 5.1 Señal esperada **pre-registrada** (antes de `t0`)

Fichero `ATA<NNN>_esperado.csv` con el esquema **v5** (aditivo al de 7 columnas):

```csv
senal_id,tipo,campo,patron,dato_componente,tecnica,nota
T1041-S1,deteccion,win_image,*\powershell.exe,Process Creation,T1041,cliente de exfiltracion
T1041-S2,deteccion,win_command_line,*ATA074*,Command Execution,T1041,ancla H4-W
T1041-S3,deteccion,win_cwd,C:\lab-attack\ATA074*,Process Creation,T1041,ancla H4-W (solo Sysmon 1)
T1041-S4,deteccion,win_target,*ATA074*,Network Connection Creation,T1041,prediccion (Sysmon 3)
T1041-A1,ambigua,syscheck_path,C:\lab-attack\ATA074\*,File Creation,T1041,artefacto del ataque
```

**Regla H4-W (mecanismo, no aspiración):** una señal `win_image` cuenta como `deteccion` **solo si**
(i) casa la imagen, **y** (ii) casa **al menos una** ancla — `win_cwd` **o** `win_command_line` **o**
`win_target`/`syscheck_path` — con `C:\lab-attack\ATA<NNN>`, **y** (iii) la fila es un **evento de
ejecución** (Sysmon `1` o Seguridad `4688`). Lo que casa la imagen y falla el ancla o el evento →
**`dudosa`** (`sin_ancla:<senal_id>`), nunca `deteccion` ni `ruido`.

**Regla de honestidad.** En Windows solo hay **4 `rule_id` con evidencia** (catálogo v1). El `esperado`
es **field-first**: declara campos y deja que la categoría `novel` haga su trabajo. Un `rule_id` solo
se declara si está **probado**; si se predice, la columna `nota` lleva **`prediccion`**.

### 5.2 C0 — "sin silenciadores" en Windows

No se usa `wazuh-logtest` con JSON de `eventchannel` (**no probado** en este proyecto). Se usa un
**C0 empírico por tanda**:

1. **Tabla de clases de evento** (`Soporte/Ataques/c0/windows/clases_evento.csv`): *dry run* fuera de
   ventana (~2 min) que provoca **una** de cada clase y registra `event_id → rule_id + level + ¿alerta?`.
   Clases: Sysmon **1, 3, 11, 23**, 4688, 4104, FIM fichero, FIM registro, **4698/106**, **7045/7036**,
   4720/4726, 1074.
2. **`ATA<NNN>_c0_plan.md` por caso**: qué clases usa y con qué `rule_id`/nivel salieron, y la
   declaración **"RS3 = RS4 = 0 ⇒ no hay enmascaramiento propio"**.

Si una clase **no alerta** se declara **punto ciego de fábrica** (análogo a `92600`) y el caso se apoya
en otra capa; si no hay otra, se declara **FN-capaz** antes de medir.

> **Límite declarado**: el C0 es **empírico**, no una prueba offline; no demuestra que *otra* línea
> del mismo EID se silencie. **Coste**: 1 dry run por tanda (5), no por caso.

### 5.3 Acciones, guardarraíles y elevación

- **Todo** escribe bajo `C:\lab-attack\ATA<NNN>\` (FIM realtime) o habla con un **destino fijo**.
- **Guardarraíl duro**: si la ruta de trabajo no empieza por `C:\lab-attack\ATA<NNN>\` **o** el destino
  no es el esperado → **aborta**. Cota de ficheros (≤ 200), tiempo (≤ 120 s), procesos (≤ 50).
- **Prohibido**: `C:\Windows`, cuentas/servicios reales (`WazuhSvc`, `Sysmon64`, `WinDefend`), el
  manager (`192.168.65.128`), cualquier IP fuera de `192.168.65.0/24`, el registro del sistema (salvo
  `bcdedit`/`reagentc` en ATA063, que el **revert** deshace).
- **Destructivos** (ATA062, ATA063, ATA067, ATA085–087): solo datos de juguete y cotas duras; el
  revert es la red.
- **Elevación**: el ataque corre como el usuario del invitado (`angel`). En B1.0 se verifica que está
  en `Administradores`; si no, se declara y se usa tarea como `SYSTEM` **solo** en 063/064/065/067.

### 5.4 Prueba del efecto (independiente de la alerta)

Cada caso define en su README **qué se mide sin mirar alertas** (§4.2 y §4.4). Se guarda en
`Logs/ATA<NNN>_iter{N}/efecto.txt`. **Ningún caso se cierra sin efecto demostrado.**

### 5.5 Doble iteración y validación manual

- **2 iteraciones** desde el **mismo snapshot**, con revert entre iteraciones y `t0` sellado **≥ 90 s
  después** de `agente Active` (`criterio_doble_iteracion.md:57-67`).
- **Criterio v2** (`:29-33`): C1′ mismo conjunto de `rule_id` `deteccion`; C2′ `|n2−n1| ≤ max(2, 10 %·n1)`;
  C3′ **0 `dudosas` sin resolver**. Si falla → **`review`** declarado.
- **Validación manual**: las `dudosa` van a `-Revision.csv`; el humano elige `deteccion` / `artefacto` /
  `ruido` con la regla **"nada del ataque se llama ruido"**. Se firma **antes** de calcular T2.

---

## 6. Laboratorio

### 6.1 Snapshot y preparación (B1.0)

1. Revert a **`lab-listo-windows-baseline`**.
2. **Desactivar/borrar `TFG-Baseline-Legit`** y las 4 `TFG-Baseline-*` del host; `schtasks /query`
   **sin** `TFG-*`. *(R1.)*
3. Crear `C:\lab-attack\` y verificar FIM realtime (`ossec.conf`).
4. Verificar **Defender OFF**, `NoAutoUpdate=1`, `wuauserv` parado, **sin suspensión**
   (`STANDBYIDLE`/`HIBERNATEIDLE`/`HYBRIDSLEEP` = 0), **hora** con VMware Tools (Δ ≤ 2 s),
   `Sysmon64`/`WazuhSvc` `Running`, agente `002` `Active`.
5. **Pre-staging** (antes de `t0`, con URL+`sha256` en `prestaging_material.md`): `rclone.exe`,
   PortableGit, `sqlite3.exe`. Verificar `where` y versión.
6. (Opcional declarado) alias en `C:\Windows\System32\drivers\etc\hosts`:
   `192.168.65.1 intranet.local nube.local paste.local hook.local` — si no, se usan IPs.
7. **Snapshot nuevo `lab-listo-windows-ataques`**. Los 3 anteriores **no se tocan**.
8. **Pre-flight del canal** (D8): `vmrun runProgramInGuest` de un `whoami` y medida de su huella.
   Si falla → fallback a tarea programada.

### 6.2 Servicios del host (por tanda)

```powershell
# HOST, antes de t0 (una vez por tanda; logs por iteración)
python Soporte\Ataques\receiver\sink_http.py  --bind 192.168.65.1 --port 9090 --tcp-port 9091 --log <iter>/sink.log
python Soporte\Ataques\receiver\sink_webdav.py --bind 192.168.65.1 --port 9092 --log <iter>/webdav.log
powershell -File Soporte\Laboratorio\internet_local\start_internet_local.ps1   # web 8080 (opcional)
```

- Firewall **acotado a `192.168.65.0/24`** (`internet_local/README.md:24-26`).
- **Se apagan al cerrar** la tanda; **nunca** se ocupan los puertos del manager (`443/1514/1515/55000`).
- El servicio de **T1499.002** (`127.0.0.1:9094`) se levanta **dentro del invitado** antes de `t0`
  (pre-staging) y se para al cerrar la ventana.

### 6.3 Orden de una iteración (guion fijo)

```
revert lab-listo-windows-ataques
start + esperar agente Active + 90 s          ← asentamiento (fuera de [t0,t1])
[servicio local pre-staged, si aplica]        ← fuera de [t0,t1]
copiar C:\lab-attack\ATA<NNN>\ (vmrun copyFileToGuest)
t0  ← marca UTC en el invitado y en el host
lanzar run.cmd (vmrun runProgramInGuest)      ← 1 cmd.exe + guion
[t0, t1]  ataque (≤ 120 s)
t1  ← marca UTC; cosechar efecto y logs (copyFileFromGuestToHost)
stop soft / revert                            ← la ventana no se reutiliza
```

- **`t0`/`t1` en UTC**, reloj verificado (Δ ≤ 2 s).
- **El material se copia antes de `t0`** (§C.2) y el revert lo destruye: **no queda artefacto**.
- **Nada se ejecuta dos veces** en la misma ventana; si falla, se descarta y se repite.

### 6.4 Aislamiento y no contaminación

| Regla | Cómo se cumple |
|---|---|
| **No tocar `victima-linux`** | VM Linux **apagada**; solo `wazuh-server` + `victima-windows` encendidas |
| **No mezclar con la ventana legítima** | B1 usa el catálogo provisional; **no** ejecuta GHOSTS ni la campaña W-XX. W3 va **después** y con **otro snapshot** |
| **NAT off** | Servicios en el **host** (`192.168.65.1`); **nada sale** de VMnet1 |
| **Sin artefactos** | Revert al final de cada iteración; `C:\lab-attack` vacío en el snapshot |
| **Sin secretos** | Contraseña del invitado por **variable de entorno**; **jamás** en el repo |
| **Manager intacto** | No se revierte; solo lectura de `/var/ossec/logs` para extraer |

---

## 7. Medición

### 7.1 Unidad, ventana y rejilla (métrica v1, sin cambios)

- **Unidad del plano ataque = caso**, **`N = 32`**.
- **Ventana canónica = `_iter1`** (sin repeticiones Windows); `_iter2` = reproducibilidad.
- **Umbrales**: `N ∈ {0, 3, 7, 10, 12}`. **Titular**: `C1 × N=0` (= `C0 × N=0` en Windows).
- **Doble conteo**: `#Alertas` **y** `#rule.id` distintos, siempre.

### 7.2 Config Windows y sus límites

```
C0 = {RS1}   C1 = {RS1, RS2}   RS2 = ∅  ⇒  C0 ≡ C1
C2 = C3 = C1  (RS3 = RS4 = 0)
```

| Límite | Consecuencia |
|---|---|
| **`C0 ≡ C1`** | Se publican 2 columnas idénticas + **complemento por capa**: Seguridad / Sysmon / PowerShell / FIM |
| **RS2 vacía** | No hay comparación `execve`-vs-base; **Sysmon es telemetría, no ruleset** (`README.md:196-201`) |
| **`C2/C3` = `C1`** | Bloques de reglas propias **vacíos** hasta el gate (L8) |
| **Nivel 3 genérico** | `67027` domina `N=3`; la caída a `N=7` **se mide**, no se supone |

### 7.3 Catálogo de ruido: provisional y re-juicio

| Versión | Reglas | Uso |
|---|---|---|
| **Provisional canónico = v1** (4 h, 72 alertas) | `60642`, `60702`, `67027`, `92201` | **T2-W principal** |
| **Sensibilidad = v1+v2** (8 h, 159) | + `594`, `598`, `750` (FIM forzado) | T2-W alternativo |
| **Definitivo** | catálogo de la **ventana legítima Windows** (72 h) | **re-juicio M1b-W** tras W3 |

**Por qué v1.** Las 3 de FIM de v2 salieron de un **escaneo forzado** (`baseline_resultado.md:363-364`):
meterlas haría que **cualquier escritura FIM del ataque** cayera en `ruido_conocido` y **borraría
detecciones**.

**Límites del provisional**: 8 h vs 72 h; 4 reglas; baseline generado por un script con un único
`powershell.exe`; **puede sobre-clasificar como `novel`** (infla detección). Se corrige en el re-juicio.

**`auto_ruido` Windows**: conjunto **vacío** (ninguna alerta del propio agente en 8 h). Se declara y
se re-mide en 72 h.

### 7.4 Qué se calcula en B1 y qué no

| Métrica | ¿B1? | Fuente |
|---|---|---|
| **TPR** (`TP_ata / 32`) | **sí** | `metrica_hids.tpr(tp, 32)` |
| `#Alertas`, `#rule.id`, `A_TP`, `A_TP^c` | **sí** | T2 |
| **`FP/hora`** (complemento) | **sí, descriptivo** | 159 / 8 h = **19,875 alertas/h** |
| **`FPR`/`TNR`/`Precisión`/`F1`/`GM`/`Usabilidad`** | **no** | Necesitan `M` y `A_FP` ⇒ **tras W3** |
| **T5 doble uso** | **provisional** | `67027` con seguridad |
| **Sensibilidad "sin `67027`"** | **sí** | variante declarada |

> **T4-W se entrega con la estructura y las filas de ataque; el plano legítimo queda `n/a` con motivo.**

### 7.5 Extracción y atribución

- **Extractor**: `extraer_alertas_windows.py` (no se toca) → `--detail` por iteración (23 columnas) y
  `--out` agregado; `--agent-id 002`.
- **Atribución**: `filtrar_ruido_windows.py` (nuevo), mismo orden, `ATTACK_ROOT = C:\lab-attack\`,
  ancla **H4-W**, `auto_ruido` vacío. **Regresión**: v1 (72) con catálogo v1 → **0 `deteccion`**;
  v2 (87) con v1+v2 → **0**.
- **Guardarraíl**: ninguna fila del ataque en `ruido_conocido`; el filtro **falla** (`exit 4`) si se
  intenta plegar a `ruido`.

---

## 8. Productos y ficheros

### 8.1 Nuevos (creados en ejecución)

| Ruta | Contenido |
|---|---|
| `Hojas/ATA_index_windows.csv` | 32 filas ATA056–ATA087 (`ata_id,tactica,tecnica,descripcion,artefacto,estado,plataforma`) |
| `Hojas/T2_ataques_windows.csv` | T2-W (largo, config × umbral) + `N_casos=32` + hashes |
| `Hojas/T4_rendimiento_windows.csv` | T4-W (ataque completo; legítimo `n/a`) |
| `Hojas/T2_ataques_windows_sens_catalogo.csv` | sensibilidad v1+v2 |
| `Hojas/T2_ataques_windows_sens_67027.csv` | sensibilidad sin `67027` |
| `Hojas/auditoria_origen_windows.csv` | ART (guid/fichero/commit) vs propia, por caso |
| `Dataset/Ataques/Comandos/windows/T<id>-<desc>/` | `ATA<NNN>_ataque.ps1`, `run.cmd`, `ATA<NNN>_esperado.csv`, `README.md`, `datos/`, `prestaging.ps1` |
| `Dataset/Ataques/Resultados/Wazuh/windows/` | `ATA<NNN>_meta.md`, `Auditado/`, `CSV/`, `Logs/ATA<NNN>_iter{N}/` (efecto, `sink.log`, `webdav.log`), `README.md` |
| `Bitacora/ATA056..087.json` | esquema Linux + `sistema: "windows"`, `c0`, `iteraciones`, `doble_iteracion` |
| `Soporte/Ataques/c0/windows/` | `clases_evento.csv`, `ATA<NNN>_c0_plan.md` |
| `Soporte/Laboratorio/windows/ataques/` | `procedimiento_ventana.md`, `armado.md`, `servicios_host.md`, `cierre.md`, `evidencias/` |
| `_fases/fase-03b-b1/{plan,change-doc}.md` | archivo del bloque (este `plan.md` al cerrar) |

### 8.2 Modificados (aditivo y con regresión)

| Fichero | Cambio | Regresión |
|---|---|---|
| `_artefactos/scripts/tabla2_ataques.py` | `--ficha-dir` (default = ruta Linux) | T2 Linux **byte a byte** |
| `Soporte/Ataques/plantilla_esperado.md` → v5 | campos `win_*` + H4-W | — |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` → v8 | + §Windows (aditivo) | — |
| `Soporte/Ataques/criterio_ataques.md §D.2` | concreción Windows (red/nube local) | — |

### 8.3 Nuevos scripts

| Script | Función | Pruebas |
|---|---|---|
| `_artefactos/scripts/filtrar_ruido_windows.py` | atribución Windows (mismo orden) | replay baseline → 0; 0 filas del ataque en ruido |
| `_artefactos/scripts/verificar_ventana_windows.py` | cobertura `[t0,t1]`, reloj, agente, huecos | ventanas reales |
| `_artefactos/scripts/resumen_windows.py` | tabla por capa (Seguridad/Sysmon/PS/FIM) | determinista |
| `_artefactos/scripts/arrancar_servicios_host.py` | start/stop de sink/WebDAV por iteración + verificación de puertos | idempotente |

### 8.4 Hashes

Cada producto con `sha256`; cadena con `auditar_cadena_huellas.py`. Cabecera de cada CSV con
`metrica_version=1`, `boveda_version=3` (`plataforma=windows`, B10-W;
`_fases/windows-legit-prep/plan.md` §11), `catalogo=provisional_v1` y los `sha256` de las entradas.
**Una cifra sin cabecera no es válida** (`metrica_hids.md:233-234`).

---

## 9. Tandas y paradas humanas

| Tanda | Qué | Salida | Parada |
|---|---|---|---|
| **B1.0 — infra** (~1,5 d) | snapshot, pre-flight, índice, esquema v5, filtro, replay baseline, servicios del host, pre-staging (rclone/git/sqlite), C0 de clases | 0 ataques; todo probado | **G-B1.0** |
| **B1.1 — piloto mixto** (~3 d) | ATA056–ATA061: 2 ART tal cual + 2 ART adaptado + 2 manual | pipeline validado + T2 parcial | **G-B1.1**: si falla, se para |
| **B1.2 — Impact** (~2,5 d) | ATA062–ATA067 (6) | T2 parcial | **G-B1.2** |
| **B1.3 — Collection** (~2,5 d) | ATA068–ATA073 (6) | T2 parcial | **G-B1.3** |
| **B1.4 — Exfiltración local** (~3,5 d) | ATA074–ATA080 (7) | T2 parcial | **G-B1.4** |
| **B1.5 — Windows-only + datos + recursos** (~3 d) | ATA081–ATA087 (7) | T2-W completo | **G-B1.5** |
| **B1.6 — cierre** (~1 d) | T2/T4-W, sensibilidades, hashes, cadena, README, `change-doc` | bloque cerrado | **G-B1-final** |

**Coste total**: ~17 días efectivos (**≈ 100 h**), 4–5 semanas de calendario.
**Recorte ofrecido**: **25 casos** (sin B1.5) ≈ 12 días / 3 semanas.

**Regla de parada**: si en una tanda **≥ 2 casos** acaban en `review` por causa del **método**, se
**para** y se revisa el diseño. No se "arregla" un caso cambiando su `esperado` después de `t0`.

**Salida del piloto (G-B1.1)** — todo o nada:
1. 6/6 con **efecto demostrado** (incluido el `sink.log`/WebDAV).
2. **0 `dudosas` sin resolver** en las 12 ventanas.
3. El **filtro** atribuye bien (0 filas del ataque en ruido) y el replay de baseline da 0.
4. T2 parcial reproducible (mismo `sha256` en 2 ejecuciones).
5. Si algo falla → **no se escala**; se corrige el pipeline y se repite el piloto.

---

## 10. Criterios de aceptación

| # | Criterio | Verificación |
|---|---|---|
| **CA-B1-01** | `ATA_index_windows.csv` tiene **32 filas**, ATA056–ATA087, técnicas del inventario | script de cuadre |
| **CA-B1-02** | Cada caso: `esperado` **firmado antes** de `t0` (`sha256` + fecha + OK humano) | `git log`/`sha256` |
| **CA-B1-03** | Cada caso: **2 iteraciones** con `-Audited.csv` y `-Revision.csv`; **0 `dudosas` sin resolver** | C3′ |
| **CA-B1-04** | Doble iteración v2: `iguales` o **`review` declarado** | fichas |
| **CA-B1-05** | **0 filas del ataque en `ruido_conocido`** | filtro + revisión |
| **CA-B1-06** | **Prueba de efecto** en los 32 (incluido `sink.log`/WebDAV/git/BD) | `Logs/.../efecto.txt` |
| **CA-B1-07** | **C0**: las 12 clases medidas con evento real; cada caso referencia la tabla | `clases_evento.csv` |
| **CA-B1-08** | Replay de baseline: v1 (72) con catálogo v1 → 0; v2 (87) con v1+v2 → 0 | test |
| **CA-B1-09** | **T2-W determinista**: 2 ejecuciones, mismo `sha256` | test |
| **CA-B1-10** | **Regresión Linux**: 128 `-Audited.csv` y T2/T4/T5 **byte a byte** | `sha256` + pytest |
| **CA-B1-11** | `T4-W` con **todas** las celdas del legítimo = `n/a` + motivo | inspección |
| **CA-B1-12** | **Piloto mixto**: ≥1 tal cual, ≥1 adaptado, ≥1 manual, todos con contraparte Linux | `auditoria_origen_windows.csv` |
| **CA-B1-13** | **Red/nube**: todo destino es local y fijo; **0 conexiones** fuera de `192.168.65.0/24` | logs del host + firewall |
| **CA-B1-14** | Laboratorio cerrado: **0 VMs**, snapshot restaurado, **0 tareas `TFG-*`**, **0 servicios del host**, `C:\lab-attack` vacío | `vmrun list`, `schtasks`, puertos |
| **CA-B1-15** | **0 secretos** en el repo | grep |
| **CA-B1-16** | `pytest` **verde** (≥ 353 + nuevos) | CI local |
| **CA-B1-17** | Cada `rule_id` predicho va marcado `prediccion` | script |

---

## 11. Verificación del tester

1. **Re-derivar TPR** desde los `-Audited.csv` sin mirar T2.
2. **Cadena de huellas**: ataque, `esperado`, detalle, audited, revisión, ficha, bitácora.
3. **`esperado` no re-escrito**: `git log` del fichero, fecha < `t0`.
4. **C0**: la tabla de clases se generó con evidencia real (no a mano).
5. **Regresión Linux**: regenerar T2/T4/T5 y comparar `sha256`.
6. **Baseline replay**: v1 (72) con v1 → 0; v2 (87) con v1+v2 → 0.
7. **Red/nube**: revisar que **todo** destino es `192.168.65.1` (o loopback/local) y que el host no
   abre puertos fuera de `192.168.65.0/24`; que los servicios se paran al cerrar.
8. **Laboratorio**: `vmrun list` = 0; `schtasks` sin `TFG-*`; puertos 8080/9090/9091/9092 cerrados.
9. **Honestidad**: ninguna cifra de `FPR`/`F1`/`GM` sin `M`; sensibilidades etiquetadas.

---

## 12. Riesgos

| # | Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|---|
| **R1** | `TFG-Baseline-Legit` (`StartWhenAvailable`) se dispara al revertir | **alta** | alto | D7: desactivar + verificar + snapshot nuevo |
| **R2** | Reloj (`w32time` off, depende de VMware Tools) | media | **crítico** | Δ ≤ 2 s antes de cada `t0`; si no, no se sella |
| **R3** | El invitado se suspende (bug de 30 min) | media | alto | `powercfg` a 0 dentro del snapshot + chequeo |
| **R4** | Defender se reactiva y bloquea el ataque | media | alto | checklist; `Get-MpComputerStatus` |
| **R5** | Volumen Sysmon/FIM desborda el manager | media | medio | cotas por caso (≤ 200 ficheros, ≤ 50 procesos, ≤ 120 s) |
| **R6** | `vmrun runProgramInGuest` no funciona | media | medio | pre-flight en B1.0 + fallback probado |
| **R7** | `win_cwd` ausente en 4688 ⇒ ancla por `command_line` (ancha) | **alta** | medio | H4-W con 3 anclas; `dudosas` visibles |
| **R8** | Tests ART piden internet/dependencias | alta | medio | comando literal + `ART_adaptado` |
| **R9** | Destructivo real (wipe/shutdown/flood) | baja | **crítico** | guardarraíl de ruta/destino + cotas + revert |
| **R10** | El catálogo provisional infla el TPR (`novel`) | **alta** | alto | sensibilidad v1+v2 + re-juicio 72 h |
| **R11** | Sin `M` ⇒ T4 incompleto | **cierta** | medio | D9: declarado; se completa tras W3 |
| **R12** | `67027` domina y el resultado es trivial | alta | medio | D6b: variante sin `67027` |
| **R13** | Secreto en el repo | baja | **crítico** | env var; grep en el cierre |
| **R14** | Windows 10 EOL (2025-10-14) | cierta | bajo | limitación declarada |
| **R15** | FIM realtime infla `A_TP` | alta | medio | doble conteo + `artefacto` para lo no declarado |
| **R16** | Los servicios del host se quedan encendidos o abren puertos de más | media | **alto** | `arrancar_servicios_host.py` con `stop` verificado; firewall acotado; CA-B1-14 |
| **R17** | Pre-staging (rclone/git/sqlite) cambia entre iteraciones | media | medio | URL+`sha256` fijados; se verifica el hash antes de cada tanda |
| **R18** | El flood/CPU/memoria satura el host o el invitado | media | alto | cotas duras (64 MiB, 512 MiB, 30 s) + `trap` de limpieza |
| **R19** | T1499.002: el servicio desechable muere antes de `t0` | media | medio | pre-staging verificado + relanzar antes de la ventana |
| **R20** | El `git push` local se confunde con un remoto real | baja | bajo | remote `file:///C:/lab-attack/...`; sin red |

---

## 13. Trazabilidad

| Afirmación | Cita verificable |
|---|---|
| Linux cerrado 55/128/53 | `state.md` (bloque `legitimo-analisis`) |
| VM, agente `002`, Sysmon, 4688, 4104, FIM | `Soporte/Laboratorio/windows/construccion_resultado.md:26-27` |
| FIM realtime `C:\lab-attack` | ídem `:27` |
| Capas y campos `win_*` | `Soporte/Laboratorio/windows/telemetria_windows.md:15-25, 60-67` |
| `ATTACK_ROOT` Windows y RS2 vacía | `Soporte/Laboratorio/windows/README.md:177, 196-201` |
| Baseline 159/7 y v1 = 72/4 | `Dataset/Legitimo/windows/{estabilidad_windows.csv,ruleids_legitimos_v1.csv}` |
| FIM forzado en v2 | `Soporte/Laboratorio/windows/baseline_resultado.md:363-364` |
| **Servicios de la "internet local"** (8080/9090/9092) y firewall | `Soporte/Laboratorio/internet_local/README.md:11-15, 24-26` |
| **TCP crudo 9091** | `Soporte/Ataques/receiver/README.md` (§2.bis); `sink_http.py:30` |
| **Alias de dominios** | `Soporte/Laboratorio/internet_local/README.md:41-49` |
| Linux adaptó red/nube (ATA019–023, 041–043, 049–050) | `Dataset/Ataques/Comandos/T*/README.md` (destinos `192.168.65.1`) |
| Linux adaptó recursos (ATA045–048, 054) | ídem (cotas y loopback/`netns`) |
| Linux adaptó datos locales (ATA016/017/031) | ídem (SQLite, libro, Maildir) |
| **13 no factibles** | `Hojas/inventario_p1_windows.csv` (columna `factibilidad`) |
| Configs C0..C3 y umbrales | `Soporte/Metrica/metrica_hids.md:167-168`; `metrica_hids.py:58-64` |
| Ventana canónica y C1′/C2′/C3′ | `metrica_hids.md:204-213`; `criterio_doble_iteracion.md:29-33` |
| `t0` ≥ 60–90 s tras `Active` | `criterio_doble_iteracion.md:57-67` |
| Esquema de señales | `Soporte/Ataques/plantilla_esperado.md:25-34` |
| Criterio ART/manual/pre-staging y §D Windows | `Soporte/Ataques/criterio_ataques.md:16-46, 102-167` |
| Extracto de campos Windows | `_artefactos/scripts/extraer_alertas_windows.py:25-35, 69-77` |
| `tabla2` hardcodea la ficha Linux | `_artefactos/scripts/tabla2_ataques.py:219` |
| Filtro Linux sin `win_*` | `_artefactos/scripts/filtrar_ruido.py:117` (y grep sin coincidencias) |
| Reglas Sysmon 3 (`92101-92110`) y ausencia de EID 23 | `Soporte/Wazuh/Configuracion/active_ruleset.txt` |
| ART pin `388942a…`; guids del piloto | `Soporte/Ataques/atomic-red-team.version`; `atomics/T1020|T1041|T1567.002|T1567.003|T1567.004/*.yaml` |
| Métrica no comparable en crudo entre plataformas | `Soporte/Metrica/metrica_hids.md:66-68, 254-268` |

---

## 14. Lo que no cuadra y predicciones declaradas

### 14.1 Problemas reales encontrados al inspeccionar

1. **`tabla2_ataques.py:219`** hardcodea `.../Wazuh/linux/{ata}_meta.md`; sin `--ficha-dir`, T2-W
   apuntaría a fichas Linux inexistentes **sin avisar**.
2. **`filtrar_ruido.py` no conoce `win_*`** (0 coincidencias) y su `ATTACK_ROOT` es Linux ⇒ sin filtro
   Windows no hay atribución. → D4 (desviación declarada de D6).
3. **`StartWhenAvailable` de la tarea de baseline** puede rearmarse al revertir y correr 248 min
   dentro de B1. → D7 / R1.
4. **No hay reglas para Sysmon EID 23** ⇒ T1485 se verá por FIM/proceso, no por "file delete".
5. **`67027` está en el catálogo** ⇒ declararla o no cambia el TPR. → D6b uniforme.
6. **El catálogo v2 contiene ruido provocado** (FIM forzado) ⇒ no canónico. → D6.
7. **No existe `M` de Windows** ⇒ `FPR` no calculable en B1.
8. **`T1114.001` (ART) exige Outlook** ⇒ adaptado a ficheros; el correo real no se mide.
9. **`T1185` no está en el clon ART** ⇒ propia + perfil sintético.
10. **`extraer_alertas_windows.py --regresion`** valida contra productos congelados, no contra el JSON
    crudo (el crudo del 08/10 no está en el repo).
11. **El host es parte del laboratorio**: sink/WebDAV/web viven en `192.168.65.1`; no es exfiltración
    a Internet. Se declara y se acota por firewall.
12. **`angel` puede no ser administrador**: 063/064/065/067 fallarían. Se verifica en B1.0.
13. **`T1048.002`/`T1048.003`: el test ART de Windows usa HTTPS a `file.io`** (cifrado por TLS), que
    **no coincide** con el mecanismo del corpus (RSA sobre el payload / texto plano por TCP crudo) ⇒
    `art_mecanismo_no_coincide` → propio. Se cita el test y el motivo.
14. **`T1486`: hay ART Windows, pero los tests exigen GPG4Win/DiskCryptor (externos) o solo dejan la
    extensión `.akira`** ⇒ AES real en .NET (`propio_por_diseno`) para poder demostrar el efecto.
15. **`T1213.006` necesita `sqlite3.exe`** (no está en Windows) ⇒ pre-staging declarado.
16. **`T1567.001` necesita `git`** (no está en Windows) ⇒ PortableGit pre-staged (~50 MB).
17. **`T1567.002` necesita `rclone`** ⇒ `rclone.exe` pre-staged (~20 MB).
18. **Los servicios del host no arrancan solos**: `start_internet_local.ps1` levanta 8080/9090/9092,
    pero **no** el TCP crudo 9091 (`--tcp-port`) ⇒ se arranca a mano por tanda y se verifica el puerto.
19. **`T1499.002`** necesita un servicio desechable en loopback **antes de `t0`**; si muere, no hay
    efecto. Se verifica y se relanza.
20. **`T1657`/`T1667` no son de red**: son datos locales (libro/mailbox), como en Linux. Se incluyen
    porque la corrección pide no excluirlas y son baratas.

### 14.2 Predicciones (declaradas como tales)

- **`rule_id` de Windows**: solo `67027`(3), `92201`(9), `60642`(3), `60702`(5) están **probados**.
  Todo lo demás (`554`, `553`, `920xx`, `918xx`, `1074`, `4698`, `7045`, `4720`) es **predicción**.
- **H-B1-1..5** (§0.3). Si fallan, se declara el fallo.
- **Volumen de alertas por ventana**: desconocido (la baseline dio 159 en 8 h; una ventana de 60 s con
  FIM realtime puede dar decenas).

### 14.3 Lo que no se puede replicar (honesto)

- `auditd` y el par `execve`/`audit_cwd`.
- `cwd` en 4688 (solo en Sysmon EID 1).
- **SaaS/Exchange/cuenta cloud/lifecycle/dispositivo de red** (las 13 no factibles).
- **Ofimática real** (Outlook), **navegador real**, **correo real (SMTP)**, **USB/audio/vídeo**.
- **Falsificación de origen** (T1498.002) y **segmento aislado** (T1557.003).
- **`FPR` en B1** (sin `M`) y la comparación **en crudo** Linux↔Windows (prohibida por la métrica).
- El reparto ART de Linux (5/43) — en Windows será distinto: **cambia el método, no el criterio**.

---

## 15. Gate humano

**Lo que se pide aprobar (5 puntos).**

1. **Corpus = 32** (ATA056–ATA087; 30 Linux + 2 Windows-only), con **14 añadidos** y **0 quitados**
   respecto del v1. **Alternativa**: recorte a **25** (sin B1.5: Windows-only + datos + recursos).
   ¿32 o 25?
2. **Piloto mixto B1.1 (6)**: T1020 y T1567.004 **ART tal cual**; T1567.002 y T1567.003 **ART
   adaptado**; T1496.001 y T1486 **manual**. Todos con contraparte Linux. ¿OK?
3. **Red/nube local**: servicios del host (8080/9090/**9091**/9092) encendidos durante B1 y **pre-staging
   de 3 herramientas** (`rclone.exe`, PortableGit, `sqlite3.exe`) con **URL+`sha256`**. ¿OK?
4. **Se mantiene** `C0 ≡ C1`, catálogo provisional **v1**, `FPR` pendiente y re-juicio posterior.
   ¿Se acepta T4 incompleto y declarado?
5. **Snapshot `lab-listo-windows-ataques`** + **desactivar `TFG-Baseline-*`** + canal
   `vmrun runProgramInGuest` (con fallback) + **`victima-linux` apagada**. ¿OK?

**Además, para que conste**: el índice será **`Hojas/ATA_index_windows.csv`** (nuevo) y **no** se
tocará `Hojas/ATA_index.csv`, para no romper el `sha256` de T2 Linux. Se acepta la **desviación
declarada** de D6 (módulo de filtro nuevo en vez de "perfil" en el mismo fichero).

**No se ejecuta nada hasta que el humano responda y el orquestador marque este plan como
`approved_by_human`.** `git push` prohibido. Las fechas las fija el humano.

---

## 16. Veredicto del planificador

**GO condicionado al gate.** La corrección del humano es correcta y el plan v1 se quedaba corto: las
técnicas de red/nube **se pueden medir** con la misma "internet local" que ya funcionó en Linux, y
excluirlas por categoría habría dejado fuera **10 casos de exfiltración y 7 de recursos** con
contraparte Linux. El corpus pasa a **32** (30 Linux + 2 Windows-only), con **piloto mixto** para no
escalar sobre un pipeline sin probar.

Lo que **no** prometo: que los 32 se detecten. Prometo que **cada cifra será reproducible y cada hueco
estará escrito** — incluidos los tres que ya se ven venir: `C0 ≡ C1`, `FPR` sin `M` y el catálogo
provisional. Si el TPR sale 32/32 a `N=3` y 6/32 a `N=7`, **ese** será el resultado.

**Riesgo principal**: R1 (tarea de baseline con `StartWhenAvailable`) y **R16** (servicios del host
encendidos). Ambos se cierran **antes** del primer ataque o no se empieza.
