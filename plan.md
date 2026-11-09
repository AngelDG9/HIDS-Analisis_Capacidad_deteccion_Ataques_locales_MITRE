---
bloque: B2
nombre: Ampliación de ataques Windows (segunda oleada) — 22 casos, N=54 y sensibilidades
version: 1
status: approved_by_human
fecha: 2026-11-09
fecha_aprobacion: 2026-11-09
aprobado_por: humano
autor: tfg-planner
nota_gate: >-
  **APROBADO (2026-11-09).** El humano acepta: (1) **22 casos** (N=54); (2) las limitaciones
  declaradas (VHD en vez de USB, LLMNR sin tercer host, reflexión sin spoofing, DHCP/correo
  sintéticos, hooking posiblemente parcial); (3) **bóveda v3.1** sin cambio de telemetría;
  (4) pre-staging de Inveigh/DLL con URL+`sha256`; (5) sensibilidades **FIM-como-detección**,
  `sin_67027`, `sin_operador` y `catalogo_v2` sobre **N=54**, con T2 canónico **sin FIM**.
depende_de: >-
  B1 CERRADO (071380e; 32 casos ATA056–ATA087, 32/32 a N=0/3, 0/32 reales a N≥7,
  T2 fb83d19d…, T5 be001594…) · _fases/fase-03b-b1/{plan,change-doc}.md ·
  Soporte/Metrica/metrica_hids.md v1 (congelada) · bóveda v3 (Windows) ·
  Soporte/Ataques/{criterio_ataques,criterio_doble_iteracion,plantilla_esperado}.md ·
  Hojas/inventario_p1_windows.csv (89/77/75/13) · Hojas/ATA_index.csv (55 Linux) ·
  Soporte/Laboratorio/internet_local/README.md (8080/9090/9091/9092; git/SQLite; host 192.168.65.1)
no_toca: >-
  _recursos/ · Hojas/ATA_index.csv · Hojas/ATA_index_windows.csv (B1) ·
  Hojas/{T2,T4,T5}*_windows.csv (B1) · Dataset/Legitimo/ · Soporte/Metrica/ ·
  corpus Linux (55 casos) · _artefactos/scripts/{extraer_alertas.py,metrica_hids.py} ·
  reglas RS3/RS4 · laboratorio Linux (victima-linux)
gate: humano
ejecuta_ahora: NADA. Este documento es de diseño; no se arranca ninguna VM ni se lanza ningún ataque.
---

# plan.md — bloque `B2` (ampliación de ataques Windows)

> **Resumen en 10 líneas.** B2 cierra la **segunda oleada** antes de la ventana legítima W3:
> **22 casos nuevos** (ATA088–ATA109) que cubren (1) las **5 diferidas de B1** (T1496.002,
> T1499.003, T1498.002, T1557.001, T1557.003), (2) las **factibles restantes con pareja Linux**
> (archivo por librería/método propio, manipulación de datos, disco, medios, GUI, web local, SMB,
> staging remoto, recolección automatizada, correo sintético) y (3) **capas nuevas** (VHD, SMB,
> SMTP, UDP, proxy, inyección). **20/22 tienen pareja Linux**; la comparación es **por técnica y
> efecto**. El corpus Windows pasa a **N=54** (32 de B1 + 22 de B2) y se publican **T2/T4/T5-W
> N=54** + **sensibilidad FIM como detección** (la deuda de B1) + `sin_67027`, `sin_operador` y
> `catalogo_v2`. **`FPR` sigue pendiente de `M` (W3)**; `C0 ≡ C1`; bóveda **v3.1** (sin cambio de
> telemetría) o **v4** si se habilita auditoría SMB/SMTP. **No se ejecuta nada sin gate.**

---

## Índice

0. [Resumen ejecutivo](#0-resumen-ejecutivo)
1. [Objetivo, alcance y qué NO entra](#1-objetivo-alcance-y-qué-no-entra)
2. [Estado de partida (B1 cerrado)](#2-estado-de-partida-b1-cerrado)
3. [Decisiones](#3-decisiones)
4. [Corpus B2: 22 casos](#4-corpus-b2-22-casos)
5. [Método (pipeline B1 reutilizado)](#5-método-pipeline-b1-reutilizado)
6. [Laboratorio, servicios y guardarraíles](#6-laboratorio-servicios-y-guardarraíles)
7. [Medición: T2/T4/T5-W N=54 y sensibilidades](#7-medición-t2t4t5-w-n54-y-sensibilidades)
8. [Productos y ficheros](#8-productos-y-ficheros)
9. [Tandas y coste](#9-tandas-y-coste)
10. [Criterios de aceptación](#10-criterios-de-aceptación)
11. [Verificación del tester](#11-verificación-del-tester)
12. [Riesgos y guardarraíles](#12-riesgos-y-guardarraíles)
13. [Trazabilidad](#13-trazabilidad)
14. [Lo que no cuadra y predicciones declaradas](#14-lo-que-no-cuadra-y-predicciones-declaradas)
15. [Gate humano](#15-gate-humano)
16. [Veredicto del planificador](#16-veredicto-del-planificador)

---

## 0. Resumen ejecutivo

### 0.1 Qué sale de B2

| # | Producto | Estado |
|---|---|---|
| 1 | **22 casos** nuevos (ATA088–ATA109) | 44 ventanas `[t0,t1]` + 22 `C0` |
| 2 | **Corpus Windows N=54** (32 B1 + 22 B2) | índice `ATA_index_windows_b2.csv` |
| 3 | `T2_ataques_windows_b2.csv` (N=54) | **completo** |
| 4 | `T2_ataques_windows_b2_solo.csv` (N=22) | vista de la oleada |
| 5 | `T4_rendimiento_windows_b2.csv` (N=54) | **TPR + `FP/hora`**; `FPR` **n/a** (W3) |
| 6 | `T5_doble_uso_windows_b2.csv` (N=54) | **provisional** |
| 7 | **Sensibilidad FIM como detección** | **nueva** (deuda B1) |
| 8 | `sin_67027` / `sin_operador` / `catalogo_v2` | regeneradas sobre N=54 |
| 9 | Comparación Linux↔Windows | **20/22 con pareja** |

### 0.2 Las tres cifras que el humano debe tener claras

1. **22 casos, N=54.** No se miden las 75: se cierran las **5 deudas**, se cubren las **capas
   nuevas** y se dejan **21 factibles no medidas** con motivo (padres, hardware sin dispositivo,
   coste/exploit).
2. **El TPR canónico de Windows pasa a N=54**; el `T2` de B1 (N=32) queda como **corte histórico**
   intacto. El re-juicio W3 (M1b-W) se hará sobre **N=54**.
3. **`FPR` sigue sin poder calcularse** (no hay `M` hasta W3). Se publica `TPR` + `FP/hora` y se
   declara el hueco. **La sensibilidad FIM no es canónica**: mide "¿hay señal de nivel alto para el
   efecto del fichero?", no sustituye al TPR.

### 0.3 Hipótesis pre-registradas

- **H-B2-1 (FIM).** Si se cuenta **FIM como detección**, los casos con **borrado** (T1485, T1561.x,
  T1565.001) suben a **`N≥7`** por `553` (nivel 7); los de **creación/modificación** (`554`/`550`,
  nivel 5) suben a `N=3` pero **no** a `N≥7`. El TPR canónico **no cambia**; la sensibilidad
  cuantifica cuánto de la "ceguera a `N≥7`" de B1 era **clasificación**, no detección.
- **H-B2-2 (librería vs utilidad).** `T1560.002` (librería .NET) y `T1560.003` (método propio)
  reproducirán el patrón de los FN Linux ATA013/ATA034: **proceso visible, archivo visible, pero
  sin señal específica**; se comparan con `T1560.001` (utilidad, B1 ATA069).
- **H-B2-3 (capas nuevas).** GUI, SMB, VHD, SMTP y proxy **no** añaden reglas de nivel alto: su
  detección será **proceso + 4104 + FIM** (nivel 3–5), como el resto de Windows.
- **H-B2-4 (canal).** `OPERADOR_WIN` sigue bastando: las nuevas técnicas **no** inician sesión como
  `angel` salvo el canal; el candado de `C:\lab-attack` evita el falso TPR.

---

## 1. Objetivo, alcance y qué NO entra

### 1.1 Objetivo

1. **Cerrar las 5 deudas de B1** con adaptación declarada.
2. **Cubrir las capas nuevas** que faltan en Windows (archivo por librería/método propio,
   manipulación de datos, disco/VHD, medios, GUI, web local, SMB, staging remoto, recolección
   automatizada, correo sintético).
3. **Ampliar el corpus a N=54** y recalcular **T2/T4/T5-W**.
4. **Pagar la deuda FIM** con una sensibilidad explícita.
5. **No tocar Linux** ni la cadena de B1.

### 1.2 Entra

- **22 casos** (§4), **20 con pareja Linux**.
- **Servicios locales**: 8080/9090/9091/9092, SMB loopback, SMTP loopback, UDP 67/5353, portal
  local, proxy local, VHD.
- **Pre-staging**: `Inveigh.ps1`, `T1056.004x64.dll` (del clon ART), utilidades de VHD.
- **Sensibilidades**: FIM-como-detección, `sin_67027`, `sin_operador`, `catalogo_v2`.

### 1.3 NO entra

- **13 no factibles** (SaaS/Exchange/cuenta cloud/lifecycle/dispositivo de red): T1213.001–.005,
  T1485.001, T1496.003/.004, T1530, T1537, T1557.004, T1602.001/.002. Motivo literal del inventario.
- **Padres ya cubiertos** por una subtécnica medida: T1048, T1056, T1074, T1114, T1213, T1491,
  T1496, T1498, T1499, T1557, T1560, T1565, T1567.
- **Hardware sin dispositivo**: T1011, T1011.001, T1052 (medio físico), T1123 (audio), T1125
  (vídeo), T1495 (firmware).
  **No se simulan** con un fichero: no ejercitan la técnica.
- **Sin servicio real**: T1114.003 **sí entra** (correo **sintético**), pero **T1491.002** (web
  pública) y **T1499.004** (exploit) **no**: no hay web publicada ni app vulnerable.
- **T1056.004** entra con **DLL del clon ART**; si el hook TLS local no dispara, `efecto_parcial`.
- **Reglas propias RS3/RS4**, **Defender ON**, **evasión**, **Velociraptor**, **P2**, **W3**.

---

## 2. Estado de partida (B1 cerrado)

| Hecho | Fuente |
|---|---|
| B1 cerrado: **32 casos**, **32/32 a N=0/3**, **1/32 a N≥7** (ATA073 `92213`, artefacto), **0/32 reales** | `state.md`; `_fases/fase-03b-b1/change-doc.md:21-38` |
| **0 dudosas**; `#Alertas` 539; `#rule.id` 3/caso (`67027`, `92032`, `92052`) | ídem |
| **T2** `fb83d19d…`; **T4** `d7557837…`; **T5** `be001594…` (17 reglas, **`67027`** doble uso) | ídem |
| Sensibilidades B1: `sin_operador` `7927564f…`, `catalogo_v2` `a4d44294…`, `sin_67027` `25f4668e…` | ídem |
| Vías B1: **2 ART tal cual, 16 ART adaptado, 14 manual** | ídem |
| Canal: **SSH** + `OPERADOR_WIN` (`60106/60137` por `angel`+tipo 3; `67028` por `angel`; `sshd.exe` `auto_ruido`) + **candado** | `change-doc.md:42-46` |
| `C0 ≡ C1` (RS2 vacía); bóveda v3; extractor **27 columnas**; snapshots `-ssh` y `-gui` | ídem |
| Puntos ciegos: Sysmon 3 (nivel 0), Sysmon 23, 7036, 4698/106, FIM registro no realtime | `B1.0_infra.md:100-101` |
| **Deuda FIM**: B1 clasificó FIM como `artefacto_ataque`; no se midió como detección | `change-doc.md:54`; contexto del humano |
| **`FPR`/`TNR`/`GM`/`Precisión`/`F1`/`Usabilidad` = n/a** (sin `M`) | `T4_rendimiento_windows.csv` |
| `review` B1: ATA071 y ATA078 (recuento, no TPR) | `change-doc.md:58-59` |

---

## 3. Decisiones

| # | Decisión | Por qué | Coste / alternativa |
|---|---|---|---|
| **D1** | **22 casos** (ATA088–ATA109), 4 tandas de 5/5/5/7 | Cierra las 5 deudas + capas nuevas; 20/22 con pareja Linux | 44 ventanas, ~15 días. Alternativa: 18 (sin B2.4 parcial) |
| **D2** | **N=54** (32 B1 + 22 B2); `ATA_index_windows_b2.csv` nuevo; **B1 intacto** | El TPR de Windows es por corpus; el corte B1 (N=32) es histórico | 1 índice + 1 T2 nuevos; B1 no se regenera |
| **D3** | **T2 canónico = N=54**; `T2_b2_solo` (N=22) como vista | Comparabilidad con Linux y re-juicio W3 | 2 ficheros |
| **D4** | **Sensibilidad FIM como detección** (nueva) | Paga la deuda de B1: ¿hay señal de nivel alto para el efecto? | `--fim-como-deteccion` + `Auditado_fim/` (paralelo) |
| **D5** | `sin_67027`, `sin_operador`, `catalogo_v2` **regeneradas sobre N=54** | Coherencia con B1 y con el corpus ampliado | 3 ficheros |
| **D6** | **Bóveda v3.1** (addendum: servicios + material; **sin cambio de telemetría**) o **v4** si se habilita auditoría SMB/SMTP | KISS: no se encienden canales nuevos | v3.1 recomendada |
| **D7** | **VHD de 100 MB** para T1561.x/T1025/T1052.001 | Destructivo contenido; el sistema no se toca | `New-VHD`/`Mount-DiskImage`; guardarraíl de ruta |
| **D8** | **T1498.002** = amplificación UDP local **sin spoofing** (segunda dirección loopback) | Windows sin `netns`/raw seguro; la amplificación es real, la reflexión se simula | Declarar `propio_por_diseno` + limitación |
| **D9** | **T1557.001** = Inveigh **dentro del invitado** + consulta local de `angel` | Sin tercer host; el hash capturado es de la cuenta de laboratorio | `ART_adaptado`; limitación "ambos roles en el mismo host" |
| **D10** | **T1557.003** = servidor UDP 67 local + **cliente sintético** | Sin `veth`/`netns`; sin broadcast en VMnet1 | `propio`; limitación "lease sintético" |
| **D11** | **T1052.001** y **T1025** con **VHD** (no USB) | No hay USB; el VHD es el "medio" | `propio`/`ART_adaptado`; limitación declarada |
| **D12** | **T1056.004** con DLL del clon ART + TLS local; si no dispara, `efecto_parcial` | Capa nueva (hooking) sin sistema real | `ART_adaptado`; coste ~1,5 d |
| **D13** | **T1114.003** con **correo sintético** (perfil + regla + sink) | No hay Outlook/Exchange; el mecanismo es la regla de reenvío | `propio`; limitación declarada |
| **D14** | **T1123/T1125/T1491.002/T1499.004 fuera** | Sin audio/vídeo/web pública/app vulnerable; simularlas sería inventar | Declarado en §1.3 |

---

## 4. Corpus B2: 22 casos

> `Linux` = ATA de la misma técnica. `Vía` = provisional (se ratifica con `guid`+`commit`).
> `Capa` = lo que el C0 de B1 demostró (sin inventar). `Efecto` = prueba independiente.

### 4.1 B2.1 — deudas de B1 (5)

| ATA | Técnica | Táctica | Linux | Vía | Servicio / capa | Acción | Efecto | Limitación |
|---|---|---|---|---|---|---|---|---|
| **ATA088** | T1496.002 Bandwidth Hijacking | Impact | ATA023 | manual | TCP crudo `9091`; proceso | 32 MiB en 1 conexión | `sink.log` `TCP len=33554432` | volumen acotado |
| **ATA089** | T1499.003 App Exhaustion | Impact | ATA046 | manual | app de juguete `127.0.0.1:9093`; proceso | 200 peticiones caras / 10 s | latencia/cola de la app | loopback |
| **ATA090** | T1498.002 Reflection Amplification | Impact | ATA054 | manual | amplificador UDP `127.0.0.1:5353` + víctima `127.0.0.2:5354` | 100 × 64 B → 4 KB | víctima recibe 400 KB | **sin spoofing**; "tercero" = 2.ª dirección loopback |
| **ATA091** | T1557.001 LLMNR/NBT-NS | Cred/Collection | — | **ART adaptado** (`deecd55f`) | Inveigh (pre-staged) + consulta local | `dir \\tfg-fake\share` | log de Inveigh con hash NTLM | **ambos roles en el invitado**; sin relay real |
| **ATA092** | T1557.003 DHCP Spoofing | Cred/Collection | ATA055 | manual | servidor UDP `127.0.0.1:67` + cliente sintético | DISCOVER/REQUEST | `lease.txt` con gateway/DNS atacante | **lease sintético**; sin VMnet1 |

### 4.2 B2.2 — archivo y manipulación (5)

| ATA | Técnica | Táctica | Linux | Vía | Capa | Acción | Efecto |
|---|---|---|---|---|---|---|---|
| **ATA093** | T1560.002 Archive via Library | Collection | **ATA013 (FN)** | manual | proceso + FIM `554` + 4104 | `[System.IO.Compression.ZipFile]` | `.zip` N entradas; extraído = `sha256` |
| **ATA094** | T1560.003 Archive via Custom Method | Collection | **ATA034 (FN)** | manual | proceso + FIM `554` + 4104 | formato propio (XOR + cabecera) | fichero propio; decodificado = `sha256` |
| **ATA095** | T1565.001 Stored Data Manipulation | Impact | ATA032 | manual | proceso + FIM `550`/`554` | alterar `libro.csv` in situ | contenido alterado; `sha256` ≠ |
| **ATA096** | T1565.002 Transmitted Data Manipulation | Impact | ATA026 | manual | proxy local `127.0.0.1:9095`; proceso + 4104 | reescribe el cuerpo en tránsito | el sink recibe el `sha256` alterado |
| **ATA097** | T1565.003 Runtime Data Manipulation | Impact | ATA036 | manual | `WriteProcessMemory` (P/Invoke); proceso + 4104 | sobrescribe una cadena del proceso de juguete | el proceso imprime la cadena alterada |

### 4.3 B2.3 — disco y medios (5)

| ATA | Técnica | Táctica | Linux | Vía | Capa | Acción | Efecto | Guardarraíl |
|---|---|---|---|---|---|---|---|---|
| **ATA098** | T1561 Disk Wipe | Impact | ATA005 | manual | proceso + FIM (VHD) | VHD 100 MB; ceros a todo el volumen | VHD corrupto; sistema intacto | solo el VHD de `lab-attack` |
| **ATA099** | T1561.001 Disk Content Wipe | Impact | ATA037 | manual | proceso + FIM | sobrescribir el contenido del VHD | contenido borrado | solo el VHD |
| **ATA100** | T1561.002 Disk Structure Wipe | Impact | ATA027 | manual | proceso + FIM | ceros a los primeros sectores del VHD | VHD no montable | solo el VHD |
| **ATA101** | T1025 Data from Removable Media | Collection | ATA044 | **ART adaptado** | proceso + FIM | montar VHD con datos y copiar | N ficheros copiados | VHD, no USB |
| **ATA102** | T1052.001 Exfiltration over USB | Exfil | — | manual | proceso + FIM | copiar el botín al VHD y desmontar | botín en el VHD | VHD, no USB |

### 4.4 B2.4 — capas nuevas (7)

| ATA | Técnica | Táctica | Linux | Vía | Servicio / capa | Acción | Efecto | Limitación |
|---|---|---|---|---|---|---|---|---|
| **ATA103** | T1039 Data from Network Shared Drive | Collection | ATA039 | **ART adaptado** | SMB `\\127.0.0.1\labshare`; proceso + 4688 | enumerar/copiar del UNC | N ficheros copiados | recurso loopback; sin auditoría SMB |
| **ATA104** | T1056.002 GUI Input Capture | Collection | ATA053 | **ART adaptado** | snapshot `-gui`; proceso + 4104 | captura + `SendKeys` | PNG + texto | **S1** (autologon) o **S2** parcial |
| **ATA105** | T1056.003 Web Portal Capture | Collection | ATA028 | manual | portal `HttpListener` `127.0.0.1:8081` | formulario + captura | `creds.txt` de juguete | portal local, no web real |
| **ATA106** | T1056.004 Credential API Hooking | Collection | ATA035 | **ART adaptado** (`de1934ea`) | DLL del clon ART + TLS local | inyectar en PowerShell de juguete | log del hook | si no dispara, `efecto_parcial` |
| **ATA107** | T1074.002 Remote Data Staging | Collection | ATA040 | manual | WebDAV `9092` / SMB del host | stage al host | ficheros en el staging remoto | host = `192.168.65.1` |
| **ATA108** | T1119 Automated Collection | Collection | ATA012 | **ART adaptado** (`cb379146`) | proceso + FIM `554` | bucle sobre `fuentes\` | N ficheros en `staging\` | rutas parametrizadas |
| **ATA109** | T1114.003 Email Forwarding Rule | Collection | ATA015 | manual | perfil de correo sintético + sink | regla de reenvío | `.eml` reenviado al sink | sin Outlook/SMTP real |

### 4.5 Representatividad

- **22/22** del inventario factible; **20/22** con pareja Linux (91 %).
- **Por táctica**: Impact **9** (T1496.002, T1499.003, T1498.002, T1565.001/.002/.003, T1561,
  T1561.001, T1561.002), Collection **10** (T1560.002/.003, T1025, T1039, T1056.002/.003/.004,
  T1074.002, T1119, T1114.003), Exfil **1** (T1052.001), Cred/Collection **2** (T1557.001/.003).
  **Collection va sobre-representada** a propósito: es donde quedan capas nuevas.
- **Vías**: **0 ART tal cual**, **6 ART adaptado** (T1557.001, T1025, T1039, T1056.002, T1056.004,
  T1119), **16 manual**. Los tests ART restantes exigen USB/red/GUI/internet: se adaptan.
- **Nuevas capas**: VHD, SMB, SMTP, UDP (67/5353), proxy, inyección, GUI, portal local, correo.

### 4.6 Lo que queda fuera (21 factibles no medidos)

| Código | Técnicas | Motivo |
|---|---|---|
| `parent_de_medida` | T1048, T1056, T1074, T1114, T1213, T1491, T1496, T1498, T1499, T1557, T1560, T1565, T1567 | Padre cubierto por una subtécnica medida |
| `hardware` | T1011, T1011.001, T1052, T1123, T1125, T1495 | Sin Bluetooth/medio físico/audio/vídeo/firmware; simular no ejercita la técnica |
| `sin_servicio` | T1491.002 | Sin web pública; el portal local es T1056.003 |
| `coste` | T1499.004 | Sin app vulnerable/exploit en el laboratorio |

> **T1123/T1125** se declaran fuera: un WAV/AVI sintético **no** es una captura de micrófono/cámara.
> Si el humano quiere, se ofrece una **variante sintética declarada** en B2.5 (no comprometida).

### 4.7 Cambios respecto de B1

| Cambio | Detalle |
|---|---|
| **Corpus** | 32 → **54** (+22; 0 quitados) |
| **T2** | Nuevo `T2_b2` **N=54**; el de B1 (N=32) queda intacto como corte histórico |
| **FIM** | Nueva **sensibilidad FIM como detección** (deuda B1) |
| **Sensibilidades** | `sin_67027`, `sin_operador`, `catalogo_v2` regeneradas sobre N=54 |
| **Bóveda** | **v3.1** (addendum) o **v4** si se habilita SMB/SMTP audit |
| **Nuevas capas** | VHD, SMB, SMTP, UDP, proxy, inyección, GUI, portal, correo |
| **Riesgo** | Destructivas (T1561.x) y hardware (VHD) con guardarraíles |

---

## 5. Método (pipeline B1 reutilizado)

- **`pre_registro` + sello antes de `t0`**: `esperado` con `sha256` + `pre_registro.sha256` +
  `sello_verificacion.txt`; el sello se verifica en `t0`. **No se reescribe** después.
- **2 iteraciones** por caso desde el mismo snapshot; `t0` ≥ 90 s tras `Agent Active`; criterio v2
  (C1′/C2′/C3′); `review` declarado, nunca FN silencioso.
- **C0**: se reutiliza la tabla real de B1 (`clases_evento.csv`); las **clases nuevas** (SMB, VHD,
  UDP, TLS) se miden en un **C0 por tanda** (dry run, fuera de ventana).
- **Efecto**: independiente de la alerta (fichero, lease, hash, latencia, hook, captura).
- **Validación manual**: `dudosa` → `-Revision.csv`; **nada del ataque en `ruido`** (candado).
- **Canal**: SSH + `OPERADOR_WIN` + candado (B1); no se toca.

---

## 6. Laboratorio, servicios y guardarraíles

### 6.1 Snapshots y bóveda

- **Reutilizar** `lab-listo-windows-ataques-ssh` (casos no interactivos) y
  `lab-listo-windows-ataques-gui` (ATA104).
- **Bóveda v3.1** (addendum): nuevos servicios y material pre-staged, **sin** cambio de Sysmon,
  agente ni ruleset. **v4** solo si se habilita auditoría SMB (`5140/5145`) o SMTP: **no se
  habilita** por KISS; se declara.
- **Sin snapshot nuevo** salvo que el C0 de clases nuevas lo exija (se declara).

### 6.2 Servicios y material

| Elemento | Dónde | Uso | Guardarraíl |
|---|---|---|---|
| Sink 9090 / TCP 9091 / WebDAV 9092 | host `192.168.65.1` | T1496.002, T1074.002, T1114.003 | destino fijo `/24` |
| SMB `\\127.0.0.1\labshare` | invitado | T1039 | solo `C:\lab-attack`; se elimina al cerrar |
| SMTP sink | loopback | T1114.003 | sin correo real |
| UDP 67 / 5353 | loopback | T1557.003 / T1498.002 | sin broadcast en VMnet1 |
| VHD 100 MB | `C:\lab-attack\ATA<NNN>\` | T1561.x, T1025, T1052.001 | solo el VHD; `Dismount-DiskImage` |
| Portal `8081` / proxy `9095` | loopback | T1056.003 / T1565.002 | sin tráfico real |
| `Inveigh.ps1` | pre-staged (URL+`sha256`) | T1557.001 | solo el invitado; hash no se guarda |
| `T1056.004x64.dll` | clon ART (sha256) | T1056.004 | solo proceso de juguete |

### 6.3 Guardarraíles duros

- **Ruta**: todo bajo `C:\lab-attack\ATA<NNN>\`; si no, **aborta**.
- **Destructivas**: **solo el VHD** de 100 MB; nunca `PhysicalDrive*`, `C:`, ni el disco del sistema.
- **Red**: solo `192.168.65.0/24` y loopback; nunca internet; nunca el manager.
- **Credenciales**: el hash capturado por Inveigh es de `angel` (laboratorio) y **no se guarda** en
  el repo; el host **no** consulta nombres durante la ventana.
- **Procesos**: la inyección (`T1056.004`) y `WriteProcessMemory` (`T1565.003`) **solo** sobre
  procesos de juguete; nunca `lsass`, `winlogon`, `services`.
- **Cierre**: VHD desmontado, share eliminado, servicios parados, 0 tareas, 0 VMs.

---

## 7. Medición: T2/T4/T5-W N=54 y sensibilidades

### 7.1 Unidad, ventana y rejilla (métrica v1, sin cambios)

- **Unidad = caso**; **N=54** (32 B1 + 22 B2); ventana canónica `_iter1`; umbrales `{0,3,7,10,12}`;
  titular `C1 × N=0` (= `C0 × N=0`); doble conteo `#Alertas` / `#rule.id`.
- **`C0 ≡ C1`** (RS2 vacía); el eje útil es el **umbral** y la **capa**.

### 7.2 T2/T4/T5

| Producto | Contenido |
|---|---|
| `T2_ataques_windows_b2.csv` | **N=54** (canónico) |
| `T2_ataques_windows_b2_solo.csv` | **N=22** (vista de la oleada) |
| `T4_rendimiento_windows_b2.csv` | **N=54**; `TPR` + `FP/hora`; `FPR/TNR/GM/Precisión/F1/Usabilidad` = `n/a` (W3) |
| `T5_doble_uso_windows_b2.csv` | **N=54**, provisional (catálogo v1+v2) |

### 7.3 Sensibilidad FIM como detección (deuda B1)

**Qué es.** Reclasificar como `deteccion` las filas **FIM de fichero** (`550` modificado, `553`
borrado, `554` añadido) cuyo `syscheck_path`/`win_target` está bajo `C:\lab-attack\ATA<NNN>`, y
recalcular T2. Se escribe en **`Auditado_fim/`** (paralelo); **no** se sobrescribe el `Auditado/`
canónico.

**Implementación.** `filtrar_ruido_windows.py --fim-como-deteccion` (aditivo; sin el flag, salida
**byte a byte** idéntica a B1).

**Por qué no es canónica.** Contar la **huella del propio ataque** como detección infla el plano de
alerta; la categoría `artefacto_ataque` existe precisamente para no hacerlo. Pero la sensibilidad
responde a una pregunta legítima: **¿hay señal de nivel alto para el efecto del fichero?** Se publica
**con y sin**; la canónica es **sin**.

**Predicción (H-B2-1).** A `N=7`, los casos con **borrado** (`553`, nivel 7) suben; los de
creación/modificación (`554`/`550`, nivel 5) **no**. Se mide, no se supone.

### 7.4 Otras sensibilidades (N=54)

| Sensibilidad | Qué mide |
|---|---|
| `sin_67027` | Cuánto del TPR depende de la regla genérica de proceso |
| `sin_operador` | Cuánto del TPR era canal (debe ser **0** con el candado) |
| `catalogo_v2` | Impacto de añadir las 3 reglas FIM de v2 al catálogo |
| `solo_b2` (N=22) | Vista de la oleada |

### 7.5 `review` y `FPR`

- **`review`**: B1 mantiene ATA071/ATA078; B2 declara los suyos (C2′). Un `review` es **TP con
  aviso**, no FN silencioso.
- **`FPR`**: **n/a** hasta W3 (`M`). `FP/hora` descriptivo (19,875 alertas/h de la baseline).

---

## 8. Productos y ficheros

| Ruta | Contenido |
|---|---|
| `Hojas/ATA_index_windows_b2.csv` | **54 filas** (ATA056–ATA109) |
| `Hojas/T2_ataques_windows_b2.csv` | T2 N=54 |
| `Hojas/T2_ataques_windows_b2_solo.csv` | T2 N=22 |
| `Hojas/T4_rendimiento_windows_b2.csv` | T4 N=54 |
| `Hojas/T5_doble_uso_windows_b2.csv` | T5 N=54 (provisional) |
| `Hojas/T2_ataques_windows_b2_sens_{fim,sin_67027,sin_operador,catalogo_v2}.csv` | sensibilidades |
| `Dataset/Ataques/Comandos/windows/T<id>-<desc>/` | 22 artefactos + `esperado` + `README` |
| `Dataset/Ataques/Resultados/Wazuh/windows/` | fichas, `Auditado/`, `Auditado_fim/`, `CSV/`, `Logs/` |
| `Bitacora/ATA088..109.json` | esquema B1 + `limitacion` cuando aplique |
| `Soporte/Ataques/c0/windows/` | clases nuevas (SMB, VHD, UDP, TLS) |
| `Soporte/Laboratorio/windows/ataques/boveda_v3_1.md` | addendum (o `boveda_v4.md`) |
| `Soporte/Laboratorio/windows/ataques/prestaging_b2.md` | Inveigh, DLL, VHD, utilidades |
| `_fases/fase-03b-b2/{plan,change-doc}.md` | archivo del bloque |

**Modificados (aditivo + regresión)**: `filtrar_ruido_windows.py` (`--fim-como-deteccion`; sin el
flag, byte a byte), `tabla2_ataques.py` (sin cambios; ya tiene `--ficha-dir`), `criterio_ataques.md
§D.2` (nuevas capas), `politica_filtrado_ruido.md` §9.7 (FIM como detección).

---

## 9. Tandas y coste

| Tanda | Casos | Coste | Parada |
|---|---|---|---|
| **B2.0 — prep** | índice, bóveda v3.1, pre-staging (Inveigh/DLL/VHD), C0 de clases nuevas, `--fim-como-deteccion` | ~1,5 d | **G-B2.0** |
| **B2.1 — deudas B1** | ATA088–ATA092 (5) | ~3,5 d | **G-B2.1** |
| **B2.2 — archivo/manipulación** | ATA093–ATA097 (5) | ~3 d | **G-B2.2** |
| **B2.3 — disco/medios** | ATA098–ATA102 (5) | ~3 d | **G-B2.3** |
| **B2.4 — capas nuevas** | ATA103–ATA109 (7) | ~4 d | **G-B2.4** |
| **B2.5 — cierre** | T2/T4/T5 N=54, sensibilidades, hashes, README | ~1 d | **G-B2-final** |

**Total**: ~16 días efectivos (**≈ 95 h**), 4–5 semanas. **Recorte ofrecido**: 17 casos (sin B2.4
completo) ≈ 12 días.

**Regla de parada**: si en una tanda **≥2 casos** acaban en `review` por método, se para. Si un
**guardarraíl** salta (ruta fuera de `lab-attack`, VHD del sistema, proceso no-juguete), se aborta y
se declara.

---

## 10. Criterios de aceptación

| # | Criterio | Verificación |
|---|---|---|
| **CA-B2-01** | `ATA_index_windows_b2.csv` = **54 filas** (ATA056–ATA109) | script de cuadre |
| **CA-B2-02** | 22 casos, 2 iteraciones, `-Audited`/`-Revision`, **0 dudosas** | C3′ |
| **CA-B2-03** | `pre_registro` + sello **antes de `t0`** en los 22 | `sha256`/`git log` |
| **CA-B2-04** | **Efecto** en los 22 (incluye VHD/SMB/SMTP/UDP/GUI/hook) | `Logs/.../efecto.txt` |
| **CA-B2-05** | **0 filas del ataque en `ruido_conocido`** | filtro + candado |
| **CA-B2-06** | T2 N=54 **determinista** (2 ejecuciones, mismo `sha256`) | test |
| **CA-B2-07** | T2 N=22 (solo B2) reproducible | test |
| **CA-B2-08** | **Sensibilidad FIM** publicada; canónica **sin** FIM | `_sens_fim` + cabecera |
| **CA-B2-09** | `sin_67027`/`sin_operador`/`catalogo_v2` sobre N=54 | ficheros |
| **CA-B2-10** | T5 N=54 provisional; `67027` doble uso | `T5_b2` |
| **CA-B2-11** | **Regresión**: B1 (T2/T4/T5 + 32 fichas) **intacto**; Linux **byte a byte** | `sha256` |
| **CA-B2-12** | Laboratorio cerrado: 0 VMs, 0 VHD montados, 0 shares, 0 tareas, 0 servicios | `vmrun`, `Get-DiskImage`, `Get-SmbShare` |
| **CA-B2-13** | **Destructivas**: solo el VHD de 100 MB; sistema intacto | guardarraíl + evidencia |
| **CA-B2-14** | **0 secretos**: hash capturado no guardado; clave fuera del repo | grep |
| **CA-B2-15** | Bóveda **v3.1** (o v4) declarada con `sha256` | `boveda_v3_1.md` |
| **CA-B2-16** | `review` declarados (B1 + B2) | fichas |
| **CA-B2-17** | `pytest` verde (≥ 389 + nuevos) | CI local |

---

## 11. Verificación del tester

1. **Corpus**: 54 filas; 22 nuevas con técnica/pareja/vía coherentes con el inventario.
2. **Sellos**: `esperado` no re-escrito; `pre_registro` < `t0`.
3. **FIM**: la sensibilidad se genera desde `Auditado_fim/`; el canónico **no** se toca.
4. **Guardarraíles**: ruta del VHD, share, procesos de juguete, hash no guardado.
5. **T2/T4/T5**: N=54; B1 intacto; Linux byte a byte.
6. **Cierre**: 0 VMs, 0 VHD montados, 0 shares, 0 servicios, 0 tareas.
7. **Honestidad**: `FPR` no aparece sin `M`; las sensibilidades están etiquetadas.

---

## 12. Riesgos y guardarraíles

| # | Riesgo | Prob. | Impacto | Mitigación |
|---|---|---|---|---|
| **R1** | T1561.x toca el disco del sistema | baja | **crítico** | solo VHD de 100 MB; comprobar ruta; abortar |
| **R2** | VHD montado residual | media | alto | `Get-DiskImage` + `Dismount-DiskImage`; CA-B2-12 |
| **R3** | T1052.001/T1025 no son USB | **cierta** | bajo | limitación declarada; VHD como medio |
| **R4** | T1557.001 captura el hash del **host** | baja | **crítico** | consulta **solo** del invitado; sin consultas del host; hash no guardado |
| **R5** | Inveigh no arranca / no captura | media | medio | `efecto_parcial` + `review`; no se inventa |
| **R6** | T1498.002 sin spoofing | **cierta** | bajo | limitación declarada; amplificación real |
| **R7** | T1557.003 lease sintético | **cierta** | bajo | limitación declarada; loopback |
| **R8** | T1056.004 no dispara el hook | media | medio | `efecto_parcial`; DLL del clon ART |
| **R9** | Inyección/`WriteProcessMemory` en proceso real | baja | **crítico** | solo procesos de juguete; abortar si no |
| **R10** | SMB share expone más de `lab-attack` | baja | alto | solo esa carpeta; eliminar al cerrar |
| **R11** | SMTP/portal/proxy abren puertos | media | medio | loopback; firewall; cerrar |
| **R12** | FIM como detección se lee como TPR real | media | alto | etiqueta "sensibilidad, no canónica" |
| **R13** | N=54 rompe la comparación con B1 | media | medio | B1 intacto; `solo_b2` N=22 |
| **R14** | `review` nuevo | media | bajo | declarado, no FN silencioso |
| **R15** | Bóveda v3.1/v4 mal declarada | baja | medio | addendum con `sha256`; CA-B2-15 |

---

## 13. Trazabilidad

| Afirmación | Cita |
|---|---|
| B1 cerrado y resultados | `state.md`; `_fases/fase-03b-b1/change-doc.md:21-38` |
| Canal `OPERADOR_WIN` y candado | `change-doc.md:42-46` |
| Extractor 27 cols y bóveda v3 | `change-doc.md:48-50` |
| Deuda FIM | `change-doc.md:54`; contexto del humano |
| Puntos ciegos | `Soporte/Laboratorio/windows/ataques/B1.0_infra.md:100-101` |
| Inventario 89/77/75/13 | `Hojas/inventario_p1_windows.csv` |
| Corpus Linux 55 | `Hojas/ATA_index.csv` |
| Servicios locales | `Soporte/Laboratorio/internet_local/README.md:11-15, 24-26` |
| Criterio ART/manual/pre-staging | `Soporte/Ataques/criterio_ataques.md:16-46, 102-167` |
| Doble iteración y `t0` | `Soporte/Ataques/criterio_doble_iteracion.md:29-33, 57-67` |
| Métrica v1 y umbrales | `Soporte/Metrica/metrica_hids.md:167-168, 204-213` |
| ART DLL T1056.004 | `Soporte/Ataques/atomic-red-team/atomics/T1056.004/bin/T1056.004x64.dll` |
| ART Inveigh T1557.001 | `…/T1557.001/T1557.001.yaml` (`deecd55f`) |
| ART T1119 | `…/T1119/T1119.yaml` (`cb379146`) |

---

## 14. Lo que no cuadra y predicciones declaradas

1. **T1498.002 no es reflexión pura**: sin spoofing ni `netns`, se simula el "tercero" con una
   segunda dirección loopback. La **amplificación** es real; la **reflexión**, declarada.
2. **T1557.001 no tiene tercer host**: Inveigh y la consulta viven en el invitado. El hash capturado
   es de `angel` (laboratorio), **no** del host. Sin relay real.
3. **T1557.003 no tiene NIC/lease real**: servidor UDP + cliente sintético en loopback. El
   mecanismo (lease con gateway/DNS del atacante) se conserva; el lease no se aplica.
4. **T1025/T1052.001 no son USB**: el VHD es un disco virtual fijo. Se declara.
5. **T1056.004 puede no disparar**: el test ART usa `https://www.example.com`; se sustituye por TLS
   local; si el hook no se ve, `efecto_parcial`.
6. **T1114.003 no tiene Outlook/Exchange**: perfil + regla + sink sintéticos. El "reenvío" es un
   fichero, no SMTP.
7. **T1123/T1125/T1491.002/T1499.004 fuera**: sin dispositivo/web pública/app vulnerable; simular
   sería inventar.
8. **FIM como detección no es canónico**: mide el efecto, no la detección del ataque; se etiqueta.
9. **N=54 cambia el denominador**: el T2 de B1 (N=32) queda como corte histórico; el re-juicio W3
   usará N=54.
10. **`FPR` sigue n/a**: sin `M` (W3). `FP/hora` es descriptivo.
11. **Bóveda v3.1 vs v4**: si se habilita SMB/SMTP audit, cambia la telemetría y hay que re-medir;
    **no se habilita** por KISS.
12. **`review`**: B1 ATA071/ATA078 + los que salgan en B2; TP con aviso, no FN.

**Predicciones**: H-B2-1..4 (§0.3). Si fallan, se declara el fallo.

---

## 15. Gate humano

**Lo que se pide aprobar (6 puntos).**

1. **Corpus 22** (ATA088–ATA109), **N=54** (32 B1 + 22 B2), con **20/22 pareja Linux**. ¿22 o 17
   (sin B2.4)?
2. **Deudas B1 con limitación declarada**: T1498.002 (sin spoofing), T1557.001 (ambos roles en el
   invitado), T1557.003 (lease sintético). ¿Se aceptan como `propio`/`ART_adaptado`?
3. **Destructivas y medios**: T1561.x **solo** en VHD de 100 MB; T1025/T1052.001 con VHD (no USB).
   ¿Se aceptan los guardarraíles y la limitación?
4. **Pre-staging**: `Inveigh.ps1` y `T1056.004x64.dll` (del clon ART) con URL/`sha256`; T1056.004
   con TLS local y posible `efecto_parcial`. ¿OK?
5. **Bóveda v3.1** (sin cambio de telemetría; no se habilita SMB/SMTP audit) **o v4** si se quiere
   auditoría SMB/SMTP. ¿Cuál?
6. **Sensibilidades**: FIM-como-detección (deuda B1) + `sin_67027` + `sin_operador` +
   `catalogo_v2`, todas sobre **N=54**; el T2 canónico es **sin FIM**. ¿OK?

**Se mantiene**: método, métrica v1, filtro/candado, `pre_registro` + sello, `C0≡C1`, `FPR`
pendiente W3, comparabilidad por técnica y efecto.

**No se ejecuta nada hasta que el humano responda y el orquestador marque este plan como
`approved_by_human`.** `git push` prohibido. Las fechas las fija el humano.

---

## 16. Veredicto del planificador

**GO condicionado al gate.** B2 es la última ventana de ataques antes de W3 y merece la pena:
cierra las **5 deudas**, cubre las **capas nuevas** que faltan y deja el corpus Windows en **N=54**
con **20 parejas Linux**. Lo que **no** prometo: que las adaptaciones de T1498.002/T1557.001/
T1557.003 sean fieles al 100 %; se declaran como **simulaciones con limitación**, no como el ataque
real. La **sensibilidad FIM** es la pieza más valiosa: puede explicar por qué B1 daba 0/32 a `N≥7`
(¿clasificación o ceguera?) sin cambiar el TPR canónico.

**Riesgo principal**: R1 (T1561.x) y R4 (hash del host en T1557.001). Ambos se cierran con
guardarraíles **antes** de la primera ventana o no se empieza.
