---
fase: 3
bloque: fase-03-p1-cierre
nombre: Cierre de P1 en Linux — inventario revisado (madres/hijas, nubes locales, GUI) y ejecución de las factibles
version: 3
status: approved_by_human
fecha: 2026-10-02
fecha_aprobacion: 2026-10-02
aprobado_por: humano
autor: tfg-planner
gate: **APROBADO (2026-10-02)**. Decisiones: **D1** bloque + Tanda A ✔ · **D2** Tanda B (3 GUI con Xvfb + 2 nubes locales) ✔ · **D3** etiqueta **`cubierta_parcial`** ✔ · **D4** **Tanda C: medir** reflector + DHCP ✔ · **D5** **no** se revisan las 3 no factibles extra ✔. **C1/C2** (cuadre + test padre/hijo) se aplican a **las 72 filas P1-Linux**.
---

# Plan — Cierre de P1 en Linux (Fase 3) · **v3 (cierre con verificación automática de TODO P1)**

> **Cambios de esta v3 (petición del humano tras la revisión fina).** Se añaden **2
> comprobaciones AUTOMÁTICAS** (por script, **no a mano**) y se **amplía el alcance de la
> verificación a las 72 filas P1-Linux**, no solo a las 30 nuevas:
> - **C1 — Cuadre de la tabla:** `Hojas/cobertura_p1_linux.csv` **suma 72** y **cuadra por
>   categoría** (`medida` + `cubierta por ATA` + `cubierta` (madre) + `cubierta_parcial` +
>   `no_factible`).
> - **C2 — Test padre/hijo (la clave):** recorre la jerarquía de `Hojas/corpus_host.csv` y
>   **falla** si una madre figura como `cubierta` con alguna forma (hija) no medida/factible;
>   si una hija se da por cubierta por **otra hija**; si una madre **cubre a sus hijas**; o si
>   una fila `cubierta por ATA<NNN>` **no resuelve** (el ataque citado no existe o no
>   corresponde a esa técnica). **Este test habría detectado T1498/T1499 sin depender de la
>   atención humana.**
> - **Motivo honesto:** la lupa de la v2 se pasó **solo por las 30 nuevas**; esta v3 la pasa por
>   las **72** y **reporta cualquier inconsistencia adicional** (y su corrección).
>
> **No cambia nada del fondo de la v2:** inventario revisado, 3 tandas, criterios del humano,
> etiqueta `cubierta_parcial`, métrica/filtro congelados, 2 iteraciones, C0 y guardarraíles
> siguen **vigentes tal cual**.

> **Cambios de esta v2 (revisión fina pedida por el humano).** Se aplican los 5 criterios:
> (1) verificación **fila a fila** de las "cubiertas" con la **precisión madres/hijas** y su
> **comprobación inversa**; (2) medir **todas** las factibles (técnica distinta = fila distinta);
> (3) **intentar las 3 dudosas de GUI** (Xvfb); (4) revisar las **14 no factibles una a una**
> distinguiendo **otra plataforma** (no equivalente local) de **nube/servicio externo**
> (reproducible montando el servicio **en el laboratorio** → factible con pre-staging);
> (5) ajustar listas, **tandas**, orden y cierre (CSV de **72** filas que **suma 72**).
>
> **Pendiente derivada:** la norma `criterio_ataques.md` §C.2.3 ("nada de nubes/emuladores") se
> **matiza** aquí por instrucción del humano: el "servicio" de nube se **monta como servicio local
> del laboratorio** (sin API ni autenticación reales). Se propone un **addendum** a §C en un bloque
> posterior; **no** se toca el fichero en esta fase.

> **Sigue vigente lo probado:** se reutiliza **tal cual** la tubería (`Soporte/Ataques/piloto_procedimiento.md`),
> la **métrica congelada** (`fase-03-metrica`), el **filtro** (`filtrar_ruido.py`) y el **criterio de
> doble iteración v2**. **No se rediseña el mecanismo de medida.** Alcance: **SOLO Linux**. **Sin NAT.**
> **Sin evasión.**

---

## 0. Resumen ejecutivo (revisado)

- **Corpus actual:** **43 técnicas** (`ATA001`–`ATA043`) → **41 DETECTADAS / 2 NO**. **104 ventanas**
  (86 base + 18 `_rev`). (`state.md`, `Hojas/ATA_index.csv`.)
- **Piscina P1-Linux:** `Hojas/corpus_host.csv` → `P1 ∧ host_eligible=YES ∧ plataformas∋Linux` = **72**
  (verificado por script en esta planificación). Descontadas las **42 técnicas únicas** ya medidas →
  **30 nodos restantes**.
- **Inventario revisado de los 30 (v2):**
  - **12 factibles** → se **miden/intentan**: 5 base + **2 nubes locales** + **2 servicios de red
    condicionales** + **3 GUI**.
  - **6 cubiertas por una medición existente** (misma técnica, con cita; incluye **T1491.002**).
  - **2 madres cubiertas** por sus formas P1-Linux (T1496, T1557).
  - **2 madres "cubierta parcial"** (T1498, T1499): sus formas medibles se miden, pero una forma es
    no factible → **no se dan por "cubiertas"** (regla del humano). *Propuesta de 4.º estado: ver §7.*
  - **8 no factibles** (revisadas una a una: **solo "otra plataforma"**).
  - *Suma: 12 + 6 + 2 + 2 + 8 = **30** ✔.*
- **Cambios respecto a la v1:**
  - Pasaron de **no factible a FACTIBLE**: **T1567.002** (nube local), **T1567.003** (paste local),
    **T1498.002** (reflector local, condicional), **T1557.003** (DHCP local, condicional).
  - Pasó de **no factible a CUBIERTA**: **T1491.002** (la página "pública" simulada de ATA007).
  - **Corregidas 2 madres mal dadas por cubiertas**: **T1498** y **T1499** (su forma .002/.004 no es
    factible → **no** pueden darse por "todas sus formas medidas").
  - **T1496** se acota a sus **formas P1-Linux** (.001/.002); sus formas .003/.004 son **SaaS** y
    quedan fuera del alcance P1-Linux (se declara).
  - **GUI (T1113, T1115, T1056.002):** las 3 se **intentan** con Xvfb (ya no son "decide el humano en
    bloque"; si alguna no sale, se declara no factible **con evidencia**).
- **Cambios respecto a la v2 (esta v3):**
  - Se añaden **C1** (cuadre de la tabla, por script) y **C2** (test padre/hijo) — **§6.3**.
  - **Alcance de la verificación = las 72 filas P1-Linux** (43 ya medidas + 30 nuevas + lo que
    salga), **no solo las 30**. La v2 solo había pasado la lupa por las 30; la v3 cierra el hueco.
  - **Cualquier inconsistencia adicional** que aparezca se **reporta y corrige** antes de cerrar
    (con su rastro en el `change-doc`).
- **Entrega final:** `Hojas/cobertura_p1_linux.csv` con **72 filas** (una por técnica P1-Linux) que
  **suma 72** (verificado por **C1**): `medida` / `cubierta por ATA<NNN>` / `cubierta (madre)` /
  `cubierta parcial` / `no factible (motivo)`, y **sin violaciones padre/hijo** (verificado por **C2**).

**Criterio de factibilidad (fijado por el humano):** *factible* = se puede hacer **en el laboratorio,
sin internet** (con **pre-staging §C** si hace falta); *no factible* = **otra plataforma** sin
equivalente local, o dependencia de la **API/autenticación real de un tercero**. **Toda técnica
distinta = una fila distinta**; solo si dos variantes son **literalmente la misma acción** se
documenta *"cubierta por X"*.

---

## 1. Objetivo y alcance

**Objetivo:** **evaluar TODAS las técnicas P1 que citan Linux** y **ejecutar las factibles**, para
**cerrar P1** con una clasificación trazable y citada de las **72** técnicas.

**Entra:** los **30 nodos P1-Linux restantes** (incl. las 3 GUI y los servicios locales), su `esperado`
(validado por el humano), su **C0**, **2 iteraciones** por técnica, ficha, bitácora y fila en
`ATA_index.csv`.

**No entra:** evasión, Windows, Fase 4, memoria, tocar métrica/filtro, repetir ataques ya hechos (§9).

---

## 2. Hechos verificados (evidencia) — ampliado en la revisión fina

- **Corpus y recuento:** `Hojas/ATA_index.csv` → **43 ataques**; `state.md` → **41/2**; **104 ventanas**;
  `pytest` **97**; cadena **1.582 citas / 0 desincronías**.
- **Piscina:** script reproducible sobre `Hojas/corpus_host.csv` → **72** (`P1 ∧ host_eligible=YES ∧
  Linux`); **42** técnicas únicas ya medidas; **30** restantes (lista exacta en §3.2).
- **Verificación de las "cubiertas" (fila a fila, con cita):**
  - **T1056.001:** el artefacto de **ATA018** es literalmente `T1056.001-Keylogging` (README §1) →
    ya medida; `ATA_index` la registra bajo el **padre `T1056`** (imprecisión de etiqueta).
  - **T1074.001:** **ATA011** ejecuta `mkdir`+`cp` sobre datos locales (README §2–§3) = *Local Data
    Staging*; `cobertura_atomic` de ATA011 apunta a `atomics/T1074.001` → ya medida (etiquetada `T1074`).
  - **T1114.003:** **ATA015** = `T1114.003-Email_Forwarding_Rule` (README §1) → ya medida.
  - **T1213.006:** **ATA016** = `T1213.006-Databases` (README §1) → ya medida (etiquetada `T1213`).
  - **T1560.002:** **ATA013** = *Archive via Library* (gzip en `python3`; README §2, GUID
    `391f5298…`) → ya medida (etiquetada `T1560`).
  - **T1491.002:** **ATA007** ("Defacement") escribe una **página "pública" simulada** (README §3) =
    *External Defacement* → **cubierta por ATA007** (cambio v2; antes "no factible").
- **Mapa ART (clon fijado `388942a…`, verificado en esta planificación):**
  - **Existen** `T1025` (**solo Windows**), `T1113` (**Linux**: `xwd` guid `8206dd0c…`; `import` guid
    `9cd1cccb…`), `T1115` (**Linux**: `xclip` guid `ee363e53…`), `T1056.002` (**solo macOS/Windows**;
    `osascript`/PowerShell), `T1567.002` (**Linux** pero `rclone`+`terraform`→**AWS S3 real** con
    claves), `T1567.003` (**solo Windows**, `pastebin` con **API key**), `T1123` (**Windows/macOS**;
    **sin Linux**), `T1125` (**solo Windows**), `T1074.001` (**Linux**, pero descarga de GitHub).
  - **No existen** en el clon: `atomics/T1011`, `T1052`, `T1495`, `T1498`, `T1499`, `T1557`,
    `T1491.002`, `T1567` (padre).
- **Normas vigentes:** `criterio_ataques.md` §A/§B/§C (+ matiz humano de §C.2.3 para "nubes locales").
- **Tubería:** `piloto_procedimiento.md` + `sink_http.py` (HTTP 9090 / modo `--tcp-port`).
- **Lecciones aplicadas:** `python3` = punto ciego (`92600`); el HIDS ve el **proceso** (R9); binario
  real vs nombre de orden; la víctima **no compila**; el **manager nunca se ataca**.

---

## 3. Inventario COMPLETO revisado de las 30 restantes

### 3.1 Método

`P1 ∧ host_eligible=YES ∧ Linux` (**72**) − técnicas únicas medidas (**42**) = **30**. Cada nodo se
clasifica con: (a) `Hojas/cobertura_atomic.csv` + clon ART (¿prueba Linux ejecutable offline?);
(b) plataformas/mecanismo ATT&CK; (c) lecciones del laboratorio. **Reglas de precisión (obligatorias):**

1. **Una hija NO cubre a otras hijas** (son distintas).
2. **Una hija NO cubre a su madre** por sí sola si la madre tiene **otras formas no medidas**.
3. **Una madre NO cubre a sus hijas.**
4. Una **madre** queda *"cubierta: todas sus formas P1-Linux medidas"* **solo** si **todas** sus
   hijas **del alcance** están `medida`/`cubierta`. Las hijas **fuera del alcance** (solo Windows,
   solo SaaS/Office) **no bloquean** y se **declaran** en la cita.
5. **Comprobación inversa:** si una madre tiene una hija P1-Linux **no medida** (o no factible) →
   **NO se marca cubierta** (se corrige: T1498, T1499).
6. **Automatización obligatoria (v3):** las reglas 1–5 y el **cuadre** se verifican **por script**
   (§6.3 **C1** y **C2**) sobre **las 72 filas P1-Linux**, no a mano. Un fallo **bloquea el cierre**.

### 3.2 Tabla de los 30 nodos (clasificación v2)

| # | Técnica | Táctica | Nombre | Clasificación v2 | Cambio v1→v2 | Evidencia / porqué |
|---|---|---|---|---|---|---|
| 1 | T1056.001 | Collection;Cred.Access | Keylogging | **cubierta por ATA018** | = | Artefacto literal `T1056.001-Keylogging` (README §1). |
| 2 | T1074.001 | Collection | Local Data Staging | **cubierta por ATA011** | = | ATA011 = `mkdir`+`cp` local; `cobertura_atomic`→`atomics/T1074.001`. |
| 3 | T1114.003 | Collection | Email Forwarding Rule | **cubierta por ATA015** | = | Artefacto literal `T1114.003-Email_Forwarding_Rule`. |
| 4 | T1213.006 | Collection | Databases | **cubierta por ATA016** | = | Artefacto literal `T1213.006-Databases`. |
| 5 | T1560.002 | Collection | Archive via Library | **cubierta por ATA013** | = | ATA013 = `T1560.002` (gzip en `python3`, GUID `391f5298…`). |
| 6 | T1491.002 | Impact | External Defacement | **cubierta por ATA007** | **NF → cubierta** | ATA007 escribe una **página "pública" simulada** (README §3). |
| 7 | T1496 | Impact | Resource Hijacking *(madre)* | **cubierta (formas P1-Linux .001/.002)** | **corregida** | ATA025 (.001) + ATA023 (.002); .003/.004 = **SaaS** (fuera de P1-Linux). |
| 8 | T1557 | Cred.Access;Collection | Adversary-in-the-Middle *(madre)* | **cubierta (forma P1-Linux .003)** | **NF → cubierta** | Su única hija P1-Linux (T1557.003) pasa a medirse; .001/.002/.004 fuera de alcance (Windows/solo-red/Network Devices). |
| 9 | T1498 | Impact | Network Denial of Service *(madre)* | **cubierta parcial** ⚠️ | **corregida** | Su forma .001 se mide; **.002 (Reflection Amplification) es no factible** → **no** puede darse por "todas medidas". |
| 10 | T1499 | Impact | Endpoint Denial of Service *(madre)* | **cubierta parcial** ⚠️ | **corregida** | Formas .001/.002/.003 se miden; **.004 (Exploitation) es no factible**. |
| 11 | T1499.001 | Impact | OS Exhaustion Flood | **FACTIBLE — medir** | = | Agotamiento **acotado** (memoria/procesos) con cotas (§B.4). ART sin `T1499` → **propio**. |
| 12 | T1499.002 | Impact | Service Exhaustion Flood | **FACTIBLE — medir** | = | Servicio **desechable** local (listener propio; **nunca** el manager) → **propio**. |
| 13 | T1499.003 | Impact | Application Exhaustion Flood | **FACTIBLE — medir** | = | App **desechable** local con cotas → **propio**. |
| 14 | T1498.001 | Impact | Direct Network Flood | **FACTIBLE — medir** | = | Flood **acotado** al receptor del HOST (nunca el manager); ART sin `T1498` → **propio**. |
| 15 | T1025 | Collection | Data from Removable Media | **FACTIBLE — medir** | = | Imagen extraíble **simulada** (loop, solo-lectura). ART **solo Windows** → **propio**. |
| 16 | T1567.002 | Exfiltration | Exfiltration to Cloud Storage | **FACTIBLE — medir** | **NF → FACTIBLE** | La **técnica** = subir a almacenamiento en nube; **se monta el servicio en el laboratorio** (WebDAV/objeto local), **sin** Mega/AWS reales. |
| 17 | T1567.003 | Exfiltration | Exfiltration to Text Storage Sites | **FACTIBLE — medir** | **NF → FACTIBLE** | La **técnica** = POST de texto a un sitio de pegado; **se monta el "paste" local**. ART solo Windows (API key de pastebin real) → sustituido. |
| 18 | T1498.002 | Impact | Reflection Amplification | **FACTIBLE — medir (condicional)** ⚠️ | **NF → FACTIBLE** | El **reflector** (DNS/NTP/memcached) se **monta local**; spoofing acotado a la víctima, **nunca** el manager. [Confirma el gate por complejidad.] |
| 19 | T1557.003 | Cred.Access;Collection | DHCP Spoofing | **FACTIBLE — medir (condicional)** ⚠️ | **NF → FACTIBLE** | Se monta un **servidor DHCP señuelo** + un **segundo cliente** desechable (VM/netns). [Confirma el gate.] |
| 20 | T1113 | Collection | Screen Capture | **FACTIBLE — intentar (GUI)** | **borderline → intentar** | ART Linux real (`xwd`/`import`); Xvfb `:99` (pantalla **sintética**, declarada). |
| 21 | T1115 | Collection | Clipboard Data | **FACTIBLE — intentar (GUI)** | **borderline → intentar** | ART Linux real (`xclip`, guid `ee363e53…`); Xvfb + `xclip`. |
| 22 | T1056.002 | Collection;Cred.Access | GUI Input Capture | **FACTIBLE — intentar (GUI)** | **borderline → intentar** | ART **sin prueba Linux** → **propio**: captura de eventos X11 (`xinput test`/XRecord) sobre Xvfb con entrada **sintética** (`xdotool`). |
| 23 | T1011 | Exfiltration | Exfil. Over Other Network Medium *(madre)* | **no factible** | = (grupo A) | Solo **Ethernet virtual**; sin otro medio. Sin ART. |
| 24 | T1011.001 | Exfiltration | Exfiltration Over Bluetooth | **no factible** | = (grupo A) | **Sin adaptador Bluetooth**. Sin ART. |
| 25 | T1052 | Exfiltration | Exfil. Over Physical Medium *(madre)* | **no factible** | = (grupo A) | Medio **físico real**; un disco virtual no sale del anfitrión. Sin ART. |
| 26 | T1052.001 | Exfiltration | Exfiltration over USB | **no factible** | = (grupo A) | **Sin USB físico**. Sin ART. |
| 27 | T1123 | Collection | Audio Capture | **no factible** | = (grupo A) ⚠️ | **Sin dispositivo de audio**; ART sin Linux. *(Existe equivalente sintético `snd-aloop` → se pregunta en el gate.)* |
| 28 | T1125 | Collection | Video Capture | **no factible** | = (grupo A) ⚠️ | **Sin cámara**; ART solo Windows. *(Existe equivalente sintético `v4l2loopback` → se pregunta.)* |
| 29 | T1495 | Impact | Firmware Corruption | **no factible** | = (grupo A) | Requiere **firmware real**; corromperlo **brick** la VM. Sin ART. |
| 30 | T1499.004 | Impact | Application or System Exploitation | **no factible** | = | Requiere **binario vulnerable + exploit** offline (la víctima no compila). *(Alternativa: binario vulnerable propio pre-staged → se pregunta.)* |

**Recuento:** 12 factibles + 6 cubiertas por ATA + 2 madres cubiertas + 2 cubiertas parciales + 8 no
factibles = **30**. ✔

### 3.3 Precisión madres/hijas — comprobación inversa (lo nuevo)

Aplicando las reglas 1–5 de §3.1 a **todas** las madres tocadas:

| Madre | Hijas P1-Linux | ¿Todas medidas? | Clasificación correcta |
|---|---|---|---|
| T1056 | .001 (cub. ATA018), .002 (se mide), .003 (ATA028), .004 (ATA035) | Sí (tras medir .002) | **cubierta: todas sus formas P1-Linux medidas** |
| T1074 | .001 (cub. ATA011), .002 (ATA040) | Sí | **cubierta: todas sus formas P1-Linux medidas** |
| T1213 | .006 (cub. ATA016); .001–.005 fuera (SaaS/Office/Windows) | Sí (en alcance) | **cubierta (forma P1-Linux .006)** |
| T1560 | .001 (ATA030), .002 (cub. ATA013), .003 (ATA034) | Sí | **cubierta: todas sus formas P1-Linux medidas** |
| T1491 | .001 (ATA033), .002 (cub. ATA007) | Sí | **cubierta: todas sus formas P1-Linux medidas** |
| T1567 | .001 (ATA022), .002 (se mide), .003 (se mide), .004 (ATA043) | Sí (tras medir .002/.003) | **cubierta: todas sus formas P1-Linux medidas** |
| T1496 | .001 (ATA025), .002 (ATA023); .003/.004 **SaaS fuera** | Sí (en alcance) | **cubierta (formas P1-Linux)** |
| T1557 | .003 (se mide); .001/.002/.004 fuera | Sí (tras medir .003) | **cubierta (forma P1-Linux .003)** |
| **T1498** | **.001 (se mide), .002 (NO factible)** | **No** | **cubierta parcial** ⚠️ (corregida) |
| **T1499** | **.001/.002/.003 (se miden), .004 (NO factible)** | **No** | **cubierta parcial** ⚠️ (corregida) |

- **Correcciones inversas (madres mal dadas por cubiertas en v1):** **T1498** y **T1499** (una forma
  no factible). En v1 también estaba mal el "T1496" (se acota a formas P1-Linux; se declara).
- **Nota de doble conteo resuelta:** las etiquetas de `ATA_index` **T1056/T1074/T1213/T1560** eran
  **madres** cuyo artefacto implementa una **hija** (.001/.001/.006/.002). En el CSV de cierre, la
  fila de la **hija** dice *"cubierta por ATA<NNN>"* y la **madre** *"cubierta: todas sus formas
  [P1-Linux] medidas"* (una sola medición por ATA; **sin** duplicar).

### 3.4 GUI (T1113, T1115, T1056.002) — **se intentan las 3**

El humano quiere **intentarlas todas**; por tanto **dejan de ser "borderline"** y pasan a
**intentar** (2 iteraciones). Servidor headless → **pre-staging Xvfb** (servidor X sintético, display
`:99`), declarado como **pantalla/entrada sintética sin usuario** en el README.

| Técnica | Cómo se intenta | Si no sale |
|---|---|---|
| **T1113** | ART Linux (`xwd -root …` guid `8206dd0c…`; `import -window root …` guid `9cd1cccb…`) sobre Xvfb `:99`. Detección por `execve` de `xwd`/`import`. | Declarar no factible citando el fallo (p. ej. sin extensión X requerida). |
| **T1115** | ART Linux (`history \| xclip -sel clip`; `xclip -o > history.txt` guid `ee363e53…`) sobre Xvfb. | Ídem. |
| **T1056.002** | **Propio** (ART solo macOS/Windows): capturar eventos de entrada X11 con `xinput test`/`test-xi2` (o cliente XRecord) mientras `xdotool` inyecta eventos sintéticos; el portapapeles/ventana son de juguete. Detección por `execve`. | Si no se logra un mecanismo fiel sin escritorio real → **no factible** con evidencia. |

> **Realismo acotado:** la captura es de una **pantalla/entrada sintéticas**; se declara en el README.
> El mecanismo (herramienta real + `execve` + escritura del artefacto) **sí** se ejercita.

### 3.5 No factibles — **revisión fina (las 14 una a una)**

**(A) "Otra plataforma" sin equivalente local → NO FACTIBLE** (8):
`T1011`, `T1011.001` (Bluetooth), `T1052`, `T1052.001` (USB), `T1123` (audio), `T1125` (cámara),
`T1495` (firmware). Motivo citado: sin el medio/dispositivo en el laboratorio (solo Ethernet virtual,
sin USB/BT/audio/cámara) y sin ART aplicable.

> **¿Alguna con equivalente?** **T1123** y **T1125** *tendrían* un equivalente **sintético**
> (`snd-aloop` / `v4l2loopback`, análogos a Xvfb); **por defecto se mantienen no factibles** salvo que
> el humano apruebe intentarlos (se pregunta en el gate). **T1011** podría simularse con un PTY serie
> (`socat`) pero **no** es fiel (no hay medio físico) → se mantiene no factible.

**(B) "Nube / servicio externo" → reprocesadas** (5):
- **T1567.002 → FACTIBLE:** se mide la **técnica** (subir a almacenamiento en nube), no el destino;
  se monta un **servicio local** (WebDAV/almacén de objetos en el HOST) y se **declara el sustituto**.
- **T1567.003 → FACTIBLE:** se monta un **"paste" local** (endpoint HTTP de pegado); sustituto declarado.
- **T1491.002 → CUBIERTA por ATA007** (la acción de ATA007 es la página "pública" simulada).
- **T1498.002 → FACTIBLE (condicional):** el **reflector** (DNS/NTP/memcached) **se monta local**;
  spoofing acotado a la víctima, **nunca** el manager.
- **T1557.003 → FACTIBLE (condicional):** se monta un **DHCP señuelo** + **segundo cliente**.

**Otras** (1): **T1499.004 → NO FACTIBLE** (exploit + binario vulnerable; la víctima no compila y no
hay PoC offline). *(Alternativa "binario vulnerable propio pre-staged" → se pregunta en el gate.)*

**Resumen del cambio:** de las 14, **4 pasan a factible**, **1 a cubierta** y **8 siguen no
factibles** (+ el padre **T1557** pasa a cubierta). **Solo** se mantienen no factibles las de **otra
plataforma** (7) y **T1499.004** (exploit).

### 3.6 Servicios de nube/red montados en el laboratorio (sustitutos declarados)

| Técnica | "Servicio" real (ART) | Sustituto **local** (laboratorio) | Material **antes de `t0`** |
|---|---|---|---|
| T1567.002 | `rclone` → Mega / **AWS S3** (claves reales) | **WebDAV/objeto local** en el HOST (`rclone serve webdav` o endpoint del receptor) | binario `rclone` (Linux amd64) **URL+`sha256`** + config local |
| T1567.003 | HTTP POST a **pastebin.com** (API key) | **"paste" local** (`POST /paste` en el receptor) | ninguna nueva (`curl` de serie) + extensión del receptor |
| T1498.002 | reflector DNS/NTP/memcached externo | **reflector local** (resolver/daemon en el HOST) | daemon **URL+`sha256`** + `hping3`/`scapy` para spoofing |
| T1557.003 | red con DHCP real | **DHCP señuelo local** + **cliente desechable** (VM/netns) | paquete DHCP **URL+`sha256`**; cliente efímero |

**Sin NAT en la ventana.** **Sin** API/autenticación de terceros. **Nunca** el manager.

---

## 4. Reparto en tandas y orden (revisado)

Orden **menos → más riesgo** + **agrupación por setup compartido**. Numeración continuada desde
`ATA043`. **Tandas de 5** (la C es condicional).

### Tanda A — "medios simulados + DoS acotado" (5 técnicas · 10 ventanas)

| ATA | Técnica | Táctica | Setup compartido | Riesgo |
|---|---|---|---|---|
| **ATA044** | T1025 | Collection | Imagen extraíble `loop` (solo-lectura) | Bajo |
| **ATA045** | T1499.001 | Impact | Cotas de recurso (memoria/procesos) | Medio |
| **ATA046** | T1499.003 | Impact | App desechable local | Medio |
| **ATA047** | T1499.002 | Impact | Servicio desechable local (listener propio) | Medio |
| **ATA048** | T1498.001 | Impact | **Receptor** `sink_http.py` en el HOST + cotas de red | Medio-alto |

### Tanda B — "pre-staging + recursos sintéticos" (5 técnicas · 10 ventanas)

| ATA | Técnica | Táctica | Setup compartido | Riesgo |
|---|---|---|---|---|
| **ATA049** | T1567.002 | Exfiltration | **Nube local** (WebDAV) en el HOST | Bajo |
| **ATA050** | T1567.003 | Exfiltration | **"Paste" local** en el receptor | Bajo |
| **ATA051** | T1113 | Collection | Pre-staging **Xvfb + x11-apps/imagemagick**, `:99` | Bajo |
| **ATA052** | T1115 | Collection | Pre-staging **Xvfb + xclip**, `:99` | Bajo |
| **ATA053** | T1056.002 | Collection;Cred.Access | Pre-staging **Xvfb + xinput/xdotool**, `:99` | Bajo-medio |

### Tanda C — "servicios de red montados" (2 técnicas · 4 ventanas · **condicional a D2**)

| ATA | Técnica | Táctica | Setup compartido | Riesgo |
|---|---|---|---|---|
| **ATA054** | T1498.002 | Impact | **Reflector local** (DNS/NTP) + spoofing acotado | **Alto** |
| **ATA055** | T1557.003 | Cred.Access;Collection | **DHCP señuelo** + segundo cliente desechable | **Alto** |

> Si el humano **no** ratifica la Tanda C, T1498.002 y T1557.003 se declaran **no factibles** (por
> decisión de alcance/riesgo, **no** por falta de equivalente) y el bloque cierra con **10** mediciones
> nuevas. La **Tanda B** (incl. GUI y nubes locales) se ejecuta **siempre**.

---

## 5. Operativa por tanda

Ciclo de **12 pasos** de `piloto_procedimiento.md` **sin cambios**: `preflight → (receptor si aplica)
→ revert/start víctima (lab-listo) → scp → dependencias → t0 → ataque → scan FIM → t1 → espera →
extraer del fichero diario → filtrar → revisar dudosas → guardar`. Doble iteración **v2**; **C0 por
técnica**; `esperado` **escrito antes y validado por el humano**.

### 5.1 Pre-staging por tanda (norma §C, con el matiz de "nube local")

- **T1025:** imagen de disco **pequeña y fijada** creada en el HOST (`dd`/`mkfs.vfat`, documentos
  señuelo); se documenta `sha256` + comando; `scp` **antes de `t0`**; `mount -o ro,loop`. **Sin NAT.**
- **DoS (A):** **preferir built-ins**. Si hace falta herramienta (`stress-ng`), **URL+`sha256`** +
  alternativa built-in. **Evitar `python3`** en la acción clave; si se usa, **C0 lo declara**.
- **T1567.002:** **servicio de nube local** en el HOST (WebDAV/objeto). `rclone` Linux **URL+`sha256`**,
  `scp`+instalación **antes de `t0`**; config del remote **local** (sin claves reales). **Nada de
  AWS/Mega.**
- **T1567.003:** **"paste" local** (`POST /paste` en `sink_http.py`); `curl` de serie. Sin material nuevo.
- **T1113/T1115/T1056.002:** paquetes **Xvfb + x11-apps/imagemagick/xclip/xinput/xdotool** (Debian)
  descargados en el HOST **antes de `t0`** (**URL+`sha256`**), `scp`+`dpkg -i`. Display `:99`.
- **T1498.002/T1557.003 (C):** daemon reflector / DHCP señuelo (**URL+`sha256`**) + `hping3`/`scapy` o
  cliente efímero. Material **antes de `t0`**. **Nunca** el manager.

### 5.2 Guardarraíles (duros, en el guion)

- **Comunes:** rutas bajo `lab-attack`/`lab-legit`; **aborta** si sale del laboratorio, toca disco/
  partición/cuenta/servicio reales, el remoto no es local o se supera una cota. **Nunca el manager.**
- **T1025:** montaje **solo-lectura**; jamás disco/partición real; desmontar y borrar la imagen al cerrar.
- **DoS acotado (T1499.x / T1498.x / T1498.002):** duración **≤ 15 s**; `ulimit` de memoria/procesos;
  servicios **desechables propios**; destino de red **solo el receptor del HOST** (`192.168.65.1`) o la
  **propia víctima**; **verificar 0 procesos residuales**; restauración inmediata.
- **T1567.x:** el destino es **solo** el servicio local; **cero** credenciales/tokens de terceros.
- **GUI:** `Xvfb :99` levantado y **matado** por ventana; sin cambios persistentes.
- **T1557.003:** el DHCP señuelo sirve **solo** al cliente efímero del laboratorio; **jamás** al manager.

### 5.3 Receptor y recursos

- **T1498.001 / T1567.003:** `Soporte/Ataques/receiver/sink_http.py` (HTTP `9090` / TCP `9091`) en el
  HOST, **antes de `t0`** y parado **tras `t1`**; `--log` por iteración. Firewall acotado
  `TFG-sink-9090` **solo si el puerto resulta inalcanzable** (retirada al cerrar).
- **T1567.002:** servicio **WebDAV** local (HOST) además del receptor. **Tanda C:** reflector/DHCP
  locales. **GUI:** display `:99` (sin firewall).

---

## 6. Verificación (`tfg-tester`) y criterios de aceptación

### 6.1 Qué comprueba el `tfg-tester`

1. **Métrica congelada** (O1+O2 por técnica/iteración) y **criterio v2** (`iguales`).
2. **`dudosa = 0`** en cada ventana nueva (revisión humana trazada).
3. **Invariante "0 filas del ataque en `ruido`"** (pertenencia por carpeta + veredictos `artefacto`),
   con las **limitaciones declaradas** (PAM/`sudo`).
4. **Regresión byte a byte de las 104 ventanas actuales** **intactas**.
5. **`pytest`** (base **97**; no debe bajar).
6. **Determinismo**: reproducir extracción/filtrado y comparar.
7. **Cadena de huellas** (`auditar_cadena_huellas.py`): **0 desincronías**.
8. **C0 por técnica** presente (`Soporte/Ataques/c0/`).
9. **Citas del inventario**: cada fila del CSV con **evidencia** (ART, plataforma o medición previa).
10. **Madres/hijas (automático)**: ejecuta **C2** (§6.3) — toda madre marcada *"cubierta"* tiene
    **todas** sus formas P1-Linux medidas/cubiertas; T1498/T1499 llevan **"cubierta parcial"** (no
    "cubierta"). Un fallo de C2 = bloqueo.
11. **Laboratorio cerrado**: receptor/WebDAV/reflector/DHCP parados, sin regla de firewall,
    Xvfb/daemons parados, **0** procesos residuales, VMs apagadas, **NAT off**, víctima a `lab-listo`.
12. **Cuadre de la tabla (automático)**: ejecuta **C1** (§6.3) — `cobertura_p1_linux.csv` con **72
    filas** que **suman 72** y **cuadran por categoría**. Un fallo de C1 = bloqueo.
13. **Muestreo al azar (humano en bucle)**: además de C1/C2, el tester elige **≥5 filas al azar** de
    las 72 y contrasta a mano su `estado`/`cita` contra `ATA_index.csv`, `corpus_atomic.csv` y el
    README del ataque — para no depender solo del script.

### 6.2 Criterios de aceptación

- **CA1 — Inventario completo:** las **72** técnicas P1-Linux están en `Hojas/cobertura_p1_linux.csv`
  con clasificación y **cita**; **la columna `estado` suma 72** y **cuadra por categoría**
  (verificado por **C1**, §6.3).
- **CA2 — Factibles medidas/intentadas:** cada factible tiene README + `esperado` (firmado) + C0 +
  guion + **2 ventanas** + ficha + bitácora + fila en `ATA_index.csv`. Las 3 GUI se **intentan**;
  T1498.002/T1557.003 solo si el gate ratifica la Tanda C.
- **CA3 — Medición:** O1+O2 con la métrica congelada; `dudosa=0`; **0 filas del ataque en `ruido`**;
  v2 `iguales`.
- **CA4 — No factibles declaradas:** cada una con **motivo + evidencia** (grupo A "otra plataforma" o
  dependencia de tercero).
- **CA5 — Regresión:** las **104 ventanas** intactas; `pytest` ≥ 97; cadena **0 desincronías**.
- **CA6 — Cierre:** laboratorio cerrado y `state.md`/`roadmap.md`/`Bitacora/` actualizados.
- **CA7 — Comprobaciones automáticas (v3):** **C1** (cuadre: 72 filas suman 72 y cuadran por
  categoría) y **C2** (padre/hijo: sin violaciones) **PASAN** sobre **las 72 filas**; el
  `tfg-tester` **re-ejecuta** ambos y **muestrea ≥5 filas al azar**. Cualquier inconsistencia
  adicional se **reporta y corrige** antes de cerrar.

---

## 6.3 Comprobaciones automáticas (v3) — **C1** y **C2**

Las dos comprobaciones viven en **un solo script determinista** (solo stdlib, **offline**, sin VM
ni red): `_artefactos/scripts/verificar_cobertura_p1.py`, con salida **exit != 0 + mensaje claro**
al primer fallo. Se ejecuta como **preflight** y de nuevo en la **verificación** del `tfg-tester`:

```
python _artefactos/scripts/verificar_cobertura_p1.py --todo
```

Se acompaña de `_artefactos/scripts/tests/test_verificar_cobertura_p1.py` (pytest, con fixtures
pequeños: caso OK, suma≠72, categoría descuadrada, técnica faltante/extra/duplicada, y las 4
violaciones de C2). **Alcance = las 72 filas P1-Linux** (43 ya medidas + 30 nuevas + lo que salga).
**Dónde vive el resultado:** la hoja de cobertura `Hojas/cobertura_p1_linux.csv`. **Quién lo
verifica:** el `tfg-tester` (re-ejecuta C1/C2 y **muestrea ≥5 filas al azar**).

### C1 — Cuadre de la tabla

Lee `Hojas/cobertura_p1_linux.csv` + `Hojas/corpus_host.csv` y **falla** si:

- el conjunto de `tecnica` del CSV **no coincide exactamente** con la piscina P1-Linux derivada
  del corpus (`P1 ∧ host_eligible=YES ∧ Linux`) → **faltantes, extras o duplicados**;
- el total de filas **≠ 72**;
- la columna `estado` **no suma 72** o **no cuadra por categoría** en **exactamente 5 grupos**
  (cada fila en uno solo): `medida` + `cubierta por ATA` + `cubierta` (madre) + `cubierta_parcial`
  + `no_factible`;
- una fila es **incoherente**: `cubierta por ATA` sin `ata_o_cubierta_por` en forma `ATA<NNN>`;
  `medida` sin ATA; `no_factible` sin `motivo_codigo`; etc.;
- el crosstab por categoría **no coincide** con la tabla de totales de **§7** (48/6/8/2/8 con el
  gate A+B+C y 4.º estado). Si el gate cambia algo (p. ej. rechaza la Tanda C o elige 3 estados),
  la tabla de §7 se actualiza **en el mismo commit** y C1 cuadra contra ella.

### C2 — Test padre/hijo (la clave)

Lee la jerarquía de `Hojas/corpus_host.csv` (`es_subtecnica`/`padre_id`) + `cobertura_p1_linux.csv`
+ `Hojas/ATA_index.csv`, y **falla** si:

1. **Madre `cubierta` con una forma (hija) no medida/factible.** Una **madre** (con hijas en el
   alcance P1-Linux) marcada `estado=cubierta` teniendo **alguna hija del alcance** que **no** sea
   `medida`/`cubierta por ATA` (es decir, `no_factible`, `cubierta_parcial`, pendiente o ausente).
   *(Este es el caso que la v2 había dado por cubierto de más en **T1498** y **T1499**.)*
2. **Hija cubierta por otra hija.** Una fila `cubierta por ATA<NNN>` cuyo ATA cita una técnica
   **hermana** (otra hija del mismo padre; ni es la propia técnica ni un ancestro suyo).
3. **Madre usada para cubrir a sus hijas.** Una fila de **hija** cita un ATA cuya técnica es **su
   madre** (una madre **no** cubre a sus hijas).
4. **Cita que no resuelve.** El `ATA<NNN>` citado **no existe** en `ATA_index.csv`, o su técnica
   **no es** la de la fila **ni un ancestro** de ella (no corresponde a esa técnica).
   - *Caso válido documentado:* el ATA está etiquetado en `ATA_index` bajo la **madre** pero su
     artefacto implementa la **hija** (p. ej. `ATA018`→`T1056.001`); ahí la fila de la hija
     *"cubierta por ATA018"* **pasa** (el ATA es ancestro de la fila). El caso inverso (el ATA es
     **descendiente**) cae en la regla 3 y **falla**.

**Detalle:** "hijas del alcance" = las que están en las 72 filas; las hijas fuera de alcance
(solo Windows/SaaS/Office) **no bloquean** y se **declaran** en la cita. Si C1/C2 detectan
**cualquier inconsistencia adicional** en las 43 ya medidas, se **reporta y corrige** (CSV y/o
`ATA_index`) y se **re-ejecutan** hasta verde; el rastro queda en el `change-doc`.

---

## 7. Ficheros que se tocarán y cierre (dónde se documenta)

**Nuevos / actualizados:**

| Qué | Ruta |
|---|---|
| **Tabla de cierre P1** (72 filas) | `Hojas/cobertura_p1_linux.csv` **(nuevo)** |
| **Verificador C1+C2** (script) | `_artefactos/scripts/verificar_cobertura_p1.py` **(nuevo)** |
| **Tests C1+C2** (pytest) | `_artefactos/scripts/tests/test_verificar_cobertura_p1.py` **(nuevo)** |
| Índice de ataques | `Hojas/ATA_index.csv` (filas `ATA044`+) |
| Mapa ART | `Hojas/cobertura_atomic.csv` (regenerado con los 30) |
| Auditoría de origen | `Hojas/auditoria_origen.csv` (append por §A.4) |
| Artefactos + README | `Dataset/Ataques/Comandos/<TEC>-<DESC>/` |
| `esperado` + C0 | `…/ATA<NNN>_esperado.csv`; `Soporte/Ataques/c0/ATA<NNN>_c0_plan.md` |
| Ventanas + fichas | `Dataset/Ataques/Resultados/Wazuh/linux/{CSV,Auditado,Logs}/`; `ATA<NNN>_meta.md` |
| Bitácoras | `Bitacora/ATA<NNN>.json` |
| Estado / roadmap | `state.md`, `roadmap.md` |
| Plan + change-doc | `_fases/fase-03-p1-cierre/` (al cerrar) |

**Forma del CSV de cierre (72 filas):**
`tecnica, tactica, nombre, es_subtecnica, padre_id, plataformas, estado, clasificacion,
ata_o_cubierta_por, motivo_codigo, motivo_detalle, cita`.

- **`estado`** ∈ {`medida`, `cubierta`, `no_factible`} (+ **`cubierta_parcial`** propuesto, ver nota).
- **Recuento objetivo (si se miden las factibles y el gate aprueba la Tanda C):**

  | estado | n | detalle |
  |---|---|---|
  | `medida` | **48** | 36 ya medidas + 12 nuevas (incl. 3 GUI); verificado por script sobre las 72 filas |
  | `cubierta` (por ATA) | **6** | T1056.001, T1074.001, T1114.003, T1213.006, T1560.002, T1491.002 |
  | `cubierta` (madre) | **8** | T1056, T1074, T1213, T1560, T1491, T1496, T1557, T1567 |
  | `cubierta_parcial` | **2** | T1498, T1499 |
  | `no_factible` | **8** | T1011, T1011.001, T1052, T1052.001, T1123, T1125, T1495, T1499.004 |
  | **Total** | **72** | ✔ |

  > **Nota `cubierta_parcial`:** el humano pidió 3 estados. Si prefiere **3**, T1498/T1499 se
  > pliegan a **`no_factible` (motivo: paraguas; su forma .002/.004 no factible; las demás medidas)**.
  > Si acepta el 4.º estado, quedan como **`cubierta_parcial`**. **Se decide en el gate (D3).**

---

## 8. Riesgos

| Riesgo | Mitigación |
|---|---|
| El DoS acotado (incl. reflect) desestabiliza la VM o el anfitrión | Cotas duras (≤15 s, `ulimit`, 0 residuales); **nunca** el manager; servicios desechables. |
| El spoofing de T1498.002 falla o es inestable | Se acota a la víctima; si no sale, **no factible** con evidencia (no se fuerza). |
| El DHCP señuelo toca al manager | Regla dura: **solo** el cliente efímero; aborta si el destino no es local-de-laboratorio. |
| GUI sintética (Xvfb) no reproduce el mecanismo | Declarar **realismo acotado**; si T1056.002 no logra captura fiel → **no factible** con evidencia. |
| Punto ciego `python3` (`92600`) reaparece | C0 por técnica; evitar `python3` en la acción clave; declarar por `rule_id` del `execve`. |
| Herramientas ausentes (sin NAT) | Pre-staging §C (pequeño, fijado, URL+`sha256`) o alternativa built-in. |
| Romper la cadena de huellas (EOL/CRLF) | **No** `checkout`/`stash`/`reset`; recalcular y auditar huellas. |
| El pre-staging contamina la ventana | Todo material **antes de `t0`**; revert restaura `lab-listo`. |
| Tiempo: se añaden 7 mediciones (nubes+GUI) y 2 condicionales | Prioridad A→B; C condicional; evasión/Windows después. |
| **C1/C2** detectan inconsistencias adicionales en las **43 ya medidas** | Se **reportan y corrigen** (CSV y/o `ATA_index`) antes de cerrar; C1/C2 se **re-ejecutan hasta verde**; rastro en el `change-doc`. |

---

## 9. Lo que NO entra (fuera de alcance)

- **Evasión** (versiones disfrazadas) — trabajo futuro (`state.md`).
- **Windows** (su línea base / adaptación del filtro) — otro bloque.
- **Fase 4** (η) y **Fase 5** (memoria).
- **Tocar la métrica, el filtro o el criterio v2** (congelados).
- **Repetir ataques ya hechos** (los 6 "cubiertos" **no se re-atacan**; las 9 repeticiones ya cerraron).
- **Usar nubes/servicios reales de terceros** (AWS/Mega/pastebin real): se sustituyen por **servicios
  locales**; **prohibido** cualquier token/clave reales.
- **Atacar el manager** o cualquier servicio/cuenta real.
- **Medio físico real** (USB/BT/audio/cámara/firmware): solo si el humano aprueba el equivalente sintético.

---

## 10. Gate humano (en lenguaje sencillo)

**Qué propongo (v2):** cerrar **P1 en Linux**. De los **30 nodos restantes**: **6 ya están medidos**
con otro nombre (con cita), **2 madres** quedan cubiertas por sus formas Linux, **12 sí se pueden
hacer** (5 de siempre + **2 nubes montadas en local** + **3 GUI con Xvfb** + **2 de red
condicionales**) y **8 no se pueden** (USB/Bluetooth/audio/cámara/firmware/exploit). Además, corregí
**2 madres** que la v1 daba por cubiertas de más (**T1498** y **T1499**) y reatribuí la **página
"pública"** de ATA007 a **T1491.002**.

**Añadido en v3 (sin decisión nueva):** la revisión fina de la v2 se pasó **solo por las 30 nuevas**;
para no depender de la atención humana, la v3 **automatiza** la validación (**C1 cuadre + C2
padre/hijo**, §6.3) y la aplica a **las 72 filas P1-Linux** (43 ya medidas + 30 nuevas). Si C1/C2
encuentran **cualquier inconsistencia** en lo ya medido, se **reporta y corrige** antes de cerrar.
Esto **no cambia** D1–D5; solo refuerza la comprobación.

**Necesito que decidas:**

- **D1 — ¿Apruebas el bloque y la Tanda A** (T1025 + 4 DoS **acotados**)? *Recomendado: sí.*
- **D2 — GUI y nubes locales (Tanda B):** las **3 GUI** con Xvfb (T1113, T1115, T1056.002) y las
  **2 nubes locales** (T1567.002 WebDAV local, T1567.003 paste local). *Recomendado: sí (medir/intentar
  todas).* Si T1056.002 no logra captura fiel, se declara no factible con evidencia.
- **D3 — Madres "cubierta parcial":** ¿aceptas un **4.º estado `cubierta_parcial`** para **T1498** y
  **T1499** (o prefieres que se plieguen a `no_factible (paraguas)`)? *Recomendado: `cubierta_parcial`.*
- **D4 — Tanda C (red condicional):** **T1498.002** (reflector local + spoofing) y **T1557.003**
  (DHCP señuelo + cliente). Son las de **mayor complejidad/riesgo**. ¿Las medimos o las declaramos
  no factibles por coste/riesgo? *Recomendado: medir si hay tiempo; si no, no factible.*
- **D5 — ¿Alguna "no factible" que yo deba reconsiderar?** Concretamente: ¿intentamos **T1123/T1125**
  con **dispositivo sintético** (`snd-aloop`/`v4l2loopback`) y **T1499.004** con un **binario
  vulnerable propio pre-staged + PoC**? *Recomendado: no (dejarlas no factibles) salvo tu criterio.*

**Con tu OK** (`status: approved_by_human`) arrancan las tandas (A y B siempre; C si D4=sí), cada una
con su C0, su `esperado` firmado y **2 iteraciones**; al cerrar, la **tabla de cierre de P1** quedará
en `Hojas/cobertura_p1_linux.csv` con **72 filas que suman 72 y cuadran por categoría** (verificado
por **C1**), **sin violaciones padre/hijo** (verificado por **C2**) y con **≥5 filas al azar**
revisadas a mano por el `tfg-tester`.
