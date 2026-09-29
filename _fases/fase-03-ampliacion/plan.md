---
fase: 3
bloque: fase-03-ampliacion
nombre: Ampliación del corpus — 15 técnicas nuevas en 3 tandas de 5 (solo Linux, sin NAT)
version: 1
status: approved_by_human
fecha: 2026-09-29
fecha_aprobacion: 2026-09-29
aprobado_por: humano
autor: tfg-planner
delegacion: "**Validado por el humano (2026-09-29)**, con revisión posterior de las decisiones y de los resultados. La ejecución se orquesta por tandas (A → B → C)."
---

# Plan — Ampliación del corpus (Fase 3): 15 técnicas nuevas en 3 tandas de 5

> **Tubería ya probada** (13 técnicas / 26 ventanas, `_fases/fase-03-escalado/change-doc.md`).
> Este bloque **reutiliza el ciclo tal cual**: no rediseña la **métrica congelada**
> (`fase-03-metrica`), ni el **filtro**, ni el **criterio de doble iteración v2**. Solo añade
> **técnicas nuevas** con su `esperado`, su C0, sus 2 ventanas y su ficha/bitácora.
> **Alcance: SOLO Linux.** Windows no entra. **Sin NAT.**

---

## 1. Objetivo

Ejecutar **15 técnicas nuevas** del corpus P1 host-eligible Linux (que no estén entre las 13 ya
cerradas), **cada una × 2 iteraciones = 30 ventanas**, con el **runbook probado**
(`Soporte/Ataques/piloto_procedimiento.md`), para ampliar la tabla de detección sin tocar la
métrica ni el filtro.

- **Estructura:** **1 bloque (`fase-03-ampliacion`), 3 tandas de 5**; la validación del orquestador,
  en **3 ratos** (uno por tanda), no en 15.
- **Unidad del trabajo:** `ATA<NNN>` por técnica; los nuevos son **ATA014 … ATA028**.

### 1.1 Hechos verificados (paso 0, solo lectura)

- **Corpus ya cerrado:** 13 técnicas (`ATA001`–`ATA013`, 26 ventanas) → **12 detectadas / 1 no**
  (`ATA013/T1560.002`, punto ciego de fábrica `92600`).
- **Piscina P1 host-eligible (verificada hoy en `Hojas/corpus_host.csv`):**
  **88** técnicas P1 host-eligible; **71** de ellas citan **Linux**; **58** Linux sin las 13 ya hechas.
  *(El encargo dice «76 de 89»: 89/76 es el total P1 host-eligible **sin filtrar por SO** (incluye
  Windows/SaaS/cloud). Tras filtrar a **Linux** quedan **71**, y **58** tras restar las 13 hechas.
  Se trabaja sobre estas 58.)*
- **Reparto por táctica de las 58 candidatas:** Impact ~23 · Collection ~17 · Exfiltration ~11
  (aprox., contando subtecnicas).
- **Cobertura ART (Linux)** de las candidatas: solo **T1056.001 (12)**, T1529 (10), T1560.001 (5),
  T1113 (4), T1560.002 (4), T1048.002 (3, ya usada en ATA008), T1048.003 (3), T1567.004 (2).
  ⇒ **casi todo el bloque se escribe a mano** (como ATA005/006/007 y el resto del escalado).
- **El HIDS de host no ve la red** en esta configuración (no hay reglas de salida en el ruleset
  base; confirmado en ATA008/ATA009): la exfiltración se detecta por el **`execve`**, y la prueba
  del efecto la da el **`sink.log`** del receptor. Consecuencia de diseño: **no se eligen N variantes
  del mismo `curl`→sink**; se busca **mecanismo/layer distinto** en cada técnica.
- **Capas presentes:** `execve` (`audit_command`/`80792`), `watch`/audit-file (`audit_file`,
  `audit_key`, sobre todo `lab-legit`), FIM/syscheck (`syscheck_path`), syslog/journald (`40700` es
  `level=0`; ojo), PAM/auth (`5501`/`5502`, `5715`) y **red** (solo receptor; invisible al HIDS).

---

## 2. Criterios de selección (explícitos, decididos por el planificador)

Se ordenan por prioridad; ante empate, decide el criterio anterior.

1. **Táctica con foco R/E/S.** Se prioriza **Impact** (Ransomware/Sabotaje) y **Exfiltration**;
   **Collection** entra como apoyo (es el paso previo de todo «robo → exfiltración»). Se evita
   sumar volumen de la misma táctica/mecanismo ya cubierto.
2. **Diversidad de capas del HIDS (diversidad REAL, no aparente).** Cada técnica debe ejercitar
   **al menos una capa distinta de `execve`**: (a) `watch`/audit-file, (b) FIM/syscheck,
   (c) syslog/journald/PAM-auth, (d) red. **Regla dura:** no se admiten dos técnicas cuyo único
   mecanismo nuevo sea «otro `curl` al receptor».
3. **Factibilidad offline (bloqueante).** Linux, **sin NAT**, sin tocar el sistema real ni servicios
   reales; herramientas **presentes** o con **fallback stdlib/coreutils/openssl/curl/wget/git**;
   «efecto» **demostrable por evidencia** (sha256 / `k/m` / estado antes-después).
4. **Dificultad/sorpresa (valor científico).** Se incluyen a propósito casos con probabilidad real
   de **NO detección** o de detección **indirecta** (hijacking de recursos, manipulación en tránsito,
   captura web), para **no sesgar** el resultado hacia «todo detectado por `execve`».
5. **Coste de escritura (KISS).** Se prefieren mecanismos reproducibles con lo que ya hay; el
   **guion propio es la norma**; cuando una atómica de ART sea adaptable, se documenta y se usa.

---

## 3. Las 15 elegidas

> **Leyenda.** *Capa* = capa del HIDS que **añade** (además de `execve`). *Vía* = **G**uion propio
> / **ART** (adaptada). *Factible* = sin NAT y dentro de los guardarraíles.

### 3.1 Tabla resumen

| ATA | Técnica | Táctica | Capa que añade | Vía | Factible s/NAT | Sorpresa |
|---|---|---|---|---|---|---|
| **ATA014** | T1114 Email Collection | Collection | file-access (`watch`) | **G** | Sí (lee spool/Maildir local) | media |
| **ATA015** | T1114.003 Email Forwarding Rule | Collection | **file-creation (FIM/watch)** | **G** | Sí (escribe regla de reenvío) | media |
| **ATA016** | T1213.006 Databases | Collection | file-access (BD local) | **G** | Sí (dep. `sqlite3`; fallback) | media |
| **ATA017** | T1657 Financial Theft | **Impact (sabotaje)** | **watch + FIM** (modifica libro) | **G** | Sí (artefacto en `lab-legit`) | media |
| **ATA018** | T1056.001 Keylogging | Collection/Cred-Access | file-write / syslog | **G** (ART adaptable) | Sí (contenido, sin PAM real) | **alta** |
| **ATA019** | T1048.001 Symmetric Encrypted Non-C2 | **Exfiltration** | red (cifrado simétrico) | **G** | Sí (receptor local) | media |
| **ATA020** | T1020 Automated Exfiltration | **Exfiltration** | red + automatización | **G** | Sí (receptor local) | baja-media |
| **ATA021** | T1029 Scheduled Transfer | **Exfiltration** | **cron → FIM/watch** + red | **G** | Sí (cron de usuario, sin sudo) | media |
| **ATA022** | T1567.001 Exfil. to Code Repository | **Exfiltration** | `git` + red (repo **local**) | **G** | Sí (bare repo local en host) | media |
| **ATA023** | T1496.002 Bandwidth Hijacking | **Impact** | red (saturación acotada) | **G** | Sí (acotado al receptor) | **alta** |
| **ATA024** | T1531 Account Access Removal | **Impact (sabotaje)** | **auth/PAM/syslog + ficheros de cuentas** | **G** | Sí (usuario desechable, sudo) | media |
| **ATA025** | T1496.001 Compute Hijacking | **Impact** | CPU/`execve` | **G** | Sí (carga acotada) | **alta** |
| **ATA026** | T1565.002 Transmitted Data Manipulation | **Impact** | red/**manipulación en tránsito** | **G** | Sí (proxy local + receptor) | **alta** |
| **ATA027** | T1561.002 Disk Structure Wipe | **Impact** | destructivo local (sobre **imagen loop**) | **G** | Sí (**solo imagen desechable**) | alta |
| **ATA028** | T1056.003 Web Portal Capture | Collection/Cred-Access | red + file | **G** | Sí (portal local acotado) | media-alta |

**Cómputo por táctica:** **Impact 6** (T1657, T1496.002, T1531, T1496.001, T1565.002, T1561.002) ·
**Exfiltration 4** (T1048.001, T1020, T1029, T1567.001) · **Collection 5** (T1114, T1114.003,
T1213.006, T1056.001, T1056.003). **10/15** en R/E/S directo.

### 3.2 Por qué cada una y qué hay que escribir

**Impact / sabotaje**
- **ATA014 T1114 (Email Collection).** Paso clásico «collection→exfil» que toca **solo ficheros
  locales** (buzón simulado en `lab-legit`). Interés: ejercita **lectura** de un repositorio concreto
  (no búsqueda por el FS como T1119). *Escribir:* guion que (a) siembra un Maildir/mbox simulado,
  (b) lo lee/parsea (`cat`/`grep`/`awk`) y (c) copia los mensajes a `lab-attack`. Señales:
  `audit_exe` + `audit_cwd` + `ambigua` de `audit_file`/`syscheck_path` sobre `lab-legit`.
- **ATA015 T1114.003 (Email Forwarding Rule).** No roba: **crea una regla de reenvío** (persistencia)
  → **escritura de fichero** que el FIM/`watch` sí puede ver; mecanismo distinto de «leer».
  *Escribir:* guion que escribe `.forward`/`.procmailrc` (home o `lab-legit`) y demuestra el reenvío
  simulado. Cuidado con señales `ambigua` (no promoverlas a `deteccion`).
- **ATA016 T1213.006 (Databases).** Colección desde una **BD local** (`.db` sembrado en `lab-legit`):
  «repositorio de información» distinto del FS plano. *Escribir:* guion que exporta/consulta la BD
  (`sqlite3 .dump` si está; si no, copia del `.db` + `strings`/`grep`, o `python3` **declarando el
  punto ciego `92600`**). **Dependencia a confirmar en el paso 0.**
- **ATA017 T1657 (Financial Theft).** **Sabotaje/fraude**: modifica un **libro de cuentas local**
  (`lab-legit`) → **watch + FIM** de verdad; comprueba si Wazuh ve la **manipulación de contenido**
  financiero simulado. *Escribir:* guion que altera `ledger.csv` (añade una transferencia fraudulenta)
  y «sustrae» una cartera simulada; señales `audit_file`/`syscheck_path` + `audit_exe` anclado.
- **ATA024 T1531 (Account Access Removal).** Sabotaje de acceso: bloquear/eliminar una cuenta →
  toca **auth/PAM/syslog y ficheros de cuentas** (capa nueva). *Escribir:* guion que crea un usuario
  de laboratorio **desechable** y lo bloquea/elimina (`useradd`/`passwd -l`/`userdel`), **solo ese
  usuario** (guardarraíl: jamás `angel`, `root` ni cuentas reales). Requiere **`sudo`** (por stdin).
- **ATA025 T1496.001 (Compute Hijacking).** «Minería» simulada: **carga de CPU sostenida**; Wazuh
  **no tiene regla de recursos** → probable detección solo por `execve` (o **ninguna** si se hace con
  builtins). Dato honesto de punto ciego. *Escribir:* guion de carga **acotada** (`openssl speed`
  o `dd`/`yes` con `timeout`) + evidencia de la carga.
- **ATA023 T1496.002 (Bandwidth Hijacking).** Saturación **acotada** de ancho de banda hacia el
  receptor; igual que arriba, **la red no es visible** → probable no-detección. *Escribir:* guion con
  **límite de tiempo/bytes y abort**, evidencia por bytes registrados en `sink.log`.
- **ATA026 T1565.002 (Transmitted Data Manipulation).** Manipula el dato **en tránsito** (proxy local
  que reescribe el cuerpo antes del receptor) → el efecto es la **alteración**, no el robo;
  probablemente invisible al HIDS de host. *Escribir:* guion + **proxy** (socat/python) + soporte en
  el receptor; evidencia = el sink recibe **sha distinto** del enviado. **La de mayor dificultad.**
- **ATA027 T1561.002 (Disk Structure Wipe).** Borrado de **estructura** (tabla de particiones),
  mecanismo distinto de ATA005 (contenido). *Escribir:* guion que crea una **imagen loop**
  desechable, la formatea/monta y destruye su estructura (`wipefs`/`dd` sobre la **imagen**),
  demostrando que deja de ser montable. **Guardarraíl DURO: ruta bajo `lab-attack`; aborta si no.**
  **Nunca** el disco real.

**Exfiltration**
- **ATA019 T1048.001 (Symmetric Encrypted Non-C2).** Variante **simétrica** del canal alternativo
  (ATA008 fue asimétrica/`wget`+openssl): cifra con clave simétrica (`openssl enc`/`gpg -c`) y envía
  por TCP al receptor. *Escribir:* guion de cifrado + envío; puede requerir un **modo TCP** en el
  receptor (extender `sink_http.py` o un `nc -l` acotado). Documentar.
- **ATA020 T1020 (Automated Exfiltration).** El fenómeno es la **automatización** (recorre y envía
  «todo» sin intervención), no un fichero concreto. *Escribir:* guion que itera sobre los datos
  «recolectados» y los envía al receptor; mide `k/m` de acciones.
- **ATA021 T1029 (Scheduled Transfer).** **Programa** la transferencia (`crontab` de `angel`, sin
  sudo) → crea un artefacto de **persistencia de job** (fichero de cron, capa FIM/`watch`) además del
  envío. *Escribir:* guion que instala una entrada de cron que exfiltra; **diseñar el disparo para
  que caiga dentro de `[t0,t1]`** (o documentarlo). Evitar que dispare fuera de la ventana.
- **ATA022 T1567.001 (Exfil. to Code Repository).** Exfiltración por **`git push`** a un
  **repositorio de código** — mecanismo distinto (`git`). Sin NAT: **bare repo LOCAL** en el HOST
  como «code repo» simulado. *Escribir:* guion `git init/commit/push` a remoto local (VMnet1).
  **Guardarraíl: NUNCA a GitHub ni al repo del TFG; sin credenciales.**

**Collection / Credential Access**
- **ATA018 T1056.001 (Keylogging).** Captura de entrada de terminal = **captura de credenciales**;
  mecanismo «oculto» (logging de stdin/historial) → **sorpresa**. *Escribir:* guion **contenido**
  (wrapper que lanza un subshell registrando la entrada/comandos a un fichero en `lab-attack`);
  **sin** tocar PAM/auditd reales. **Alternativa ART** («Logging bash history to syslog»); decisión
  en ejecución. Ojo: si se usa `python3`, reproducir/declarar `92600`.
- **ATA028 T1056.003 (Web Portal Capture).** Captura de credenciales por un **portal web falso**
  servido localmente + cliente que envía → mezcla **red + fichero**. *Escribir:* guion que levanta
  un puerto de escucha acotado y registra el POST de credenciales **simuladas** (sin datos reales).
  Si el servidor es `python3` cae en el **punto ciego `92600`** (interesante, se declara); se puede
  evitar con `nc`/bash para no mimetizar el sesgo. **La más sensible al diseño** (ver riesgos).

> **Nota de trabajo:** **14 de las 15** se escriben a mano (guion propio). Solo **T1056.001** tiene
> pruebas Linux de ART directamente utilizables; se documenta si se adapta.

---

## 4. Reparto en 3 tandas y orden

**Criterio de orden:** (1) primero lo de **menor riesgo y setup compartido nulo**, para validar la
tubería en las capas nuevas; (2) después lo que **comparte receptor** (se paga el setup una vez por
ventana); (3) al final lo que requiere **`sudo`, sistema/destructivo-acotado o mayor dificultad**,
cuando el equipo ya lleva 2 tandas de rodaje. Dentro de cada tanda: **de lo más simple a lo más
complejo**.

### Tanda A — «Recolección local + integridad de ficheros» (sin receptor, sin sudo)
Foco: **`watch`/FIM**, acceso y escritura de ficheros (en `lab-legit` y `lab-attack`). Bajo riesgo.

| Orden | ATA | Técnica |
|---|---|---|
| A1 | **ATA014** | T1114 Email Collection |
| A2 | **ATA016** | T1213.006 Databases |
| A3 | **ATA015** | T1114.003 Email Forwarding Rule |
| A4 | **ATA017** | T1657 Financial Theft |
| A5 | **ATA018** | T1056.001 Keylogging |

### Tanda B — «Exfiltración y canal de red» (receptor compartido en el HOST, sin sudo)
Foco: **red** (receptor) + automatización/programación. El receptor se levanta **una vez por
ventana** (log por iteración) y se retira al cerrar la tanda.

| Orden | ATA | Técnica |
|---|---|---|
| B1 | **ATA019** | T1048.001 Symmetric Encrypted Non-C2 |
| B2 | **ATA020** | T1020 Automated Exfiltration |
| B3 | **ATA023** | T1496.002 Bandwidth Hijacking |
| B4 | **ATA021** | T1029 Scheduled Transfer |
| B5 | **ATA022** | T1567.001 Exfil. to Code Repository |

### Tanda C — «Sabotaje, sistema y casos límite» (puede requerir sudo; destructivo-acotado; mayor dificultad)
Foco: **auth/PAM, manipulación en tránsito, recursos, estructura de disco**. Máxima intensidad de
guardarraíles.

| Orden | ATA | Técnica |
|---|---|---|
| C1 | **ATA024** | T1531 Account Access Removal |
| C2 | **ATA025** | T1496.001 Compute Hijacking |
| C3 | **ATA028** | T1056.003 Web Portal Capture |
| C4 | **ATA026** | T1565.002 Transmitted Data Manipulation |
| C5 | **ATA027** | T1561.002 Disk Structure Wipe |

> **Por qué este orden global:** A valida las capas de **fichero/FIM** sin dependencias; B aísla el
> **único setup compartido** (receptor) en un tramo y prueba las variantes de red; C deja para el
> final lo que exige **privilegios, proxies y material destructivo desechable**, donde cualquier
> sorpresa cuesta menos porque la tubería ya está rodada.

---

## 5. Operativa por tanda (reutiliza el ciclo probado)

Se reutiliza **exactamente** `Soporte/Ataques/piloto_procedimiento.md` (12 pasos) y la plantilla
`Soporte/Ataques/plantilla_esperado.md` **v4**. **Por técnica** (`ATA<NNN>`), **2 iteraciones**:

```text
esperado (firmado/validado ANTES)  →  C0 en el manager (logtest + preflight base-contra-base)
  →  snapshot lab-listo  →  t0 (UTC, tras asentamiento)  →  ataque  →  t1
    →  extraer del FICHERO DIARIO [t0,t1] (UTC)  →  filtrar (filtrar_ruido.py, modo ataque)
      →  revisar dudosa  →  plegar  →  ficha + bitácora + ATA_index.csv
        →  repetir (iter2)  →  criterio doble iteración v2
```

- **`esperado` primero.** Cada `ATA<NNN>_esperado.csv` se redacta **antes** de atacar, con la
  convención **H4** (`audit_exe` **+** `audit_cwd` de la carpeta) y las señales de **contexto**
  (`audit_file`/`audit_dir`/`syscheck_path`) cuando la técnica toque rutas vigiladas.
- **C0 por técnica.** Antes del primer `t0`, chequeo **base-contra-base** (`wazuh-logtest`) para
  descubrir **silenciadores de fábrica** (como `92600` con `python3`). Si aparece uno, **se
  documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
  propias (D5 del bloque anterior).
- **Receptor (solo tanda B y C3/C4).** `Soporte/Ataques/receiver/sink_http.py` en el HOST
  (`192.168.65.1:9090`), log por iteración; extender con un **modo TCP** si ATA019/ATA026 lo piden.
  Regla de firewall acotada y **retirada** al cerrar.
- **Aislamiento por agente** (solo `victima-linux` en los conteos), **fichero diario** (no
  `alerts.json`), **UTC**.

### Guardarraíles (invariantes, de siempre)

1. **Nada destructivo al sistema real ni a servicios reales.** Todo el material vive en
   `lab-attack`/`lab-legit` (juguete). **T1561.002 solo sobre imagen loop**; **T1531 solo sobre un
   usuario desechable**; **T1496.00x acotadas** con límite y abort.
2. **Sin NAT.** El «servicio»/«webhook»/«code repo»/«fontanería de red» son **locales** (host).
3. **`sudo` solo cuando la técnica lo exige** (T1531), con la contraseña por **stdin** (`sudo -S`),
   **nunca** interactivo (lección del incidente de ATA011).
4. **Guardarraíles en el guion:** aborta si una ruta sale de `lab-attack`, si toca una cuenta/servicio
   real, o si el remoto de `git` no es el local (ATA022).
5. **Receptor + regla de firewall retirados** al cerrar cada tanda; **snapshot `lab-listo`** entre
   ventanas; **el manager NO se revierte**.
6. **Higiene de secretos** (repo **público**): cero credenciales en ficheros del repo.

Convivencia de capas: las técnicas que escriben **fuera de `lab-attack`** (Tanda A, cron, cuentas)
generan filas `ambigua`/fuera de `ATTACK_ROOT` → se resuelven por **señal declarada** o **veredicto
humano `artefacto`**; **nunca** `ruido` (guardarraíl `exit 4`).

---

## 6. Verificación (`tfg-tester`) y criterios de aceptación

### 6.1 Qué comprueba el `tfg-tester` **por tanda**

| # | Comprobación |
|---|---|
| TV1 | **Métrica congelada** aplicada sin cambios: **O1** (`detectado SÍ/NO` + `rule_id` + 1ª evidencia) y **O2** (`k/m`); nº bruto y `rule_id` distintos solo como **anexo**. |
| TV2 | **0 filas del ataque en `ruido`/`auto_ruido`** en las ventanas de la tanda (guardarraíl). |
| TV3 | **`dudosa = 0`** tras la revisión humana de cada ventana. |
| TV4 | **Doble iteración v2 `iguales`** (mismo conjunto de `rule_id` de `deteccion`, recuento estable, sin dudosa) — o `review` **justificado**. |
| TV5 | **C0** por técnica (base-contra-base) documentado; sin silenciadores nuevos, o **documentados**. |
| TV6 | **Determinismo:** re-filtrar produce **mismo `sha256`**; **`pytest` verde** (93 + los que añada este bloque, si los hay). |
| TV7 | **Regresión: las 26 ventanas previas byte a byte** (mensaje/`sha256`), pilotos intactos. |
| TV8 | **Cadena de huellas** coherente: `esperado` ↔ `ataque.sh` ↔ `-Audited`/`-Revision` ↔ bitácora ↔ ficha. |
| TV9 | **Laboratorio cerrado** (receptor parado, firewall retirado, VMs apagadas, **NAT off**) — declarado. |
| TV10 | Sin secretos; **sin commit/push**; `filtrar_ruido.py`/política/métrica, `_recursos/`, `Reglas/`, `BBDD/`, `xlsx` **intactos**. |

### 6.2 Criterios de aceptación del bloque

- **CA-B1** — **15 técnicas × 2 iteraciones = 30 ventanas** ejecutadas con `esperado` validado
  **antes** del primer `t0`.
- **CA-B2** — **15/15** con veredicto **O1** reportado (incluidos los **NO** detectados, sin sesgo).
- **CA-B3** — **0 filas del ataque en `ruido`/`auto_ruido`** (30 ventanas).
- **CA-B4** — **`dudosa = 0`** (o veredicto humano por fila, trazable).
- **CA-B5** — **Doble iteración v2** `iguales` (o `review` justificado) en las 15.
- **CA-B6** — **Métrica y filtro intactos** (hash de `filtrar_ruido.py` y política sin cambios).
- **CA-B7** — **Regresión** de las 26 ventanas previas **byte a byte**; **`pytest` verde**.
- **CA-B8** — **Cadena de huellas** coherente; fichas + bitácoras + `Hojas/ATA_index.csv` al día.
- **CA-B9** — **Laboratorio cerrado** y sin residuos; **NAT off**.
- **CA-B10** — Sin secretos, sin `push`; `_recursos/`, `Reglas/`, `BBDD/`, `xlsx` intactos.
- **CA-B11 (valor)** — **≥1 hallazgo documentado** (punto ciego nuevo, o capa no cubierta) — el
  bloque debe poder decir **algo** además de «detectado/no detectado».

---

## 7. Ficheros que se tocarán

| Ruta | Cambio |
|---|---|
| `Dataset/Ataques/Comandos/<TEC>-<DESC>/` (×15) | `ATA<NNN>_ataque.sh` + `ATA<NNN>_esperado.csv` + `README.md` |
| `Soporte/Ataques/c0/ATA<NNN>_{c0_plan.md,logtest.txt,preflight.md}` (×15) | C0 base-contra-base |
| `Dataset/Ataques/Resultados/Wazuh/linux/CSV/…` | `ATA<NNN>_iterN-Detalle.csv` (+ `_raw`) — 30 |
| `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/…` | `-Audited.csv` (+ `-Revision.csv`) — 30 |
| `Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA<NNN>_iterN/` | evidencia (`times.log`, `ejecucion.out`, `sink.log`…) |
| `Dataset/Ataques/Resultados/Wazuh/linux/ATA<NNN>_meta.md` (×15) | ficha (métrica O1+O2) |
| `Bitacora/ATA<NNN>.json` (×15) | bitácora append-only |
| `Hojas/ATA_index.csv` | **+15 filas** (`ATA014`…`ATA028`) |
| `Soporte/Ataques/receiver/` | **modo TCP** (si ATA019/ATA026 lo piden) + nota |
| `Soporte/Ataques/piloto_procedimiento.md` | notas de la ampliación (si procede) |

**Intactos:** `_artefactos/scripts/filtrar_ruido.py` y su política, la métrica, los `esperado` ya
firmados, las 26 ventanas previas, `Soporte/Ataques/plantilla_esperado.md` (salvo nota), `_recursos/`,
`Reglas/**`, `BBDD/`, `Detecciones.xlsx`.

---

## 8. Riesgos y mitigación

| # | Riesgo | Mitigación |
|---|---|---|
| R1 | **Dependencia ausente** sin NAT (`sqlite3`, `socat`, `nc`, `wipefs`, `git`) | Verificar en el **paso 0**; preferir coreutils/openssl/curl/wget/git; **fallback stdlib**; si es imprescindible, decidir con el humano (NAT temporal + snapshot, declarado). |
| R2 | **Punto ciego `python3` (`92600`)** mimetiza una no-detección | No basar la detección en `python3`; si una técnica lo necesita (ATA016/ATA028), **declararlo** como en ATA013. |
| R3 | **Escritura fuera de `lab-attack`** (lab-legit, cron, cuentas, home) → `ambigua`/pertenencia | Declarar señales de contexto; revisar `dudosa`; veredicto `artefacto`; **nunca** `ruido` (`exit 4`). |
| R4 | **`sudo` interactivo rompe la ventana** (incidente ATA011) | `sudo -S` por **stdin**; comprobar exit codes; pre-staging; auditar el árbol antes de reintentar. |
| R5 | **Técnicas destructivas/de cuentas/recursos** (ATA027/ATA024/ATA025/ATA023) | Guardarraíles **duros** (solo imagen loop / usuario desechable / límite y abort); snapshot. |
| R6 | **`git push` accidental** al repo del TFG o a GitHub (ATA022) | Remoto **local** obligatorio; guardarraíl que **aborta** si el remoto no es el local; sin credenciales. |
| R7 | **Cron dispara fuera de `[t0,t1]`** (ATA021) | Diseñar el disparo dentro de la ventana; si no, documentar y repetir. |
| R8 | **Sobrecarga de red/CPU** (ATA023/ATA025) afecta a la VM/host | Límite de tiempo/bytes/umbral y **abort**; ventanas cortas. |
| R9 | **Muchas técnicas solo detectables por `execve`** (poca discriminación) | Aceptarlo y **reportarlo como hallazgo** (el HIDS de host no ve la red); ya se diversifican mecanismos. |
| R10 | **Volumen de escritura** (15 guiones) → tiempo | KISS; reutilizar plantillas/plantilla H4; **3 tandas separables** en sesiones. |
| R11 | **Fallo de reporte del ejecutor** (HTTP 400) dejando trabajo hecho | **Auditar el árbol antes de reintentar** (lección registrada). |
| R12 | **`autocrlf`/git reescribe bytes** y rompe hashes | No `checkout`/`stash`/`reset`; si git toca bytes, **recalcular huellas** afectadas. |
| R13 | **ATA028 (portal web) sensible al diseño** (¿portal falso? ¿handler?) | Definir en el paso 0; enfoque acotado (listener + cliente simulado); fallback a **T1667 Email Bombing** o **T1567.004 Webhook** si no es viable. |

---

## 9. Qué NO entra (fuera de alcance)

- **Windows** (ni como víctima ni como pruebas). Nada.
- **Bloque de evasión** (repetición de técnicas en **versión disfrazada**): **queda para el futuro**,
  cuando esté cubierta la cobertura P1. No en este bloque.
- **Cambiar la métrica** (está **congelada**, `fase-03-metrica`) ni **rediseñar el filtro**.
- **Fase 4** («precio de la detección», robustez/rendimiento η).
- **DoS puro y reinicio**: T1498/.001/.002, T1499/.001–.004, T1529 — **fuera** (disruptivos y off
  R/E/S).
- **No factibles headless**: T1113 Screen Capture, T1123 Audio, T1125 Video, T1115 Clipboard,
  T1025/T1052.001 USB.
- **No factibles sin NAT/cloud**: T1567.002/.003, T1213 (SaaS), T1537, T1530, T1485.001, T1491.002
  (y los webhooks reales de T1567.004) → se **declaran**, no se ejecutan.
- **Alto riesgo/complejidad, diferidas**: T1495 Firmware, T1557/.003 (MITM/DHCP), T1561.001 (contenido,
  ya cubierto por ATA005), T1565.001/.003 (at-rest/runtime), T1048.003 (una 2ª variante T1048).
- **Reescritura de `esperado`** ya firmados y **recálculo de los pilotos** (histórico).

---

## 10. Gate y validación

- **Validación (2026-09-29):** el plan y los **`esperado`** cuentan con **validación humana registrada**,
  con **revisión posterior** (`change-doc` + fichas + tabla).
- **Sin `status: approved_by_human`**, **ni `tfg-executor` ni ningún otro** ejecuta.
- **`push`:** los commits son **locales**; publicar es del humano.

---

## 11. Pasos del bloque (resumen ejecutable)

1. **Gate:** **validación humana registrada** del plan y de los `esperado` de la **tanda A** → `approved`.
2. **Tanda A** (ATA014–ATA018): C0 → 2 iteraciones × 5 → filtrar/revisar/plegar → fichas/bitácora →
   `tfg-tester` (TV1–TV10) → cierre de tanda.
3. **Tanda B** (ATA019–ATA023): idem, con **receptor** en el HOST y su retirada al cerrar.
4. **Tanda C** (ATA024–ATA028): idem, con **sudo** (ATA024), **proxy** (ATA026) y **destructivo sobre
   imagen loop** (ATA027).
5. **Cierre del bloque:** `change-doc.md` (`fase-03-ampliacion`), `state.md`, `roadmap.md`,
   `Hojas/ATA_index.csv`, y **gate final** con el humano.
