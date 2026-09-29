---
fase: 3
bloque: fase-03-ampliacion-2
nombre: Ampliación del corpus (ronda 2) — 15 técnicas Linux nuevas en 3 tandas de 5 (sin NAT)
version: 1
status: approved_by_human
fecha: 2026-09-29
fecha_aprobacion: 2026-09-29
aprobado_por: humano
autor: tfg-planner
delegacion: "**Validación humana registrada** (2026-09-29), con **revisión posterior** de las decisiones y de los resultados. Ejecución orquestada por tandas (A → B → C)."
---

# Plan — Ampliación del corpus (Fase 3, ronda 2): 15 técnicas Linux nuevas en 3 tandas de 5

> **Tercera ronda de ampliación.** Reutiliza **tal cual** la tubería probada
> (`Soporte/Ataques/piloto_procedimiento.md`), la **métrica congelada** (`fase-03-metrica`), el
> **filtro** (`filtrar_ruido.py`) y el **criterio de doble iteración v2**. **No se rediseña nada del
> mecanismo de medida**: solo se añaden técnicas nuevas con su `esperado`, su C0, sus 2 ventanas y su
> ficha/bitácora.
>
> **Alcance: SOLO Linux.** Windows no entra. **Sin NAT.** **Sin evasión.**

---

## 0. Resumen ejecutivo

- **Corpus actual:** **28 técnicas** (`ATA001`–`ATA028`), **56 ventanas** → **27 DETECTADAS / 1 NO**
  (`ATA013/T1560.002`, punto ciego de fábrica `92600`).
- **Objetivo del bloque:** **15 técnicas Linux nuevas × 2 iteraciones = 30 ventanas** (nuevas serán
  `ATA029`–`ATA043`), en **3 tandas de 5**, con **la métrica y el filtro intactos**.
- **Estructura:** **1 bloque (`fase-03-ampliacion-2`), 3 tandas**; la validación humana, en **3 ratos**
  (uno por tanda), no en 15.
- **Resultado esperado (honesto):** reparto mixto; se incluyen a propósito técnicas con probabilidad
  real de **no detección** (recursos, manipulación en memoria/tránsito, archivo por método propio) para
  **no sesgar** el resultado hacia «todo detectado por `execve`». El valor del bloque es el **hallazgo**,
  no el «15/15».

---

## 1. Objetivo y hechos verificados (paso 0, solo lectura)

### 1.1 Objetivo

Ejecutar **15 técnicas nuevas** de la piscina **P1 host-eligible que citan Linux** (que **no** estén entre
las 28 ya cerradas), cada una × 2 iteraciones, con el runbook probado, para seguir cerrando la cobertura
P1 en Linux **sin tocar la métrica ni el filtro**.

### 1.2 Hechos verificados hoy (inspección de solo lectura)

- **Hechas:** 28 técnicas (`Hojas/ATA_index.csv`, 28 filas; `cerrado`/`review`). **No se repiten.**
- **Piscina (verificada en `Hojas/corpus_host.csv`):** **72** técnicas **P1 · host-eligible · citan
  Linux**; **44** restantes tras restar las 28 hechas. *(La cifra «~58/~30» del encargo/roadmap es la
  cuenta anterior a esta ronda; el recuento exacto hoy es **72 / 44**.)*
- **Las 44 restantes son todas de Collection/Exfiltration/Impact** (no hay P1 Linux en
  Stealth/Persistence/PrivEsc: aquellas son **P2**). De ellas, **~16 son factibles con capa distinta**
  y el resto son **no factibles o duplicados de mecanismo** (ver §9).
- **Cobertura ART (Linux):** de las elegidas, tienen pruebas Linux adaptables **T1005, T1048.002,
  T1048.003, T1529, T1560.001, T1567.004** (6/15). El resto (**9/15) se escriben a mano**.
- **Capas del HIDS disponibles:** `execve` (`audit_command`/`80792`), `watch`/audit-file
  (`audit_file`/`audit_dir`/`audit_key`), FIM/syscheck (`syscheck_path`), syslog/journald
  (`40700` es `level=0` — ojo), PAM/auth (`5501`/`5502`, `5715`, `5402`) y **red** (solo el receptor;
  **invisible** al HIDS). **No hay reglas de red ni de recursos** (hallazgo R9, confirmado).

### 1.3 Lecciones incorporadas (obligatorias en esta ronda)

1. **`audit_exe` con el NOMBRE REAL del binario o con glob.** `audit` registra el binario resuelto:
   `nc` → `/usr/bin/nc.openbsd`, `mkfs.ext4` → `/usr/sbin/mke2fs`. Un patrón por nombre de orden
   **no casa** → la fila baja a `artefacto` en vez de `deteccion`. **Regla:** declarar el binario
   **real** (o glob `*nc.openbsd`, `*mke2fs`) verificado **en el paso 0** de cada técnica.
2. **Evitar `ambigua` por `rule_group` amplios.** Los grupos anchos capturan *churn* ajeno y degradan
   la fila. Declarar por `rule_id` concreto o por `audit_exe` anclado.
3. **El ataque vive en `/home/angel/lab-attack/ATA<NNN>/`; el efecto declarado, en `lab-legit`.**
   Todo lo que el ataque **escriba** va bajo `lab-attack` (pertenencia automática → `artefacto_ataque`,
   **nunca `ruido`**); lo que **simule el activo legítimo** (ficheros a robar/manipular/deface) vive en
   `lab-legit`.
4. **Punto ciego `92600` (`python3`).** La regla de fábrica suprime el `execve` **y** el `watch` de
   `python3`. **No basar la detección en `python3`**; si una técnica lo necesita, **declararlo** (como
   ATA013) y ofrecer un camino alternativo con `nc`/`bash`/coreutils.
5. **Leer no deja rastro.** `auditd -p wa` (escritura/atributos) → **leer** un fichero **no** alerta.
   Las técnicas de «recolección por lectura» se detectan por el **`execve` del lector**, no por el acceso.

---

## 2. Criterios de selección (explícitos; ante empate decide el criterio anterior)

1. **Táctica con foco R/E/S.** Se prioriza **Impact** y **Exfiltration**; **Collection** entra como
   apoyo (paso previo del «robo → exfiltración»).
2. **Diversidad REAL de capas del HIDS.** Cada técnica debe **añadir** al menos una capa distinta de
   `execve`: (a) `watch`/audit-file, (b) FIM/syscheck, (c) syslog/journald/PAM-auth, (d) red
   (receptor/share). **Regla dura:** no se admiten dos técnicas cuyo único mecanismo nuevo sea
   «otro `execve`»; se evita repetir «otro `curl` al receptor».
3. **Factibilidad offline (bloqueante).** Linux, **sin NAT**, sin tocar servicios ni cuentas reales;
   herramientas **presentes** o con **fallback** (stdlib/coreutils/openssl/curl/wget/git);
   **efecto demostrable por evidencia** (sha256 / `k/m` / estado antes-después).
4. **Dificultad/sorpresa (valor científico).** Se incluyen a propósito casos con **probabilidad real
   de NO detección** o de detección **indirecta** (recursos, manipulación de memoria/en tránsito,
   archivo por método propio, reinicio) → permiten **reportar un hallazgo**, no solo «detectado».
5. **Coste de escritura (KISS).** Se prefieren mecanismos reproducibles con lo que ya hay; el
   **guion propio es la norma**; cuando una atómica de ART sea adaptable, **se documenta** y se usa.
6. **Continuidad metodológica.** Se mantiene el patrón ya aplicado de cubrir **padre + subtecnica**
   como nodos ATT&CK **distintos** (p. ej. `T1561.001` tras `T1561`; `T1565.001/.003` tras `T1565`),
   declarando la relación y el posible solapamiento de mecanismo.

---

## 3. Las 15 elegidas

> **Leyenda.** *Capa que añade* = capa del HIDS **distinta** del `execve`. *Vía*: **G** = guion propio ·
> **ART** = atómica Linux adaptada. *Factible s/NAT* = sí/no y por qué.

### 3.1 Tabla resumen

| ATA | Técnica (ATT&CK) | Táctica | Capa que añade | Vía | Factible s/NAT | Sorpresa |
|---|---|---|---|---|---|---|
| **ATA029** | T1005 Data from Local System | Collection | `watch`/file-access (lectura selectiva) | **ART** (adaptable) | Sí (datos simulados en `lab-legit`) | baja |
| **ATA030** | T1560.001 Archive via Utility | Collection | `execve` **utility** (`tar`/`zip`) + FIM | **ART** (adaptable) | Sí (sin red) | baja-media |
| **ATA031** | T1667 Email Bombing | Impact | **file-creation masiva** (FIM/`watch`) + syslog | **G** | Sí (buzón local simulado) | media |
| **ATA032** | T1565.001 Stored Data Manipulation | Impact | **FIM/watch de contenido** en reposo | **G** | Sí (activo simulado en `lab-legit`) | media |
| **ATA033** | T1491.001 Internal Defacement | Impact | **FIM/watch** sobre raíz web local | **G** | Sí (web simulada local) | media |
| **ATA034** | T1560.003 Archive via Custom Method | Collection | `execve` método propio (¿punto ciego?) | **G** | Sí (sin red) | **alta** |
| **ATA035** | T1056.004 Credential API Hooking | Collection / Cred-Access | **module-load / process** (`LD_PRELOAD`) | **G** | Sí (binario de laboratorio) | **alta** |
| **ATA036** | T1565.003 Runtime Data Manipulation | Impact | **process/memory** (`ptrace`/`/proc/<pid>/mem`) | **G** | Sí (proceso de laboratorio) | **alta** |
| **ATA037** | T1561.001 Disk Content Wipe | Impact | destructivo local (sobre **imagen loop**) | **G** | Sí (**solo imagen desechable**) | alta |
| **ATA038** | T1529 System Shutdown/Reboot | Impact | syslog/journald + ciclo de arranque | **ART** (adaptable) | Sí (reinicio de la **VM víctima**) | alta |
| **ATA039** | T1039 Data from Network Shared Drive | Collection | **network-share** (NFS/SMB local) | **G** | Sí (export local en VMnet1) | media |
| **ATA040** | T1074.002 Remote Data Staging | Collection | **red** (staging a host/recurso) | **G** | Sí (destino local en VMnet1) | media |
| **ATA041** | T1048.002 Asymmetric Encrypted Non-C2 | Exfiltration | red + **cifrado asimétrico** | **ART** (adaptable) | Sí (receptor local) | media |
| **ATA042** | T1048.003 Unencrypted Non-C2 | Exfiltration | red (**texto claro**) | **ART** (adaptable) | Sí (receptor local) | baja |
| **ATA043** | T1567.004 Exfiltration Over Webhook | Exfiltration | red (endpoint **webhook**) | **ART** (adaptable) | Sí (webhook local) | media |

**Cómputo por táctica:** **Impact 6** (T1667, T1565.001, T1491.001, T1565.003, T1561.001, T1529) ·
**Exfiltration 3** (T1048.002, T1048.003, T1567.004) · **Collection 6** (T1005, T1560.001, T1560.003,
T1056.004, T1039, T1074.002). **9/15 en R/E/S directo.** **15/15 factibles sin NAT.**

### 3.2 Por qué cada una y qué hay que escribir

**Impact / sabotaje (6)**

- **ATA029 · T1005 (Data from Local System).** Recolección **dirigida** de ficheros locales concretos
  (no búsqueda exhaustiva como T1119). Interés: prueba la detección por el **`execve` del lector** y
  **confirma la lección «leer no deja rastro»** (`-p wa`). *Escribir:* guion que siembra datos en
  `lab-legit` y los lee/copia a `lab-attack`. **ART** tiene atómicas Linux adaptables
  («Copy/Move files», `grep` sobre local system). Señales: `audit_exe` **real** del lector + `audit_cwd`.
- **ATA030 · T1560.001 (Archive via Utility).** **Contraste científico con ATA013** (`T1560.002`
  library/`python3`, **NO detectado por `92600`**): el **mismo objetivo** («archivar lo recolectado»)
  hecho con **utilidad de línea de órdenes** (`tar`/`zip`/`gzip` vía `tar`) **sí** deja `execve`.
  *Escribir:* guion `tar`/`gzip` sobre el material recolectado. **ART** tiene 5 pruebas Linux.
  Señales: `audit_exe` del binario real (`/usr/bin/tar`).
- **ATA031 · T1667 (Email Bombing).** Saturación de un **buzón local** por volumen de mensajes
  → **creación masiva de ficheros** (FIM/`watch`) + posible syslog del MTA local. Distinto de
  ATA014 (leer buzón) y ATA015 (regla de reenvío): aquí el mecanismo es el **volumen**. *Escribir:*
  guion que genera **N mensajes acotados** en un Maildir simulado de `lab-legit` y demuestra el
  crecimiento. **Sin ART** → guion propio. Señales: `audit_exe` + `syscheck_path`/`audit_dir`.
- **ATA032 · T1565.001 (Stored Data Manipulation).** Manipula datos **en reposo** (fichero/ledger),
  **no** en tránsito (ATA026/T1565.002) → **FIM/watch de contenido**. *Escribir:* guion que altera un
  registro simulado en `lab-legit` y deja **sha256 antes ≠ después**. **Sin ART**. Señales:
  `audit_file`/`syscheck_path` + `audit_exe` anclado (ojo con el `sed -i` de ATA006: aquí el objeto es
  un activo concreto, no un fichero arbitrario).
- **ATA033 · T1491.001 (Internal Defacement).** **Modifica la raíz web local** (contenido servido),
  distinto de ATA007 (defacement genérico con `cp`): el objeto y la capa (FIM sobre el **webroot**) son
  nuevos. *Escribir:* guion que reescribe `index.html` (u homólogo) en el webroot simulado y demuestra
  el cambio. **Sin ART** (las atómicas son Windows). Señales: `syscheck_path`/`audit_file` + `audit_exe`.
- **ATA036 · T1565.003 (Runtime Data Manipulation).** Manipula datos **de un proceso en ejecución**
  (argumentos/entorno/memoria vía `ptrace`, `gdb` o `/proc/<pid>/mem`) → capa **process/memory**,
  habitualmente **poco cubierta**. *Escribir:* guion que lanza un proceso de laboratorio inocuo y le
  altera un dato en memoria, con **evidencia antes/después**. **Sin ART**. Señales: `audit_exe` +
  `audit_command`; **probable punto ciego** → declararlo. **Una de las de mayor dificultad.**
- **ATA037 · T1561.001 (Disk Content Wipe).** **Contenido** (a diferencia de ATA027/T1561.002, que
  destruyó la **estructura**): sobrescribe el contenido de una **imagen loop desechable** y demuestra
  que el contenido cambia sin dañar la estructura. *Escribir:* guion `dd`/`shred` **solo sobre la
  imagen loop** creada en `lab-attack`. **Sin ART**. **Guardarraíl DURO: ruta bajo `lab-attack`;
  aborta si no; jamás el disco real.**
- **ATA038 · T1529 (System Shutdown/Reboot).** Único caso **disruptivo-acotado**: reinicia la **VM
  víctima** (desechable, restaurable por snapshot) → probar si Wazuh ve el **cierre/arranque**
  (syslog/journald, `Host Status`). *Escribir:* guion de **reinicio programado** de la víctima tras
  sellar `t0`; la **restauración** la hace el operador (snapshot `lab-listo`). **ART** tiene ~10
  pruebas (Windows/Linux). Señales: `audit_exe` (`shutdown`/`systemctl`) + journald
  (**cuidado: `40700` es `level=0`**). **La de mayor precaución; ver §5/§8.**

**Collection / Credential Access (6)**

- **ATA029** ya tratada arriba (T1005).
- **ATA034 · T1560.003 (Archive via Custom Method).** Archiva con **método propio** (p. ej. encoder
  `base64`/XOR/concatenación con coreutils), **sin** utilidad estándar → **probable no detección** si
  se hace con *builtins*. Es el **tercer vértice** del trío de archivo (utility / library / custom) y
  el de mayor valor de «punto ciego». *Escribir:* guion de archivado propio con evidencia de
  reconstrucción. **Sin ART**. Señales: `audit_exe` (si usa binario) o declarar el punto ciego.
- **ATA035 · T1056.004 (Credential API Hooking).** Hook de API por **`LD_PRELOAD`** sobre un binario de
  laboratorio para **capturar credenciales simuladas** → capa **module-load / process**. Distinto de
  ATA018 (keylogging) y ATA028 (portal). *Escribir:* un `.so` trivial (o `ltrace`/`strace` como
  fallback) + guion; **sin PAM/auditd reales**. **Sin ART** (atómicas Windows). Señales: `audit_exe` +
  `audit_file` del `.so` en `lab-attack`. **Dependencia:** compilador (`gcc`) — verificar en paso 0.
- **ATA039 · T1039 (Data from Network Shared Drive).** Recolecta desde un **recurso compartido
  local** (export NFS/SMB en **VMnet1**), no desde el FS local → capa **network-share**.
  *Escribir:* preparar el **export local** (en el host o la víctima) + guion que monta/lee y copia a
  `lab-attack`. **Sin ART Linux**. Señales: `audit_exe` del cliente (`mount`/`cp`) + ruta del share.
- **ATA040 · T1074.002 (Remote Data Staging).** **Staging remoto**: mueve lo recolectado a un
  destino **remoto local** (host/recurso en VMnet1) en vez de dejarlo local (ATA011/T1074.001).
  *Escribir:* guion que copia el material al destino local (share/SSH/receptor) y demuestra la llegada
  por **sha256**. **Sin ART** (no existe la carpeta). Señales: `audit_exe` + red (receptor).
- **ATA030/ATA034** ya tratadas arriba (T1560.001 / T1560.003).

**Exfiltration (3)**

- **ATA041 · T1048.002 (Asymmetric Encrypted Non-C2).** Exfiltración por canal alternativo con
  **cifrado asimétrico** (`gpg`/`openssl rsautl`) — **distinto** del simétrico de ATA019
  (T1048.001). *Escribir:* par de claves **efímero** en `lab-attack` + cifrado + envío por TCP al
  receptor. **ART** tiene 3 pruebas Linux. Prueba: `sink.log` con sha del **blob cifrado**; round-trip
  == original. **Guardarraíl:** claves **desechables**, cero credenciales de repo.
- **ATA042 · T1048.003 (Unencrypted Non-C2).** El mismo canal **en claro** (FTP/HTTP plano/`nc`),
  para **comparar** con ATA008/ATA019/ATA041 la influencia del cifrado en la detección (que es
  **solo del proceso**, no del contenido). *Escribir:* guion de envío en claro al receptor. **ART** 3
  pruebas Linux. **Guardarraíl:** dato de juguete; no repetir endpoint de ATA019.
- **ATA043 · T1567.004 (Exfiltration Over Webhook).** Publica el dato a un **endpoint webhook**
  local (`POST /hook`) — mecanismo de servicio web distinto de ATA009 (`/api/upload`) y ATA010
  (`/c2/beacon`). *Escribir:* guion de `POST` JSON al receptor + extensión mínima del receptor para
  `/hook`. **ART** 2 pruebas Linux. Prueba: `sink.log` con sha idéntico. **Guardarraíl: webhook
  LOCAL** (nunca servicios reales/cloud).

---

## 4. Reparto en 3 tandas y orden

**Criterio de orden:** (1) primero lo **de menor riesgo y sin setup de red**, para validar la tubería en
las capas nuevas de **fichero/FIM**; (2) después lo de **proceso/memoria y sistema** (requiere
construir/utilizar artefactos y el **reinicio de la VM**), **sin receptor**; (3) al final lo de **red**,
que **comparte un único setup** (receptor + recurso compartido local), pagado una vez por ventana.
Dentro de cada tanda: **de lo más simple a lo más complejo**.

### Tanda A — «Recolección e integridad de ficheros» (sin receptor, sin sudo)
Foco: `watch`/FIM, lectura selectiva y manipulación/defacement de contenido local. Bajo riesgo.

| Orden | ATA | Técnica |
|---|---|---|
| A1 | **ATA029** | T1005 Data from Local System |
| A2 | **ATA030** | T1560.001 Archive via Utility |
| A3 | **ATA031** | T1667 Email Bombing |
| A4 | **ATA032** | T1565.001 Stored Data Manipulation |
| A5 | **ATA033** | T1491.001 Internal Defacement |

### Tanda B — «Proceso, memoria y sistema» (sin receptor; material propio; reinicio al final)
Foco: `execve` de método propio, `LD_PRELOAD`, memoria de proceso, imagen loop y **reinicio**.
Máxima precaución en los dos últimos.

| Orden | ATA | Técnica |
|---|---|---|
| B1 | **ATA034** | T1560.003 Archive via Custom Method |
| B2 | **ATA035** | T1056.004 Credential API Hooking |
| B3 | **ATA036** | T1565.003 Runtime Data Manipulation |
| B4 | **ATA037** | T1561.001 Disk Content Wipe |
| B5 | **ATA038** | T1529 System Shutdown/Reboot |

### Tanda C — «Red: almacenamiento y exfiltración» (receptor + recurso compartido compartidos)
Foco: **capa de red** con un **único setup** (receptor `sink_http.py` + export local). El receptor se
levanta **una vez por ventana** (log por iteración) y se retira al cerrar la tanda.

| Orden | ATA | Técnica |
|---|---|---|
| C1 | **ATA039** | T1039 Data from Network Shared Drive |
| C2 | **ATA040** | T1074.002 Remote Data Staging |
| C3 | **ATA041** | T1048.002 Asymmetric Encrypted Non-C2 |
| C4 | **ATA042** | T1048.003 Unencrypted Non-C2 |
| C5 | **ATA043** | T1567.004 Exfiltration Over Webhook |

> **Por qué este orden global:** A valida las capas de **fichero/FIM** con coste mínimo; B aísla el
> **material específico** (`.so`, memoria, imagen loop) y deja el **reinicio** al final de un tramo ya
> rodado; C concentra el **setup de red** en un tramo, pagándolo una sola vez y comparando variantes de
> cifrado/endpoint **sobre el mismo receptor**.

---

## 5. Operativa por tanda y guardarraíles

### 5.1 Ciclo por técnica (reutiliza el runbook probado)

Se reutiliza **exactamente** `Soporte/Ataques/piloto_procedimiento.md` (12 pasos) y la plantilla
`Soporte/Ataques/plantilla_esperado.md`. **Por técnica** (`ATA<NNN>`), **2 iteraciones**:

```text
esperado (firmado/validado ANTES)  →  C0 en el manager (logtest + preflight base-contra-base)
  →  snapshot lab-listo  →  t0 (UTC, tras asentamiento ≥60-90 s)  →  ataque  →  t1
    →  extraer del FICHERO DIARIO [t0,t1] (UTC) por AGENTE  →  filtrar (filtrar_ruido.py, modo ataque)
      →  revisar dudosa  →  plegar  →  ficha + bitácora + ATA_index.csv
        →  repetir (iter2)  →  criterio doble iteración v2
```

- **`esperado` primero.** Cada `ATA<NNN>_esperado.csv` se redacta **antes** de atacar, con la
  convención **H4** (`audit_exe` **+** `audit_cwd` de la carpeta) y las señales de **contexto**
  (`audit_file`/`audit_dir`/`syscheck_path`) cuando la técnica toque rutas vigiladas.
  - **`audit_exe` con el binario REAL** (o glob): `tar` → `/usr/bin/tar`, `gpg` → `/usr/bin/gpg`,
    cliente NFS → binario real. **Verificado en el paso 0 de cada técnica.**
  - **Sin `rule_group` amplios** (usar `rule_id` concreto o `audit_exe` anclado).
- **C0 por técnica.** Antes del primer `t0`, chequeo **base-contra-base** (`wazuh-logtest`) para
  descubrir **silenciadores de fábrica** (como `92600` con `python3`). Si aparece uno, **se documenta**
  y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas propias.
- **Receptor (solo tanda C).** `Soporte/Ataques/receiver/sink_http.py` en el HOST
  (`192.168.65.1`, HTTP + `--tcp-port`), **log por iteración**; extensión mínima para el endpoint
  `/hook` (ATA043). Regla de firewall acotada y **retirada** al cerrar la tanda (si hiciera falta:
  la experiencia previa fue que los puertos eran alcanzables).
- **Recurso compartido (ATA039/ATA040).** Export **local** en **VMnet1** (NFS/SMB), sin NAT; retirado
  al cerrar la tanda.
- **Aislamiento por agente** (solo `victima-linux` en los conteos), **fichero diario** (no
  `alerts.json`), **UTC**.

### 5.2 Guardarraíles (invariantes)

1. **Nada destructivo al sistema real ni a servicios reales.** Todo el material vive en
   `lab-attack` (ataque) y `lab-legit` (activo simulado). **T1561.001 solo sobre imagen loop**;
   **T1529 solo reinicia la VM víctima** (restaurable); **T1667/T1496 acotados** con límite y abort.
2. **Sin NAT.** «Servicio», «webhook», «code repo» y «recurso compartido» son **locales** (VMnet1).
3. **`sudo` solo cuando la técnica lo exija**, con la contraseña por **stdin** (`sudo -S`), **nunca**
   interactivo (lección del incidente de ATA011).
4. **Guardarraíles en el guion:** aborta si una ruta sale de `lab-attack`, si toca una cuenta/servicio
   real, si el destino de red no es local, o si el reinicio no es de la VM de laboratorio.
5. **Receptor + share + regla de firewall retirados** al cerrar cada tanda; **snapshot `lab-listo`**
   entre ventanas; **el manager NO se revierte**.
6. **Higiene de secretos** (repo **público**): cero credenciales en ficheros del repo (claves de
   ATA041 **desechables**, generadas en `lab-attack`).
7. **Convivencia de capas:** las técnicas que escriben **fuera de `lab-attack`** (`lab-legit`, webroot,
   buzón) generan filas `ambigua`/fuera de `ATTACK_ROOT` → se resuelven por **señal declarada** o
   **veredicto humano `artefacto`**; **nunca** `ruido` (guardarraíl `exit 4`).
8. **Registrar y declarar** los puntos ciegos conocidos (`92600` `python3`; `40700` `level=0`) y la
   **«lectura no deja rastro»** en cada ficha afectada.

---

## 6. Verificación (`tfg-tester`) y criterios de aceptación

### 6.1 Qué comprueba el `tfg-tester` **por tanda**

| # | Comprobación |
|---|---|
| TV1 | **Métrica congelada** aplicada sin cambios: **O1** (`detectado SÍ/NO` + `rule_id` + 1ª evidencia) y **O2** (`k/m`); nº bruto y `rule_id` distintos solo como **anexo**. |
| TV2 | **0 filas del ataque en `ruido`/`auto_ruido`** en las ventanas de la tanda (guardarraíl). |
| TV3 | **`dudosa = 0`** tras la revisión humana de cada ventana (o veredicto por fila, trazable). |
| TV4 | **Doble iteración v2 `iguales`** (mismo conjunto de `rule_id` de `deteccion`, recuento estable, sin dudosa) — o `review` **justificado**. |
| TV5 | **C0** por técnica (base-contra-base) documentado; **sin silenciadores nuevos**, o **documentados**. |
| TV6 | **Determinismo:** re-filtrar produce **mismo `sha256`**; **`pytest` verde** (93 + los que añada este bloque, si los hay). |
| TV7 | **Regresión: las 56 ventanas previas byte a byte** (mensaje/`sha256`), pilotos intactos. |
| TV8 | **Cadena de huellas** coherente: `esperado` ↔ `ataque.sh` ↔ `-Audited`/`-Revision` ↔ bitácora ↔ ficha (`auditar_cadena_huellas.py`). |
| TV9 | **Laboratorio cerrado** (receptor parado, share retirado, firewall retirado, VMs apagadas, **NAT off**; imagen loop eliminada; usuario/proceso desechables sin residuo). |
| TV10 | Sin secretos; **sin commit/push**; `filtrar_ruido.py`/política/métrica, `_recursos/`, `Reglas/`, `BBDD/`, `xlsx` **intactos**. |
| TV11 | **`audit_exe` con el binario real/glob** en cada `esperado` nuevo (lección de esta ronda). |

### 6.2 Criterios de aceptación del bloque

- **CA-B1** — **15 técnicas × 2 iteraciones = 30 ventanas** ejecutadas con `esperado` validado
  **antes** del primer `t0`.
- **CA-B2** — **15/15** con veredicto **O1** reportado (incluidos los **NO** detectados, sin sesgo).
- **CA-B3** — **0 filas del ataque en `ruido`/`auto_ruido`** (30 ventanas), bajo la pertenencia por
  carpeta; las filas de la **sesión** del ataque se **declaran** (limitación conocida).
- **CA-B4** — **`dudosa = 0`** (o veredicto humano por fila, trazable).
- **CA-B5** — **Doble iteración v2** `iguales` (o `review` justificado) en las 15.
- **CA-B6** — **Métrica y filtro intactos** (hash de `filtrar_ruido.py` y política sin cambios).
- **CA-B7** — **Regresión** de las **56 ventanas previas byte a byte**; **`pytest` verde**.
- **CA-B8** — **Cadena de huellas** coherente; fichas + bitácoras + `Hojas/ATA_index.csv` al día.
- **CA-B9** — **Laboratorio cerrado** y sin residuos; **NAT off**.
- **CA-B10** — Sin secretos, sin `push`; `_recursos/`, `Reglas/`, `BBDD/`, `xlsx` intactos.
- **CA-B11 (valor)** — **≥1 hallazgo documentado** (punto ciego nuevo, o capa no cubierta); el bloque
  debe poder decir **algo** además de «detectado/no detectado».
- **CA-B12** — Cada `esperado` nuevo declara `audit_exe` con el **binario real o glob** (verificado).

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
| `Hojas/ATA_index.csv` | **+15 filas** (`ATA029`…`ATA043`) |
| `Soporte/Ataques/receiver/sink_http.py` | **endpoint `/hook`** (si ATA043 lo pide) + nota |
| `Soporte/Ataques/piloto_procedimiento.md` | notas de la ronda 2 (si procede) |

**Intactos:** `_artefactos/scripts/filtrar_ruido.py` y su política, la métrica congelada, los `esperado`
ya firmados, las **56 ventanas** previas, `Soporte/Ataques/plantilla_esperado.md` (salvo nota),
`_recursos/`, `Reglas/**`, `BBDD/`, `Detecciones.xlsx`.

---

## 8. Riesgos y mitigación

| # | Riesgo | Mitigación |
|---|---|---|
| R1 | **Dependencia ausente** sin NAT (`gcc`, `gpg`, `nfs`/`smbclient`, `tar`, `zip`) | Verificar en el **paso 0**; preferir coreutils/openssl/tar; **fallback** (`.so` precompilado, `ltrace`); si es imprescindible, decidir con el humano antes de tocar nada. |
| R2 | **Punto ciego `python3` (`92600`)** mimetiza una no-detección | No basar la detección en `python3`; declararlo (como ATA013) y ofrecer camino con `nc`/`bash`/coreutils. |
| R3 | **Escritura fuera de `lab-attack`** (`lab-legit`, webroot, buzón) → `ambigua`/pertenencia | Declarar señales de contexto; revisar `dudosa`; veredicto `artefacto`; **nunca** `ruido` (`exit 4`). |
| R4 | **`sudo` interactivo rompe la ventana** (incidente ATA011) | `sudo -S` por **stdin**; comprobar exit codes; pre-staging; auditar el árbol antes de reintentar. |
| R5 | **Técnicas destructivas/sistema** (ATA037 imagen loop; ATA038 reinicio; ATA031 volumen) | Guardarraíles **duros** (solo imagen loop / solo VM víctima / límite de N con abort); snapshot `lab-listo`; restauración tras ATA038. |
| R6 | **T1529 (reinicio) rompe la ventana/cadena temporal** | Ejecutarla **al final** de la tanda B; sellar `t0` antes; documentar `t1` tras la reconexión del agente; snapshot como red de seguridad. *(Alternativa KISS si el humano prefiere no reiniciar: sustituir por T1074.001 Local Data Staging.)* |
| R7 | **ATA035/ATA036 poco cubiertas** (hook/memoria) | Aceptarlo y **reportarlo como hallazgo**; probar el C0 para ver si hay silenciador. |
| R8 | **Recurso compartido mal montado** (ATA039/ATA040) deja filas fuera de pertenencia | Declarar la ruta del share como señal de contexto; resolver `dudosa` por veredicto; documentar. |
| R9 | **Muchas técnicas solo detectables por `execve`** (poca discriminación) | Aceptarlo y reportarlo (el HIDS de host no ve la red); ya se diversifican mecanismos. |
| R10 | **Volumen de escritura** (15 guiones) → tiempo | KISS; reutilizar plantillas/plantilla H4; **3 tandas separables** en sesiones. |
| R11 | **Fallo de reporte del ejecutor** (HTTP 400) dejando trabajo hecho | **Auditar el árbol antes de reintentar** (lección registrada). |
| R12 | **`autocrlf`/git reescribe bytes** y rompe hashes | No `checkout`/`stash`/`reset`; si git toca bytes, **recalcular** huellas afectadas. |
| R13 | **Piscina P1 Linux casi agotada** (quedan 44, **~16 factibles con capa distinta**) | Tras esta ronda, la siguiente debería abrir **P2** (Stealth/CredAccess/PrivEsc/Execution) o **cerrar P1**; decidir con el humano al cierre. |

---

## 9. Qué NO entra (fuera de alcance)

- **Windows** (ni como víctima ni como pruebas). Nada.
- **Bloque de EVASIÓN** (repetir técnicas en **versión disfrazada**): **queda para el futuro**, cuando
  esté cubierta la cobertura P1. No en este bloque.
- **Cambiar la métrica** (congelada, `fase-03-metrica`) ni **rediseñar el filtro**.
- **Fase 4** («precio de la detección», robustez/η).
- **No factibles headless (P1 Linux):** T1113 Screen Capture, T1123 Audio, T1125 Video, T1115
  Clipboard, T1025/T1052.001 USB, T1056.002 GUI Input Capture.
- **No factibles sin NAT/cloud:** T1213 (SaaS), T1491.002 (external), T1567.002/.003 (cloud),
  T1530, T1537, T1485.001.
- **DoS puro y físico (P1):** T1498/.001/.002, T1499/.001–.004, T1011/.001 (Bluetooth), T1052
  (medio físico) — **fuera** (disruptivos o sin soporte físico en el laboratorio).
- **Alto riesgo, diferidas:** T1495 Firmware, T1557/.003 (MITM/DHCP).
- **Duplicados de mecanismo ya cubierto** (se declaran, no se ejecutan): T1074.001 (≈ATA011),
  T1056 (≈ATA018), T1496 (≈ATA025/ATA023), T1213 (≈ATA016), T1565.002/002 ya hechas.
- **P2** (Stealth/Credential Access/Privilege Escalation/Persistence/Execution): **no** en esta ronda;
  se evalúan para la siguiente (ver R13).
- **Reescritura de `esperado`** ya firmados y **recálculo de las 56 ventanas** (histórico).

---

## 10. Gate y validación

- **Validación humana pendiente (gate).** El presente plan y, en su momento, **cada
  `ATA<NNN>_esperado.csv`** deben contar con **validación humana registrada** (con **revisión
  posterior**), como en los bloques anteriores.
- **Sin `status: approved_by_human`**, **ni `tfg-executor` ni ningún otro** ejecuta.
- **Registro:** la aprobación se anota en este fichero (frontmatter + nota fechada) y en `state.md`;
  la revisión posterior, en el `change-doc` del bloque.
- **`push`:** los commits son **locales**; publicar es del humano.

---

## 11. Pasos del bloque (resumen ejecutable)

1. **Gate:** validación humana registrada del plan y de los `esperado` de la **tanda A** → `approved`.
2. **Tanda A** (`ATA029`–`ATA033`): C0 → 2 iteraciones × 5 → filtrar/revisar/plegar →
   fichas/bitácora → `tfg-tester` (TV1–TV11) → cierre de tanda.
3. **Tanda B** (`ATA034`–`ATA038`): idem, con material propio (`.so`, memoria, imagen loop) y
   **reinicio de la VM** al final (ATA038) + restauración por snapshot.
4. **Tanda C** (`ATA039`–`ATA043`): idem, con **receptor** y **recurso compartido** en el HOST/VMnet1
   y su retirada al cerrar.
5. **Cierre del bloque:** `change-doc.md` (`fase-03-ampliacion-2`), `state.md`, `roadmap.md`,
   `Hojas/ATA_index.csv`, y **gate final** con el humano (incluida la decisión sobre la **siguiente
   ronda**: P2 o cierre de P1).
