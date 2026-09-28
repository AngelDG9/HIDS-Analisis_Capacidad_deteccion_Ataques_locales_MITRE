---
fase: 3
bloque: fase-03-escalado
tarea: 3.4 (escalar al resto del corpus) · T-09/T-10/T-11 · R-09/R-13
nombre: Escalado — cerrar las 7 técnicas restantes del corpus (Linux)
version: 1
status: approved_by_human
fecha: 2026-09-28
fecha_aprobacion: 2026-09-28
aprobado_por: humano
autor: tfg-planner
gate: **APROBADO ✔ (2026-09-28)** — D1 **1 bloque / 2 tandas** · D2 **validación humana de los `esperado` por tanda** · D3 **ataque en `lab-attack`, efecto en `lab-legit`** · D4 **ATA010 con el receptor HTTP ya existente** · D5 **NO se escriben reglas RS3** (los puntos ciegos se documentan) · D6 **orden aceptado**. **Arranca la TANDA A** (ATA001 → ATA006 → ATA005 → ATA003). El `esperado` de la tanda se valida **ANTES** de atacar (CA1).
---

# Plan — Bloque `fase-03-escalado`: cerrar las 7 técnicas que faltan

> **Objetivo del bloque:** llevar el corpus de **6 → 13 ataques cerrados** ejecutando las **7
> técnicas Linux restantes** con el **ciclo ya probado** (snapshot → `t0` → ataque → `t1` →
> extraer del fichero diario → filtrar → ficha + bitácora), **aprovechando que la métrica y el
> filtro están arreglados y congelados**.
>
> **Regla que manda en este bloque:** **NO se rediseña cómo se cuenta** (métrica `fase-03-metrica`
> congelada) **ni se toca el filtro** (`filtrar_ruido.py`). El escalado es **ejecución + medición**,
> no ingeniería de la herramienta. Si un ataque nuevo expusiera un defecto del filtro, **se para y
> se propone un bloque aparte**; no se "arregla" a mitad del escalado.
>
> **Fichero único de retorno del bloque: este `plan.md`.** Los datos van a `Dataset/`, la memoria a
> `Bitacora/` y las fichas.

---

## 0. Alcance

- **Entra:**
  1. Diseñar y ejecutar los **7 ataques** que faltan (2 iteraciones cada uno) — §1/§4.
  2. Agruparlos en **tandas** dentro de este plan, con **punto de parada segura** entre tandas — §2.
  3. **Captura C0 por técnica** (pre-flight base-contra-base) — §4 (columna C0).
  4. Redacción de **7 `esperado`** (señales candidatas) y su **validación humana agrupada** — §4/§8.
  5. Medir con la **métrica congelada** (O1+O2), fichas, bitácoras y las **7 filas** de `ATA_index.csv`.
  6. **Verificación de regresión** de las 6 ventanas ya cerradas y de los 7 ataques nuevos — §6.
- **NO entra:** Windows; η / "precio de la detección" (Fase 4, **no se instrumenta** la Fase 3);
  RS3/RS4 **salvo** que el C0 demuestre un silenciador de fábrica y el humano lo apruebe (D5);
  rediseñar métrica/filtro; editar los **6 cerrados**; memoria; `BBDD/`; `Hojas/Detecciones.xlsx`;
  tocar `_recursos/`; commits/push (los hace el orquestador).

---

## 1. Inventario de los 7 que faltan (verificado sobre el repo)

> Cobertura ART: `Hojas/cobertura_atomic.csv`. Estado: `Hojas/ATA_index.csv`. **Verificado además
> que "ART lo cubre en Linux" ≠ "ejecutable en nuestro laboratorio sin NAT".**

| ATA | Técnica | Táctica | ART Linux | ¿Ejecutable sin NAT? | Qué existe ya | Qué hay que escribir | Dificultad |
|---|---|---|---|---|---|---|---|
| **ATA001** | T1486 Data Encrypted for Impact | Impact | **4 test** (gpg/7z/ccrypt/**openssl**) | **SÍ** (openssl; gpg puede faltar) | `T1486-Data_Encrypted_for_Impact/ATA001_esperado.csv` (**es un EJEMPLO**, no real) | guion `ATA001_ataque.sh` + README + **rehacer el `esperado` real** | **Baja** |
| **ATA003** | T1490 Inhibit System Recovery | Impact | **0 Linux** (solo Windows) | — (custom) | nada | guion + README + `esperado` + carpeta | **Media** |
| **ATA005** | T1561 Disk Wipe | Impact | **sin pruebas** | — (custom) | nada | guion + README + `esperado` + carpeta | **Media** |
| **ATA006** | T1565 Data Manipulation | Impact | **sin pruebas** | — (custom) | nada | guion + README + `esperado` + carpeta | **Media** |
| **ATA009** | T1567 Exfiltration Over Web Service | Exfiltration | 3 test (rclone→nube / terraform+AWS) | **NO** (nube + claves + NAT) → **custom** | nada | guion + README + `esperado` + carpeta | **Media** |
| **ATA010** | T1041 Exfiltration Over C2 Channel | Exfiltration | **0 Linux** (solo Windows) | — (custom) | nada | guion + README + `esperado` + carpeta | **Alta** |
| **ATA011** | T1074 Data Staged | Collection | 1 test (`curl` desde GitHub) | **NO** (descarga de internet) → **custom** | nada | guion + README + `esperado` + carpeta | **Baja-Media** |

**Nota metodológica para la memoria:** de los 7, **solo 1 (ATA001) usa ART tal cual**; los otros 6
son **ataque propio** por dos motivos distintos y ambos legítimos: *(a)* ART **no trae pruebas Linux**
(ATA003/005/006/010); *(b)* ART **sí trae prueba Linux pero no es ejecutable** en un laboratorio
**sin NAT** (ATA009 pide nube+AWS; ATA011 descarga de GitHub). Es la misma distinción ya declarada
en `state.md`: *"la técnica no aplica a Linux"* ≠ *"la biblioteca no la cubre en Linux"*; aquí
añadimos una tercera: *"la prueba no es ejecutable en un lab aislado"* → **se escribe a mano, no se
excluye**.

**Riesgo de solapamiento a declarar (evitar crítica de "mismo ataque"):** ATA011 (T1074 *Data
Staged*), ATA012 (T1119 *Automated Collection*) y ATA013 (T1560 *Archive Collected Data*) son
**vecinas**. Se distinguen en el README por **qué acción** las caracteriza: ATA011 = **reunir** lo
recogido en un directorio de *staging* (`mkdir`/`cp`); ATA012 = **recolectar automáticamente**
(`find`+`cp`); ATA013 = **archivar/comprimir** (`gzip`). Se documenta explícitamente.

---

## 2. Estructura del bloque y por qué

### 2.1 Opciones

| Opción | Pros | Contras |
|---|---|---|
| **Un bloque con 2 tandas (4 + 3)** ← reco. | Un solo plan/gate/`change-doc`/verificación; **una** puesta en marcha de VMs; pipeline ya caliente | Plan largo; 14 ventanas; riesgo de parada a media ejecución |
| 7 micro-bloques | Gates pequeños | 7× sobrecarga de plan/gate/cierre; 7 arranques de laboratorio |
| 2 bloques separados | Cierres intermedios | Duplica la ceremonia y la puesta en marcha; **no aporta** al resultado |

### 2.2 Recomendación: **1 bloque, 2 tandas**

- **Tanda A — "Impact local" (4):** ATA001, ATA006, ATA005, ATA003.
- **Tanda B — "Collection + Exfiltration" (3):** ATA011, ATA009, ATA010.

**Por qué así:**

1. **Coste de VMs.** Arrancar/revertir la víctima y desplegar el extractor se hace **una vez** al
   principio del bloque; cada tanda es "seguir midiendo". Dos bloques repetirían esa puesta en marcha.
2. **Red agrupada.** Los dos ataques de exfiltración (ATA009/ATA010) **comparten el receptor del
   host** (`sink_http.py` + regla de firewall). Se agrupan para **levantar el receptor una sola vez**
   y **retirarlo al cerrar la tanda B** (no dejar el laboratorio con red abierta a medias).
3. **Riesgo de dejar el laboratorio a medias.** El plan fija un **punto de parada segura** al final
   de la tanda A: los 4 ataques quedan **cerrados, con ficha y bitácora**, la víctima **revertida a
   `lab-listo`**, la red apagada y `state.md`/`ATA_index.csv` actualizados. Si se agota el tiempo, la
   tanda B puede **abrirse como bloque nuevo** sin nada a medias.
4. **Carga de validación humana** acotada: el humano valida los **4 `esperado` de la tanda A** y,
   tras cerrarla, los **3 de la tanda B** (2 gates, no 7) — §8.

**Regla de la unidad:** el plan es **uno**; las **tandas son tareas** (coherente con `tfg-flow`).

---

## 3. Orden recomendado de ejecución

```
Tanda A (Impact local)          Tanda B (Collection + Exfil)
  1. ATA001  T1486 (openssl)      5. ATA011  T1074 (staging)
  2. ATA006  T1565 (manipulación) 6. ATA009  T1567 (web service)
  3. ATA005  T1561 (wipe)         7. ATA010  T1041 (C2)
  4. ATA003  T1490 (inhibit recovery)
```

- **Por dificultad:** primero la más parecida a lo ya hecho (**ATA001**: cifrado con `openssl`,
  hermano conceptual de ATA013/`gzip`) → calienta el ciclo; las de mayor riesgo (systemd/root en
  ATA003, canal en ATA010) van **al final de su tanda**.
- **Por dependencias:** ATA009/ATA010 **después** de ATA008 (ya resuelto el patrón receptor +
  firewall). ATA010 el último de todo.
- **Por familias MITRE:** tanda A = **Impact**; tanda B = **Collection + Exfiltration**.
- **Por capas del HIDS que se ejercitan** (diversidad deliberada): ATA001/ATA005/ATA011 → **execve**
  (`80792`); ATA006/ATA003 → **watch/FIM** (`80790/80781`, `syscheck_path`) sobre `lab-legit`/`/etc`;
  ATA009/ATA010 → **red saliente** (el HIDS ve el `execve` del cliente, no el canal). Se registra en
  cada ficha **qué capa** disparó.
- **Orden dentro de tanda B:** ATA011 (local, sin receptor) → ATA009 (receptor, sencillo) →
  ATA010 (el más complejo).

---

## 4. Los 7 ataques (acciones, señales candidatas, C0, evidencia, prueba de ejecución)

> **Nota común (convención congelada `plantilla_esperado.md` v4):** toda señal `audit_exe` se
> **acompaña** del ancla `audit_cwd=/home/angel/lab-attack/ATA<NNN>/*`. Los artefactos viven en
> `/home/angel/lab-attack/ATA<NNN>/` (**no vigilado** → detección por **execve**). Solo el **efecto**
> puede escribirse en `lab-legit` (**vigilado** → watch), y esas filas se declaran **`ambigua`**
> (van a `dudosa` y las resuelve el humano), **nunca `deteccion`** — patrón ya usado en ATA007.
>
> **C0 (pre-flight base-contra-base):** antes de cada ataque, `wazuh-logtest` con una línea real del
> binario clave para descubrir **silenciadores de fábrica** (como `92600` con `python3`). El
> resultado se guarda en `Soporte/Ataques/c0/ATA<NNN>_logtest.txt` + `_preflight.md`.

### ATA001 · T1486 Data Encrypted for Impact — **ART (openssl)**

- **Acciones:** copiar un fichero no sensible a la carpeta del ataque y **cifrarlo** con
  `openssl enc -aes-256-cbc -pbkdf2 -salt -in … -out …` (SIN elevación). Fallback a `gpg` si
  `openssl` no estuviera (comprobación `which` en preflight).
- **Señales candidatas (`esperado`):** `T1486-S1` `deteccion,audit_exe,openssl` +
  `T1486-S2` `deteccion,audit_cwd,…/ATA001/*`. *(El `esperado` actual del repo es un **ejemplo**:
  se sustituye por el real antes de atacar.)*
- **C0:** verificar que `openssl` **no** cae en silenciador de fábrica (se espera `80792` nivel 3 → NO avisa).
- **Evidencia:** `Logs/ATA001_iter*/` + `sha256` del guion; **prueba de éxito:** el descifrado
  (`openssl enc -d` con la misma clave) **reconstruye** el original ⇒ el ciphertext es válido (el
  ataque "funcionó" más allá de la alerta).

### ATA006 · T1565 Data Manipulation — **custom**

- **Acciones:** **alterar el contenido** de un fichero *mock* en `lab-legit` (append/replace con
  `sed -i`/`echo >>`) y, opcionalmente, **falsear el mtime** (`touch -t`) y el modo (`chmod`).
- **Señales candidatas:** `T1565-S1` `deteccion,audit_exe,sed` + ancla; `T1565-A1`/`A2`
  `ambigua,rule_id,80790`/`80781` (escritura en `lab-legit`, la tapa el baseline → `dudosa`).
- **C0:** `sed`/`touch`/`chmod` no silenciados.
- **Evidencia + prueba:** `grep` del marcador inyectado **presente** y mtime alterado ⇒ la
  manipulación ocurrió.
- **Solapamiento:** se distingue de ATA002 (destruir) y ATA007 (defacement): aquí se **modifica**
  el dato sin destruirlo ni publicarlo.

### ATA005 · T1561 Disk Wipe — **custom**

- **Acciones:** crear un **fichero de trabajo** en la carpeta del ataque (p. ej. 32 MB) y
  **machacarlo** con `dd if=/dev/urandom` y/o `shred -n 1 -z`. **Jamás** se toca un dispositivo
  real (`/dev/sda…`). Guardarraíl en el guion: aborta si el destino no está bajo `lab-attack`.
- **Señales candidatas:** `T1565→T1561` ojo: `T1561-S1` `deteccion,audit_exe,dd` + `S2`
  `audit_exe,shred` + ancla. `dd` ya está probado (ATA002 → `80792`).
- **C0:** `dd`/`shred` no silenciados.
- **Evidencia + prueba:** `sha256` del fichero **antes ≠ después**, tamaño estable ⇒ se sobrescribió.

### ATA003 · T1490 Inhibit System Recovery — **custom**

- **Acciones (Linux):** **borrar unos "puntos de recuperación" mock** (`rm -rf` sobre un directorio
  *mock* en `lab-legit`) y/o **deshabilitar un temporizador *lab-owned***. **No** se desactiva
  ningún servicio real del sistema (ni `wazuh-agent`, ni `cron`, ni `chrony`).
- **Señales candidatas:** `T1490-S1` `deteccion,audit_exe,rm` (+ `systemctl` si se usa un timer) +
  ancla; `T1490-A1` `ambigua,rule_id,80790/80781` (borrado bajo watch).
- **C0:** `rm`/`systemctl` no silenciados. **Si se usa `journald`,** C0 debe incluir una **línea
  journald real** (lección del `40700 = level 0` de ATA004); si no la hay, la detección se declara
  por el **`rule_id` del `execve`** y el punto ciego se documenta.
- **Evidencia + prueba:** `test -e` de los "puntos de recuperación" pasa de **existe** a **no existe**.

### ATA011 · T1074 Data Staged — **custom** (ART Linux pide internet)

- **Acciones:** **reunir** unos ficheros legibles en un directorio de *staging* del ataque
  (`mkdir -p` + `cp`), dejándolos listos para una exfiltración posterior. **Sin** `find` masivo
  (eso es ATA012) y **sin** comprimir (eso es ATA013).
- **Señales candidatas:** `T1074-S1` `deteccion,audit_exe,mkdir` + `S2` `audit_exe,cp` + ancla.
- **C0:** `mkdir`/`cp` no silenciados.
- **Evidencia + prueba:** **lista e inventario (`sha256`)** de los ficheros *staged*.

### ATA009 · T1567 Exfiltration Over Web Service — **custom** (ART pide nube/NAT)

- **Acciones:** **subir** un fichero *staged* al **receptor del host** (`sink_http.py` en
  `192.168.65.1:9090`) mediante un cliente de "servicio web" (`curl`/`wget` POST a `/api/upload`).
  Se **reutiliza** el receptor del piloto (no se inventa infraestructura).
- **Señales candidatas:** `T1567-S1` `deteccion,audit_exe,curl` (y/o `wget`) + ancla.
- **C0:** `curl`/`wget` no silenciados.
- **Evidencia + prueba:** `sink.log` del host con **método, IP, tamaño y `sha256`** del cuerpo; el
  hash **coincide** con el del fichero *staged* ⇒ el dato **salió** de la víctima.

### ATA010 · T1041 Exfiltration Over C2 Channel — **custom**

- **Acciones:** abrir un **canal de mando y control** hacia el host y enviar un payload/beacon.
  **Primario (recomendado):** reutilizar `sink_http.py` como **C2 sobre HTTP** (el `curl`/`bash`
  que hace el POST es el `execve` visible). **Alternativa:** pequeño listener TCP en el host + `nc`/`bash /dev/tcp`.
  La elección final depende de las dependencias disponibles en la víctima (**sin NAT**: no se instala nada).
- **Señales candidatas:** `T1041-S1` `deteccion,audit_exe,<cliente>` + ancla.
- **C0:** el cliente elegido no silenciado por el ruleset base.
- **Evidencia + prueba:** `sink.log`/log del listener con el payload recibido + `sha256`.
- **Decisión:** D4 (§8). **Si ninguna vía es viable**, ATA010 se declara **NO ejecutable** con
  justificación (no se fuerza el resultado).

> **Cómo se demuestra que el ataque funcionó (transversal):** en **todos** se captura evidencia
> **independiente de la alerta** (efecto observable: descifrado válido, marcador inyectado, hash
> cambiado, fichero borrado, inventario, `sink.log`). La alerta es la **medición**, no la prueba del ataque.

---

## 5. Operativa (lo que hay que hacer bien, aprendido de los bloques anteriores)

1. **Snapshots.** `base-limpia` = Ubuntu prístino; `lab-listo` = agente Wazuh + RS2 + `lab-legit`.
   Antes de **cada** iteración: `revertToSnapshot lab-listo` en la **víctima**. **El manager NO se
   revierte** (conserva las alertas). `base-limpia` solo como red de seguridad última.
2. **Arranque del bloque (pre-flight general):**
   - Manager: `wazuh-manager|indexer|dashboard` = `active`; agente `001` `Active`; `df -h /` ≥ 10 GB.
   - **Reconfirmar `OPERADOR_SRCIPS` = `192.168.65.1`** con `ipconfig` en el host (cambia si cambia
     VMnet1) — predicado `OPERADOR` de H3.
   - **Desplegar el extractor:** `sha256` de `extraer_alertas.py` **repo ↔ manager** deben coincidir
     **antes de medir** (lección del *gap de despliegue* de `fase-03-piloto-custom` §8.1).
   - Relojes víctima↔manager `|Δ| < 1 s`; **NAT desconectado** (no reconectar).
3. **Fichero diario (regla dura).** Extraer de
   `/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json`, **NUNCA** de `alerts.json`
   (rota a diario y se reinicia al arrancar el manager). Cada ventana registra **su** fichero diario.
4. **Tiempos.** `t0`/`t1` en **UTC** en la víctima; `t0` sellado **≥ 60–90 s tras** el agente
   `Active` (H2: el churn de arranque queda **antes** de `t0`, sin recortar la ventana). Scan FIM
   forzado entre ataque y `t1`.
5. **Ruido del operador (contaminación conocida).** Nuestro login dispara `find` de
   `update-motd.d` (`cwd=/`) y `systemctl --user` al cerrar sesión; son **ajenos**.
   **Mitigación:** (a) hacer el login/`scp` **antes** de `t0` y **esperar el asentamiento** para que
   ese churn caiga **fuera** de `[t0,t1]`; (b) **no** ejecutar comandos interactivos durante la
   ventana; (c) **cerrar sesión después de `t1`**, no dentro; (d) confiar en el filtro: las señales
   `audit_exe` sin ancla van a **`dudosa`**, no a `deteccion`; `5715` con `srcip=192.168.65.1` y
   `19004` se auto-excluyen.
6. **Aislamiento por agente.** `extraer_alertas.py` no filtra por agente; se filtra a
   `agent_name == victima-linux` (paso 9 del runbook). Nunca llegan filas de otros agentes.
7. **Receptor (solo tanda B, ATA009/ATA010).** Levantar `sink_http.py` en el **host** antes de `t0`;
   crear la regla de firewall acotada **solo si el puerto está bloqueado**; **parar receptor y
   retirar la regla al cerrar la ventana** (no dejar red abierta).
8. **Higiene.** Contraseñas **solo por stdin**, nunca en ficheros; `_recursos/` solo lectura;
   **sin `git push`**; **no** `checkout`/`stash`/`reset` sobre `esperado`/`Audited` (rompería los
   `sha256`); CSV **UTF-8 sin BOM** con **LF**.
9. **Parada segura.** Al cerrar la tanda A: víctima en `lab-listo`, receptor/firewall retirados,
   `state.md`/`ATA_index.csv`/fichas/bitácoras al día. La tanda B puede ir en la misma sesión o en otra.

---

## 6. Verificación (qué comprueba `tfg-tester`) y criterios de aceptación

### 6.1 Verificación

- **Por tanda (incremental):**
  - Reproduce **byte a byte** el filtrado de cada ventana nueva (mismo `-Detalle.csv` → mismo
    `-Audited.csv`; **determinismo R-13**, 2 pasadas).
  - Cuadra los conteos y los `sha256` de la cadena: `esperado` ↔ `ataque.sh` ↔ `-Audited`/`-Revision`
    ↔ `Bitacora/ATA<NNN>.json` ↔ `ATA<NNN>_meta.md`.
  - Comprueba **aislamiento por agente**, `dudosa = 0` al cierre, métrica O1+O2 registrada,
    **0 filas del ataque en `ruido_conocido`/`auto_ruido`**.
  - Comprueba que el `esperado` tiene **firma de validación humana** en su cabecera.
- **Al cerrar el bloque:**
  - **Regresión de la métrica congelada:** los **12 `-Audited.csv`** de los 6 cerrados siguen
    **idénticos** (no se tocó `filtrar_ruido.py` ni sus datos). `pytest` **verde** (93, sin regresión).
  - Sólo las **7 filas** nuevas tocadas en `ATA_index.csv`; sin secretos; sin `push`; los 6 cerrados,
    el baseline y `_recursos/` intactos.

### 6.2 Criterios de aceptación

| # | Criterio |
|---|---|
| **CA1** | Los 7 ataques tienen `esperado` **redactado antes y validado por el humano** (firma), guion y README. |
| **CA2** | **C0 por técnica** ejecutado y declarado (con silenciador o sin él). |
| **CA3** | **2 iteraciones** por ataque (14 ventanas): `lab-listo` entre ambas, `t0` tras asentamiento, fichero diario, aislamiento por agente. |
| **CA4** | Métrica **O1+O2** por ventana (SÍ/NO + `rule_id` + `k/m`), **sin `dudosa` sin resolver**. |
| **CA5** | **0** filas del ataque en `ruido_conocido`/`auto_ruido` (las del ataque → `deteccion`/`artefacto_ataque`). |
| **CA6** | Doble iteración **v2** aplicada → `iguales`/`review` con motivo. |
| **CA7** | **Regresión intacta:** las 12 ventanas de los 6 cerrados **byte a byte**; `pytest` verde; métrica/filtro **sin cambios**. |
| **CA8** | Fichas (7) + bitácoras (7) + `ATA_index.csv` (solo 7 filas) coherentes; cadena de huellas verificada. |
| **CA9** | Sin secretos; sin commit/push; `_recursos/` y `Hojas/Detecciones.xlsx` intactos. |
| **CA10** | Cierre de laboratorio: receptor parado, firewall retirado, víctima en `lab-listo`, NAT desconectado. |

---

## 7. Riesgos y mitigación · Ficheros · Qué NO entra

### 7.1 Riesgos

| Riesgo | Mitigación |
|---|---|
| Prueba ART **no ejecutable sin NAT** (ATA009/ATA011) | Ataque **custom offline** (receptor local); **no** reconectar NAT. |
| **Wipe/borrado dañan la VM** (ATA005/ATA003) | Objetivo **solo** mock/scratch en `lab-attack`/`lab-legit`; guardarraíl en el guion; `lab-listo` como red. |
| **Silenciador de fábrica** (como `92600`) oculta una técnica | **C0 por técnica**; si aparece, se documenta y la detección se declara por el `execve`; **RS3 solo con aprobación humana** (D5). |
| **Ruido del operador** contamina `deteccion` | Login antes de `t0` + asentamiento; nada interactivo en ventana; logout tras `t1`; ancla ⇒ `dudosa`. |
| **Gap de despliegue** (extractor obsoleto en el manager) | Chequeo `sha256` repo↔manager **antes de medir**. |
| **`autocrlf` rompe hashes** | No `checkout/stash/reset`; regenerar por script; verificar `sha256`. |
| **Bloque largo / parada a medias** | **Punto de parada segura** tras la tanda A; `state.md` por ataque. |
| **Solapamiento T1074/T1119/T1560** | Distinción declarada en README (§1) y en las fichas. |
| **ATA010 sin vía viable** | D4: HTTP-C2 con el receptor; si no, se declara **no ejecutable** (no se fuerza). |

### 7.2 Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `Dataset/Ataques/Comandos/T1486-…/ATA001_ataque.sh` + `README.md` | **nuevos** (ART openssl) |
| `Dataset/Ataques/Comandos/T1486-…/ATA001_esperado.csv` | **sustituido** por el real (hoy es EJEMPLO) |
| `Dataset/…/T1490-…/`, `T1561-…/`, `T1565-…/`, `T1567-…/`, `T1041-…/`, `T1074-…/` | **carpetas nuevas**: `ATA<NNN>_ataque.sh` + `ATA<NNN>_esperado.csv` + `README.md` |
| `Soporte/Ataques/c0/ATA<NNN>_{logtest.txt,preflight.md}` (×7) | **nuevos** (C0 por técnica) |
| `Dataset/…/linux/CSV/ATA<NNN>_iter{1,2}-Detalle.csv` (+`_raw`) (×7×2) | **nuevos** |
| `Dataset/…/linux/Auditado/ATA<NNN>_iter{1,2}-{Audited,Revision}.csv` (×7×2) | **nuevos** |
| `Dataset/…/linux/Logs/ATA<NNN>_iter{1,2}/` (×7×2) | **nuevos** (`times.log`, `ejecucion.out`, `sha256_artefacto.txt`, `deps…`) |
| `Dataset/…/linux/ATA<NNN>_meta.md` (×7) | **nuevas fichas** |
| `Bitacora/ATA<NNN>.json` (×7) | **nuevas** |
| `Hojas/ATA_index.csv` | **solo las 7 filas** (→ `cerrado`/`review` + artefacto) |
| `Soporte/Ataques/piloto_procedimiento.md` | nota menor: receptor/C2 y tandas nuevas (si hace falta) |

**No se toca:** `_artefactos/scripts/filtrar_ruido.py` (**congelado**), `extraer_alertas.py`,
`preflight_enmascaramiento.py`, `politica_filtrado_ruido.md`, `criterio_doble_iteracion.md`,
`plantilla_esperado.md`, las **12 ventanas de los 6 cerrados**, el **baseline**, `Hojas/Detecciones.xlsx`,
`BBDD/`, `_recursos/`.

### 7.3 Qué NO entra
Windows; η/Fase 4 (no se instrumenta la detección); rediseño de la métrica/filtro; RS3/RS4 salvo
D5; memoria; `BBDD/`; `xlsx`; tocar `_recursos/`; commits/push.

---

## 8. Gate humano (decisiones en lenguaje sencillo)

> **Contexto en una frase:** ya tenemos **6 ataques** medidos con una regla de contar **congelada**
> y limpia; ahora **ejecutamos los 7 que faltan** para cerrar el corpus de 13, **sin cambiar cómo
> contamos**. Tu trabajo de validación se reparte en **dos ratos** (uno por tanda), no en siete.

- **D1 — Estructura (recomendado: 1 bloque, 2 tandas).**
  ¿Hacemos los 7 de una vez agrupados en 2 tandas (4 Impact + 3 Collection/Exfiltración) con un
  punto de parada segura, o en bloques separados?
  - **A (rec.):** 1 bloque, 2 tandas. Menos ceremonia, una puesta en marcha de VMs, cierre limpio.
  - B: 2 bloques separados (más cierres, más arranques).
  - C: 7 mini-bloques (descartado: 7 gobernanzas para el mismo trabajo).

- **D2 — Tu validación de los `esperado` (recomendado: por tanda).**
  Te llevo los **4 `esperado` de la tanda A** en una tabla sencilla (qué comando hace el ataque y
  qué señal esperamos) y me dices sí/no; luego los **3 de la tanda B**. Así son **2 ratos**.

- **D3 — Dónde escribe cada ataque (recomendado: artefacto en `lab-attack`, efecto en `lab-legit`).**
  Mantener el ataque en su carpeta (`lab-attack` → detección por `execve`) y solo el **efecto** en la
  carpeta vigilada (`lab-legit` → señales `ambigua`, revisión humana). Alternativa: forzar más
  señales de fichero (más ruido de baseline a revisar).

- **D4 — ATA010 "canal C2" (recomendado: reutilizar el receptor HTTP del host).**
  - **A (rec.):** usar el receptor que ya tenemos como **C2 sobre HTTP** (el `curl`/`bash` es el
    `execve` visible).
  - B: escribir un **listener TCP** aparte (+`nc`/`bash /dev/tcp`).
  - C: dejar ATA010 **fuera** y declararlo (no forzar el resultado).

- **D5 — ¿Escribimos reglas propias (RS3)? (recomendado: NO, salvo silenciador de fábrica).**
  Por defecto **no** se escribe ninguna regla nueva: se mide con lo de fábrica y, si el **C0**
  descubre un punto ciego (como `92600`), se **documenta** y se declara la detección por el
  `execve`. Solo si tú lo apruebas se escribe RS3 (con su pre-flight anti-enmascaramiento).

- **D6 — Orden propuesto (recomendado: aceptar).**
  Tanda A: ATA001 → ATA006 → ATA005 → ATA003. Tanda B: ATA011 → ATA009 → ATA010.

---

## 9. Referencias

- Métrica congelada: `_fases/fase-03-metrica/change-doc.md`, `plan.md` (D1–D5).
- Runbook del ciclo: `Soporte/Ataques/piloto_procedimiento.md`; doble iteración:
  `Soporte/Ataques/criterio_doble_iteracion.md` (v2); señales: `Soporte/Ataques/plantilla_esperado.md` (v4).
- Filtro: `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` (v6).
- Corpus y cobertura: `Hojas/ATA_index.csv`, `Hojas/cobertura_atomic.csv`.
- Lecciones: `_fases/fase-03-piloto-custom/change-doc.md` (H-A/H-B/H-C),
  `Soporte/Ataques/piloto_procedimiento.md` §8.
