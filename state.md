# state.md — Estado vivo del proyecto

> Memoria externa del `tfg-orchestrator`. Al retomar el TFG, lo primero que se lee es este
> fichero. Se actualiza en cada transición (no se reescribe la historia: se edita el estado).

---

## Estado actual

- **Fase:** 3 — **EN CURSO**: **43 técnicas** ejecutadas (**86 ventanas** + **18 de repetición** = **104**) → **41 detectadas / 2 no** (ATA013 y ATA034). **Bloques:** `filtro` · `preflight` · `atomic` · `piloto` · `afinado` · `piloto-custom` · `cabos(-cierre)` · `gitattributes` · `senales(-ratificacion)` · `metrica` · `escalado` · `ampliacion` · `ampliacion-2` · `auditoria-metodologica` · **`repeticiones` ✔ (2026-10-02)**. Detalle en `_fases/fase-03-*/change-doc.md`.
- **✅ REPETICIONES CERRADAS (2026-10-02) — 9/9 DETECTADAS.** Las 9 que la auditoría marcó (**por ART:** ATA024/029/030/038 · **por pre-staging:** ATA014/016/029/035/036/037/038; **unión = 9**, ATA029 y ATA038 con **los dos motivos**). **Contabilidad:** el **original no se toca**; la repetición se **añade** con sufijo **`_rev`** (`esperado_rev` firmado · `-rev1/rev2` · ficha con **§Repetición auditada** · bitácora con bloque `"repeticion"` · **`Hojas/repeticiones.csv`** con 9 filas). **La repetición es la medición canónica** para esas 9. **Verificado:** ART real (4 `guid` en el clon, commit `388942a…`) y **pre-staging genuino** (material fuera de `[t0,t1]`; `python3`/`dpkg`/`useradd`/`mkfs.ext4` = 0 dentro). **86 ventanas base intactas**; `ATA_index` 43 filas; `pytest` **97**; cadena **1.582/0**.
  - **⭐ Valor añadido:** tener **original + repetición** permite **comparar** (¿cambia la detección si el material se prepara antes / si se usa ART?).
  - **⚠️ Anomalía nueva declarada:** el **re-escaneo SCA** tras el reinicio (ATA038) genera **18 filas `19010/19011`** que caen a `novel`→`deteccion` → **mismo patrón que `rule_id 11`** (artefacto del criterio congelado); **no compromete veredictos**; **no se toca el filtro**; **candidato a arreglo futuro**.
  - **Corpus homogéneo:** todas las técnicas con **fuente+motivo** y **material externo declarados**.
- **✅ AUDITORÍA METODOLÓGICA CERRADA (2026-10-01)** — auditoría de **los 43** (con citas que resuelven) + **3 criterios escritos** + arreglo del falso positivo + `.gitattributes`. **Sin atacar nada.**
  - **Auditoría (`Hojas/auditoria_origen.csv`, 43 filas):** **ART tal cual 5 · ART adaptado 1 · propio 37**. Motivos: `propio_por_diseno` 24 · `art_requiere_red_nube` 8 · `na_art_usado` 6 · `art_no_prueba_plataforma` 2 · **`no_se_comprobo` 2** (ATA029, ATA030: había prueba ART y no consta por qué no se usó) · `art_mecanismo_no_coincide` 1.
  - **📌 CANDIDATOS A REPETIR (decide el humano):** **por ART** → ATA024, ATA029, ATA030, ATA038 · **por pre-staging** → ATA014, ATA016, ATA029, ATA035, ATA036, ATA037, ATA038. *(2 ventanas cada uno; en bloque posterior.)*
  - **📘 NORMAS (`Soporte/Ataques/criterio_ataques.md`, 1 documento, neutro de plataforma):** **(A) ART** = usar si corre en la plataforma del laboratorio ∧ offline ∧ mismo mecanismo (citar `guid`+fichero+`commit`); si hay que adaptarla, anotarlo; si no → propio **+ motivo**; **se decide ANTES de atacar**. **(B) Ataque manual** = método paso a paso (técnica → *data components* → acciones → guardarraíles → C0 → prueba del efecto → validación). **(C) Pre-staging** = **cuándo** (falta algo que no está en el laboratorio) + **3 cómo** (antes de `t0` · pequeño y fijado con URL+`sha256` · nada de nubes → "no factible") + **un solo modo por técnica**. *(La norma es para los ataques NUEVOS; los 43 no se re-atacan.)*
  - **Las casillas** `fuente_norm`+`motivo_codigo`+`motivo_detalle` añadidas a **las 43 bitácoras** (aditivo).
  - **🔧 FALSO POSITIVO `rule_id 11` ARREGLADO** (con prueba): predicado **estrecho y al final** ("grupo `stats` + origen manager → `auto_ruido:stats`). **85/86 ventanas byte a byte idénticas**; **solo cambia ATA035_iter2** (2 líneas); `deteccion` **449→448**; **ATA035 sale de `review`**; **4 tests nuevos**; política **v7**; `pytest` **97**.
  - **🧰 `.gitattributes`**: `*.b64 binary` · `*.png binary` · `*.sh text eol=lf` — **sin `.csv`** (con `.csv` se rompían 97 huellas). **Clon: 420 → 376** desincronías (mejora 44, no empeora). **⚠️ Excepción aceptada por el humano:** *"un clon reproduce las 1.411 huellas"* **no es alcanzable** (EOL mezclados) → **bloque futuro: normalización + recálculo de huellas**.
  - **🗺️ Mapa ART regenerado:** `Hojas/cobertura_atomic.csv` **13 → 43 filas**.
  - **Verificación `tfg-tester`: PASA** (tras 1 FALLA: las citas apuntaban a un volcado temporal → **corregidas 43/43** con verificador propio).
- **✅ AMPLIACIÓN RONDA 2 CERRADA (2026-09-29; validación humana y revisión posterior) — 14 de 15 DETECTADAS (ATA029–ATA043).** Tanda A (T1005, T1560.001, T1667, T1565.001, T1491.001) **PASA** · Tanda B (T1560.003, T1056.004, T1565.003, T1561.001, T1529) **PASA** (4/5) · Tanda C (T1039, T1074.002, T1048.002, T1048.003, T1567.004) **PASA**. **C0 de los 15 sin silenciadores**; v2 `iguales` en 14 (ATA035 en `review`); **`dudosa=0`**; **0 filas del ataque en `ruido`**.
  - **⭐ EL HALLAZGO DEL TFG — "¿qué decide la detección?":** la **misma técnica de archivar** es **detectada** con **utilidad** (`tar`, ATA030), **suprimida** con **librería** (`python3`, ATA013) y **sin telemetría** con **método propio/builtins** (ATA034). → **Lo que decide es la IMPLEMENTACIÓN, no la técnica.**
  - **Otros:** capa nueva en ATA038 (el manager ve el cierre/arranque por el **estado del agente**: `503`/`506`); el HIDS ve el **proceso**, no el **mecanismo** (`LD_PRELOAD`, `ptrace`); **leer no deja rastro**; el **`syscheck` no vigila `lab-legit`** (la capa real fue el `watch`); **`audit_exe` = nombre REAL del binario** (lección aplicada).
  - **⚠️ Limitaciones declaradas:** (1) **`rule_id 11`** (alerta interna de Wazuh) contada como `novel`→`deteccion` en **2 de 86** ventanas → **falso positivo del criterio congelado** (no cambia veredictos; candidato a arreglo futuro); (2) **pivotes sin NAT** (el "recurso de red" → **daemon `rsync` local**; payloads de ATA035/036 **precompilados** y versionados como `.c`/`.b64`); (3) **riesgo CRLF en los `.b64`** (propuesta: `.gitattributes` mínimo — **pendiente de tu decisión**); (4) **`estado` = criterio PROCESAL**, no indicador de detección.
  - **Cifras del corpus (86 ventanas):** 83.625 filas · `deteccion` **449** · `artefacto_ataque` 2.045 · `ruido_conocido` 26.401 · `auto_ruido` 54.730 · `dudosa` **0**. **Por táctica: Impact 19/19 · Exfiltration 10/10 · Collection 12/14.**
  - **📌 R13 — DECISIÓN PENDIENTE (para ti):** la **piscina P1-Linux queda casi agotada** (~29 restantes, muchas no factibles sin NAT o con mecanismo repetido) → **abrir P2** o **dar P1 por cerrada** y pasar a **evasión / Windows / Fase 4 / memoria**.
- **✅ AMPLIACIÓN CERRADA (2026-09-29; validación humana y revisión posterior) — 15 técnicas nuevas (ATA014–ATA028), 15/15 DETECTADAS.** Tandas: **A** (recolección/integridad: T1114, T1213.006, T1114.003, T1657, T1056.001) · **B** (exfiltración: T1048.001, T1020, T1496.002, T1029, T1567.001) · **C** (sistema: T1531, T1496.001, T1056.003, T1565.002, T1561.002). Todas por `80792` anclado; **C0 de los 15 sin silenciadores**; v2 `iguales`; **`dudosa=0`**; **verificación PASA** en las 3 tandas (2 FALLA corregidos). **Cifras globales (56 ventanas):** 51.297 filas · `deteccion` **301** · `artefacto_ataque` 1.392 · `ruido_conocido` 15.504 · `auto_ruido` 34.100.
  - **⭐ Hallazgos:** (1) **ATA024/T1531 ejercita 4 capas** (`execve` + `watch /etc` + **FIM `550`** + **syslog `5901-5903`**, estas `novel`); (2) **audit registra el BINARIO REAL, no el nombre**: `nc`→`nc.openbsd`, `mkfs.ext4`→`mke2fs` → **declarar `audit_exe` con el nombre real o glob**; (3) **sin reglas de red/recursos** (el ancho de banda no se ve); (4) **cron sí alerta** por syslog (`2832`) y por `watch` del spool; (5) **`python3` refuerza su punto ciego** (`92600` suprime también el `watch`); (6) **leer no deja rastro** (`auditd -p wa`) → se detecta por el `execve` del lector.
  - **⚠️ Limitación nueva declarada:** *"0 filas del ataque en `ruido`"* se cumple **bajo la pertenencia por carpeta**; quedan fuera las filas de la **sesión** del ataque (**PAM/`sudo`, sin `cwd`**): **30** en ATA024, **4** en ATA027 (ruta URL-encoded), **1** en ATA026. **Ninguna es detección** y **no son corregibles** con la métrica congelada → declaradas en fichas, bitácoras y runbook §12.
  - **📌 NOTA — EVASIÓN (trabajo FUTURO, acordado):** cuando esté cubierta la **cobertura P1 en Linux**, se repetirán las técnicas en **versión DISFRAZADA** (misma acción envuelta en un **intérprete/renombrada/empaquetada**) para medir la **degradación** de la detección (*"¿aguanta cuando el atacante se esconde?"*). **Un solo disfraz, igual para todas** (para que se puedan comparar) y **dos versiones por técnica** (a la vista / disfrazada). **NO entra** en los bloques de cobertura.
  - *(Los dos bullets siguientes son los registros **parciales** escritos durante la ejecución.)*
- **🟡 AMPLIACIÓN · TANDA B EJECUTADA (2026-09-29, bloque `fase-03-ampliacion`) — ✅ verificada PASA (2026-09-29).** Las **5 técnicas de exfiltración/red** del plan (`ATA019`–`ATA023`) con **2 iteraciones** cada una = **10 ventanas**: **5/5 DETECTADAS**, todas por **`80792`** (`execve`, RS2), **C0 sin silenciadores**, **`dudosa=0`**, **0 filas del ataque en `ruido`**, doble iteración **v2 `iguales`**. Efecto demostrado por evidencia: **ATA019** blob **cifrado simétrico** (`openssl enc`) enviado por **TCP crudo** (`sink.log` sha256 idéntico + round-trip), **ATA020** 4/4 ficheros automatizados, **ATA023** 32 MiB acotados, **ATA021** transferencia programada por **cron** disparada dentro de la ventana, **ATA022** `git push` a **repo LOCAL** (`file://`, guardarraíl R6 respetado). **`pytest` 93.** Detalle en `Dataset/Ataques/Resultados/Wazuh/linux/ATA0{19,20,21,22,23}_meta.md` + `Bitacora/ATA0{19,20,21,22,23}.json`.
  - **⭐ Hallazgos tanda B:** (1) **R9 confirmado** (ATA023): Wazuh **no tiene reglas de red/recursos** → el ancho de banda **no se ve**, solo el `execve`. (2) **ATA021**: la capa **syslog de cron** sí alerta con **`2832`** (*Crontab entry changed*) y `/var/spool/cron` genera **`watch`** de fábrica (`80791`/`80782`) — **no declarados** → plegados a **`artefacto`**. (3) **Modo TCP** añadido al receptor (`sink_http.py --tcp-port`, retrocompatible). (4) **Churn del operador** (`cat`/`head`/`dash` `cwd=/` + PAM) resuelto a **`ruido`**; el **lanzador `/bin/sh` de cron** y los efectos sobre el repo `git` a **`artefacto`** (nunca `ruido`).
  - **Laboratorio cerrado:** receptor parado, **sin regla de firewall** (nunca se creó), **VMs apagadas**, víctima revertida a **`lab-listo`**, **NAT off**.
- **🟡 AMPLIACIÓN · TANDA C EJECUTADA (2026-09-29, bloque `fase-03-ampliacion`) — ✅ verificada PASA (2026-09-29).** Las **5 técnicas de sabotaje/sistema** (`ATA024`–`ATA028`) con **2 iteraciones** cada una = **10 ventanas**: **5/5 DETECTADAS**, todas por **`80792`** (`execve`, RS2); **C0 sin silenciadores**; **`dudosa=0`**; doble iteración **v2 `iguales`**; **`pytest` 93**; cadena de huellas **coherente (0 desincronías)**. **ATA024/T1531** ejercita **4 capas** (execve + **watch `/etc`** + **FIM `550`** + **syslog `5901/5902/5903`**, estas últimas **`novel`**); **ATA025/T1496.001** CPU al **100 %** acotado (R9: sin reglas de recursos); **ATA028/T1056.003** portal falso local (`nc`, evita `92600`) captura credenciales de juguete; **ATA026/T1565.002** proxy local reescribe **en tránsito** (el `sink.log` recibe el sha **manipulado**, ≠ original); **ATA027/T1561.002** **solo imagen loop** (estructura destruida, no montable, **0 loops residuales**). **⭐ Hallazgo de sistema:** audit registra el **binario real**, no el nombre de la orden → `nc`→`/usr/bin/nc.openbsd`, `mkfs.ext4`→`/usr/sbin/mke2fs` **no casan** (O2 1/2 y 6/7); declarar `audit_exe` con el **nombre real**/glob. **Guardarraíles:** usuario desechable **borrado**, **0** procesos `yes`, **0** loops, firewall **ausente**, VMs **apagadas**, NAT **off**.
- **✅ Señales ancladas (2026-09-28):** una señal de **`deteccion`** casa **solo si** `exe` **∧** el `cwd` casa el **ancla** del `esperado` **∧** es un **evento de ejecución**; **lo que no ancla → `dudosa`** (nunca descartado). **Recuento limpio:** ATA004 5→**3**, ATA007 4→**2**, ATA012 11→**6/7** (0 ajenas); **los 3 del piloto, byte a byte idénticos**; **86 tests**; `CA13` cerrado.
- **✅ RATIFICACIÓN HUMANA DE LOS 17 VEREDICTOS (2026-09-28):** las **13** de procesos ajenos (nuestro login) = **`ruido`**; las **4 escrituras del defacement** (ATA007) = **`deteccion`** (son el ataque; el doble conteo se evita con las **dos cifras**: *alertas* vs *`rule_id` distintos*). **ATA007 queda `deteccion=4`/ventana (1 evento, 3 `rule_id`)**; las otras 5 ventanas **byte a byte idénticas**. Bloque `fase-03-senales-ratificacion` CERRADO.
- **✅ MÉTRICA Y "PERTENENCIA AL ATAQUE" CERRADAS (2026-09-28, bloque `fase-03-metrica`):** (a) **métrica congelada** = **O1** `detectado=SÍ/NO` + **qué `rule_id`** + primera evidencia, y **O2** **acciones cubiertas `k/m`**; el nº bruto de alertas y los `rule_id` distintos quedan como **anexo**, nunca como resultado. (b) **Categoría nueva `artefacto_ataque`** = *"es del ataque, pero no es la detección de la técnica"* (pista floja), automática, **NUNCA `ruido`**; más **ancla por ruta** (`audit_file`/`audit_dir`/`syscheck_path`), **guardarraíl** (`veredicto=ruido` sobre fila del ataque → `exit 4` y no escribe) y **tercer veredicto humano `artefacto`**. (c) **Cifras:** `deteccion` **39 (sin cambios)**, `artefacto_ataque` **84** (78 automáticos + 6 humanos), `ruido_conocido` 1.836→**1.752**, **veredicto 5/1 intacto**; **0** filas del ataque en `ruido`. **93 tests.** Las 12 ventanas regeneradas; los 3 del piloto cubiertos **sin** editar sus `esperado`.
  - **⭐ Hallazgo del bloque:** la huella del propio ataque caía en `ruido_conocido` (`collected.tar.gz`, los procesos del guion…): **84 filas**. **ATA013 gana matiz:** el ataque **sí dejó 6 filas** en su carpeta; lo que no alerta es su señal (`python3`, suprimida por `92600`).
  - **⚠️ Limitaciones declaradas (memoria):** la pertenencia es **mecánica** (cubre `ATTACK_ROOT`); una fila del ataque fuera de ella (el `mkdir public_site` en `lab-legit`) **se atribuye por veredicto humano**; la **"pertenencia" NO es una detección del HIDS, es atribución post-hoc**; la **checklist (`esperado`) sigue siendo el punto débil** (se escribe antes y la valida el humano); los `-Revision.csv` son la **foto pre-plegado** (por eso sus conteos difieren del `-Audited`).
  - **⚠️ Anomalía de proceso:** la 1ª llamada al ejecutor **falló (HTTP 400) sin reportar pero dejó trabajo hecho**; la 2ª completó. Auditado por el tester: sin daño, sin nada prohibido tocado.
- **✅ TANDA A CERRADA (2026-09-29, bloque `fase-03-escalado`) — 4/4 DETECTADOS** con la métrica congelada: **ATA001/T1486** (cifrado, `openssl`) · **ATA006/T1565** (manipulación, `sed`) · **ATA005/T1561** (borrado, `dd`+`shred`) · **ATA003/T1490** (inhibir recuperación, `rm`). Todos detectados por **`80792`** (`audit_command`, RS2); **C0 sin puntos ciegos** (ningún silenciador); doble iteración v2 **`iguales`**; **0 filas del ataque en `ruido`**; efecto **demostrado por evidencia** (cifrado/descifrado con `sha256` idéntico, contenido manipulado, huella antes≠después, copias borradas); `pytest` **93**.
  - **✅ Normalización de criterio (2026-09-29):** las **4 escrituras de ATA007** pasan de `deteccion` a **`artefacto`** (`deteccion` 4→**2**, el `execve` del `cp`; **sigue DETECTADO**) → **regla única**: *el `esperado` declara; lo `ambigua` **nunca** es detección (efecto → `artefacto`)*. **ATA006** ratificado igual.
  - **✅ Realismo acotado declarado** (4 READMEs + runbook §10): *la técnica y el comando son reales; el alcance es de laboratorio y el entorno está "limpio" (sin usuarios/servicios reales); las rutas del ataque son conocidas por el analista*.
  - **Cifras del repo (20 ventanas):** `deteccion` **51**, `artefacto_ataque` **276**, `ruido_conocido` 2.141, `auto_ruido` 12.555. **10 ataques hechos / 3 pendientes (tanda B).**
- **✅ TANDA B CERRADA (2026-09-29) — 3/3 DETECTADOS → CORPUS COMPLETO (13/13 técnicas, 26 ventanas).** **ATA011/T1074** (staging, `mkdir`+`cp`) · **ATA009/T1567** (exfiltración por servicio web, `curl` → receptor; **`sha256` del `sink.log` idéntico** = el dato salió de verdad) · **ATA010/T1041** (canal C2, `curl` → `/c2/beacon`). Todos por **`80792`**; **C0 sin silenciadores**; v2 **`iguales`**; **`dudosa=0`** (ninguna fila que ratificar); laboratorio cerrado (receptor parado, sin regla de firewall, VMs apagadas).
  - **⭐ RESULTADO FINAL DEL CORPUS: 12 detectados / 1 no (ATA013)** — la única no detectada por **punto ciego de fábrica** (`92600` suprime el `execve` de `python3`), aunque el ataque **sí dejó 6 rastros** en su carpeta.
  - **Cifras del repo (26 ventanas):** filas **18.862** · `deteccion` **65** · `artefacto_ataque` **325** · `ruido_conocido` **2.146** · `auto_ruido` **16.326** · `dudosa` **0**. **`pytest` 93.** Regresión: las 20 ventanas previas **intactas**.
  - **Anomalía registrada:** un **primer intento de ATA011 iter1 se abortó a media ventana** (el prompt de `sudo` en `stderr` mató el job); se **descartó y repitió**, y el tester confirmó **0 residuo** (una sola ráfaga en `[t0,t1]`, sin solapes, sin duplicados).
- **⚠️ Riesgo latente (integridad):** `core.autocrlf=true` **sin protección de los CSV** → un `git checkout`/`stash`/`reset --hard`/clon reescribe finales de línea y **rompe la cadena de huellas**. **Estado (2026-10-01):** existe **`.gitattributes`** (`*.b64 binary` · `*.png binary` · `*.sh text eol=lf`) — **NO** incluye los `.csv` (con `*.csv eol=lf` se **rompen 97 huellas**: están CRLF en disco y LF en git). **Un clon NO reproduce las 1.411 huellas** (420 sin el fichero → 376 con él; **excepción aceptada**). **Bloque futuro: normalizar finales de línea + recalcular huellas.** **NO hacer `checkout`/`stash` sobre `esperado`/`Audited`.**
- **✅ Cabos de cierre HECHOS (2026-09-28):** (a) el hallazgo del **`40700` CONFIRMADO en vivo** (`level="0"` leído en el manager; salida literal en la ficha de ATA004 §8.1); (b) corregidos los **4 textos residuales** (docstring de `filtrar_ruido.py` ×2, `piloto_procedimiento.md`, `T1489/README.md`); (c) añadido **`.gitattributes`** (`*.csv`/`*.json` → `eol=lf`) → los **`sha256` de los 9 ficheros no cambian**; (d) matizada en la ficha de ATA004 la descripción de las reglas hermanas del `40700` (alertan **`40702`-`40704`**; `40701` también es nivel 0; `40705` es cambio de hora).
- **🎯 Resultados del piloto-custom (el camino "ataque manual" — 2 escritos por nosotros + 1 de ART):** los **3 se DETECTAN** (veredicto v2 `iguales`): **ATA007/T1491** (Defacement), **ATA012/T1119** (Automated Collection) y **ATA004/T1489** (Service Stop). **Cifra limpia = 1 evento (`80792`, el `execve`) por ataque**; el resto de alertas es **redundancia** o **ruido ajeno**. **0 sorpresas** (`novel`) en las 6 ventanas.
- **⭐ Hallazgo 1 (diseño): el ancla de H4 NO funciona.** El patrón `…/ATA<NNN>/*` no casa el `cwd` real (sin barra) y, **aunque se corrija, no puede anclar**: el filtro evalúa las señales como **OR**, no como `exe AND cwd`. **H4 es aspiracional, no un mecanismo.**
- **⭐ Hallazgo 2: las señales por `audit_exe` son ANCHAS** → cuentan como detección **procesos ajenos** (los `find` de `update-motd.d` y los `systemctl --user` del **login/cierre del operador**) y **promueven a `deteccion` las escrituras** que el plan quería `ambigua` (**CA13 no se cumple**).
- **✅ Hallazgo 3 (arreglado): gap de despliegue** — el `extraer_alertas.py` **del manager estaba obsoleto** → el predicado `OPERADOR` (H3) no funcionaba. Desplegado (sha = repo) y re-extraído. **Lección:** repo y manager **en sincronía** (desplegar antes de medir).
- **🎯 Primeros resultados reales (Wazuh de fábrica, RS2):** **ATA002 (T1485) DETECTADO** (4·4) · **ATA008 (T1048.002) DETECTADO** (2·2, exfiltración **confirmada** por `sha256`) · **ATA013 (T1560.002) NO DETECTADO** (0·0). Los 3 en `review` por **ruido de arranque** (detecciones idénticas).
- **⭐ Hallazgo principal (ATA013):** **punto ciego de fábrica** — la regla del propio Wazuh **`92600` (nivel 0)**, **hermana** de `80792` (mismo grupo `audit`), **suprime** la alerta del `execve` de `python3` → **mimetiza** el fenómeno del pre-flight, pero **sin reglas nuestras**. **Mejora:** el **pre-flight C1 no cubre base-contra-base**.
- **Paso:** **laboratorio Wazuh operativo y baseline grabado.** Wazuh **4.14.7** (manager/indexer/dashboard `active`; agente 001 `victima-linux` `active`); **detección-only**; **4 capas** con `active_ruleset.txt` **sin colisiones** (RS3 y RS4 **vacías** en Fase 2, declarado); **NAT desconectado**; snapshot **`lab-listo`** en ambas VMs; **baseline de 2 ventanas × 4 h** → catálogo agregado **12 `rule.id`, 13.574 alertas, 0 UNKNOWN, ruido ESTABLE** (v1 6.837 / v2 6.737). Acceso y `vmrun` documentados (`ssh_setup.md`, `vmrun_config.md`).
- **Hallazgo principal:** **~54% del ruido es auto-ruido del propio HIDS** — `80791` de **`wazuh-agentd`** reescribiendo su estado cada ~5 s (≈2.877 alertas por ventana) + `80792` de hijos de **`wazuh-syscheckd`** y **`wazuh-logcollector`** (cwd `/var/ossec`, ≈806). **Es la cifra válida como base de filtrado de FP** (el 88,6% es solo la cuota de esas dos reglas, **no** auto-ruido).
- **Siguiente acción:** 1) **las ~29 técnicas restantes de Linux, sin evasión** (con las normas ya escritas: cada ataque nace con **fuente+motivo** y **material externo** declarados); 2) **bloque futuro anotado: normalización de finales de línea + recálculo de huellas**; 3) **candidatos a arreglo futuro del filtro**: `rule_id 11` (arreglado ✔) y **`19010/19011` (SCA)** — mismo patrón; 4) **EVASIÓN** → **Windows** → **Fase 4** → **memoria**. **Corpus: 43 técnicas (+9 repeticiones), 41 detectadas.**
- **⚠️ Cabos del afinado (aplicar al escalar):** (1) arreglar el **default de `--out`/`--rev-out`** de `filtrar_ruido.py` (hoy apunta **sin `linux/`**); (2) **reconfirmar `OPERADOR_SRCIPS`** (`192.168.65.1`) en cada arranque del laboratorio; (3) **producir una captura C0 por técnica** antes de medir; (4) ojo con las **señales `rule_group` amplias** (las PAM de un atacante caerían en `baseline`); (5) añadir puntero en el runbook §6 (frase histórica).
- **✅ Hecho (2026-09-25) — bloque `fase-03-filtro` (A2.1):** herramienta **`filtrar_ruido.py`** que etiqueta cada alerta como `deteccion` / `ruido_conocido` / `auto_ruido` / `dudosa` (con **revisión humana trazable**), política escrita (`politica_filtrado_ruido.md`) y **27 tests en verde**. Criterio validado contra el baseline: **0 detecciones** sobre las dos ventanas.
- **✅ Hecho (2026-09-25) — bloque `fase-03-preflight` (A2.2):** herramienta **`preflight_enmascaramiento.py`** (el "examen" de nuestras reglas): **C1** cadena `<if_sid>` (offline) y **C2** hermana (diferencial con `wazuh-logtest`); declaración de solapamientos en `solapamientos_declarados.csv`; **solo `exit 0` permite desplegar**; **46 tests en verde**. **🔎 Hallazgo: el caso "hermana" queda DEMOSTRADO** — una regla **sin** `<if_sid>` (solo `if_group`+`match`) **también suprime** la base, y ese patrón lo usa el **propio ruleset de Wazuh** (regla real `80790`). El manager quedó **restaurado y verificado**.
- **✅ Hecho (2026-09-25) — bloque `fase-03-atomic` (A2.3):** **Atomic Red Team** clonado en `Soporte/Ataques/atomic-red-team/` (pin `388942a…`, 344 técnicas, **ignorado por git**; sidecar con URL+commit) + **mapa de cobertura** `Hojas/cobertura_atomic.csv` (**recomputado de forma independiente y coincide 13/13**). **🔎 Resultado: 7/13 cubiertas en Linux**; 4/13 **solo Windows** (`T1490`, `T1491`, `T1041`, `T1119`) y 2/13 **sin pruebas** (`T1561`, `T1565`) → **6/13 requerirán script propio**. **No se ejecutó ninguna prueba atómica** (aprobado así). **58 tests en verde.**
- **📌 Distinción documentada (para la memoria):** *"la técnica no aplica a Linux"* ≠ *"la biblioteca no la cubre en Linux"*. En los 4 de "solo Windows" **la técnica sí vale en Linux** → se escriben a mano, **no se excluyen**.
- **⚠️ Cabo a revisar en Fase 3 (del pre-flight):** el manifiesto tiene **rangos solapados** (RS1 fortigate 44600–81646 **cubre** el subrango RS2 80700–80794) → **la etiqueta RS podría ser incorrecta** para una regla fortigate en ese subrango. **Comprobar si afecta al recuento por capas.**
- **⚠️ REGLA OPERATIVA para la Fase 3:** las alertas se extraen del **fichero diario** (`/var/ossec/logs/alerts/<AAAA>/<Mes>/ossec-alerts-<DD>.json`), **NO** de `alerts.json` (solo contiene el día en curso y se reinicia al arrancar el manager).
- **⚠️ Cabo conocido del filtro:** depende del **fichero de señales esperadas por ataque** (`ATA<NNN>_esperado.csv`, se redacta **antes** de atacar y **lo valida el humano**). **Es el punto donde se puede sesgar el resultado** y añade trabajo por ataque.
- **🔴 ANTES de la primera regla RS3 de Fase 3:** ~~construir el pre-flight~~ **✅ HECHO en A2.2** (y el caso "regla hermana" **demostrado**). **Se sigue aplicando la norma:** toda regla propia nueva pasa el examen antes de desplegarse.
- **Deuda menor:** la autenticación por **clave** en el nivel 1 (portátil→sobremesa) **no está habilitada** (`administrators_authorized_keys` no existe) → hoy funciona **por contraseña**, y así está declarado en `ssh_setup.md`.
- **Limitaciones declaradas del baseline:** actividad **sintética** (servidor sin usuario humano); 2×4 h (no cubre ciclos semanales/mensuales); el catálogo es un **superconjunto** del ruido esperable durante un ataque (el script no correrá en Fase 3) → usarlo como **referencia acotada**, no como oráculo de FP; y la comparación v1/v2 mide **determinismo del procedimiento**, no variabilidad humana.
- **Decisión humana (2026-09-23):** baseline en **DOS ventanas de 4 h en horas distintas** (noche + tarde) para cubrir mejor el ciclo diario y poder medir la **estabilidad del ruido**. La 1ª incluye el mantenimiento diario (~06:25); la 2ª no.
- **G1/G2 fijados:** **Wazuh 4.14.7** (heap del indexer 1 GB); RuleSets aprobados con **RS4 vacía** (en Fase 3 se probarán reglas externas **curadas**, con `lab-listo` como red de seguridad).
- **Desviaciones y erratas registradas:** ver `_fases/fase-02/plan.md` **§12** — resize del LV (24→48 GB, **aceptada**); el agente **sí** traía `<active-response>` de fábrica; **`wazuh-execd` no es unidad systemd** (daemon interno; vuelve en cada reinicio del manager, pero es **inerte**); el algoritmo de clasificación por rango era imposible → **por fichero de origen**; la regla *smoke* `100000` **retirada antes del baseline** por enmascarar RS1.
- **Verificado antes de la ventana 1:** el *vulnerability-detector* del manager **no puede descargar CVE** (sin NAT) pero **solo produce errores de log, 0 alertas** → se deja intacto y documentado (no contamina el catálogo).
- **⚠️ Norma anti-enmascaramiento (aprobada 2026-09-23, `rulesets_diseno.md` §9):** Wazuh emite **una alerta por evento**; una regla propia que case el mismo evento (**hija o hermana**) **suprime** la detección base. Prohibido `<if_sid>` sobre base que se quiera conservar; verificación obligatoria con `wazuh-logtest -v`; recuento `RS1∩RS3` declarado; aplica también a RS4 y cadenas multinivel.
- **🔴 PENDIENTE OBLIGATORIO antes de escribir la primera regla de Fase 3:** construir el **pre-flight** del §9.8 (script que detecta si una regla RS3 con `<if_sid>` cuelga de una base RS1 y **falla** salvo solapamiento declarado). Hoy es **solo un compromiso escrito**: el script **no existe**. Y, si se quiere certeza, **comprobar empíricamente el caso "regla hermana"** (hoy solo está razonado, no demostrado en el laboratorio).
- **⚠️ Timestamps de Wazuh en UTC** (`+0000`) aunque las VMs estén en Madrid → las ventanas `t0`/`t1` y `extraer_alertas.py` deben trabajar en **UTC**.
- **⚠️ Detalle del snapshot:** `lab-listo` se tomó **antes** de alinear `/etc/timezone` (la zona efectiva ya era correcta) → ese fichero legacy dice `Etc/UTC` dentro del snapshot; **sin efecto práctico**.
- **⚠️ EL REPOSITORIO ES PÚBLICO** (confirmado por el humano el 2026-09-23): extremar la **higiene de secretos**. Auditoría del **historial completo** (2026-09-23): la contraseña del laboratorio, claves privadas y ficheros de credenciales **nunca** se han versionado ✔. Aun así: **jamás** escribir secretos en ficheros del repo.
- **Pendiente de Fase 1:** presentar el **hito H1** al tutor.
- **⏳ PENDIENTE DE LA TUTORÍA (decisiones abiertas):**
  - **Tamaño final del corpus**: los **13** actuales son la **primera tanda**; el TFG tendrá **decenas o cientos** de ataques solo para Wazuh. Hay que confirmar el alcance.
  - **Precio de la detección**: ¿se acepta medirlo en **ataques representativos** (declarándolo como limitación), o lo quiere en todos?
  - **Windows** como víctima: ¿se necesita para alguna técnica, o todo en Linux?
  - **Hitos H1 y H2**: siguen sin presentar.
  - ⚠️ **Cifras desfasadas a corregir cuando se confirme el alcance:** `context.md` §3, `roadmap.md` (Fase 3) y `requirements.md` (T-03) siguen diciendo **"12-15 técnicas"**. **No se tocan hasta tener la cifra real** — cambiar un número inventado por otro no arregla nada.
- **✅ DECIDIDO (2026-09-24):** el **corpus CRECE** (los 13 son la primera tanda, no el total del TFG); el **precio de la detección se mide SOLO en la Fase 4** y con **ataques representativos** (**cuántos y cuáles → al principio de la Fase 4**; si sobra tiempo, se amplía); **la Fase 3 NO se instrumenta** — un medidor dentro de la víctima generaría telemetría falsa (auditd captura cada `execve`) y **ensuciaría el recuento de detecciones**, que es el resultado principal.
- **⏭️ NOTA PARA EL FUTURO — plan de sistemas operativos (2026-09-25):**
  - **Ahora: SOLO Linux** — las técnicas **de Linux** y las **híbridas**, en Linux.
  - **Después (si la tutoría lo pide y hay tiempo): Windows** — las técnicas **de Windows** y las **híbridas otra vez** (cada ataque **en secuencia**, nunca Linux y Windows a la vez).
  - **Convención de carpetas** (para que los datos futuros **nazcan ordenados**, sin mover nada después): `Dataset/Legitimo/<so>/…` y `Dataset/Ataques/Resultados/Wazuh/<so>/…`. *(El baseline actual se queda donde está; se mueve el día que Windows se confirme.)*
  - **Dos ganchos a recordar al montar Windows:** (1) `filtrar_ruido.py` lleva dentro supuestos **de Linux** (los procesos del propio Wazuh y los nombres de campo `audit.*`/`syscheck.*`) → habrá que añadir su equivalente; (2) el **baseline** habrá que **partirlo por sistema**.
  - **Nada de esto urge:** las tres preparaciones (código, carpetas, redacción) se **dejan conscientemente**; coste estimado al hacerlas: **~1 h**.
- **Decisiones humanas fijadas (2026-09-19):**
  - Interpretación **amplia** del filtro inverso (DC de red no elegibles pero no anulan host; T1039).
  - **T1046 = híbrida/válida** (ratificada; caso red pura → T1595).
  - **STIX en gitignore** + commit de URL/`.sha256` (repo ligero).
  - `Hojas/Mapeos.xlsx` **diferido** a Fase 3/5.
  - **Corpus = 13 técnicas** (7 Impact / 3 Exfiltration / 3 Collection) → **primera tanda**; el corpus final será **mayor** (ver "Pendiente de la tutoría").

## Fase 0 — CERRADA ✔

- Commit local: `865ee17 Fase 0: arquitectura de agentes del TFG y planificacion slim`.
- Arquitectura de agentes y roadmap slim revisados por el humano. Sin push.

## Fase 1 — Corpus MITRE — CERRADA ✔

- Entregables: `_artefactos/mitre/enterprise-attack-v19.1.json` (+ `.sha256`),
  `_artefactos/scripts/extraer_tecnicas_host.py` + tests, `Hojas/corpus_host.csv`
  (697 técnicas; **625 host-eligible**), `Hojas/lista_tecnicas_validas.md`,
  `Hojas/ATA_index.csv` (**13 técnicas**).
- Verificación `tfg-tester`: **PASA** (15 tests, reproducibilidad byte a byte). Detalle en `_fases/fase-01/change-doc.md`.
- **Commit local:** `cfeaa3a Fase 1: corpus MITRE v19.1 (filtro inverso host) y 13 tecnicas seleccionadas`.
- Pendiente: **hito H1** al tutor (el `push` lo hace el humano).

## Fase 2 — Laboratorio Wazuh (F-02) — CERRADA ✔ (2026-09-23)

- **Plan v2 aprobado** (commit `afeb1d6`) y **repo clonado** en el sobremesa (`D:\TFG\...`).
- **Hipervisor:** VMware Workstation **Pro 26H1** en el sobremesa (Windows 10, 16 GB, VMs en `D:\TFG-VMs`).
- **Red:** `VMnet1` = `192.168.65.0/24` (las VMs se ven entre sí y con el host); adaptador **NAT** añadido para instalar y dejado **desconectado** (en operación normal, solo `VMnet1` activa).
- **VMs** (Ubuntu Server **24.04.5 LTS**, usuario `angel`, snapshots `base-limpia` y `lab-listo`):

  | VM | IP | vCPU | RAM | Disco |
  |---|---|---|---|---|
  | `wazuh-server` | `192.168.65.128` | 2 | 6 GB | 50 GB |
  | `victima-linux` | `192.168.65.129` | 2 | 3 GB | 20 GB |

- **Wazuh 4.14.7 operativo** (manager/indexer/dashboard + agente `victima-linux` `active`); detalle en **`_fases/fase-02/change-doc.md`**.
- **Documentación T-04:** `Soporte/Laboratorio/README.md` + `topologia.png` + `topologia.mmd` ✔
- **Verificado:** ping cruzado entre VMs OK; snapshots `base-limpia` y `lab-listo` hechos.
- **Acceso:** portátil → sobremesa por **SSH sobre Tailscale** (`100.82.127.119`, usuario `angel`); los **agentes (opencode) corren en el sobremesa**. OpenSSH Server en Windows 10 habilitado ✔

## Tareas transversales pendientes

- [ ] (Más adelante) Redactar la **declaración de uso de IA** para la memoria (ver `Soporte/Normativa_IA.md`).

## Cortes / incidencias

- (ninguno)

## Historial de sesiones

- **Sesión 1:** diseño del planteamiento y ejecución de la Fase 0 (docs slim + agentes).
- **Sesión 2:** revisión de la Fase 0 + limpieza (nombres y restos heredados) + investigación de
  las políticas de IA de la ETSI/US.
- **Sesión 3:** Fase 1 completa — STIX v19.1, script de filtro inverso + tests, corpus (697 →
  625 host-eligible) y **selección humana de 13 técnicas**; verificación PASA y cierre.
- **Sesión 4:** montaje del laboratorio (2 VMs Ubuntu + snapshots) y **acceso remoto**
  (Tailscale + OpenSSH en Windows 10); decisión de que los **agentes corran en el sobremesa**;
  `_fases/fase-02/plan.md` de Fase 2 → **v2** (pendiente de aprobación).
- **Sesión 5:** retomada **en el sobremesa (Windows 10)**: plan v2 **aprobado** (commit `afeb1d6`),
  repo **clonado y limpio**, recon del laboratorio (`vmrun` localizado, VMs apagadas). Siguiente:
  tarea **2.3** (versión Wazuh + NAT temporal + IPs fijas).
- **Sesión 6:** permisos de los agentes pasados a **V2** (allow por defecto + lista negra concreta;
  el campo heredado `temperature` los invalidaba en silencio). **Tarea 2.3** hecha (NAT + IPs
  fijas + internet verificado). **T-05 (2.4/2.5)** hecha: **Wazuh 4.14.7** all-in-one y agente
  `victima-linux` **active**, con smoke test `rule.id 5710` OK. **Verificación del tester: PASA**
  (con matices: resize del LV fuera de encargo, `unattended-upgrades` sin decidir, basura `NUL`).
  G1 fijado: 4.14.7 + heap del indexer a 1 GB.
- **Sesión 7:** **T-07 completo (2.6/2.7/2.8)** y **2.9**. Modo **detección-only** verificado y
  **actualizaciones automáticas desactivadas**. Gate **G2 aprobado** (RuleSets RS1..RS4; **RS4 vacía**,
  a probar en Fase 3 con reglas externas curadas). `active_ruleset.txt` **sin colisiones**.
  **NAT desconectado** de forma persistente, relojes alineados y **snapshot `lab-listo`** en ambas VMs.
  Hallazgos importantes: el agente **sí** traía `<active-response>` de fábrica; `wazuh-execd` **no** es
  unidad systemd; el algoritmo de clasificación por rango era **imposible** → **por fichero de origen**;
  y **la regla *smoke* `100000` enmascaraba `5710`** → **retirada antes del baseline** y norma
  **anti-enmascaramiento** escrita (`rulesets_diseno.md` §9). Erratas registradas en `_fases/fase-02/plan.md` §12.
- **Sesión 8:** **baseline completo y Fase 2 CERRADA.** Baseline en **2 ventanas × 4 h** (noche
  `00:45–04:45Z` y tarde `12:00–16:00Z`): **12 `rule.id`, 13.574 alertas, 0 UNKNOWN, ruido
  ESTABLE**. Hallazgo: **~54% del ruido es auto-ruido del propio HIDS**. Verificaciones del tester
  **PASA** (con correcciones de atribución y etiquetado aplicadas). Tareas 2.11 (documentar acceso
  y `vmrun`) y 2.12 (cierre) completadas; `_fases/fase-02/change-doc.md` escrito y `roadmap.md` actualizado.
  VMs apagadas limpiamente con los snapshots `base-limpia` y `lab-listo` conservados.
- **Sesión 9:** **gestión de agentes y planes** (permiso de inspección al planificador; convención
  **"la unidad es el plan"** → bloques archivados en `_fases/<bloque>/`) y **primer bloque de la
  Fase 3 cerrado**: **`fase-03-filtro` (A2.1)**, la herramienta de filtrado de ruido, con
  verificación **PASA**. Hallazgo: **`alerts.json` rota a diario** → en Fase 3 hay que extraer del
  fichero diario.
- **Sesión 10:** **segundo bloque de la Fase 3 cerrado**: **`fase-03-preflight` (A2.2)**, el examen
  anti-enmascaramiento, con verificación **PASA** y el **caso "hermana" DEMOSTRADO empíricamente**
  (una regla sin `<if_sid>` también suprime la base; el propio ruleset de Wazuh usa ese patrón).
- **Sesión 11:** **tercer y último bloque de preparación cerrado**: **`fase-03-atomic` (A2.3)** —
  Atomic Red Team clonado y **fijado** (pin `388942a…`, ignorado por git, sidecar versionado) y
  **mapa de cobertura** de las 13 técnicas: **7/13 cubiertas en Linux**, 4/13 solo Windows, 2/13 sin
  pruebas → **6/13 requerirán script propio**. **No se ejecutó ninguna prueba atómica.** Verificación
  **PASA**. **La preparación de la Fase 3 queda terminada**: el siguiente paso es **el piloto de ataques**.
- **Sesión 12:** **PILOTO DE ATAQUES CERRADO**: **3 ataques × 2 iteraciones** (ciclo completo por primera
  vez). Resultados: **ATA002 DETECTADO**, **ATA008 DETECTADO** (exfiltración confirmada por `sha256`) y
  **ATA013 NO DETECTADO**. **⭐ Hallazgo: un punto ciego de FÁBRICA** (la regla `92600` del propio Wazuh
  suprime la base para `python3`). Los 3 en `review` por el **ruido de arranque**. Verificación del tester
  **15/16 PASA** (la única FALLA —el **registro** del gate humano— subsanada). **4 mejoras anotadas (H1–H4)**
  para el escalado. Cierre operativo hecho (firewall retirado, receptor parado, víctima revertida).
- **Sesión 13:** **AFINADO CERRADO (H1–H4)** antes de escalar: **H1** chequeo **C0 base-contra-base** en el
  pre-flight (golden real: `python3`→`92600` nivel 0 → **avisa**; `ls`→`80792` → no); **H2** criterio de doble
  iteración **v2** (la detección decide; sanidades a aviso; **ventana completa**, `t0` tras el asentamiento);
  **H3** el filtro **solo auto-excluye lo demostrable** (`5715` con `srcip` del operador; **`5501/5502` → `dudosa`** *(matizado en `fase-03-cabos`: solo si el `esperado` no declara campos siempre evaluables; si los declara → `baseline`)*;
  `19004` por grupo) — **prueba de seguridad reproducida**: detecciones intactas y **0 falsos negativos**;
  **H4** convención de señales (`audit_exe`+`audit_cwd`). **75 tests en verde** y **el piloto intacto (18/18 hashes)**.
  Verificación **PASA**.
- **Sesión 14:** **PILOTO-CUSTOM CERRADO** (el camino "ataque escrito por nosotros"): **ATA007/T1491** y
  **ATA012/T1119** (manuales) + **ATA004/T1489** (ART), **2 iteraciones** cada uno → **los 3 DETECTADOS**
  (v2 `iguales`), con **0 sorpresas**. **Hallazgos:** el **ancla de H4 no funciona** (señales **OR**, no AND);
  las **señales por `audit_exe` son anchas** (cuentan procesos ajenos del login del operador); y un **gap de
  despliegue** (el extractor del manager estaba obsoleto → H3 inerte) **arreglado** con la lección de sincronía.
  Verificación **PASA** con **2 no-conformidades de diseño** (`CA13` y H4) a corregir antes de escalar.
- **Sesión 15:** **CABOS CERRADOS (4 arreglos de registro)**: cita a un fichero inexistente corregida; cabeceras de
  los 3 `esperado` con la **validación humana** (y **6 audited regenerados**, cifras **idénticas**); texto de las
  PAM corregido; y **hallazgo resuelto**: la regla de fábrica **`40700` es `level=0`** → **parar un servicio no
  alerta** de fábrica (la expectativa era imposible, no silenciada). Verificación **PASA**. **⚠️ Detectado riesgo
  `autocrlf`** (rompería la cadena de hashes) y quedan **2 cabos pequeños** de cierre.
- **Sesión 16:** **3 bloques cerrados**: **`fase-03-gitattributes`** (se intentó blindar el repo con
  `.gitattributes`; **rompía un binario y las huellas** → **revertido** y la limitación documentada);
  **`fase-03-senales`** (arreglo de fondo: una señal `deteccion` casa solo si `exe` **∧** `cwd` anclado **∧**
  evento de ejecución; lo que no ancla → `dudosa`; retrocompatibilidad byte a byte de los pilotos); y su
  **ratificación** (17 veredictos: 13 ajenos → `ruido`; 4 escrituras del defacement → `deteccion`).
- **Sesión 17:** **`fase-03-metrica` CERRADA** — se congela la **métrica** (SÍ/NO + regla + acciones `k/m`),
  se crea la categoría **`artefacto_ataque`** ("es del ataque, pero no es la detección": **nunca `ruido`**)
  con **ancla por ruta** + **guardarraíl** + **veredicto humano `artefacto`**, y se regeneran las 12 ventanas.
  **84 filas** del ataque salen de `ruido` (78 automáticas + 6 humanas); `deteccion` **39 sin cambios**;
  **veredicto 5/1 intacto**. **2 FALLA del tester corregidos** (el `mkdir` de ATA007; 8 cabeceras
  `-Revision` obsoletas y el autocita de ATA008, que resultó **sí corregible**). **PASA.** 93 tests.
  **Métrica congelada: no se vuelve a tocar cómo se cuenta.**
- **Sesión 18:** **`fase-03-escalado` CERRADA — CORPUS COMPLETO (13/13 técnicas, 26 ventanas)**: **TANDA A**
  (ATA001/T1486, ATA006/T1565, ATA005/T1561, ATA003/T1490) y **TANDA B** (ATA011/T1074, ATA009/T1567,
  ATA010/T1041) → **7/7 DETECTADOS**, todos por `execve` anclado (`80792`) y con **C0 sin silenciadores**.
  **RESULTADO FINAL: 12 detectados / 1 no (ATA013**, punto ciego de fábrica `92600`; el ataque **sí** dejó 6
  rastros). **Normalización de criterio:** las escrituras de **ATA007** pasan a `artefacto` (sigue detectado) y
  **ATA006** se ratifica igual → **regla única**. **Prueba estrella del efecto:** `sha256` del `sink.log` ==
  `sha256` del dato (el dato **salió de verdad**). **Realismo acotado declarado** (7 READMEs + runbook §10).
  Verificación **PASA** en las 2 tandas; **0 residuo** del intento abortado de ATA011 iter1; 93 tests.
  **Cifras del repo:** 18.862 filas · `deteccion` **65** · `artefacto_ataque` **325** · `ruido_conocido` **2.146**
  · `auto_ruido` **16.326** · `dudosa` **0**. **Dos llamadas al ejecutor fallaron con HTTP 400 dejando trabajo
  hecho** (auditado).
- **Sesión 19:** **AMPLIACIÓN · TANDA B ejecutada** (bloque `fase-03-ampliacion`; pendiente de `tfg-tester`):
  **ATA019/T1048.001** (cifrado **simétrico** + **TCP crudo**), **ATA020/T1020** (exfiltración **automatizada**),
  **ATA023/T1496.002** (bandwidth **acotado**), **ATA021/T1029** (**cron** de usuario) y **ATA022/T1567.001**
  (`git push` a **repo local**). **5/5 DETECTADAS** por `80792`; v2 **`iguales`**; **`dudosa=0`**; **0 filas del
  ataque en `ruido`**; **`pytest` 93**. **Modo TCP** añadido al receptor (`--tcp-port`, retrocompatible). **Hallazgo
  R9 confirmado** (sin reglas de red/recursos → solo `execve`) y **`2832`/`watch` de cron** no declarados →
  `artefacto`. Laboratorio cerrado (receptor parado, firewall ausente, VMs apagadas, NAT off).
- **Sesión 20:** **AMPLIACIÓN · TANDA C ejecutada** (bloque `fase-03-ampliacion`; pendiente de `tfg-tester`): **ATA024/T1531** (cuenta desechable, 4 capas), **ATA025/T1496.001** (CPU acotada), **ATA028/T1056.003** (portal falso local), **ATA026/T1565.002** (manipulación en tránsito) y **ATA027/T1561.002** (wipe de SOLO imagen loop). **5/5 DETECTADAS** por `80792`; v2 `iguales`; `dudosa=0`; 0 filas del ataque en ruido; pytest 93; cadena de huellas coherente. Hallazgo de sistema: symlinks (`nc`/`mkfs.ext4`) no casan con `audit_exe`. Lab cerrado (usuario desechable borrado, 0 loops, firewall ausente, VMs apagadas, NAT off).
- **Sesión 21:** **`fase-03-ampliacion` CERRADA (con validación humana; revisión posterior)** — **15 técnicas nuevas (ATA014–ATA028) en 3 tandas**, todas **DETECTADAS**: **Tanda A** (T1114, T1213.006, T1114.003, T1657, T1056.001) **PASA** · **Tanda B** (T1048.001, T1020, T1496.002, T1029, T1567.001) **PASA** tras **1 FALLA** (una fila PAM mal plegada en ATA021) · **Tanda C** (T1531, T1496.001, T1056.003, T1565.002, T1561.002) **PASA** (con cabos de documentación). **Corpus: 28 técnicas / 56 ventanas → 27 detectadas / 1 no.** **Regresión byte a byte de las 26 ventanas previas**; `pytest` **93**; **auditor nuevo** `auditar_cadena_huellas.py` (915 citas) y **1 huella desincronizada corregida** (ATA001). **Limitación nueva declarada** (filas de la *sesión* del ataque en `baseline`) y **📌 nota de evasión** para el futuro. *(Con validación humana registrada y revisión posterior.)*
- **Sesión 22:** **`fase-03-ampliacion-2` CERRADA (ronda 2)** — **15 técnicas nuevas (ATA029–ATA043), 14 DETECTADAS**, en **3 tandas de 5** (las 3 **PASA**). **Corpus: 43 técnicas / 86 ventanas → 41 detectadas / 2 no** (ATA013 y **ATA034**). **⭐ Hallazgo del TFG:** *la misma técnica de archivar es **detectada** con utilidad, **suprimida** con librería (`92600`) y **sin telemetría** con método propio* → **lo que decide la detección es la implementación**. Capa nueva en ATA038 (estado del agente `503`/`506`); el HIDS ve el proceso, no el mecanismo; `rule_id 11` (FP del criterio congelado, declarado); pivote a **daemon `rsync`** sin NFS/SMB; **`.b64` con riesgo CRLF** (pendiente de decisión). **R13: P1-Linux casi agotada** → decidir P2 o cerrar P1. `pytest` **93**; auditor de huellas: **1.411 citas, 0 desincronías**.
- **Sesión 23:** **`fase-03-auditoria-metodologica` CERRADA (auditoría de los 43 + criterios)** — **sin atacar nada**. **Auditoría:** ART tal cual 5 · adaptado 1 · propio 37; **`no_se_comprobo` 2** (ATA029/030: había prueba ART y no consta el porqué). **Las 2 listas de repetir:** por ART (ATA024/029/030/038) · por pre-staging (ATA014/016/029/035/036/037/038). **3 criterios escritos** en `Soporte/Ataques/criterio_ataques.md` (ART · ataque manual · pre-staging), **neutros de plataforma**. **Falso positivo `rule_id 11` arreglado con prueba** (85/86 ventanas idénticas; `deteccion` 449→448; ATA035 sale de `review`). **`.gitattributes`** creado (3 líneas, sin `.csv`); **clon: 420→376** (mejora); **excepción aceptada** + **bloque futuro de normalización**. **Mapa ART 13→43.** Verificación **PASA** (tras 1 FALLA: citas corregidas 43/43). `pytest` **97**.
- **Sesión 24:** **`fase-03-repeticiones` CERRADA — 9/9 DETECTADAS.** Las 9 que marcó la auditoría (**ART:** ATA024/029/030/038 · **pre-staging:** ATA014/016/029/035/036/037/038; **unión = 9**), con el **original intacto** y la repetición **añadida** con sufijo **`_rev`** (**canónica** para esas 9; `Hojas/repeticiones.csv` con 9 filas). **Verificado por el tester:** ART real (4 `guid` en el clon, commit `388942a…`) y **pre-staging genuino** (material fuera de `[t0,t1]`; `python3`/`dpkg`/`useradd`/`mkfs.ext4` = 0 dentro). **86 ventanas base intactas**; `ATA_index` 43 filas; `pytest` **97**; cadena **1.582/0**. **⭐ Valor añadido:** original + repetición permiten **comparar**. **⚠️ Anomalía nueva:** el **re-escaneo SCA** tras el reinicio (18 filas `19010/19011` → `novel`) — mismo patrón que `rule_id 11`; declarada, sin tocar el filtro. *(Incidencias: reinicio del PC a mitad → R1+R2 hechas, R3 sin contabilidad → completada, R4 → hecha; 2 cortes por `HTTP 400`.)*
