# Resultados Wazuh — Windows (B1.1, repetición con `esperado` sellado)

> **Bloque B1**, tanda **B1.1**. **Repetición** ejecutada el **2026-11-08** (20:37–21:23Z)
> por `tfg-executor` sobre `plan.md` v3 (`approved_by_human`, commit `dfe516c`).
> **Solo** `victima-windows` + manager; `victima-linux` apagada. **Sin secretos.**
> Canal **SSH** (`lab-listo-windows-ataques-ssh`).

## 0. CA-B1-02 — **PASA**

- Los 6 `ATA<NNN>_esperado.csv` están **sellados en git** (`dfe516c`).
- **Antes de cada `t0`** se verificó `sha256(esperado) == ATA<NNN>_pre_registro.sha256`
  y se registró el timestamp UTC en `Logs/ATA<NNN>_iter<N>/sello_verificacion.txt`.
- Los 12 pares `(sello, t0)` cumplen `sello < t0`; los 12 `-Audited.csv` y los 12
  `-Detalle.csv` llevan en su cabecera el `sha256` sellado.
- La primera tanda (19:10–19:12Z) se descartó: el `esperado` se modificó después de `t0`
  (ver `Soporte/Laboratorio/windows/ataques/B1.1_pre_registro_incidencia.md`). Esta es la
  medida canónica.

## 1. Pre-flight (PASA)

`Soporte/Ataques/c0/windows/preflight_b1_1_repeticion/`: un hijo de `sshd.exe` lanzado desde
`C:\lab-attack\ATA056` genera `67027`/`92052` y el filtro lo atribuye a la **carpeta**
(`deteccion`/`artefacto_ataque`), **no** a `operador`/`auto_ruido`.
**43 filas, 10 `deteccion`, 0 `dudosa`, 0 filas del ataque en ruido.**

## 2. Casos y resultados

| ATA | Técnica | Vía | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|---|
| ATA056 | T1020 | ART tal cual `9c780d3d` | `PUT` sink 9090, `sha256` | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA057 | T1567.004 | ART tal cual `f0057c81` | `POST /hook`, `sha256` JSON | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA058 | T1567.002 | ART adaptado `8529ee44` | 4 ficheros WebDAV, `sha256` | **6** | **6** | `67027,92032,92052` | 0/0 |
| ATA059 | T1567.003 | ART adaptado `c2e8ab6e` | `POST /paste`, `sha256` | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA060 | T1496.001 | manual | CPU 10,95→99,0 % / 2,26→96,98 % | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA061 | T1486 | manual AES-256 | 5/5 `sha256`≠ + roundtrip | **5** | **5** | `67027,92032,92052` | 0/0 |

- **6/6** con efecto demostrado en **2/2** iteraciones (`Logs/ATA<NNN>_iter<N>/efecto.txt`).
- **0** `dudosa` sin resolver en las 12 ventanas.
- Doble iteración **`iguales`** en los 6.
- Detección por **proceso** (`4688`→`67027`; Sysmon 1→`92032`/`92052`). **Sin** capa de red
  (`Sysmon 3` nivel 0) ni de recursos (R9). **H-B1-5′ confirmada.**
- FIM (`554`/`553`) es **ancla/artefacto**, no detección (H4-W).

## 3. T2-W canónico parcial

`Hojas/T2_ataques_windows.csv` — **60 filas**, `N_casos=6`, `corpus=32`, **sin** marca
`NO CANÓNICO`, `CA-B1-02 PASA` en la cabecera. **Rutas relativas** en los `-Audited.csv` (D-2).

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **6/6 (1,000)** | **6/6 (1,000)** | 0/6 | 0/6 | 0/6 |

- `#Alertas`: 5 (ATA056/057/059/060/061), 6 (ATA058); total **31**.
- `#rule.id` distintos por caso: **3** (`67027`, `92032`, `92052`).
- **`sha256 = 5a4144fdb4f46c7f06d8bd0d80df420a0ec0189d80def8230717e6ae27fe19d3`**
  (3 ejecuciones idénticas).
- La detección es de nivel 3–4; a `N≥7` se pierde (mismo patrón que Linux con `80792`).

### 3.1 Sensibilidad `--sin-operador`

`Hojas/T2_ataques_windows_sens_sin_operador.csv`: TPR **idéntico** (6/6, 6/6, 0/6…).
Las filas del canal (`60106/60137/67024/67023/67028`) pasan a **`dudosa`**, no a `deteccion`.
El `esperado` field-first (sin `rule_id=67027`) impide que el canal infle el TPR.

## 4. T4-W parcial

`Hojas/T4_rendimiento_windows.csv` — **`sha256 = 5a0e0ad08d17c932f4740fcc024b1b814901586144bc4ddb5047c13a489a6721`**
- TPR calculable; `FPR/TNR/GM/Precisión/F1/Usabilidad = n/a` (sin `M`).
- `FP/hora = 19,875` descriptivo (159 alertas / 8 h baseline Windows).
- `N = 6 (piloto; corpus B1 = 32)`; `boveda_version_windows=3`; rutas relativas.

## 5. Filtro, replay y regresión

| Comprobación | Resultado |
|---|---|
| **0 filas del ataque en `ruido_conocido`/`auto_ruido`** | **0 violaciones** (chequeo por `win_image`/`win_command_line`, no solo por `ts+rule_id`) |
| **`dudosa` sin resolver** | **0** en las 12 ventanas |
| **Replay baseline v1** (72) | **0** detecciones |
| **Replay baseline v2** (87) | **0** detecciones |
| **`pytest`** | **389 passed** |
| **Regresión Linux** | **semántica 875/875** filas idénticas a `ATA020_iter1-Detalle.csv`; `extraer_alertas.py` **intacto**. No byte a byte por CRLF/`#` preexistente (D-9). |

### 5.1 Corrección del candado (durante la repetición)

`filtrar_ruido_windows.py` (`es_del_ataque`) comparaba la carpeta con barras simples contra
un `win_command_line` **escapado** (`\\`): una fila de `rclone.exe` con
`C:\lab-attack\ATA058` podía caer en `ruido_conocido`. Se añadió `_sin_dobles()` para colapsar
barras antes de comparar. Diff: **+10/−4**; `pytest` 389 OK. No se tocó ningún `esperado`.

## 6. Ficheros

- Fichas: `ATA056_meta.md` … `ATA061_meta.md`.
- `CSV/ATA<NNN>_iter<N>-Detalle.csv` (cabecera con `esperado` + `sha256` sellado) + `-Agregado.csv`.
- `Auditado/ATA<NNN>_iter<N>-Audited.csv` + `-Revision.csv` (**resuelta**, 0 dudosas)
  + `-Revision_pre.csv` (foto pre-plegado) + `-Revision_in.csv` (entrada de veredictos).
- `Logs/ATA<NNN>_iter<N>/`: `sello_verificacion.txt`, `efecto.txt`, `efecto_local.txt`,
  `sink.log` (si red), `times.log`, `times_host.log`.
- `Auditado_sens_sin_operador/` (6 ventanas canónicas).
- `Bitacora/ATA056.json` … `ATA061.json`; C0: `Soporte/Ataques/c0/windows/ATA0NN_c0.md`.
- Preflight: `Soporte/Ataques/c0/windows/preflight_b1_1_repeticion/`.
- Índice del piloto: `Hojas/ATA_index_windows_piloto.csv` (el índice de 32 no se toca).

## 7. Limitaciones declaradas

1. **Canal SSH sin IP** en el `4624`; predicado por usuario/regla, no por IP.
2. **`win_command_line` escapado** (`\\`, `\"`): las anclas usan `*lab-attack*ATA<NNN>*`.
3. **ATA058**: FIM de `rclone.conf`/`rclone.out` observado en iter2; en iter1 no apareció en
   la ventana. No afecta a detección (proceso) ni a efecto (4/4 PUT).
4. **`boveda_version`**: `metrica_hids.py` congelado con `VERSION_BOVEDA=2` (bóveda Linux);
   `boveda_version_windows=3` se declara en la nota de T2/T4-W.
5. **`no_json=1`** en algunas ventanas: una línea del diario no era JSON válido; el extractor
   la cuenta y no la inventa.
6. **Grupo mixto `ts+rule_id`**: en ATA058 iter1 conviven `WmiApSrv.exe` (baseline) y
   `rclone.exe` (detección) con el mismo `67027` y timestamp; verificado por `win_image`.


## 8. B1.2 — ATA062–ATA067 (6 casos, 12 ventanas)

> Ejecutado el **2026-11-08 (21:55–23:02Z)** con los `esperado` sellados en `7bce82d`.
> **Token SSH High** (`S-1-16-12288`): no se necesitó tarea `Highest`; `win_user=angel` en todos.
> `CA-B1-02`: 12/12 sellos verificados **antes** de `t0`; `-Audited.csv` y `-Detalle.csv` con el
> `sha256` sellado.

| ATA | Técnica | Efecto | Iter1 | Iter2 | Dudosas |
|---|---|---|---|---|---|
| ATA062 | T1485 | 5/5 sobrescritos + borrados | 5 | 5 | 0/0 |
| ATA063 | T1490 | bcdedit `No`/`IgnoreAllFailures`; `reagentc` parcial | 5 | 5 | 0/0 |
| ATA064 | T1489 | servicio juguete `Running→Stopped`, borrado | 6 | 6 | 0/0 |
| ATA065 | T1531 | usuario juguete creado y borrado | 5 | 5 | 0/0 |
| ATA066 | T1491.001 | `index.html` sobrescrito (`sha256`≠) | 5 | 5 | 0/0 |
| ATA067 | T1529 | `boot_before < boot_after`; agente `Active` | 19 | 19 | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; las herramientas se ejecutan
  desde copias dentro de `C:\lab-attack\ATA<NNN>\` para que la carpeta esté en la línea de comandos).
- **ATA063**: `reagentc /disable` quedó **parcial** (la copia local no devolvió salida); el efecto
  principal es `bcdedit` (`recoveryenabled No`, `bootstatuspolicy IgnoreAllFailures`). Declarado.
- **ATA064**: `ToyService.exe` compilado en el caso; el `sc.exe`/binario del sistema no es
  service-aware. Efecto real `Running→Stopped`.
- **ATA067**: el reinicio genera ruido de arranque `92066`/`92031` (novel) que la regla congelada
  cuenta como detección; **no cambia el TPR**, pero infla `#Alertas`/`#rule.id` de ATA067.

### T2-W parcial (12 casos: 6 B1.1 + 6 B1.2)

`Hojas/T2_ataques_windows.csv` — **120 filas**, `N_casos=12`, `corpus=32`, `CA-B1-02 PASA`.
**`sha256 = f2a619597c9a05d16a1eb61e15e68defa2e7dbef390d87a320f915a4eada5cee`** (reproducible).

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **12/12** | **12/12** | 0/12 | 0/12 | 0/12 |

- `#Alertas` total: **76**; `#rule.id` distintos: 3 por caso, salvo ATA064=4 (`92307`) y ATA067=7.
- T4-W: **`sha256 = 01c9ef83c7590e585eb8d511f8e110f2b91600946c1a4b40c580170a55e34fc3`**.
- Sensibilidad `--sin-operador`: TPR idéntico (12/12, 12/12, 0/12); canal a `dudosa`.
- Replay v1/v2: **0**; `pytest` **389**; regresión Linux semántica **875/875**.

---

# B1.3 - Collection (ATA068-ATA073)

> **Bloque B1**, tanda **B1.3**. Ejecutada el **2026-11-09** sobre `plan.md` v3
> (`approved_by_human`). `esperado` **sellado en `c0c1058`**; `sha256` verificado antes de
> cada `t0` en `Logs/ATA<NNN>_iter<N>/sello_verificacion.txt`. **Solo** `victima-windows`
> + manager; `victima-linux` apagada. **Sin secretos.**

## B1.3.0 - CA-B1-02 PASA (12/12)

Los 12 pares `(sello, t0)` cumplen `sello < t0`; los 12 `-Audited.csv` y `-Detalle.csv`
llevan el `sha256` sellado. El `esperado` no se modifico.

## B1.3.1 - Canal

- **ATA068/069/070**: snapshot `lab-listo-windows-ataques-ssh`; SSH; token **High**
  (`S-1-16-12288`).
- **ATA071/072/073**: snapshot `lab-listo-windows-ataques-gui`; autologon `angel`,
  sesion 1 `console`; tarea **`TFG-Attack-<ATA>`** `InteractiveToken`, `UserId=angel`,
  accion `cmd.exe /c C:\lab-attack\ATA<NNN>\run.cmd`, disparo `t0+30 s`, creada antes
  de `t0` y borrada tras `t1`. Verificado `LogonType: Interactive`.

## B1.3.2 - Casos y resultados

| ATA | Tecnica | Canal | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|---|
| ATA068 | T1005 | SSH | `inventario.txt` con 20 ficheros | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA069 | T1560.001 | SSH | `datos.zip` 20 entradas, 2275 bytes | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA070 | T1074.001 | SSH | `staging` 30 ficheros; `robocopy_rc=1` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA071 | T1113 | S1 | `screen.png` real 136813/152829 bytes, 1024x768 | 75 | 59 | `67027,92032,92052` | 0/0 |
| ATA072 | T1115 | S1 | clipboard == `TFG-CLIP-2026-B1.3`; `91824` | 64 | 64 | `67027,91824,92032,92052` | 0/0 |
| ATA073 | T1056.001 | S1 | `key.log` secuencia completa; `cadena_detectada=True` | 102 | 102 | `67027,92027,92032,92052,92213` | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; 0 violaciones en las 12 ventanas).
- **ATA071**: doble iteracion **`review`** por recuento (`|59-75|=16 > max(2, 7.5)`); mismo
  conjunto de `rule_id` y 0 `dudosas`. El ruido de arranque/sesion S1 infla `#Alertas`.
- **ATA072**: `91824` (Powershell collected clipboard data, nivel 4) es deteccion directa no
  declarada en el `esperado`; se registra como `deteccion` (no como ruido).
- **ATA073**: `92213` (nivel 15, Sysmon 11) lo dispara el `Add-Type` del propio script
  (compilacion C# en `%TEMP%`), no el canal; se registra como deteccion `novel`. Por eso
  el TPR a `N>=7` es **1/18** (solo ATA073), no 0/18.
- **ATA073**: el `SendKeys` original capturaba una secuencia parcial; se sustituyo por
  `keybd_event` con hold de 150 ms (misma semantica de efecto). El `esperado` no se toco.

## B1.3.3 - T2-W parcial (18 casos: 6 B1.1 + 6 B1.2 + 6 B1.3)

`Hojas/T2_ataques_windows.csv` - **180 filas**, `N_casos=18`, `corpus=32`, `CA-B1-02 PASA`.
**`sha256 = d6312d34fee5c221a5b2fd36302956c8bd253d00b5f3b30a12777cd5f922e405`**.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **18/18** | **18/18** | **1/18** | **1/18** | **1/18** |

- `#Alertas` total (N=0): **332**; `#rule.id` distintos por caso: 3 (salvo ATA064=4,
  ATA067=7, ATA072=4, ATA073=5).
- T4-W: **`sha256 = fcc44f96936ccdee6ca8f3677c59a3cd2f4efbb1dee0891c1b854c9e38749a74`**.
- Sensibilidad `--sin-operador`: TPR **identico** (18/18, 18/18, 1/18, 1/18, 1/18); el canal
  pasa a `dudosa`, no a `deteccion` (`Hojas/T2_ataques_windows_sens_sin_operador.csv`).
- Replay baseline v1/v2: **0**; `pytest` **389 passed**; regresion Linux semantica **875/875**.

## B1.3.4 - Limitaciones

1. **S1** (ATA071/072/073) genera ruido de proceso de arranque/sesion que infla
   `#Alertas`; el TPR no cambia. ATA071 queda en `review` por recuento.
2. **ATA073** tiene una deteccion de nivel 15 (`92213`) por el `Add-Type`; es real, pero
   no estaba pre-declarada. Se documenta como `novel`.
3. **H-B1-5***: deteccion por proceso; sin capa de red ni de recursos.

---

# B1.4 - Exfiltracion local (ATA074-ATA080)

> **Bloque B1**, tanda **B1.4**. Ejecutada el **2026-11-09** sobre `plan.md` v3
> (`approved_by_human`). `esperado` **sellado en `7e3e872`**; `sha256` verificado antes de
> cada `t0`. **Solo** `victima-windows` + manager; `victima-linux` apagada. **Sin secretos.**

## B1.4.0 - CA-B1-02 PASA (14/14)

Los 14 pares `(sello, t0)` cumplen `sello < t0`; los 14 `-Audited.csv` y `-Detalle.csv`
llevan el `sha256` sellado. El `esperado` no se modifico.

## B1.4.1 - Canal

- **ATA074/075/076/077/078/080**: snapshot `lab-listo-windows-ataques-ssh`; SSH; token **High**.
- **ATA079**: snapshot `lab-listo-windows-ataques-gui`; autologon `angel`, sesion 1;
  tarea **`TFG-Attack-ATA079`** `InteractiveToken`, `UserId=angel`, accion
  `cmd.exe /c C:\lab-attack\ATA079\run.cmd`, disparo `t0+30 s`, creada antes de `t0` y
  borrada tras `t1`; la tarea de transferencia `TFG-ATA079` se crea dentro y se borra al final.
- **Pre-staging ATA078/080**: PortableGit y `sqlite3.exe` se copian a **`C:\tfg-tools`**,
  **fuera** del FIM `C:\lab-attack` (realtime). En `C:\lab-attack` la extraccion de
  PortableGit generaba cientos de eventos `554` de FIM que contaminaban la ventana.

## B1.4.2 - Casos y resultados

| ATA | Tecnica | Canal | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|---|
| ATA074 | T1041 | SSH | `sink.log` POST + `sha256` | 6 | 6 | `67027,92032,92052` | 0/0 |
| ATA075 | T1048.001 | SSH | `sink.log` TCP + `sha256` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA076 | T1048.002 | SSH | `sink.log` POST + `sha256` + descifrado | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA077 | T1048.003 | SSH | `sink.log` TCP + `sha256` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA078 | T1567.001 | SSH | `git log` repo bare + `push` | 10 | 13 | `67027,92032,92052` | 0/0 |
| ATA079 | T1029 | S1 | `sink.log` POST + `Last Run Time` | 132 | 128 | `67027,92032,92052` | 0/0 |
| ATA080 | T1213.006 | SSH | `dump.sql` 20 filas + `sha256` | 8 | 8 | `67027,92032,92052` | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; 0 violaciones en las 14 ventanas).
- **ATA078**: doble iteracion **`review`** por recuento (`|13-10|=3 > max(2, 1)`); mismo
  conjunto de `rule_id` y 0 `dudosas`. La diferencia es el numero de procesos `git` hijos.
- **ATA079**: S1 infla `#Alertas` (132/128) por ruido de sesion/arranque; el TPR no cambia.
- **ATA074** es `ART_adaptado`: se cita T1041 `d1253f6e` y se cambia el executor a `curl.exe`.

## B1.4.3 - T2-W parcial (25 casos: 6 B1.1 + 6 B1.2 + 6 B1.3 + 7 B1.4)

`Hojas/T2_ataques_windows.csv` - **250 filas**, `N_casos=25`, `corpus=32`, `CA-B1-02 PASA`.
**`sha256 = 3945d7b80b9e8012129fe729d9b669dc05fa7d2f19e0b2ad8ba634c4c3e86cf2`**.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **25/25** | **25/25** | **1/25** | **1/25** | **1/25** |

- `#Alertas` total (N=0): **503**; `#rule.id` distintos por caso: 3 (salvo ATA064=4,
  ATA067=7, ATA072=4, ATA073=5).
- El unico TP a `N>=7` sigue siendo **ATA073** (`92213`, nivel 15); los 7 casos B1.4 son
  detecciones de nivel 3-4.
- T4-W: **`sha256 = 5b9334df11a954d22266bd06b0e4aef761b69d6ba4ec8f142f1ed5f1009b9994`**.
- Sensibilidad `--sin-operador`: TPR **identico** (25/25, 25/25, 1/25, 1/25, 1/25); el canal
  pasa a `dudosa`, no a `deteccion` (`Hojas/T2_ataques_windows_sens_sin_operador.csv`,
  `sha256 = b5eff998949c718ac3f6adecb1d8de3a9358629b1c59d21944606e82db49feb3`).
- Replay baseline v1/v2: **0**; `pytest` **389 passed**; regresion Linux semantica **875/875**.
- Indice de 25 casos: `Hojas/ATA_index_windows_piloto_25.csv`
  (`sha256 = 39d35b913ef934296e04e25250f8f567c65015c021f72638cda068d53f85c414`).

## B1.4.4 - Limitaciones

1. **ATA078** queda en `review` por recuento de procesos `git` (10 vs 13), no por deteccion.
2. **ATA079** (S1) infla `#Alertas` por ruido de sesion; el TPR no cambia.
3. **ATA074** es `ART_adaptado` (executor `curl.exe`), no `ART` estricto.
4. **H-B1-5***: deteccion por proceso; sin capa de red (Sysmon 3 ciego) ni de recursos.

---

# B1.5 - Windows-only + datos + recursos (ATA081-ATA087)

> **Bloque B1**, tanda **B1.5**. Ejecutada el **2026-11-09** sobre `plan.md` v3
> (`approved_by_human`). `esperado` **sellado en `4e41f38`**; `sha256` verificado antes de
> cada `t0`. **Solo** `victima-windows` + manager; `victima-linux` apagada. **Sin secretos.**

## B1.5.0 - CA-B1-02 PASA (14/14)

Los 14 pares `(sello, t0)` cumplen `sello < t0`; los 14 `-Audited.csv` y `-Detalle.csv`
llevan el `sha256` sellado. El `esperado` no se modifico.

## B1.5.1 - Casos y resultados

| ATA | Tecnica | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|
| ATA081 | T1114.001 | 21 ficheros (20 .eml + 1 .pst) + `mail.csv` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA082 | T1185 | Cookies + Login Data; cabecera SQLite | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA083 | T1667 | 25 `.eml` en mailbox local | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA084 | T1657 | transferencia 1500; A=3500 / B=2500 | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA085 | T1498.001 | `sink.log` 8 lineas TCP de 8 MiB (64 MiB) | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA086 | T1499.001 | Available MBytes 3031.7 -> 2504.9 / 3115.1 -> 2592 | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA087 | T1499.002 | 200 peticiones; `servicio_responde=False` | 6 | 6 | `67027,92027,92032,92052` | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; 0 violaciones en las 14 ventanas).
- **ATA081** es `ART_adaptado` (Outlook -> perfil sintetico `.eml`/`.pst`).
- **ATA082-087** son manuales (perfil/libro/mailbox sinteticos, flood TCP, presion de memoria,
  servicio loopback desechable).
- **ATA086**: el HIDS **no tiene capa de recursos**; el efecto es `Available MBytes` y la
  deteccion esperada es solo de proceso.
- **ATA087**: el servicio desechable se agota (`ok=10`, `fail=190`, `servicio_responde=False`)
  y se para al final.

## B1.5.2 - T2-W parcial (32 casos)

`Hojas/T2_ataques_windows.csv` - **320 filas**, `N_casos=32`, `corpus=32`, `CA-B1-02 PASA`.
**`sha256 = 06c4f0b57f67299f74baa9740649402e52ad7f386b98277253c7e933fd81dd10`**.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **32/32** | **32/32** | **1/32** | **1/32** | **1/32** |

- `#Alertas` total (N=0): **539**; `#rule.id` por caso: 3 (salvo ATA064=4, ATA067=7,
  ATA072=4, ATA073=5, ATA087=4).
- El unico TP a `N>=7` sigue siendo **ATA073** (`92213`, nivel 15).
- T4-W: **`sha256 = 90d4c7bf4ce37b59fb058d4b1a764ed32aa3ffa57a1142f65d19c245c3759101`**.
- Sensibilidad `--sin-operador`: TPR **identico** (32/32, 32/32, 1/32, 1/32, 1/32); el canal
  pasa a `dudosa`, no a `deteccion` (`Hojas/T2_ataques_windows_sens_sin_operador.csv`,
  `sha256 = 7927564f0232697f5e33a9dd19f6b843e5e1043a1366fdd4ea43c437e0176fe7`).
- Replay baseline v1/v2: **0**; `pytest` **389 passed**; regresion Linux semantica **875/875**.
- Indice de 32 casos: `Hojas/ATA_index_windows_piloto_32.csv`
  (`sha256 = 71fa15124663557a2a6968b5f7a8fe625e06a0bb59201d6d39c58e3b417c68e4`).

## B1.5.3 - Limitaciones

1. **ATA086** no tiene capa de recursos en el HIDS: solo se prueba el efecto (`Available MBytes`).
2. **ATA081** es `ART_adaptado` (Outlook -> perfil sintetico), no `ART` estricto.
3. **ATA082-087** son manuales; el motivo esta en cada `README.md`.
4. **H-B1-5***: deteccion por proceso; sin capa de red (Sysmon 3 ciego) ni de recursos.


---

# B1.6 - Cierre del bloque B1 (32 casos)

> **Solo cierre**: sin VM, sin ataques, sin commits. Detalle completo en
> `Soporte/Laboratorio/windows/ataques/B1.6_cierre.md`.

## B1.6.1 - T2/T4 finales

| Producto | Filas | `sha256` |
|---|---|---|
| `Hojas/T2_ataques_windows.csv` | 320 | `fb83d19d5eec915d00699ae6a2ecfe50e5ffa5e5c06e67a2b5435d1206167ec5` |
| `Hojas/T4_rendimiento_windows.csv` | 19 metricas | `d7557837ef8623d9a92c165949e5706639bc376551dd2c01b74bc4cb50aa7177` |
| `Hojas/ATA_index_windows_piloto_32.csv` | 32 | `71fa15124663557a2a6968b5f7a8fe625e06a0bb59201d6d39c58e3b417c68e4` |

- `T2`: `N_casos=32`, `corpus=32`, `CA-B1-02 PASA`, rutas relativas, reproducible (2 ejecuciones).
- `T4`: **`N = 32`** (corregido desde `N = 55`), TPR + `FP/hora`; `FPR/TNR/GM/Precision/F1/Usabilidad = n/a`;
  `boveda_version_windows=3`; `sha256_entradas` = T2 final.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **32/32** | **32/32** | **1/32** | **1/32** | **1/32** |

- `#Alertas` total (N=0): **539**; `#rule.id` por caso: 3 (salvo ATA064=4, ATA067=7,
  ATA072=4, ATA073=5, ATA087=4).
- El unico TP a `N>=7` es **ATA073** (`92213`, nivel 15), **artefacto de compilacion**
  (`Add-Type`), no keylogging: el `1/32` es "deteccion por tooling".
- **`review`**: ATA071 (C2') y ATA078 (10 vs 13 procesos `git`). **`efecto_parcial`: ninguno**.

## B1.6.2 - Sensibilidades (NO CANONICAS)

| Producto | TPR (`N=0/3/7/10/12`) | `#Alertas` N=0 | `sha256` |
|---|---|---|---|
| `T2_ataques_windows_sens_sin_operador.csv` | 32/32, 32/32, 1/32, 1/32, 1/32 | 536 | `7927564f0232697f5e33a9dd19f6b843e5e1043a1366fdd4ea43c437e0176fe7` |
| `T2_ataques_windows_sens_catalogo_v2.csv` | 32/32, 32/32, 1/32, 1/32, 1/32 | 539 | `a4d4429429b8f10d87f67cacfbe9890e839a9a1c62fc9a541cadfe73f31b88c6` |
| `T2_ataques_windows_sens_sin_67027.csv` | 32/32, 32/32, 1/32, 1/32, 1/32 | **847** | `25f4668e3bb95c132290b4ef8051fafc82823f396c0efa616cf435331bf50720` |

- `sin_operador`: canal a `dudosa`, TPR identico.
- `catalogo_v2` (`ruleids_legitimos_v2.csv`, 7 reglas): mismo conjunto de `rule_id`; TPR y
  `#Alertas` identicos. **NO CANONICO.**
- `sin_67027` (D6b): al quitar `67027` del catalogo, las filas baseline pasan a `novel` y
  `#Alertas` sube a **847** (ATA067 125, ATA079 170, ATA087 27); el TPR no cambia. **NO CANONICO.**

## B1.6.3 - T5 doble uso provisional

`Hojas/T5_doble_uso_windows.csv` - **17 reglas**, **1 doble uso** (`67027`),
`sha256 = be0015944290a24dbb4c41ec3efbe8181c561438e0318dc7c5965c0499d1c2b9`.
`67027`: 132 alertas baseline v1+v2, **281 detecciones en ataque** (32/32 casos).
Provisional: catalogo baseline Windows v1+v2; no consumir como T5 final.

## B1.6.4 - Cadena y deudas

- `auditar_cadena_huellas.py`: **citas verificadas=2214**, omitidas=78, **0 desincronias**.
  Observacion no bloqueante: autocita `revision=` de ATA001 (Linux; linaje).
- `sha256sums`: `Soporte/Laboratorio/windows/ataques/B1.6_sha256sums.txt`.
- Deudas cerradas: **T4 `N=32`**; **ATA073 `92213`** artefacto de compilacion; **ATA071**
  `review` + `s1_task_principal` vacio en iter1; **ATA078** `review` + pre-staging
  `C:\tfg-tools`; **ATA079** intentos fallidos fuera de ventana; **ATA086** fix de
  compromiso de paginas antes del `t0` valido (~527 MB); **ATA074/081** `ART_adaptado` con
  commit ART `388942ad`; **ATA085/087** efecto real sin capa de red/recursos;
  **`boveda_version` 2 (metrica) + 3 (boveda Windows)**; regresion Linux **875/875**
  semantica (no byte a byte); `pytest` **389** en `_artefactos/scripts/tests` (raiz falla
  por `atomic-red-team`/`pydantic`, preexistente).


---

# B2.1 - Deudas de B1 (ATA088-ATA092)

> **Bloque B2**, tanda **B2.1**. Ejecutada el **2026-11-09** sobre `plan.md` v1
> (`approved_by_human`). `esperado` **sellado en `06c0694`**; `sha256` verificado antes de
> cada `t0`. **Solo** `victima-windows` + manager. **Sin secretos.**

## B2.1.0 - CA-B1-02 PASA (10/10)

Los 10 pares `(sello, t0)` cumplen `sello < t0`; los 10 `-Audited.csv` y `-Detalle.csv`
llevan el `sha256` sellado. El `esperado` no se modifico.

## B2.1.1 - Casos y resultados

| ATA | Tecnica | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|
| ATA088 | T1496.002 | `sink.log` 1 linea TCP len=33554432 | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA089 | T1499.003 | latencia 0.3 -> 5253 / 5049 ms; `exhausted=True` | 16 | 16 | `67027,92027,92032,92052` | 0/0 |
| ATA090 | T1498.002 | `sent=6400 recv=409600 ratio=64` | 6 | 6 | `67027,92027,92032,92052` | 0/0 |
| ATA091 | T1557.001 | **`efecto_parcial`**: `capturado=False`; hash no guardado | 7 | 7 | `67027,92004,92027,92032,92052` | 0/0 |
| ATA092 | T1557.003 | `lease.txt` ip=192.168.65.200 gw/dns=192.168.65.1; `ack_ok=True` | 6 | 6 | `67027,92027,92032,92052` | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; 0 violaciones en las 10 ventanas).
- **ATA091**: Inveigh arranca (elevado, LLMNR/NBNS/mDNS/SMB/HTTP enabled) pero **no captura**
  el hash en el escenario **co-locado** (el servidor SMB/HTTP del sistema ocupa 445/80 y no hay
  tercer host); `capturado=False`, `longitud=0`. **No se inventa**; el hash NTLM no se guarda.
  La deteccion esperada sigue siendo de proceso.
- **ATA089**: la app es de juguete en loopback 9093; se para al final; no se toca el host.
- **ATA090**: 2.a direccion loopback `127.0.0.2`; sin spoofing; `ReuseAddress` por mDNS.

## B2.1.2 - T2-W parcial (37 casos: 32 B1 + 5 B2.1)

`Hojas/T2_ataques_windows_b2_piloto_37.csv` - **370 filas**, `N_casos=37`, `corpus=54`,
`CA-B1-02 PASA`. **`sha256 = 38114d8abb1488f46e013f21482db371fdf189d733453a9ac2d0af92f942884c`**.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **37/37** | **37/37** | **1/37** | **1/37** | **1/37** |

- `#Alertas` total (N=0): **579**; `#rule.id` por caso: 3 (salvo ATA064=4, ATA067=7,
  ATA072=4, ATA073=5, ATA087=4, ATA089=4, ATA090=4, ATA091=5, ATA092=4).
- El unico TP a `N>=7` sigue siendo **ATA073** (`92213`, nivel 15).
- T4-W: **`sha256 = 5f1c1177ce7b6340ea2b662e94df6d7a7618e835fb696ff14ec7fe654ae596c4`**;
  `N = 37`; `FPR/TNR/GM/Precision/F1/Usabilidad = n/a`; `FP/hora` descriptivo 19,875.
- Sensibilidad `--sin-operador`: `Hojas/T2_ataques_windows_b2_piloto_37_sens_sin_operador.csv`,
  **`sha256 = 362607c19e005b5f7ad017cb4e64b76ca1b7e3d384423922b682c973e97698df`**; TPR
  **identico** (37/37, 37/37, 1/37, 1/37, 1/37); el canal pasa a `dudosa`.
- Indice de 37: `Hojas/ATA_index_windows_b2_piloto_37.csv`
  (`sha256 = f24346c2480d9cffe167f18fd6c60d13b906ea5eca962c9d62715b23a1e67e2f`), **staged**.
- Replay v1/v2: **0**; `pytest` **390 passed**; regresion Linux semantica **875/875**.

## B2.1.3 - Limitaciones

1. **ATA091 `efecto_parcial`**: Inveigh co-locado no captura el hash (SMB/HTTP del sistema);
   sin tercer host/relay. El hash no se guarda.
2. **ATA089/090/092** son loopback: deteccion de proceso; Sysmon 3 ciego para la red.
3. **ATA088** requiere el sink del HOST 9091; los demas no.
4. El **N=54 final** y las sensibilidades completas quedan para **B2.5**.


---

# B2.2 - Archivo y manipulacion de datos (ATA093-ATA097)

> **Bloque B2**, tanda **B2.2**. Ejecutada el **2026-11-09** sobre `plan.md` v1
> (`approved_by_human`). `esperado` **re-sellado en `a2eca10`**; `sha256` verificado antes
> de cada `t0`. **Solo** `victima-windows` + manager. **Sin secretos.**

## B2.2.0 - CA-B1-02 PASA (10/10)

Los 10 pares `(sello, t0)` cumplen `sello < t0`; los 10 `-Audited.csv` y `-Detalle.csv`
llevan el `sha256` sellado. El `esperado` no se modifico tras el sello.

## B2.2.1 - Casos y resultados

| ATA | Tecnica | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|
| ATA093 | T1560.002 | `.zip` .NET, 20 entradas, `extraido_ok=True` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA094 | T1560.003 | `TFGARCH1`, 20 ficheros, `decodificado_ok=True` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA095 | T1565.001 | `libro.csv` alterado; `sha256_antes != despues` | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA096 | T1565.002 | sink recibe `sha256` distinto del fichero; `proxy.log` | 6 | 6 | `67027,92027,92032,92052` | 0/0 |
| ATA097 | T1565.003 | `WriteProcessMemory` `write_ok=True`; cadena alterada | 8 | 8 | `67027,92032,92052,92213` | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; 0 violaciones en las 10 ventanas).
- **ATA093**: en iter1 disparo **`91846`** ("Powershell used .NET compression method"); **no
  estaba en el `esperado`**, se clasifico `artefacto_ataque` y queda como **candidata a senal
  del catalogo v2 / B2.5**.
- **ATA096**: el proxy 9095 lee un solo `Read`; el body llego en un segmento posterior, asi que
  `proxy.log` registra `orig=e3b0c442...` (body vacio) y reenvia solo `MANIPULADO-POR-PROXY`
  (`len=21`). El efecto es valido (`sha256_original != sha256_modified`; `sink.log` con el sha
  alterado), pero **no se reenvia el body original**. Mejora propuesta en B2.5: leer
  `Content-Length` en bucle.
- **ATA097**: el primer iter1 (19:52:42) fallo con `GUARDARRAIL: toy no arranco` porque
  `[UIntPtr]256` no es convertible en PowerShell 5.1. Se corrigio `ATA097_toy.ps1` a
  `[UIntPtr]::new(256)` (y `::new(0)` en `VirtualFree`); esa iteracion se archivo fuera del
  repo. Las validas son **19:58:40** y **20:02:31**. El `esperado` no se toco.

## B2.2.2 - T2-W parcial (42 casos: 32 B1 + 5 B2.1 + 5 B2.2)

`Hojas/T2_ataques_windows_b2_piloto_42.csv` - **420 filas**, `N_casos=42`, `corpus=54`,
`CA-B1-02 PASA`. **`sha256 = 3c4172d6e20db481a4ed7e33b3545cfac2758f6e870b9c5ab93ed7c9e1b64e5b`**.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **42/42** | **42/42** | **2/42** | **2/42** | **2/42** |

- `#Alertas` total (N=0): **608**.
- TP a `N>=7`: **ATA073** y **ATA097** (`92213`, nivel 15). El resto solo detecta a `N=0`/`N=3`.
- T4-W: **`sha256 = 92be80a57a2ab5be074f768161d6bba34e881bdbd7f02679522e8eed121b2e87`**;
  `N = 42`; `FPR/TNR/GM/Precision/F1/Usabilidad = n/a`; `FP/hora` descriptivo **19,875**
  (159 alertas / 8 h baseline Windows).
- Sensibilidad `--sin-operador`: `Hojas/T2_ataques_windows_b2_piloto_42_sens_sin_operador.csv`,
  **`sha256 = edb01625ffe281b2061bd88c6920df3879616217ffe240a631996e2485eadfa3`**; TPR
  **identico** (42/42, 42/42, 2/42, 2/42, 2/42); el canal pasa a `dudosa`.
- Indice de 42: `Hojas/ATA_index_windows_b2_piloto_42.csv`
  (`sha256 = 45c32b803033e67c8f810d7dc6c1471feb8dcc5b6d93c115fadcf20803355fc8`), **staged**.
- Replay v1/v2: **0**; `pytest` **393 passed**; regresion Linux semantica **875/875**.

## B2.2.3 - Limitaciones

1. **ATA096**: el proxy no reenvia el body original (caveat declarado); el efecto de
   manipulacion se prueba por el `sha256` distinto en el sink.
2. **ATA093/094/095/097** son locales: deteccion de proceso; Sysmon 3 ciego para la red.
3. **ATA097** depende de `OpenProcess`/`WriteProcessMemory` sobre el toy; en este laboratorio
   funciono (`write_ok=True`), pero si el token no lo permite se declararia `efecto_parcial`.
4. El **N=54 final** y las sensibilidades completas quedan para **B2.5**.


---

# B2.3 - Disco y medios (ATA098-ATA102)

> **Bloque B2**, tanda **B2.3**. Ejecutada el **2026-11-09** sobre `plan.md` v1
> (`approved_by_human`). `esperado` **sellado en `312d9fe`**; `sha256` verificado antes de
> cada `t0`. **Solo** `victima-windows` + manager. **Sin secretos.**

## B2.3.0 - CA-B1-02 PASA (10/10)

Los 10 pares `(sello, t0)` cumplen `sello < t0`; los 10 `-Audited.csv` y `-Detalle.csv`
llevan el `sha256` sellado. El `esperado` no se modifico.

## B2.3.1 - Casos y resultados

| ATA | Tecnica | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|
| ATA098 | T1561 | VHD corrupto (`0xFF`; footer intacto) | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA099 | T1561.001 | contenido a cero (footer intacto) | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA100 | T1561.002 | no montable (footer destruido) | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA101 | T1025 | 20 docs copiados; `sha256` coinciden | 5 | 5 | `67027,92032,92052` | 0/0 |
| ATA102 | T1052.001 | 20 ficheros en el VHD; persistido | 5 | 5 | `67027,92032,92052` | 0/0 |

- **0 filas del ataque en `ruido_conocido`/`auto_ruido`** (candado; 0 violaciones en las 10 ventanas).
- **VHD**: solo `C:\lab-attack\ATA<NNN>\labdisk100.vhd` (100 MiB, `sha256=04c8899c…9f9aad`);
  nunca `PhysicalDrive*`/`C:`/sistema. `Dismount-DiskImage` en `finally`.
- **Hallazgo de ejecucion**: el agente FIM bloquea el VHD recien copiado por `scp`; el runner
  copia localmente (`labdisk100_src.vhd` -> `labdisk100.vhd`) y el script reintenta la apertura.
- **ATA101**: ART adaptado (`guid=0b29f7e3-a050-44b7-bf05-9fb86af1ec2e`,
  `atomics/T1025/T1025.yaml`, commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`). El primer
  intento fallo por `Set-Disk` (param sets) y `Get-Disk`; corregido (disco por
  `BusType=File Backed Virtual` + `Location`, `Set-Disk` en dos pasos, reintento de particion).
- **ATA102**: el primer intento fallo al remontar ("Not enough available capacity") porque
  `Get-Partition` no veia la particion a tiempo; corregido con reintento y orden por tamano.
- Las iteraciones fallidas de ATA098/ATA101/ATA102 se archivaron **fuera del repo**.

## B2.3.2 - T2-W parcial (47 casos: 32 B1 + 5 B2.1 + 5 B2.2 + 5 B2.3)

`Hojas/T2_ataques_windows_b2_piloto_47.csv` - **470 filas**, `N_casos=47`, `corpus=54`,
`CA-B1-02 PASA`. **`sha256 = a980cfc32a0c73efeb8dfd1b4da4c724a47ff9b7539fb61f99c8a11257636610`**.

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **47/47** | **47/47** | **2/47** | **2/47** | **2/47** |

- `#Alertas` total (N=0): **633**. Los 5 casos nuevos: 5 alertas y 3 `rule_id` cada uno.
- TP a `N>=7`: **ATA073** y **ATA097** (`92213`, nivel 15).
- T4-W: **`sha256 = f43404c120f90c37e9593094dbd0258970b50e789a969f591107ba0f9ba08cbb`**;
  `N = 47`; `FPR/TNR/GM/Precision/F1/Usabilidad = n/a`; `FP/hora` descriptivo **19,875**
  (159 alertas / 8 h baseline Windows).
- Sensibilidad `--sin-operador`: `Hojas/T2_ataques_windows_b2_piloto_47_sens_sin_operador.csv`,
  **`sha256 = 67a92ec3326d7b2b9a237b5e825b3e872348eecbebae0c7e7ea3e92d52106861`**; TPR
  **identico** (47/47, 47/47, 2/47, 2/47, 2/47); el canal pasa a `dudosa`.
- Indice de 47: `Hojas/ATA_index_windows_b2_piloto_47.csv`
  (`sha256 = 0ec75d457ac7ee98e112676e23909053257cc8288040e2ccd08e633f28d7bee4`), **staged**.
- Replay v1/v2: **0**; `pytest` **396 passed**; regresion Linux semantica **875/875**.

## B2.3.3 - Limitaciones

1. **VHD pre-staged vacio** (100 MiB, sin FS): ATA098/099/100 siembran `0xAA` antes de
   borrar/corromper; ATA101/102 lo inicializan/formatean en la ventana. Es el escenario de
   juguete declarado.
2. **ATA101/102** dependen de `Mount-DiskImage`/`Initialize-Disk`/`Format-Volume`; si el
   montaje falla en otra ejecucion, se declarara `efecto_parcial`.
3. **ATA100** da `no_montable=True` porque `Mount-DiskImage` rechaza el footer a cero; si
   Windows lo tolerara, se declararia `efecto_parcial`.
4. El **N=54 final** y las sensibilidades completas quedan para **B2.5**.
