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
