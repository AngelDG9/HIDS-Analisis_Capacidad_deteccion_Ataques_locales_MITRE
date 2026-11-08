# Resultados Wazuh — Windows (B1.1, piloto mixto)

> **Bloque B1**, tanda **B1.1**. Ejecutado el **2026-11-08** por `tfg-executor` sobre
> `plan.md` v3 (`approved_by_human`, commit `fe4b873`). **Solo** `victima-windows` + manager;
> `victima-linux` apagada. **Sin secretos.** Canal **SSH** (`lab-listo-windows-ataques-ssh`).
>
> ## ⚠️ CA-B1-02 — estas ventanas son **ensayo de pipeline**, no medida canónica
>
> Los 6 `esperado` se modificaron a `19:11:27Z`, **después** del `t0` de ATA056 iter1
> (`19:10:16Z`): se añadió una señal FIM (`syscheck_path`) y se cambió el patrón de
> `win_command_line` (de `*C:\lab-attack\ATA<NNN>*` a `*lab-attack*ATA<NNN>*`, porque el
> JSON de Wazuh escapa las barras). **No es solo formato: cambian señales.** Los originales
> se recuperaron del object store de snapshots de OpenCode y están en
> `Soporte/Ataques/c0/windows/pre_registro_b1_1_original/`. Detalle y diff:
> `Soporte/Laboratorio/windows/ataques/B1.1_pre_registro_incidencia.md`.
>
> **Decisión:** **no se aceptan** como medida. Las 12 ventanas se repetirán con el `esperado`
> actual congelado por `ATA<NNN>_pre_registro.sha256` (creado antes del nuevo `t0`). Los
> `Hojas/T2_ataques_windows.csv` y `T4_rendimiento_windows.csv` se marcan **NO CANÓNICOS**
> hasta esa repetición. Lo que **sí** queda validado es el **pipeline** (efecto, extracción,
> filtro, 0 dudosas, 0 filas del ataque en ruido, replay 0).

---

## 0. Alcance

- **6 casos** (ATA056–ATA061), **2 iteraciones** cada uno = **12 ventanas** `[t0,t1]`.
- **No** se ejecuta B1.2+; **no** se toca el corpus Linux ni `Hojas/ATA_index.csv`.
- `C0 = C1 = {RS1}` (RS2 vacía) ⇒ `C0 ≡ C1`; catálogo provisional **v1** (4 reglas).
- Métrica **v1** (O1 + O2); `t0` ≥ **90 s** tras agente `002` **Active**.

## 1. Pre-flight (PASA)

Ver `Soporte/Laboratorio/windows/ataques/B1.1_preflight.md` y
`Soporte/Ataques/c0/windows/preflight_b1_1/`. Un hijo de `sshd.exe` lanzado desde
`C:\lab-attack\ATA056` genera `67027`/`92052` y el filtro lo atribuye a la **carpeta**
(`deteccion`/`artefacto_ataque`), **no** a `operador`/`auto_ruido`. **0** filas del ataque en ruido.

## 2. Casos y resultados

| ATA | Técnica | Vía | Efecto (prueba) | Iter1 | Iter2 | `rule_id` | Dudosas |
|---|---|---|---|---|---|---|---|
| ATA056 | T1020 | ART tal cual `9c780d3d` | `PUT` sink 9090, `sha256` | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA057 | T1567.004 | ART tal cual `f0057c81` | `POST /hook`, `sha256` JSON | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA058 | T1567.002 | ART adaptado `8529ee44` | 4 ficheros WebDAV, `sha256` | **6** | **6** | `67027,92032,92052` | 0/0 |
| ATA059 | T1567.003 | ART adaptado `c2e8ab6e` | `POST /paste`, `sha256` | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA060 | T1496.001 | manual | CPU 11,3→97,8 %; RAM | **5** | **5** | `67027,92032,92052` | 0/0 |
| ATA061 | T1486 | manual AES-256 | 5/5 `sha256`≠ + roundtrip | **5** | **5** | `67027,92032,92052` | 0/0 |

- **6/6** casos con **efecto demostrado** en las **2** iteraciones.
- **0** `dudosa` sin resolver en las **12** ventanas (resueltas antes de T2).
- **0** filas del ataque en `ruido_conocido`/`auto_ruido` (candado de pertenencia).
- Doble iteración **`iguales`** en los 6 (mismo conjunto de `rule_id`, mismo recuento).

### 2.1 Qué detecta (y qué no)

- **Capa real = proceso** (`4688` → `67027`; Sysmon 1 → `92032`/`92052`). **No** hay capa de
  red (`Sysmon 3` nivel 0) ni de recursos (R9). **H-B1-5′ confirmada**.
- **FIM** (`554`/`553`) es **ancla/artefacto** en el filtro congelado (H4-W), **no** detección.
- ATA058 añade una detección extra por `rclone.exe` (misma `rule_id` `67027`); el `#rule.id`
  distintos sigue siendo **3**.
- El **efecto no es detección**: `sink.log`, CPU y `sha256` van en `Logs/ATA<NNN>_iter<N>/efecto.txt`.

## 3. T2-W parcial (métrica v1)

`Hojas/T2_ataques_windows.csv` (**60 filas** = 6 casos × 2 configs × 5 umbrales;
`N_casos=6`, **T2 parcial 6/32**). **NO CANÓNICO** (CA-B1-02: el `esperado` se modificó tras
`t0`; ver `B1.1_pre_registro_incidencia.md`). Reproducible: tres ejecuciones dan el mismo
`sha256` (`d0cc6e63…`), ya con **rutas relativas** en los `-Audited.csv` (D-2).

| Config | `N=0` | `N=3` | `N=7` | `N=10` | `N=12` |
|---|---|---|---|---|---|
| **C0 = C1** | **6/6** (TPR 1,000) | **6/6** (1,000) | 0/6 (0,000) | 0/6 (0,000) | 0/6 (0,000) |

- **`#Alertas`** por caso/ventana: 5 (ATA056/057/059/060/061), 6 (ATA058); **`#rule.id`
  distintos = 3** (`67027`, `92032`, `92052`) en todos.
- **Lectura**: la detección es de **nivel 3–4**; a `N≥7` se pierde. Es el mismo patrón que
  Linux (`80792` nivel 3): el umbral alto es el que discrimina.
- **Sensibilidad `--sin-operador`** (`Hojas/T2_ataques_windows_sens_sin_operador.csv`):
  TPR **idéntico** (6/6, 6/6, 0/6…). La diferencia está en las **dudosas**: sin predicado,
  las 5–6 filas de logon del canal (`60106/60137/67024/67023/67028`) pasan a `dudosa`;
  con predicado, a `ruido_conocido` (`operador:*`). **El sesgo del canal no infla el TPR**
  porque el `esperado` es **field-first** (no declara `rule_id=67027`): las filas del canal
  no tienen campos de señal. La sensibilidad queda publicada.

## 4. T4-W parcial

`Hojas/T4_rendimiento_windows.csv` (formato ancho, `M=n/a`). **TPR** calculable; **FPR/TNR/
GM/Precisión/F1/Usabilidad n/a** (sin `M`). **`FP/hora` descriptivo = 19,875**
(159 alertas / 8 h de la baseline Windows).

## 5. Filtro, replay y regresión

| Comprobación | Resultado |
|---|---|
| **Replay baseline v1** (72 filas, catálogo v1) | **0** detecciones — PASA |
| **Replay baseline v2** (87 filas, catálogo v1+v2) | **0** detecciones — PASA |
| **0 filas del ataque en `ruido_conocido`/`auto_ruido`** | **0** en las 12 ventanas |
| **`dudosa` sin resolver** | **0** en las 12 ventanas |
| **`pytest`** | **389 passed** |
| **Regresión Linux** | `extraer_alertas.py` **no modificado**; re-extracción de ATA020 iter1: **875/875 filas idénticas** a `ATA020_iter1-Detalle.csv` (mismo orden y valores). El `sha256` byte a byte **no** coincide por dos motivos **preexistentes**: (a) el fichero congelado usa **CRLF** y el extractor escribe **LF**; (b) el extractor actual añade una línea `#` de cabecera que el congelado no tiene. Se declara. |

## 6. Ficheros

- Fichas: `ATA056_meta.md` … `ATA061_meta.md`.
- `CSV/ATA<NNN>_iter<N>-Detalle.csv` + `-Agregado.csv`.
- `Auditado/ATA<NNN>_iter<N>-Audited.csv` + `-Revision.csv`.
- `Logs/ATA<NNN>_iter<N>/`: `efecto.txt`, `efecto_local.txt`, `sink.log` (si red), `times.log`,
  `times_host.log`, `ejecucion.out`, `ssh_run.out`.
- `Auditado_sens_sin_operador/` (6 ventanas canónicas, sensibilidad).
- Bitácoras: `Bitacora/ATA056.json` … `ATA061.json`.
- C0: `Soporte/Ataques/c0/windows/ATA056_c0.md` … `ATA061_c0.md`.
- Índice del piloto: `Hojas/ATA_index_windows_piloto.csv` (6 filas; el índice de 32 no se toca).

## 7. Desviaciones y lo que no cuadra

1. **Canal SSH sin IP**: el `4624` de SSH no trae `ipAddress` (B1.0-SSH). El predicado es por
   usuario/regla (`60106/60137/67024/67023/67028`), no por IP. Declarado.
2. **`win_command_line` viene escapado** en el JSON de Wazuh (`\\`, `\"`). Por eso las anclas
   del `esperado` usan `*lab-attack*ATA<NNN>*` (sin barras invertidas), no la ruta literal.
3. **Copia del caso dentro de `[t0,t1]`**: en el primer intento de ATA056 la copia
   (`rmdir`/`move`/`sftp`) cayó dentro de la ventana y generó filas del canal atribuidas a la
   carpeta. Se corrigió con un **gap de 15 s** entre la copia y `t0`. Las ventanas oficiales
   no contienen operaciones de copia.
4. **ATA058**: `rclone` exige `pass` obscurecida; se eliminó `user/pass` del remote WebDAV
   (el sink no autentica). El destino incluye un timestamp UTC para no colisionar entre
   iteraciones.
5. **`boveda_version`**: `metrica_hids.py` está congelado con `VERSION_BOVEDA=2` (bóveda Linux).
   En las cabeceras de T2/T4-W se declara `boveda_version_windows=3` (bóveda v3) sin tocar el
   módulo congelado.
6. **`no_json=1`** en algunas ventanas: una línea del diario no era JSON válido; el extractor
   la cuenta y no la inventa. No afecta a las filas del ataque.
7. **Ejecuciones de ingeniería descartadas** (no son medida): ATA056 (2 intentos con
   `Invoke-WebRequest` sin `-UseBasicParsing`/`ProgressPreference`) y ATA058 (2 intentos con
   `rclone` y `pass` no obscurecida). Las ventanas oficiales son las que están en `Logs/`.
