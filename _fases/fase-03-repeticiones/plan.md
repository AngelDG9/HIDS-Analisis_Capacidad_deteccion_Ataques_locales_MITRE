---
bloque: fase-03-repeticiones
fase: 3
status: approved_by_human
version: 1
fecha: 2026-10-01
fecha_aprobacion: 2026-10-01
aprobado_por: humano
autor: tfg-planner
gate: **APROBADO (2026-10-01)**. Decisiones del humano: **ATA024 = ART adaptado** (anotar qué se cambia) · **ATA029 = pre-staging de `sqlite3`/`strings`** (traerlos antes e instalar offline; si no sale → declarar "no factible offline") · el **original no se toca**; la repetición se **añade** con sufijo **`_rev`** y es la **canónica** para esas 9.
---

# Plan — Bloque de **repeticiones auditadas** (`fase-03-repeticiones`)

> Repetir los **9 ataques** que la auditoría metodológica marcó, en **tandas pequeñas**, con el
> laboratorio ya probado. **No se ataca en este bloque de planificación**: aquí solo se diseña.
> **La métrica y el filtro están congelados** (`_fases/fase-03-metrica/change-doc.md`): este bloque
> **no los toca**. El corpus sigue con **43 técnicas**.

---

## 0. Objetivo

Ejecutar **9 repeticiones** (2 iteraciones cada una = **18 ventanas nuevas**) que corrijan los dos
defectos declarados por la auditoría —(**A**) no haber probado la atómica de ART cuando era viable,
**(B**) sembrar el material *dentro* de `[t0,t1]`— dejando **constancia trazable** de que cada
repetición cumple su motivo, **sin borrar** los resultados originales.

**Entregable:** 18 ventanas auditadas + fichas/bitácoras actualizadas + `Hojas/repeticiones.csv`
(nueva) + veredicto del `tfg-tester`.

---

## 1. Hechos verificados (con cita)

- **Unión de las 2 listas = 9 ataques distintos.** Lista A (por ART): **ATA024, ATA029, ATA030,
  ATA038**. Lista B (por pre-staging): **ATA014, ATA016, ATA029, ATA035, ATA036, ATA037, ATA038**
  (`_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` §1.1 líneas 40-43 y §2 líneas
  72-83; `Hojas/auditoria_origen.csv`, columnas `candidato_repetir_art` / `candidato_repetir_prestaging`).
- **ATA029 y ATA038 llevan LOS DOS motivos** → una sola repetición que arregla ambos
  (`Hojas/auditoria_origen.csv` líneas 31 y 40: `sí,sí`).
- **Motivos exactos.** *Por ART* = había prueba de ART **usable** (misma plataforma, offline, mismo
  mecanismo) y no se usó o no consta el porqué; **ATA029/ATA030** están como `no_se_comprobo`
  (hueco declarado) (`auditoria_decisiones.md` §3 H1/H2). *Por pre-staging* = el ataque **prepara su
  material dentro de `[t0,t1]`** (ensucia la ventana) sin que esa preparación sea la técnica
  (`criterio_ataques.md` §C).
- **Normas vigentes:** `Soporte/Ataques/criterio_ataques.md` §A (ART) · §B (ataque manual) · §C
  (pre-staging). **Métrica/filtro congelados** (`_fases/fase-03-metrica/change-doc.md` §2.1/§2.2).
- **Tubería probada:** `Soporte/Ataques/piloto_procedimiento.md` (esperado firmado → **C0** →
  `lab-listo` → `t0` → ataque → `t1` → extraer del **fichero diario en UTC** → filtrar → ficha/
  bitácora; **2 iteraciones** v2). **Sin NAT.**
- **Regla de oro de la repetición (citada):** *"una repetición **no borra** el resultado anterior:
  se **añade ventana** y se **declara el cambio de método** en ficha y bitácora"*
  (`auditoria_decisiones.md` líneas 91-92).
- **Coste unitario invariante:** **2 ventanas** por repetición (`auditoria_decisiones.md` línea 20).

---

## 2. Las 9 repeticiones (motivo · qué cambia · dificultad)

Columnas: **M** = motivo (`ART` / `PRE` / ambos). **ART citada** con `guid`; commit del clon
`388942adbd9641f4dfdcf079d7efe9a75ec0ac43` (`Soporte/Ataques/atomic_red_team.md` §3).

| ATA | Técnica | M | Qué cambia respecto al original | Dificultad |
|---|---|---|---|---|
| **ATA030** | T1560.001 Archive via Utility | ART | Sustituir el guion propio (`tar -czf`) por la atómica **«Data Compressed - nix - tar Folder or File»** (`atomics/T1560.001/T1560.001.yaml`, guid `7af2b51e-ad1c-498c-aca8-d3290c19535a`): parametrizar `input_file_folder`/`output_file` al `lab-attack`; `fuente_norm → art_tal_cual`. Cierra el `no_se_comprobo`. | **Baja** |
| **ATA029** | T1005 Data from Local System | ART + PRE | Ejecutar la atómica **«Find and dump sqlite databases (Linux)»** (guid `00cbb875-7ae4-4cf1-b638-e543fd825300`) **pre-steando** los 3 `src/` (`art`, `gta.db`, `sqlite_dump.sh`) **antes de t0** en lugar del `curl` remoto. Cierra `no_se_comprobo` + limpia la semilla. ⚠️ Dependencias: ver §7-R3. | **Media-alta** |
| **ATA024** | T1531 Account Access Removal | ART | Ejecutar la atómica **«Change User Password via passwd»** (guid `3c717bf3-2ecc-4d79-8ac8-0bfbf08fbce6`, `elevation_required: true`) → **ART_adaptado**: el original además **bloqueaba y eliminaba**; la atómica **solo cambia la contraseña** → anotar qué se recorta. Cuenta **desechable**, `sudo` por `stdin`. | **Media-alta** |
| **ATA014** | T1114 Email Collection | PRE | Mover la **siembra del mbox** en `lab-legit` a **antes de t0**; la ventana mide solo la recolección (`grep`/`cp`). Nuevo `esperado` sin las `ambigua` del `watch` de la semilla. | **Baja-media** |
| **ATA016** | T1213.006 Databases | PRE | Sembrar la **BD SQLite** (hoy con `python3`→`92600`) **antes de t0**; la ventana mide solo `cp`/`grep`. Revalidar `esperado`. | **Media** |
| **ATA035** | T1056.004 Credential API Hooking | PRE | **Crear/decodificar el payload** (`hook.so`/`credfetch`) bajo `lab-attack` **antes de t0**; la ventana solo ejecuta (`LD_PRELOAD`). Sin `sudo`. | **Media** |
| **ATA036** | T1565.003 Runtime Data Manipulation | PRE | **Pre-staging** de `memedit`/`target`/estado **antes de t0**; la ventana solo hace el `ptrace`. Ojo `yama.ptrace_scope=1` (ya resuelto con `PR_SET_PTRACER`). | **Media** |
| **ATA037** | T1561.001 Disk Content Wipe | PRE | Crear `disk.img` (ext4) **antes de t0**; la ventana solo hace el wipe. **Guardarraíl duro: solo imagen loop, nunca disco real.** `sudo` para `losetup`/`mount`. | **Media-alta** |
| **ATA038** | T1529 System Shutdown/Reboot | ART + PRE | Ejecutar la atómica de reinicio (guid `6326dbc4-444b-4c04-88f4-27e94d0327cb`, «Restart System via `shutdown`») declarándola `art_tal_cual` (parametrizada) y **pre-steando** el guion/estado **antes de t0**. `t1` se sella **tras la reconexión**. | **Alta** |

> **Referencias del cambio (por ataque):** README `§2`/`§3` de cada técnica
> (`Dataset/Ataques/Comandos/<TEC>-<DESC>/README.md`) + `esperado` actual (mismo directorio). El
> `esperado_rev` se redacta **antes** y lo **valida el humano** (§B.7 del criterio).

---

## 3. Reparto en tandas y orden

**Criterio:** agrupar por **setup compartido** y ordenar de **menos a más riesgo/disrupción**
(ART simple → semillas → payloads/loop → reinicio al final).

| Tanda | Ataques (orden interno) | Setup compartido | Por qué juntos |
|---|---|---|---|
| **R1 — ART runner** | ATA030 → ATA029 → ATA024 | Ejecución de **atómicas ART** (copia al vuelo del dir `atomics/T<ID>/`, `Soporte/Ataques/atomic_red_team.md` §4) | Comparten el mismo banco de pruebas ART; dificultad creciente (sin `sudo` → semilla → `sudo`). Valida el camino ART con la más simple. |
| **R2 — Pre-staging de semilla legítima** | ATA014 → ATA016 | Sembrar material en **`lab-legit`** antes de `t0` y medir solo la lectura | Mismo patrón: aislar la recolección de su siembra. |
| **R3 — Pre-staging de payloads** | ATA035 → ATA036 → ATA037 | Material precompilado/imagen en **`lab-attack`** antes de `t0` | Mismo patrón: preparar el material fuera de la ventana. ATA037 añade `loop`+`sudo`. |
| **R4 — ART + pre-staging disruptivo** | ATA038 | **Reinicio de la VM víctima** | Se aísla y va **la última**: `t1` no se puede sellar hasta la reconexión. |

**Orden global:** **R1 → R2 → R3 → R4**. R4 al final por ser **disruptiva**.

---

## 4. 📌 Contabilidad — cómo conviven el original y su repetición (DECISIÓN)

**Principio:** *el original no se toca; la repetición se **añade** y **pasa a ser la medición
canónica** de esas 9 técnicas; el original queda como antecedente declarado.*

### 4.1 Nombres de los ficheros de la repetición

Sufijo **`_rev`** (ventanas `rev1`/`rev2`) — **no** se usa `-Revision`, que ya es el CSV de revisión
humana pre-plegado (`filtrar_ruido.py`, paso 11 del runbook).

| Artefacto | Original (intacto) | Repetición (nuevo) |
|---|---|---|
| Señales esperadas | `…/ATA<NNN>_esperado.csv` | `…/ATA<NNN>_esperado_rev.csv` *(nuevo, firmado)* |
| Script/artefacto | `…/ATA<NNN>_ataque.sh` | `…/ATA<NNN>_ataque_rev.sh` *(o el flujo ART documentado)* |
| Detalle por alerta | `CSV/ATA<NNN>_iterN-Detalle.csv` | `CSV/ATA<NNN>_revN-Detalle.csv` (+ `_raw`) |
| Auditado + revisión | `Auditado/ATA<NNN>_iterN-{Audited,Revision}.csv` | `Auditado/ATA<NNN>_revN-{Audited,Revision}.csv` |
| Evidencia | `Logs/ATA<NNN>_iterN/` | `Logs/ATA<NNN>_revN/` |
| C0 | `c0/ATA<NNN>_logtest.txt` / `_preflight.md` | `c0/ATA<NNN>_rev_logtest.txt` / `_rev_preflight.md` |
| Ficha | `ATA<NNN>_meta.md` | **misma** ficha + sección **«§ Repetición auditada (rev)»** |
| Bitácora | bloque `iteraciones` (original) | **append** de un bloque `"repeticion"` (append-only) |

> **Una ficha por técnica** (no se duplica el fichero); la repetición se **añade como sección**.

### 4.2 ¿Reescribir el `esperado` o escribir uno nuevo? → **uno NUEVO**

- Se escribe **`ATA<NNN>_esperado_rev.csv`** y se **firma la validación humana antes del primer
  `t0`** (§B.7). **Nunca** se reescribe ni recalibra el `esperado` original: rompería su `sha256` y
  la cadena de huellas (`piloto_procedimiento.md` §0, nota de huellas).
- El nuevo esperado **declara el método corregido**: en pre-staging, desaparecen las señales
  `ambigua` de la siembra (esa ya no cae en `[t0,t1]`); en ART, las señales se ajustan al binario
  real de la atómica (lección `audit_exe` = **binario real**).

### 4.3 ¿Cuál va a la **tabla final**? → **la repetición** (con el original citado)

- **La repetición es el valor canónico** de las 9 en la tabla final: es la **corrección
  metodológica** (condición ART cumplida o ventana limpia).
- **El original se conserva** como **antecedente/comparación declarada** en la ficha (§4.1) y en
  `Hojas/repeticiones.csv`; **sus ficheros no se tocan** (regla de oro).
- **Ambos se reportan siempre**; si el veredicto difiere, se explica en la ficha y en el
  `change-doc`. Cifras: **43 técnicas (sin cambio)**; **ventanas 86 → 104** (las 18 de repetición se
  declaran **aparte**, nunca mezcladas en la cifra base).

### 4.4 ¿`ATA_index`? → **no se toca**

- `Hojas/ATA_index.csv` sigue con **43 filas** y `estado=cerrado` (ya lo está). **No** se le añaden
  columnas (evita churn y no aporta al corpus).

### 4.5 Constancia del **motivo** → campo nuevo + hoja nueva

- **Bitácora:** el bloque `"repeticion"` lleva **`motivo_repeticion`** ∈ {`art`, `prestaging`,
  `art+prestaging`} + **`motivo_detalle`** (con cita a la auditoría) + refs y hashes.
- **`Hojas/repeticiones.csv` (NUEVA, aditiva)** — el ledger de las 9:
  `ata_id, tecnica, motivo_repeticion, metodo_original, metodo_repeticion, ref_original,
  ref_repeticion, veredicto_original, veredicto_repeticion, nota`.
- **No** se modifican `auditoria_origen.csv` ni `cobertura_atomic.csv`.

---

## 5. Operativa

**Ciclo probado** (`Soporte/Ataques/piloto_procedimiento.md` §0/§2), **por repetición × iteración**:

```text
preflight (manager+agente+relojes+espacio; NAT OFF)
  → C0 (logtest + preflight) de la repetición y esperado_rev FIRMADO
    → revert víctima a lab-listo (el manager NO se revierte) + esperar agente Active
      → PRE-STAGING del material ANTES de t0   (solo motivos PRE/ambos)
        → t0 (UTC, en la víctima)
          → ejecutar la atómica ART o el guion_rev
            → scan FIM forzado + t1 (UTC)
              → esperar 60 s (o 300 s si nada)
                → extraer del FICHERO DIARIO (UTC) → filtrar por agente → filtrar_ruido.py
                  → resolver dudosas → ficha + bitácora + repeticiones.csv
```

- **2 iteraciones** por repetición (v2 `iguales`); `t0` **tras ≥ 90 s** de asentamiento.
- **Receptor: no aplica.** Ninguna de las 9 usa red (ATA029 se resuelve con `src/` local). **Sin
  NAT**, **sin regla de firewall**.
- **ART:** copia **al vuelo** del directorio `atomics/T<ID>/` a `lab-attack/` y ejecución del
  comando del YAML parametrizado (`atomic_red_team.md` §4); citar **`guid`+`path`+`commit`**.

**Guardarraíles (duros):**
- **ATA037:** **solo** imagen de fichero desechable; **jamás** un disco/partición real; `trap` que
  detacha el loop → **0 loops residuales**.
- **ATA024:** **solo** usuario desechable (`tfg-victim01`); **jamás** cuentas reales; `trap` de
  limpieza.
- **ATA038:** **solo** la VM `victima-linux` (exige `hostname`+IP); **jamás** el manager ni el
  anfitrión; reinicio **programado** y **en último lugar**.
- **ATA035/ATA036:** **solo** procesos/payloads de laboratorio.
- **Higiene:** contraseña de `sudo` **por `stdin`**, nunca en el repo; datos de juguete.
- **Cierre:** receptor/daemon parados, sin regla de firewall, víctima a `lab-listo`, VMs apagadas,
  **NAT off**.

---

## 6. Verificación (qué comprueba el `tfg-tester`)

| # | Comprobación | Criterio |
|---|---|---|
| **V1** | **El motivo se cumple** — ART: la bitácora cita `guid`+`path`+`commit` de una prueba de **esta plataforma**, **offline** y del **mismo mecanismo** (o `ART_adaptado` con nota); PRE: consta que el material entra **antes de `t0`** y **ninguna** señal de siembra (`80790/80781/80782`) cae en `[t0,t1]`. | 9/9 |
| **V2** | **0 filas del ataque en `ruido`** en las 18 ventanas nuevas (bajo la pertenencia por carpeta; las filas de **sesión PAM/`sudo` sin `cwd`** se **declaran** como limitación conocida). | 0 filas |
| **V3** | **Regresión byte a byte** de las **86 ventanas previas** (Audited/Revision + fichas + bitácoras de origen). | idénticas |
| **V4** | **`pytest`** (97) en verde. | 97 |
| **V5** | **Determinismo**: 2 pasadas de filtrado → mismo `sha256`; doble iteración **v2 `iguales`** en las 9. | 9/9 |
| **V6** | **Cadena de huellas** coherente en las 18 (`esperado_rev` ↔ `ataque_rev` ↔ Audited/Revision ↔ bitácora ↔ ficha). | 0 desincronías |
| **V7** | **`Hojas/repeticiones.csv`** completa (9 filas) y coherente con las bitácoras; `ATA_index.csv` **intacto** (43 filas). | ✔ |
| **V8** | **Laboratorio cerrado**: NAT off, sin receptor, sin firewall, VMs apagadas, **0 loops**, **0 cuentas desechables**. | ✔ |

**Criterios de aceptación (CA):**
- **CA-R1:** 9 repeticiones × 2 iteraciones = **18 ventanas**, cada una con C0, `esperado_rev`
  firmado, ficha y bitácora.
- **CA-R2:** cada repetición **cumple su motivo** (V1).
- **CA-R3:** **0 filas del ataque en `ruido`** (V2).
- **CA-R4:** **regresión byte a byte** de las 86 ventanas previas (V3).
- **CA-R5:** `pytest` verde, determinismo y cadena de huellas (V4-V6).
- **CA-R6:** original **intacto**; `repeticiones.csv` completa; `ATA_index` con 43 filas (V7).
- **CA-R7:** guardarraíles respetados y laboratorio cerrado (V8).
- **CA-R8:** **métrica y filtro sin cambios** (ninguna edición en `filtrar_ruido.py`, política ni
  `cobertura_atomic.csv`).

---

## 7. Riesgos y decisiones abiertas

- **R1 (ATA024 — ART parcial):** la única atómica Linux de T1531 **solo cambia la contraseña**
  (`passwd`), no elimina la cuenta; y es **interactiva** + `sudo`. **Mitigación:** declarar
  `ART_adaptado` (anotar qué se recorta) y pasar la contraseña por `stdin`; si el humano prefiere,
  aceptar el hueco como *resuelto: la atómica Linux es interactiva/de mecanismo parcial*. → **Decide
  el humano en el gate.**
- **R2 (pre-staging fuera de la ventana):** el material se crea antes de `t0`; el revert posterior a
  cada iteración lo elimina → hay que **re-preparar antes de cada `iter`**. Declarado en el runbook.
- **R3 (ATA029 — deps `sqlite3`/`strings` ausentes):** la atómica de T1005 exige `sqlite3`, `curl`
  y `strings`; en la víctima **no están** y ATA016 lo confirma (`T1213.006-Databases/README.md`
  §3). **Opciones:** (a) pre-stejar un binario `sqlite3` fijado (URL+`sha256`); (b) declarar la
  atómica T1005 **«no factible offline»** y resolver el `no_se_comprobo` como *no factible sin NAT*
  (manteniendo la repetición **solo por pre-staging** con el guion propio). → **Decide el humano.**
- **R4 (ATA037/ATA038 `sudo`):** riesgo operativo; mitigado por guardarraíles duros (solo imagen /
  solo víctima) y `sudo` por `stdin`.
- **R5 (reboot):** la ventana de ATA038 depende de la reconexión; hacer **en último lugar**.
- **R6 (huellas/CRLF):** **no** hacer `checkout`/`stash`/`reset` sobre `esperado`/`Audited`; recalcular
  hashes tras cualquier operación de git que toque finales de línea (`piloto_procedimiento.md` §0).

---

## 8. Qué NO entra (fuera de alcance)

- Las **~29 técnicas restantes** de Linux (P1-Linux casi agotada; R13 pendiente de decisión).
- **EVASIÓN** (2.ª pasada disfrazada) — trabajo futuro declarado.
- **Windows** (línea base + adaptar el filtro).
- **Fase 4** (η) y **memoria** (Fase 5).
- **Tocar la métrica o el filtro** (congelados), `politica_filtrado_ruido.md` o `cobertura_atomic.csv`.
- **Reescribir el ataque original** ni sus ficheros/`esperado`/hashes.
- Ampliar el corpus: el corpus sigue con **43 técnicas**.

---

## 9. Gate humano (lenguaje sencillo)

> **Qué te pido que apruebes:**
> 1. Repetir **estos 9 ataques**, en **4 tandas** (R1: ATA030/029/024 · R2: ATA014/016 · R3:
>    ATA035/036/037 · R4: ATA038), **2 veces cada uno** (18 ventanas), con el laboratorio ya probado.
> 2. **Cómo conviven original y repetición:** el original **no se borra**; la repetición se **añade**
>    con el sufijo `_rev`, se le escribe un **esperado nuevo** (firmado por ti antes del primer `t0`)
>    y **pasa a ser el resultado canónico** de esas 9 en la tabla final, dejando el original como
>    comparación.
> 3. **Nada de esto toca la métrica ni el filtro**, ni reescribe el ataque original.
> 4. **Dos decisiones abiertas** (marca la que prefieras): **ATA024** (¿`ART_adaptado` con `passwd` o
>    se acepta el hueco?) y **ATA029** (¿pre-stejar `sqlite3` o declarar la atómica «no factible
>    offline»?).
>
> Con tu **OK** se marca este plan `approved_by_human` y se pasa a ejecutar.
