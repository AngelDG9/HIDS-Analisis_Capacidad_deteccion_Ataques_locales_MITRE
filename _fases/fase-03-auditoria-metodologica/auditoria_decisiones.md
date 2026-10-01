# Auditoría metodológica — decisiones (las 2 listas)

> **Entregable para el humano** del bloque `fase-03-auditoria-metodologica`. Redactado el
> **2026-10-01**. Recoge las **dos listas de repetición** (por ART / por pre-staging) que el
> humano decidirá **después** de leer esta auditoría, más la **nota de hallazgos**.
> **Aquí no se repite ningún ataque**: es un bloque de análisis. Insumos:
> `Hojas/auditoria_origen.csv` (T1), `Hojas/cobertura_atomic.csv` (mapa regenerado) y las
> bitácoras/READMEs de los 43.

## 0. Resumen de la auditoría (43 ataques)

- **Por `fuente`:** `ART_tal_cual` **5** · `ART_adaptado` **1** · `propio` **37**.
- **Por `motivo_codigo`:** `na_art_usado` **6** (no aplica: se usó ART) · `propio_por_diseno` **24** ·
  `art_requiere_red_nube` **8** · `art_no_prueba_plataforma` **2** · `art_mecanismo_no_coincide` **1**
  · `no_se_comprobo` **2**.
- **`no_se_comprobo` = 2** (`ATA029`, `ATA030`): el mapa da prueba Linux (`tests_linux=1` y `=5`) y
  el plan las marcaba ART adaptable, pero no consta en el repo que se comprobara/ejecutara la
  atómica → se declaran **hueco honesto** (ver §3, H2). Las **6** filas que sí usaron ART llevan
  `motivo_codigo=na_art_usado` (el motivo describe **por qué NO se usó ART**, así que no aplica).
- **Coste de repetir un ataque (unitario, invariante):** **2 ventanas** =
  revert + `t0` + ataque + `t1` + extracción + filtrado + ficha + bitácora, con **C0** y
  **validación humana del `esperado`** antes del primer `t0`. (Runbook: `piloto_procedimiento.md`.)

---

## 1. Lista A — repetir por ART (ejecutar la atómica de ART donde hoy hay guion propio)

**Criterio (las tres condiciones, todas):**
1. el ataque es **`propio`**;
2. el mapa (`Hojas/cobertura_atomic.csv`) le da **≥1 prueba de esta plataforma** (`tests_linux ≥ 1`);
3. esa prueba es **ejecutable offline sin NAT** y del **mismo mecanismo**.

**Resultado del cruce (propios con `tests_linux ≥ 1`):** hay **9** candidatos por la condición 2,
pero **5 caen** por la condición 3 (`art_requiere_red_nube` / `art_mecanismo_no_coincide`).

### 1.1 Candidatos que **PASAN** las tres condiciones

| ATA | Técnica | Prueba ART (esta plataforma) | Mecanismo / offline | Coste |
|---|---|---|---|---|
| **ATA029** | T1005 Data from Local System | `atomics/T1005` (1 test Linux) | Recolección dirigida local; la prueba de ART copia/lee ficheros locales → **offline** | 2 ventanas |
| **ATA030** | T1560.001 Archive via Utility | `atomics/T1560.001` (5 tests Linux) | Archivado con utilidad (`tar`) → **offline**, **mismo mecanismo** | 2 ventanas |
| **ATA024** | T1531 Account Access Removal | `atomics/T1531` (1 test Linux) | Gestión de cuenta local → **offline** (requiere `sudo`, ya previsto) | 2 ventanas |
| **ATA038** | T1529 System Shutdown/Reboot | `atomics/T1529` (10 tests Linux) | Reinicio del host → **offline**; ya se ejecutó propio con reinicio | 2 ventanas |

> **Prioridad:** alta para **ATA030** (contraste científico directo con ATA013/ATA034: la misma
> acción "archivar" hecha con **utilidad de ART**); media para **ATA029** y **ATA024**;
> **ATA038** es disruptivo (reinicio) → al final si se hace.

### 1.2 Candidatos que **NO pasan** (con motivo)

| ATA | Técnica | Por qué no entra en la Lista A |
|---|---|---|
| ATA009 | T1567 Exfiltration Over Web Service | `art_requiere_red_nube`: las 3 pruebas Linux usan `rclone`→nube o `terraform`+AWS. |
| ATA011 | T1074 Data Staged | `art_requiere_red_nube`: la única prueba Linux descarga de GitHub. |
| ATA041 | T1048.002 Asymmetric Encrypted Non-C2 | `art_requiere_red_nube`: la prueba usa servicios cloud (file.io). |
| ATA043 | T1567.004 Exfiltration Over Webhook | `art_requiere_red_nube`: pruebas contra servicios cloud. |
| ATA042 | T1048.003 Unencrypted Non-C2 | `art_mecanismo_no_coincide`: ART trae HTTP/`python3`; el corpus quiere TCP crudo sin el punto ciego `92600`. |

---

## 2. Lista B — repetir por pre-staging (sembrar el activo **antes** de `t0` para limpiar la lectura)

**Criterio:** el ataque **siembra el activo legítimo dentro de `[t0,t1]`** y esa semilla genera
señales `ambigua`/`artefacto` que **ensucian** la lectura, **siempre que la creación de la semilla
NO sea la técnica**. Es decir: la semilla debería entrar **antes de `t0`** (pre-staging) para que
la ventana mida **solo el ataque**, no el montaje.

**Candidatos (declaración de semilla en el `esperado` como `ambigua`/efecto):**

| ATA | Técnica | Semilla que ensucia la ventana | Qué ganaría repitiendo con pre-staging | Coste |
|---|---|---|---|---|
| **ATA014** | T1114 Email Collection | Siembra del mbox en `lab-legit` (watch `80790/80781/80782`) | La ventana mediría solo la recolección (`grep`/`cp`), sin la escritura de la semilla | 2 ventanas |
| **ATA015** | T1114.003 Email Forwarding Rule | Creación de `.forward`/`.procmailrc`; **pero aquí la creación ES la técnica** | ⚠️ **NO aplica**: la semilla es la técnica → excluido por el criterio | — |
| **ATA016** | T1213.006 Databases | Siembra de la BD SQLite en `lab-legit` (watch) | Aísla la recolección (`cp`/`grep`) de la siembra (`python3`→`92600`) | 2 ventanas |
| **ATA017** | T1657 Financial Theft | Siembra/modificación del libro en `lab-legit`; **la modificación ES la técnica** | ⚠️ **NO aplica**: parte del efecto es la técnica | — |
| **ATA029** | T1005 Data from Local System | Semilla de los 3 ficheros en `lab-legit/srv_data` (watch) | Aísla la recolección de la siembra | 2 ventanas |
| **ATA031** | T1667 Email Bombing | El Maildir puede pre-existir; el **volumen ES la técnica** | ⚠️ **NO aplica**: el volumen es la técnica | — |
| **ATA032** | T1565.001 Stored Data Manipulation | Siembra del ledger; **la manipulación ES la técnica** | ⚠️ **NO aplica** | — |
| **ATA033** | T1491.001 Internal Defacement | Siembra del `index.html` en el webroot; **la reescritura ES la técnica** | ⚠️ **NO aplica** | — |
| **ATA035** | T1056.004 Credential API Hooking | Creación del payload bajo `lab-attack` (watch `80790/80781`) | Aísla la ejecución del hook de la escritura de material | 2 ventanas |
| **ATA036** | T1565.003 Runtime Data Manipulation | Creación del payload/estado (watch) | Aísla la manipulación en memoria de la escritura del material | 2 ventanas |
| **ATA037** | T1561.001 Disk Content Wipe | Creación de `disk.img`/payload (watch) | Aísla el wipe de la preparación de la imagen | 2 ventanas |
| **ATA038** | T1529 System Shutdown/Reboot | `ATA038_*.sh` y ficheros de estado (watch) | Aísla el reinicio de la escritura del guion | 2 ventanas |
| **ATA024** | T1531 Account Access Removal | Escrituras en `/etc` (watch) son **la técnica** | ⚠️ **NO aplica** | — |

> **Nota:** los ataques que **leen** (no escriben) en `lab-legit` (`ATA029/ATA039`) ya están
> limpios por diseño (la siembra ocurre en la carpeta del ataque o fuera de `[t0,t1]`). La Lista B
> se ciñe a los que **siembran el activo legítimo dentro de la ventana** sin que esa siembra sea
> la técnica: **ATA014, ATA016, ATA029, ATA035, ATA036, ATA037, ATA038**.

> **Regla de oro (recordatorio):** una repetición **no borra** el resultado anterior: se **añade
> ventana** y se **declara el cambio de método** en ficha y bitácora.

---

## 3. Nota de hallazgos

- **H1 — `no_se_comprobo` = 2.** El cruce mecánico de las 43 filas con el mapa regenerado no deja
  ninguna fila sin clasificar: **41** tienen motivo legítimo y **2** se declaran **hueco honesto**
  (`ATA029`, `ATA030`).
- **H2 — `ATA029`/`ATA030` = `no_se_comprobo`.** El mapa dice que SÍ hay prueba Linux
  (`tests_linux=1` y `=5`) y el plan las marcaba como **ART adaptable**, pero se **ejecutó guion
  propio** sin dejar constancia en el repo de que se comprobara/ejecutara la atómica. Por la
  **regla de honestidad**, el `motivo_codigo` anterior **`art_no_prueba_plataforma` se corrige a
  `no_se_comprobo`** (hueco declarado), en vez de dejar un motivo que **contradice** al mapa. Ambas
  son candidatas de la Lista A para **comprobarlo** repitiendo con ART.
- **H3 — Deuda histórica del campo `fuente`.** No está normalizado (`"ART"`, `"atomic-red-team"`,
  `"custom"`); la auditoría **no lo oculta**: añade `fuente_norm` **aditivo** (ver §A.4 del
  `criterio_ataques.md`) y conserva el literal.
- **H4 — Mezcla de grados de ART en el corpus.** De los 6 con nexo ART, solo **ATA018** es
  `ART_adaptado`; los otros **5** son `ART_tal_cual`. El resto (**37**) es **propio**; el grueso
  (**24**) es `propio_por_diseno` (diseño deliberado: capas nuevas, control del efecto, variantes).
- **H5 — Frontera morado/verde.** El mapa regenerado da **25/43** con prueba ART y **15/43**
  "cubierta en Linux"; el corpus real usó ART en solo **6/43**, lo que confirma la distinción ya
  documentada: *"ART lo cubra" ≠ "ejecutable en el laboratorio sin NAT con el mismo mecanismo"*.

---

## 4. Qué decide el humano (posterior a esta auditoría, no se ejecuta aquí)

1. Leer la **Lista A** y la **Lista B** y elegir **qué ataques repetir** en el **bloque siguiente**.
2. Confirmar si `ATA029`/`ATA030` se repiten **con la atómica de ART** (Lista A) o se dejan como
   hueco declarado (`no_consta`).
3. Recordar que la **norma de pre-staging** (`criterio_ataques.md` §C) aplica a **ataques nuevos**,
   no a los 43 ya ejecutados.
