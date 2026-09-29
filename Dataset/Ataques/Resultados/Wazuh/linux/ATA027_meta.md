---
fase: 3
bloque: fase-03-ampliacion
tanda: C
ata_id: ATA027
tecnica: T1561.002
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA027 · T1561.002 Disk Structure Wipe (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda C**, 5.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **SOLO una imagen de fichero** (`lab-attack/ATA027/disk.img`): **nunca** discos/particiones reales.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA027** |
| Técnica | **T1561.002 — Disk Wipe: Disk Structure Wipe** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **con `sudo`** (solo `mount`/`umount`/`losetup`) |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `dd`, `sfdisk`, `mkfs.ext4`→`mke2fs`, `wipefs`, `mount`, `umount`, `losetup` |
| Efecto | estructura (MBR+ext4) **destruida**; la imagen **deja de ser montable**; **sin loop residual** |
| Elevación | **sí** (`sudo`, solo `mount`/`umount`/`losetup`) |
| Guardarraíl **DURO** | destino **solo** imagen de fichero bajo `lab-attack/ATA027`; aborta si la ruta tiene `/dev/`; `trap` que detacha loops |

Artefacto: `.../T1561.002-Disk_Structure_Wipe/ATA027_ataque.sh`
(`sha256=adf302815c43ce25b61f48ddba4689a50a76a0c718fdab707b841ebf4d19c0a1`).
Señales: `.../ATA027_esperado.csv` (`sha256=c72d8a6789a9b42aa74da5b40e97b2e03de71fb622f124f537b0b48ca1e3a6a6`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA027_logtest.txt` (`sha256=14917ba30364e539327d84b77d48bc1bad8629efae9f6f9e02099301c243af68`)
→ `ATA027_preflight.md` (`sha256=9f7fb1ce3a336b77d47dd86cd58454819e1e4dfb79049716ee025f64e7dfa946`) **PASA**
(7 eventos `dd`/`sfdisk`/`mkfs.ext4`/`wipefs`/`mount`/`umount`/`losetup` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras 90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T03:58:37Z` | `2026-09-29T03:59:10Z` | 33 s | 1277 | `adf30281…c0a1` |
| 2 | `2026-09-29T04:02:14Z` | `2026-09-29T04:02:47Z` | 33 s | 1144 | `adf30281…c0a1` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA027
SUDO_PW='<contrasena>' bash ATA027_ataque.sh   # dd+sfdisk+mkfs.ext4+losetup+mount … wipefs+dd (wipe)
```

## 6. Evidencia

`Logs/ATA027_iter{1,2}/`: `times.log`, `ejecucion.out`, `estructura_antes.txt`,
`estructura_despues.txt`.

**Prueba de éxito — la estructura de la imagen se destruyó:**

| Iter | `file -s` ANTES | `file -s` DESPUÉS | montaje después | loop residual | `DISK_STRUCTURE_WIPE` |
|---|---|---|---|---|---|
| 1 | ext4 (`UUID=fda48236…`) | **`data`** | **falla** | **0** | **OK** ✅ |
| 2 | ext4 (`UUID=c6b99477…`) | **`data`** | **falla** | **0** | **OK** ✅ |

`blkid_tras_wipe=no_reconoce` en ambas; `sha256` de la imagen **antes ≠ después**.

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1286 | 1278 | 1277 |
| 2 | 1154 | 1145 | 1144 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1277 | **13** | 608 | 596 | **0** | 60 | 24 | 1253 | 0 | 0 |
| 2 | 1144 | **14** | 612 | 461 | **0** | 57 | 31 | 1113 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 13 | 1 · `{80792}` | 13 | 0 |
| 2 | 14 | 1 · `{80792}` | 14 | 0 |

Herramientas detectadas (ancladas al `cwd`): `dd`(2), `sfdisk`(2), `wipefs`(1), `mount`(2),
`umount`(1), `losetup`(5-6). **`mkfs.ext4` NO casa** (ver §10).
- **`dudosa` resueltas:** iter1 → 2 `80792` `sin_ancla` **+ 21 de la sesión `sudo` del ataque**
  (`5402`/`5501`/`5502`, `dstuser=root`) → `artefacto`; **2** PAM del operador (`dstuser=angel`) →
  `ruido`. iter2 → 21 de la sesión `sudo` → `artefacto`; **7** PAM del operador → `ruido`. **Ninguna**
  fila del ataque (carpeta) ni de la sesión `sudo` del ataque queda en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `03:58:39.978Z` `audit_exe=/usr/bin/dd` | **6/7** | 13 / 60 / 596 | 13 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `04:02:16.222Z` `audit_exe=/usr/bin/dd` | **6/7** | 14 / 57 / 461 | 14 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|14−13|=1 ≤ 2`; sin dudosas. Ver `Bitacora/ATA027.json`.

## 10. Limitaciones y hallazgos

1. **⭐ HALLAZGO (mismo sistema que ATA028/ATA026):** el `esperado` declara `audit_exe=mkfs.ext4`, pero
   audit registra `/usr/sbin/mke2fs` (el binario real; `mkfs.ext4` es un enlace/alternativa) → **NO
   casa** (**O2 = 6/7**). **Regla práctica:** declarar `audit_exe` con el **nombre real** del binario
   o un **glob**, no con el nombre de la orden.
2. **Sin regla de "estructura de disco":** el HIDS ve los **procesos**, no que se haya borrado un
   MBR/GPT (y aquí es una **imagen**, no un disco real).
3. **Guardarraíl DURO respetado:** solo imagen de fichero; **0** loops residuales; **ningún** disco
   real tocado. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
4. **Línea para ratificar:** las filas de la **sesión `sudo` del propio ataque** (`5402` y
   `5501/5502` con `dstuser=root`) se resolvieron a **`artefacto`** (es el ataque, no la detección);
   las **PAM del operador** (`dstuser=angel`) a **`ruido`**. Ver §8.1.
5. **Huellas del ataque declaradas** (no son detección): 4 filas `80791` de la ruta URL-encoded del
   `disk.img`. Ver **§10.1**.

### 10.1 Huellas del ataque declaradas — **NO son detección**

> Añadido en `fase-03-ampliacion` (cabos de documentación, 2026-09-29). **No** se recalcula nada
> (métrica **congelada** y `esperado` **firmado**).

- **Qué filas:** **4** (`80791`, **2 por iteración**) con
  `audit_file=/dev/disk/by-loop-ref/\x2fhome\x2fangel\x2flab-attack\x2fATA027\x2fdisk.img` y
  `audit_dir=/dev/disk/by-loop-ref/` (la **ruta URL-encoded** del `disk.img`; `cwd=/`).
- **Dónde caen:** en **`ruido_conocido`/`baseline`**.
- **Por qué NO son detección y por qué el mecanismo NO las caza:** la pertenencia por carpeta mira
  `audit_cwd` **o** la **ruta**: aquí el `cwd` es `/` y la ruta es un **enlace simbólico del kernel**
  (`/dev/disk/by-loop-ref/…`) cuyo componente de la carpeta del ataque va **URL-encoded**
  (`\x2fhome\x2fangel\x2flab-attack\x2fATA027\x2f…`) → **no** contiene el literal
  `lab-attack/ATA027` que la prueba de pertenencia busca y **no** se caza. Son **escrituras `watch`**
  del **setup loop** del propio ataque, no la detección declarada. Nada del ataque **se pierde**: la
  técnica sigue **DETECTADA** por los **`80792`** (`dd`/`sfdisk`/`wipefs`/`mount`/`umount`/`losetup`,
  anclados al `cwd`) — ver §8.2.

### 10.2 Alcance del invariante «0 filas del ataque en `ruido`» y asimetría declarada

- El invariante **«0 filas del ataque en `ruido_conocido`/`auto_ruido`»** se cumple **bajo la
  pertenencia por carpeta** (fila con `audit_cwd`/ruta que cae bajo `lab-attack/ATA<NNN>` → paso 3.5
  → **`artefacto_ataque`**, **nunca** `ruido`); las 4 filas de §10.1 son la **excepción declarada**
  (ruta **ofuscada** por el enlace del kernel).
- **Asimetría metodológica (declarada):** el **mismo evento real** —la **sesión PAM/`sudo` del
  ataque**— acaba en **`artefacto`** aquí (ATA027), pero en **`ruido_conocido`/`baseline`** en
  **ATA024**. La diferencia **no** es el evento, sino si el `esperado` declara **algún campo siempre
  evaluable** (`rule_id`/`rule_group`): ATA024 declara `rule_id` (las `ambigua` `80790/80781/80782`)
  → no dispara `sin_campos` → `baseline`; ATA027 **no** lo declara → `sin_campos` → `dudosa` →
  veredicto humano **`artefacto`**. Es una **limitación declarada del mecanismo congelado** (no se
  toca el filtro). Ver el runbook §12.
