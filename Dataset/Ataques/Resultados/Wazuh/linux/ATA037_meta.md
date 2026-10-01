---
fase: 3
bloque: fase-03-ampliacion-2
tanda: B
ata_id: ATA037
tecnica: T1561.001
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA037 · T1561.001 Disk Content Wipe (SOLO imagen loop) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda B**, 4.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Contraste con ATA027/T1561.002:** allí se destruyó la **estructura** (dejó de montar); aquí el
> **contenido**, y la **estructura permanece** (sigue montando).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA037** |
| Técnica | **T1561.001 — Disk Wipe: Disk Content Wipe** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **`sudo` solo** para `mount`/`umount`/`losetup` |
| Capa del HIDS | **`execve`** de las herramientas de disco (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `dd`, `mkfs.ext4`(→`mke2fs`), `mount`, `umount`, `losetup` — **solo** sobre la **imagen de fichero** |
| Efecto | el **contenido** del dato cambia (`sha256` antes ≠ después) y la **estructura** sigue intacta (la imagen **sigue montando**) |
| Elevación | **sí**, `sudo` (por `stdin`), solo para `mount`/`umount`/`losetup` |
| Guardarraíl DURO | destino **imagen de fichero regular** bajo `lab-attack/ATA037`; aborta con `/dev/` o si no es "regular file" |

Artefacto: `.../T1561.001-Disk_Content_Wipe/ATA037_ataque.sh`
(`sha256=4e11e9a473f4d50ac83dc761e4afe51bc530ca16e995c84a40736d3c0e66d8ae`).
Señales: `.../ATA037_esperado.csv` (`sha256=1177844722b5482a1a893f04953506b658a59a983d0aaf9f1fe2b0f7fc3a3755`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA037_logtest.txt` (`sha256=18321e9b11ab46f5c6d3922714858339adcc6d4411ad544703116ee96ac7c3c0`)
→ `ATA037_preflight.md` (`sha256=ea027de313324aa32fb4482086ea4581f5f2c5ee113a2f190cd748aa2b58554e`) **PASA**
(5 eventos dd/mke2fs/mount/umount/losetup → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
~95 s. **No usa receptor.** **Guardarraíl cumplido:** el wipe fue **solo** sobre `disk.img`.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T10:44:19Z` | `2026-09-29T10:44:51Z` | 32 s | 1052 | `4e11e9a4…d8ae` |
| 2 | `2026-09-29T10:48:38Z` | `2026-09-29T10:49:11Z` | 33 s | 1049 | `4e11e9a4…d8ae` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA037
printf '%s\n' '<pw>' | bash ATA037_ataque.sh   # dd + mkfs.ext4 + mount + dd urandom + umount + remount
```

## 6. Evidencia

`Logs/ATA037_iter{1,2}/`: `times.log`, `ejecucion.out`, `estructura_antes.txt`, `estructura_despues.txt`.

**Prueba de éxito — CONTENIDO borrado, ESTRUCTURA intacta:**

| Iter | `sha_dato_antes` | `sha_dato_despues` | `file -s` tras wipe | `blkid` | remonta | `loop_residual` |
|---|---|---|---|---|---|---|
| 1 | `bb9f8df6…3af8` | `20c32ac7…f46d` | **ext4** | reconoce | **SÍ** | **0** |
| 2 | `bb9f8df6…3af8` | `49d8997f…a27d` | **ext4** | reconoce | **SÍ** | **0** |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1058 | 1052 | 1052 |
| 2 | 1056 | 1049 | 1049 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1052 | **14** | 612 | 393 | **0** | 33 | 37 | 1015 | 0 | 0 |
| 2 | 1049 | **13** | 607 | 392 | **0** | 37 | 37 | 1012 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 14 | 1 · `{80792}` | 14 (6 `losetup`, 3 `dd`, 2 `mount`, 2 `umount`, 1 `mke2fs`) | 0 |
| 2 | 13 | 1 · `{80792}` | 13 (5 `losetup`, 3 `dd`, 2 `mount`, 2 `umount`, 1 `mke2fs`) | 0 |

- **`80792`:** `execve` de las **5 herramientas** de disco ancladas al `cwd` (`S1`–`S5` ∧ `S6`).
- **`dudosa` resuelta:** **1/iter2** `80792` `losetup` **sin `cwd`** (el **setup loop** del ataque) →
  **`artefacto`** (es el ataque, pero **no** la detección declarada anclada) — **nunca** `ruido`.
- **`artefacto_ataque` (auto):** `chown`, `stat`, `file`, `blkid`, `sha256sum`, `rm`… No hay filas
  del ataque en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `10:44:20Z` `Audit: Command: /usr/bin/dd` | **5/5** (`S1`…`S5`) | 14 / 33 / 393 | 14 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `10:48:39Z` `Audit: Command: /usr/bin/dd` | **5/5** (`S1`…`S5`) | 13 / 37 / 392 | 13 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|13−14| = 1 ≤ max(2, 1.4) = 2`. **C3′:** ✅ sin dudosas
  (1 resuelta por veredicto humano `artefacto`). Ver `Bitacora/ATA037.json`.

## 10. Limitaciones y hallazgos

1. **Capa local (`execve`).** El HIDS ve **las herramientas de disco**, no el «borrado» como tal
   (R9). Todo el efecto es local a la **imagen de fichero**.
2. **Contraste de la pareja de disco:** `T1561.001` (contenido, **estructura intacta**) vs
   `T1561.002` (ATA027, estructura destruida) — **misma detección** (`80792`), **distinto efecto**.
3. **`audit_exe` con el binario real:** `mkfs.ext4` → **`/usr/sbin/mke2fs`** (declarado como REAL;
   evita la pérdida de O2 de la ronda anterior).
4. **Guardarraíl DURO respetado:** solo imagen de fichero (`regular file`), **0 loops residuales**,
   **nada montado** al cerrar. Realismo acotado declarado (README §9).

## 11. Filas `ruido` (para ratificación)

- **iter1: 393**; **iter2: 392** — **baseline** (PAM del login del operador, `sshd`, `591`…), ajenas
  al ataque. **0** filas del ataque en `ruido`.

---

## § Repetición auditada (rev)

> Bloque `fase-03-repeticiones` (**tanda R3**), **2026-10-01**. `esperado_rev` firmado **APROBADO 2026-10-01 (validación humana)** ANTES del primer `t0`. Añadido por `tfg-executor`. **Sin secretos.**

### Motivo

- **`motivo_repeticion` = `prestaging`.** Auditoría metodológica (`_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` §2; `Soporte/Ataques/criterio_ataques.md` §C): el ataque **creaba y formateaba (`mke2fs`) la imagen dentro de `[t0,t1]`**, ensuciando la ventana con la preparación (que **no es la técnica**).

### Qué cambió respecto al original (el original NO se toca)

- **Método original:** propio — `dd` (crear imagen) + `mkfs.ext4` (`mke2fs`) + `mount` + escribir dato + `dd urandom` (wipe) + `umount`, **todo dentro** de la ventana.
- **Método de la repetición (pre-staging):** la **imagen `disk.img` (ext4) se crea y formatea ANTES de `t0`** (modo `prestage`); la ventana ejecuta **solo** el wipe del contenido (montar + sobrescribir in place + desmontar). Desaparece la señal de `mke2fs` (formateo = preparación, ya fuera de la ventana).
- **Material antes de `t0`:** `disk.img` (16 777 216 bytes, ext4, `sha_dato_antes=bb9f8df61474d25e71fa00722318cd387396ca1736605e1248821cc0de3d3af8`); ver `Logs/ATA037_rev{1,2}/prestaging.out`.

### Iteraciones (rev)

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | auto_ruido | ruido_conocido | artefacto_ataque | dudosa |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-01T21:45:49Z` | `2026-10-01T21:46:21Z` | 967 | **10** | 625 | 301 | 31 | 0 |
| 2 | `2026-10-01T21:49:45Z` | `2026-10-01T21:50:18Z` | 977 | **11** | 636 | 300 | 30 | 0 |

### Resultado (métrica congelada O1+O2)

- **O1 (detectado):** sí — `rule_id` = `['80792']`.
- **O2 (acciones cubiertas):** iter1 = 4/4 · iter2 = 4/4 (`S1`=`dd`, `S2`=`mount`, `S3`=`umount`, `S4`=`losetup`; el ancla `S5` no es detector).
  - iter1 primera evidencia: `2026-10-01T21:45:50.948Z` `audit_exe=/usr/sbin/losetup`.
  - iter2 primera evidencia: `2026-10-01T21:49:47.271Z` `audit_exe=/usr/sbin/losetup`.
- **Doble iteración (v2):** `iguales` (mismo `rule_id` de detección; `|11−10|=1 ≤ 2`; sin dudosas).
- **`dudosa` resueltas:** iter1: artefacto=1 (`losetup` sin `cwd` = setup loop del ataque) + ruido=31 · iter2: ruido=31.
- **0 filas del ataque en `ruido`** (pertenencia por carpeta).

### Prueba de efecto (independiente de la alerta)

- iter1: `sha_dato_antes=bb9f8df6…3af8` ≠ `sha_dato_despues=1caa9ea3…c30c`; `file -s` = **ext4**, `blkid` reconoce, **la imagen sigue montando**; `loop_residual=0`.
- iter2: `sha_dato_antes=bb9f8df6…3af8` ≠ `sha_dato_despues=0508c143…9b0e`; estructura `ext4` intacta y montable; `loop_residual=0`.

### Cómo se cumple el motivo (pre-staging)

- La imagen se creó y formateó **ANTES de `t0`** (`prestaging.out`: `PRESTAGE=OK`); **ninguna** señal `ambigua` de la siembra (`80790`/`80781`/`80782`) cae en `[t0,t1]`. La ventana mide **solo** las herramientas del wipe, todas ancladas al `cwd`.

### Trazabilidad

- `esperado_rev`: `…/T1561.001-Disk_Content_Wipe/ATA037_esperado_rev.csv` (`sha256=c0c157a378010946beaa36f7ef16f9bfb9ef2ca3fe135503b850ec5955127ac0`).
- `ataque_rev`: `…/T1561.001-Disk_Content_Wipe/ATA037_ataque_rev.sh` (`sha256=1539bea4c9ed7f9d1629b1e01bf970c60d971ec90ce3b0d97d22a5603801cc50`).
- C0: `Soporte/Ataques/c0/ATA037_rev_logtest.txt` + `ATA037_rev_preflight.md` (**PASA**, sin silenciadores).
- Detalle: `…/CSV/ATA037_rev{1,2}-Detalle.csv` · Auditado: `…/Auditado/ATA037_rev{1,2}-Audited.csv`.
