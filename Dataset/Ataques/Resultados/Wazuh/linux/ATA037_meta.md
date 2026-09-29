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
