# ATA037 · T1561.001 — Disk Content Wipe (SOLO imagen loop, contenido ≠ estructura)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda B**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA037** |
| Técnica | **T1561.001 — Disk Wipe: Disk Content Wipe** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **`sudo` solo** para `mount`/`umount`/`losetup` |
| Capa del HIDS que ejercita | **`execve`** de las herramientas de disco (`80792`) |

## 2. Qué hace y dónde escribe

- **Qué hace:** **borra el CONTENIDO** de un disco: crea una **imagen de fichero desechable**
  (`disk.img`), le da **filesystem ext4**, la **monta (loop)**, escribe un dato dentro y
  **sobrescribe su contenido** (`dd` de `urandom` **in place**) **sin dañar la estructura**: la
  imagen **sigue siendo ext4** y **sigue montando** tras el wipe.
- **Contraste con ATA027/T1561.002** (Disk Structure Wipe): allí se destruyó la **estructura** (la
  imagen **dejó** de ser montable); aquí se destruye el **contenido** y la **estructura
  permanece**.
- **Destino:** **solo** `/home/angel/lab-attack/ATA037/disk.img` (+ `mnt/`). **Jamás** discos ni
  particiones reales.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `dd`(`/usr/bin/dd`), `mkfs.ext4`(→`/usr/sbin/mke2fs`), `mount`, `umount`, `losetup`(`/usr/sbin/losetup`), `file`, `blkid`, `sha256sum` |
| Dependencias | ninguna nueva |
| Elevación | **sí**, `sudo` (por `stdin`), **solo** para `mount`/`umount`/`losetup` (+ `chown` del punto de montaje) |

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA037` y `scp -r` del directorio de la técnica ahí.
2. `cd /home/angel/lab-attack/ATA037 && bash ATA037_ataque.sh 2>&1 | tee ejecucion.out`
   (la contraseña de `sudo` va por **stdin**; **nunca** a fichero). Imprime `T0=…`/`T1_LOCAL=…`.

## 5. Señales esperadas (convención H4)

`ATA037_esperado.csv`:

- `T1561.001-S1..S5` (**deteccion**) `audit_exe ∈ {/usr/bin/dd, /usr/sbin/mke2fs, /usr/bin/mount,
  /usr/bin/umount, /usr/sbin/losetup}` — herramientas de disco (`80792`). **Binario real** de
  `mkfs.ext4` = `/usr/sbin/mke2fs` (lección de la ronda anterior).
- `T1561.001-S6` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA037/*` — ancla H4.
- `T1561.001-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — creación/escritura de ficheros
  (efecto) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de las herramientas de disco (`80792`, nivel 3), ancladas al `cwd`.
- La capa es **local** (no hay red): el HIDS ve el **proceso**, no el "borrado" como tal.

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: el **contenido** del dato cambió (`sha_dato_antes ≠ sha_dato_despues`) y la
**estructura** sigue intacta (`file -s` sigue diciendo `ext4`, `blkid` reconoce, y la imagen
**SIGUE montando** tras el wipe). **Sin loop residual.** Evidencia en `Logs/ATA037_iter*/`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `disk.img`). El manager **no** se revierte.
- **Higiene:** `trap` detacha el loop al salir; **0 loops residuales** y **nada montado** al
  terminar; sin secretos (la contraseña va por `stdin`).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (se destruye **solo** una
> **imagen de fichero desechable**, nunca un disco real); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**.
