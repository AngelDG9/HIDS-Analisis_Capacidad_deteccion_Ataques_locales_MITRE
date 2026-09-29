# ATA027 · T1561.002 — Disk Structure Wipe (SOLO imagen de fichero, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda C**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA027** |
| Técnica | **T1561.002 — Disk Wipe: Disk Structure Wipe** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **con `sudo`** (solo `mount`/`umount`/`losetup`) |

## 2. Qué hace y dónde escribe

- **Qué hace:** **destruye la estructura** de un disco — pero **SOLO de una imagen de fichero
  desechable**: crea `disk.img`, le da una **tabla de particiones (MBR)** y un **ext4**, la
  **monta**, y luego **destruye su estructura** (`wipefs -a` + `dd` de ceros sobre la cabecera),
  demostrando que la imagen deja de ser reconocible **ni montable**.
- **Destino:** **solo** `/home/angel/lab-attack/ATA027/disk.img` (+ punto de montaje
  `lab-attack/ATA027/mnt`).
- **Capa del HIDS que ejercita:** **`execve`** de las herramientas de disco
  (`dd`/`sfdisk`/`mkfs.ext4`/`wipefs`/`mount`/`umount`/`losetup`).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `dd`, `sfdisk`, `mkfs.ext4`, `wipefs`, `mount`, `umount`, `losetup`, `file`, `blkid` (de serie) |
| Dependencias | ninguna nueva (util-linux 2.39.3, e2fsprogs 1.47.0) |
| Elevación | **sí**: `sudo` **solo** para `mount`/`umount`/`losetup` (`sudo -S` por stdin) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA027/`.
2. Pasar la contraseña de `sudo` **por el entorno** o **por stdin** (1.ª línea), nunca en el guion:

   ```bash
   cd /home/angel/lab-attack/ATA027
   SUDO_PW='<contrasena>' bash ATA027_ataque.sh 2>&1 | tee ejecucion.out
   ```

   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA027_esperado.csv` (todas **deteccion**):

- `T1561.002-S1..S7` `audit_exe ∈ {dd, sfdisk, mkfs.ext4, wipefs, mount, umount, losetup}` (`80792`).
- `T1561.002-S8` `audit_cwd=/home/angel/lab-attack/ATA027/*` — ancla H4.

> **No hay señales `ambigua`:** todo ocurre **fuera** de rutas vigiladas.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de las herramientas de disco (`80792`, nivel 3) anclado al `cwd`.
- **No hay regla de "estructura de disco"**: lo que se ve es el **proceso**, no que se haya
  borrado un MBR/GPT (y **aquí es una imagen**, no un disco real).

## 7. Prueba de éxito (independiente de la alerta)

**Antes:** `file -s` = ext4 y el montaje **funciona** (se escribe `marcador_estructura.txt`).
**Después:** `file -s` = `data`, `blkid` **no reconoce** nada y el montaje **FALLA**; **sin loop
residual**. `sha256` antes ≠ después. Evidencia en `Logs/ATA027_iter*/ejecucion.out` +
`estructura_antes.txt`/`estructura_despues.txt`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte. El guion
  lleva un **`trap`** que **detacha** cualquier loop residual.
- **Higiene:** **nunca** se tocan discos/particiones/dispositivos reales; el loop deriva de la
  imagen del ataque. Sin datos reales.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (**solo** una imagen de
> fichero desechable; **no** se destruye la máquina); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**.
