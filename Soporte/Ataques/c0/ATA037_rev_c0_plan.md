# C0 · pre-flight base-contra-base — ATA037_rev · T1561.001 (dd, mkfs.ext4, mount, umount, losetup)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA037_rev).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base para las herramientas de disco.
**No** se escriben reglas propias (D5). Nota: la **imagen** (`disk.img` ext4) se **crea en el
pre-staging** (antes de `t0`); la ventana hace **solo el wipe** (`mount`+`dd`+`umount`).

## Comandos clave

`dd`, `mkfs.ext4` (→ binario real `/usr/sbin/mke2fs`), `mount`, `umount`, `losetup`
(herramientas de disco; **solo** sobre la **imagen de fichero**).

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL en la víctima (root solo para leer el log) ejecutando las
herramientas en modo benigno (`--version`/`-V`) y volcando su evento `audit(…)`.
**2.** `wazuh-logtest -v` en el manager. **3.** Guardar en
`Soporte/Ataques/c0/ATA037_rev_logtest.txt`. **4.** `preflight_enmascaramiento.py
--logtest-base-c0 …` → `ATA037_rev_preflight.md`.

## Resultado (ejecutado)

- 5 eventos analizados; ganadora **`80792`** en los 5 (`/usr/bin/dd`, `/usr/sbin/mke2fs`,
  `/usr/bin/mount`, `/usr/bin/umount`, `/usr/sbin/losetup`), **`level 3` → SÍ avisan**. **Sin
  silenciador.** → **RESULTADO: PASA**.
- Se confirma el **binario real** `mkfs.ext4 → /usr/sbin/mke2fs` (declarar el REAL).

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
