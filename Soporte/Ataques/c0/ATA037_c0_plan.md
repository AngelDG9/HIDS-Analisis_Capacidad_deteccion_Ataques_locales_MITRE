# C0 · pre-flight base-contra-base — ATA037 · T1561.001 (dd, mkfs.ext4, mount, umount, losetup)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA037).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`dd`, `mkfs.ext4` (→ binario real `/usr/sbin/mke2fs`), `mount`, `umount`, `losetup`
(herramientas de disco; solo sobre la **imagen de fichero** del ataque).

## Pasos (con las VMs encendidas)

**1. Capturar las líneas de audit REALES en la víctima** (root solo para leer el log): se
ejecutaron en modo benigno (`--version` / `-V`) y se volcaron sus eventos.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA037_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA037_logtest.txt`
→ `ATA037_preflight.md`.

## Resultado (ejecutado)

- 5 eventos analizados; ganadora **`80792`** (*Audit: Command*) en los 5, **`level 3` → SÍ avisan**;
  se confirma el **binario real** `mkfs.ext4 → /usr/sbin/mke2fs` (declarar el REAL).
- **Sin silenciador.** → PASA (`ATA037_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
