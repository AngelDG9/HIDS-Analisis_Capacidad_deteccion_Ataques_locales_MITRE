# C0 · pre-flight base-contra-base — ATA027 · T1561.002 (dd, sfdisk, mkfs.ext4, wipefs, mount, umount, losetup)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA027).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`dd`, `sfdisk`, `mkfs.ext4`, `wipefs`, `mount`, `umount`, `losetup` (herramientas de disco; solo
sobre la **imagen de fichero** del ataque).

## Resultado (ejecutado)

- 7 eventos analizados; ganadora **`80792`** (*Audit: Command*) en los 7, **`level 3` → SÍ avisan**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA027_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
