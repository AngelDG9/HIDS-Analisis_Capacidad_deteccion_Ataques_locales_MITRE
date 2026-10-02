# C0 · pre-flight base-contra-base — ATA044 · T1025 (mount, losetup, cp…)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA044).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`mount`, `losetup`, `cp`, `find`, `sha256sum`, `umount` (acciones de la ventana).

## Pasos (ejecutados)

**1.** En la víctima se generaron invocaciones benignas (`--version`) y se capturaron los eventos
reales de `audit.log` con `Soporte/Ataques/c0/c0_capture.sh`.
**2.** `wazuh-logtest -v` en el manager → `Soporte/Ataques/c0/ATA044_logtest.txt`.
**3.** Informe con `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA044_preflight.md`.

## Resultado (ejecutado)

- **6 eventos** analizados; ganadora **`80792`** (*Audit: Command*) en los 6, **`level 3` → SÍ avisan**
  (`/usr/bin/mount`, `/usr/sbin/losetup`, `/usr/bin/cp`, `/usr/bin/find`, `/usr/bin/sha256sum`, `/usr/bin/umount`).
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA044_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
