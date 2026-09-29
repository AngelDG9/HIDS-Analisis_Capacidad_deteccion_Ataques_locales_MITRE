# C0 · pre-flight base-contra-base — ATA040 · T1074.002 (rsync, staging remoto)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA040).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`rsync` (cliente que envía el material estagiado al recurso remoto del laboratorio).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima** (root solo para leer el log): se ejecutó
`rsync --version` (benigno) y se volcó su evento de `execve` (mismo binario que ATA039).

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA040_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA040_logtest.txt`
→ `ATA040_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /usr/bin/rsync*), **`level 3` → SÍ avisa**.
- **Sin silenciador.** → PASA (`ATA040_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
