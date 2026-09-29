# C0 · pre-flight base-contra-base — ATA024 · T1531 (useradd, userdel, passwd)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA024).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`useradd`, `userdel`, `passwd` (herramientas de gestión de cuentas).

## Pasos (con las VMs encendidas)

**1. Capturar las líneas de audit REALES en la víctima** (root solo para leer el log):
se ejecutó cada herramienta de forma benigna (`--version`) y se volcó su línea de `audit(…)`.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA024_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA024_logtest.txt`
→ `ATA024_preflight.md`.

## Resultado (ejecutado)

- 3 eventos analizados; ganadora **`80792`** (*Audit: Command*) en los 3, **`level 3` → SÍ avisan**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA024_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
