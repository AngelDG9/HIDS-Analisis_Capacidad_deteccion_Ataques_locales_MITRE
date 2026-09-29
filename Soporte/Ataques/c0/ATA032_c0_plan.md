# C0 · pre-flight base-contra-base — ATA032 · T1565.001 (sed)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA032).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`sed` (la manipulación del ledger en reposo).

## Pasos (con las VMs encendidas)

**1. Capturar la línea de audit REAL en la víctima** (root solo para leer el log):
se ejecutó `sed --version` (benigno) y se volcó su línea de `audit(…)`.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA032_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA032_logtest.txt`
→ `ATA032_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /usr/bin/sed*), **`level 3` → SÍ avisa**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA032_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
