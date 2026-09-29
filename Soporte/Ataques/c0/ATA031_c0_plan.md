# C0 · pre-flight base-contra-base — ATA031 · T1667 (cp)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA031).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`cp` (la entrega de cada mensaje del bombardeo de correo).

## Pasos (con las VMs encendidas)

**1. Capturar la línea de audit REAL en la víctima** (root solo para leer el log):
se ejecutó `cp --version` (benigno) y se volcó su línea de `audit(…)`.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA031_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA031_logtest.txt`
→ `ATA031_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /usr/bin/cp*), **`level 3` → SÍ avisa**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA031_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
