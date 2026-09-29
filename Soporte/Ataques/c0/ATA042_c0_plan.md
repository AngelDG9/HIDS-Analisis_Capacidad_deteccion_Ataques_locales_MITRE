# C0 · pre-flight base-contra-base — ATA042 · T1048.003 (nc.openbsd)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA042).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`nc.openbsd` (envío EN CLARO por TCP crudo). **Ojo:** `nc` es un **enlace** → el `execve` registra el
**binario real** `/usr/bin/nc.openbsd`.

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima** (root solo para leer el log): se ejecutó
`nc.openbsd -h` (benigno) y se volcó su evento de `execve`.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA042_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA042_logtest.txt`
→ `ATA042_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /usr/bin/nc.openbsd*), **`level 3` → SÍ avisa**.
- **Sin silenciador.** → PASA (`ATA042_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
