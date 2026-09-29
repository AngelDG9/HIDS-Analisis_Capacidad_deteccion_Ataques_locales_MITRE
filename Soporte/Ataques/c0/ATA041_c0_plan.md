# C0 · pre-flight base-contra-base — ATA041 · T1048.002 (openssl, curl)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA041).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`openssl` (par RSA + cifrado/descifrado asimétrico) y `curl` (envío del blob cifrado).

## Pasos (con las VMs encendidas)

**1. Capturar las líneas de audit REALES en la víctima** (root solo para leer el log): se ejecutaron
`openssl version` y `curl --version` (benignos) y se volcaron sus eventos de `execve`.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA041_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA041_logtest.txt`
→ `ATA041_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** en ambos (*Audit: Command: /usr/bin/openssl* y
  */usr/bin/curl*), **`level 3` → SÍ avisa**.
- **Sin silenciador.** → PASA (`ATA041_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
