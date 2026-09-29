# C0 · pre-flight base-contra-base — ATA034 · T1560.003 (método propio: builtins)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA034).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

**Ninguno propio del ataque**: el archivado por **método propio** se implementa con **builtins de
bash** (`read`/`printf`/redirección) → **no ejecuta ningún binario externo**. Se comprueba como
control el **intérprete** realmente usado (`/usr/bin/bash`, invocado desde la carpeta del ataque).

## Pasos (con las VMs encendidas)

**1. Capturar la línea de audit REAL en la víctima** (root solo para leer el log): se ejecutó una
copia de `bash` bajo `lab-attack/ATA034/` (`shell_c0 -c 'true'`, benigno) y se volcó su evento.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA034_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA034_logtest.txt`
→ `ATA034_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /home/angel/lab-attack/ATA034/shell_c0*),
  **`level 3` → SÍ avisa**.
- **Sin silenciador.** → PASA (`ATA034_preflight.md`).
- **Nota (punto ciego declarado):** el **intérprete** (`bash`) **sí** alerta por `80792`, pero es
  **genérico** (lo dispara cualquier script): **no** identifica la técnica y **no** se declara como
  señal de detección. El **método propio** (builtins) **no deja execve de herramienta**.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
