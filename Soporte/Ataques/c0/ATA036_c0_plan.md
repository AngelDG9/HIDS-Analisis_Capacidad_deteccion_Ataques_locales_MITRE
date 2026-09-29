# C0 · pre-flight base-contra-base — ATA036 · T1565.003 (memedit)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA036).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`memedit` (la herramienta de manipulación en memoria por `ptrace`) — binario **de laboratorio**
bajo `lab-attack/ATA036/`. Control: se probó una copia bajo esa ruta para confirmar que un `execve`
de esa ruta alerta.

## Pasos (con las VMs encendidas)

**1. Capturar la línea de audit REAL en la víctima** (root solo para leer el log): se ejecutó el
stand-in `…/ATA036/memedit_c0` (benigno) y se volcó su evento.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA036_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA036_logtest.txt`
→ `ATA036_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command:
  /home/angel/lab-attack/ATA036/memedit_c0*), **`level 3` → SÍ avisa**.
- **Sin silenciador.** → PASA (`ATA036_preflight.md`).
- **Punto ciego declarado:** `ptrace` y la escritura en `/proc/<pid>/mem` **no** generan evento con
  este ruleset (audit solo audita `execve` y escrituras de fichero).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
