# C0 · pre-flight base-contra-base — ATA036_rev · T1565.003 (memedit)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA036_rev).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base para la herramienta de manipulación.
**No** se escriben reglas propias (D5). Nota: el **payload** (`memedit`/`target`) se **decodifica
en el pre-staging** (antes de `t0`); el C0 cubre el `execve` de la herramienta.

## Comandos clave

`memedit` (herramienta de manipulación en memoria del proceso de laboratorio). Control: se ejecutó
un **stand-in** `…/ATA036/memedit_c0` (copia de `/usr/bin/true`) para confirmar que un `execve` de
esa ruta alerta.

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL en la víctima (root solo para leer el log) ejecutando el
stand-in `…/ATA036/memedit_c0` (benigno). **2.** `wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA036_rev_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA036_rev_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (`/home/angel/lab-attack/ATA036/memedit_c0`),
  **`level 3` → SÍ avisa**. **Sin silenciador.** → **RESULTADO: PASA**.
- **Punto ciego declarado:** el `ptrace` y la escritura en `/proc/<pid>/mem` **no** generan evento.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
