# C0 · pre-flight base-contra-base — ATA030_rev · T1560.001 (tar, gzip)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA030_rev).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base para los comandos clave de la atómica ART.
**No** se escriben reglas propias (D5).

## Comandos clave

`tar` (utilidad de archivado de la atómica `tar -cvzf`) y `gzip` (compresor invocado por `tar -z`).

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL en la víctima (root solo para leer el log) ejecutando las
herramientas de forma benigna (`--version`) y volcando el evento `audit(…)`.
**2.** Ejecutar `wazuh-logtest -v` en el manager con esas líneas.
**3.** Guardar en `Soporte/Ataques/c0/ATA030_rev_logtest.txt`.
**4.** Generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA030_rev_logtest.txt`
→ `ATA030_rev_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (*Audit: Command: /usr/bin/tar* y */usr/bin/gzip*),
  **`level 3` → SÍ avisan**. **Sin silenciador.** → **RESULTADO: PASA**.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
