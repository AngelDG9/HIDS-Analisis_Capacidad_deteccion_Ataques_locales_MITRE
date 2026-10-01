# C0 · pre-flight base-contra-base — ATA024_rev · T1531 (passwd)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA024_rev).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin`.

## Objetivo

Descubrir **silenciadores de fábrica** para el comando de la atómica ART adaptada. **No** se
escriben reglas propias (D5).

## Comandos clave

`passwd` (cambio de contraseña de la atómica «Change User Password via passwd»). La atómica
**solo cambia la contraseña** (el original además creaba/bloqueaba/eliminaba).

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL de `passwd` (`passwd --help`) en la víctima.
**2.** `wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA024_rev_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA024_rev_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /usr/bin/passwd*),
  **`level 3` → SÍ avisa**. **Sin silenciador.** → **RESULTADO: PASA**.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
