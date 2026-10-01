# C0 · pre-flight base-contra-base — ATA014_rev · T1114 (grep, cp)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA014_rev).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** para los comandos de la colección. **No** se escriben
reglas propias (D5).

## Comandos clave

`grep` (extracción de los asuntos del buzón) y `cp` (copia del buzón a la carpeta del ataque).
La **siembra** del buzón pasa a antes de `t0` (pre-staging), así que solo se mide la recolección.

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL de `grep` y `cp` (benignos) en la víctima.
**2.** `wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA014_rev_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA014_rev_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (`grep`, `cp`), **`level 3` → SÍ avisan**.
  **Sin silenciador.** → **RESULTADO: PASA**.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
