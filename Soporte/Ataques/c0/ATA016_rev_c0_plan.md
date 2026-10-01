# C0 · pre-flight base-contra-base — ATA016_rev · T1213.006 (cp, grep)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA016_rev).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** para los comandos de la colección. **No** se escriben
reglas propias (D5). Nota: la **siembra** de la BD (`python3`, punto ciego conocido `92600`) pasa a
antes de `t0`; el C0 cubre la **colección** (`cp`, `grep`).

## Comandos clave

`cp` (copia de la BD) y `grep` (extracción de los códigos).

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL de `cp` y `grep` (benignos) en la víctima.
**2.** `wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA016_rev_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA016_rev_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (`cp`, `grep`), **`level 3` → SÍ avisan**.
  **Sin silenciador.** → **RESULTADO: PASA**.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
