# C0 · pre-flight base-contra-base — ATA035_rev · T1056.004 (base64, credfetch)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA035_rev).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base para los comandos clave de la técnica.
**No** se escriben reglas propias (D5). Nota: el **payload** (`hook.so`/`credfetch`) se
**decodifica en el pre-staging** (antes de `t0`); el C0 cubre el `base64` del prestage y el
`execve` del binario **de laboratorio**.

## Comandos clave

`base64` (materializa el payload `.b64` en el prestage) y el binario **de laboratorio**
`credfetch` (el proceso con el hook `LD_PRELOAD`). Control: se ejecutó un **stand-in**
`…/ATA035/credfetch_c0` (copia de `/usr/bin/true`) para confirmar que un `execve` de esa ruta alerta.

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL en la víctima (root solo para leer el log): `base64 --version`
y el stand-in `…/ATA035/credfetch_c0` (benignos), volcando el evento `audit(…)` combinado.
**2.** `wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA035_rev_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA035_rev_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (`/usr/bin/base64` y
  `/home/angel/lab-attack/ATA035/credfetch_c0`), **`level 3` → SÍ avisan**. **Sin silenciador.**
  → **RESULTADO: PASA**.
- **Punto ciego declarado:** la **carga del módulo** (`LD_PRELOAD`) y la **intercepción** de la API
  **no** generan evento propio (audit no audita env ni cargas de `.so`).

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
