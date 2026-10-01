# C0 · pre-flight base-contra-base — ATA029_rev · T1005 (find, sqlite3, strings)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA029_rev).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** para los comandos de la atómica ART
«Find and dump sqlite databases (Linux)». **No** se escriben reglas propias (D5).

## Comandos clave

`find` (descubre las BDs), `sqlite3` (vuelca las tablas) y `strings` (lee el magic «SQLite format 3»).
`sqlite3` y `strings` se instalaron OFFLINE (pre-staging de paquetes §C) para poder capturar su
`execve` real.

## Pasos (con las VMs encendidas)

**1.** Con `sqlite3`/`binutils` instalados offline, capturar la línea de audit REAL de cada binario
(`--version`) en la víctima.
**2.** `wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA029_rev_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA029_rev_preflight.md`.

## Resultado (ejecutado)

- 3 eventos analizados; ganadora **`80792`** en los tres (`/usr/bin/find`, `/usr/bin/sqlite3`,
  `/usr/bin/x86_64-linux-gnu-strings`), **`level 3` → SÍ avisan**. **Sin silenciador.** → **PASA**.
- **Nota (binario real):** `strings` es un **symlink**; audit registra
  `exe="/usr/bin/x86_64-linux-gnu-strings"` → el patrón de la señal usa `/usr/bin/*strings`.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
