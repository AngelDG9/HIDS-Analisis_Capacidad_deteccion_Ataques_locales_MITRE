# C0 · pre-flight base-contra-base — ATA038_rev · T1529 (systemctl / shutdown)

> **Estado: EJECUTADO** (antes del primer `t0` de la repetición ATA038_rev).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base para el comando de reinicio.
**No** se escriben reglas propias (D5). Nota: el **estado** (`pre_reboot.txt`) se **escribe en el
pre-staging** (antes de `t0`); la ventana ejecuta **solo** la atómica
«Restart System via `shutdown`» (`shutdown -r #{timeout}`, `timeout=+1`), declarada `art_tal_cual`.

## Comandos clave

`shutdown -r` (**enlace a `/usr/bin/systemctl`**; `systemd 255`).

## Pasos (con las VMs encendidas)

**1.** Capturar la línea de audit REAL en la víctima (root solo para leer el log) ejecutando
`shutdown --help` (benigno; **no** reinicia) y volcando su evento `audit(…)`.
**2.** `wazuh-logtest -v` en el manager. **3.** Guardar en
`Soporte/Ataques/c0/ATA038_rev_logtest.txt`. **4.** `preflight_enmascaramiento.py
--logtest-base-c0 …` → `ATA038_rev_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (`/usr/bin/systemctl`), **`level 3` → SÍ avisa**.
  **Sin silenciador.** → **RESULTADO: PASA**.
- **Capa nueva declarada (estado del agente):** el C0 cubre el `execve` del comando; las reglas de
  estado del agente (`503`/`506`) son del manager y se declaran en el `esperado_rev`.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
