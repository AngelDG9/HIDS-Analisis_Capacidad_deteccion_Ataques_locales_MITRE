# C0 · pre-flight base-contra-base — ATA021 · T1029 (crontab, curl, dash + línea CRON)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA021).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`crontab` (programación del job), `curl` (transferencia programada) y el **lanzador `/bin/sh`**
(`dash`) de cron. Además, una **línea CRON real de journald** para comprobar si la capa de cron
(syslog/journald) alerta.

## Pasos (con las VMs encendidas)

**1. Capturar las líneas REALES:**

```bash
# en victima-linux (192.168.65.129)
crontab -l                             # execve benigno de crontab (no hay crontab -> sin cambios)
curl --version                         # execve benigno de curl
/bin/sh -c true                        # execve benigno del lanzador dash
# linea CRON real: instalar un job inocuo, esperar ~75 s y capturar la linea de journald
printf '%s\n' '* * * * * echo TFG-C0 > /tmp/tfg_c0.txt' | crontab -
sleep 75
journalctl --since "-5 min" --no-pager | grep -a CRON | tail -3   # (linea real)
crontab -r
```

**2. Ejecutar `wazuh-logtest -v` en el manager** con las 3 líneas de audit + la línea CRON
(`/tmp/ATA021_in.txt`) → `Soporte/Ataques/c0/ATA021_logtest.txt`; **3.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA021_logtest.txt`
→ `ATA021_preflight.md`.

## Resultado (ejecutado)

- `crontab`, `curl` y `dash` → **`80792`** (*Audit: Command*), **`level 3` → SÍ avisan**. **Sin**
  silenciador.
- **Línea CRON** (`CRON[pid]: (angel) CMD (…)`) → **`1002`** (*Unknown problem somewhere in the
  system*, level 2) **como línea cruda**: las reglas de cron de fábrica (`2830`–`2834`) **no casan**
  el `program_name=CRON` (su patrón es `crond|crontab`), y las PAM del `cron:session` (`5521`/`5522`)
  son **nivel 0** (suprimidas). ⇒ **la capa syslog de cron no aporta detección útil**; la detección
  efectiva es el **`execve`** (`80792`). Se documenta.
- **RESULTADO: PASA** (`ATA021_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
