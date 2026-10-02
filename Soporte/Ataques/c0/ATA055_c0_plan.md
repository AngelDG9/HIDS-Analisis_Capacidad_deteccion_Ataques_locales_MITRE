# C0 · pre-flight base-contra-base — ATA055 · T1557.003 (`busybox`, `ip`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA055).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`busybox` (**binario real `/usr/bin/busybox`**; applets `udhcpd` (señuelo) y `udhcpc` (cliente))
e `ip` (**binario real `/usr/bin/ip`**; setup del segmento local).

## Resultado (ejecutado)

- **2 eventos** analizados; ganadora **`80792`** (*Audit: Command*) en los 2, **`level 3` → SÍ avisan**
  (`/usr/bin/busybox`, `/usr/bin/ip`).
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA055_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
