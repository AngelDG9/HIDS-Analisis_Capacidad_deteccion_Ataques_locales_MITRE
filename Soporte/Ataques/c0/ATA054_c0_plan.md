# C0 · pre-flight base-contra-base — ATA054 · T1498.002 (`perl`, `ip`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA054).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`perl` (**binario real `/usr/bin/perl`**; reflector/spoofer/target) e `ip`
(**binario real `/usr/bin/ip`**, tras el symlink `/usr/sbin/ip`; setup del segmento local).

## Resultado (ejecutado)

- **2 eventos** analizados; ganadora **`80792`** (*Audit: Command*) en los 2, **`level 3` → SÍ avisan**
  (`/usr/bin/perl`, `/usr/bin/ip`).
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA054_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
