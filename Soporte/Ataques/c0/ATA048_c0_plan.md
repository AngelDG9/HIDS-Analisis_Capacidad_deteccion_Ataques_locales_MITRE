# C0 · pre-flight base-contra-base — ATA048 · T1498.001 (nc.openbsd, head, timeout)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA048).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`nc` (**binario real `/usr/bin/nc.openbsd`**), `head`, `timeout` (flood TCP acotado).

## Resultado (ejecutado)

- **3 eventos** analizados; ganadora **`80792`** (*Audit: Command*) en los 3, **`level 3` → SÍ avisan**
  (`/usr/bin/nc.openbsd`, `/usr/bin/head`, `/usr/bin/timeout`).
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA048_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
