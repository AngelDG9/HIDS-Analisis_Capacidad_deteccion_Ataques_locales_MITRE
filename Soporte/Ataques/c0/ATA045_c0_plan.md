# C0 · pre-flight base-contra-base — ATA045 · T1499.001 (dd, timeout, free, rm)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA045).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`dd` (relleno acotado de memoria), `timeout` (cota), `free` (medida), `rm` (limpieza).

## Resultado (ejecutado)

- **4 eventos** analizados; ganadora **`80792`** (*Audit: Command*) en los 4, **`level 3` → SÍ avisan**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA045_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
