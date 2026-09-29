# C0 · pre-flight base-contra-base — ATA025 · T1496.001 (yes, timeout)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA025).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`timeout` (lanzador acotado) y `yes` (proceso de carga de CPU).

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (*Audit: Command*) en los 2, **`level 3` → SÍ avisan**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA025_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
