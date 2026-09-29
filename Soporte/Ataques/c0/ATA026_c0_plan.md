# C0 · pre-flight base-contra-base — ATA026 · T1565.002 (nc, sed)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA026).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`nc` (proxy local / emisor) y `sed` (reescritura del cuerpo **en tránsito**).

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (*Audit: Command*) en los 2, **`level 3` → SÍ avisan**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA026_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
