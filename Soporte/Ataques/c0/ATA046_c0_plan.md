# C0 · pre-flight base-contra-base — ATA046 · T1499.003 (curl, xargs, seq, timeout)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA046).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`curl` (peticiones caras), `xargs`/`seq` (lanzadores), `timeout` (cota).
La **app** (`python3`) arranca en el **pre-staging** (fuera de la ventana): su posible punto ciego
(`92600`) **no** afecta a la detección de la acción.

## Resultado (ejecutado)

- **4 eventos** analizados; ganadora **`80792`** (*Audit: Command*) en los 4, **`level 3` → SÍ avisan**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA046_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
