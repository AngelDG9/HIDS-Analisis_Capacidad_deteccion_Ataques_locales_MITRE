# C0 · pre-flight base-contra-base — ATA028 · T1056.003 (nc, curl)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA028).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`nc` (portal falso) y `curl` (cliente que envía las credenciales).

> **Nota:** el portal se sirve con **`nc`**, NO con `python3` → **no** se activa el punto ciego de
> fábrica **`92600`** (que sí suprime el `execve` de `python3`).

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (*Audit: Command*) en los 2, **`level 3` → SÍ avisan**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA028_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
