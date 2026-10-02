# C0 · pre-flight base-contra-base — ATA050 · T1567.003 (`curl`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA050).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`curl` (**binario real `/usr/bin/curl`**, de serie; POST del texto al "paste" local).

## Resultado (ejecutado)

- **1 evento** analizado; ganadora **`80792`** (*Audit: Command*) **`level 3` → SÍ avisa**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA050_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
