# C0 · pre-flight base-contra-base — ATA052 · T1115 (`xclip`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA052).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`xclip` (**binario real `/usr/bin/xclip`**, paquete xclip pre-steado; poner/leer el portapapeles).

## Resultado (ejecutado)

- **1 evento** analizado; ganadora **`80792`** (*Audit: Command*) **`level 3` → SÍ avisa**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA052_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
