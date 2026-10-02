# C0 · pre-flight base-contra-base — ATA049 · T1567.002 (`rclone`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA049).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`rclone` (`/home/angel/lab-legit/rclone`, cliente de nube; en la ventana `lab-attack/ATA049/rclone`).

## Resultado (ejecutado)

- **1 evento** analizado; ganadora **`80792`** (*Audit: Command*) **`level 3` → SÍ avisa**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA049_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
