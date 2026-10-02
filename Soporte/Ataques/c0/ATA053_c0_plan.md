# C0 · pre-flight base-contra-base — ATA053 · T1056.002 (`xinput`, `xdotool`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA053).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`xinput` (`/usr/bin/xinput`, capturador X11) y `xdotool` (`/usr/bin/xdotool`, inyector de entrada).
Ambos paquetes pre-steados.

## Resultado (ejecutado)

- **2 eventos** analizados; ganadora **`80792`** (*Audit: Command*) **`level 3` → SÍ avisan**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA053_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
