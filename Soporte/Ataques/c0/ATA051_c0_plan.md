# C0 · pre-flight base-contra-base — ATA051 · T1113 (`xwd`, `xwud`)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA051).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`xwd` (**binario real `/usr/bin/xwd`**, captura) y `xwud` (`/usr/bin/xwud`, revisión). Ambos del
paquete **x11-apps** pre-steado.

## Resultado (ejecutado)

- **2 eventos** analizados; ganadora **`80792`** (*Audit: Command*) **`level 3` → SÍ avisan**.
- **Sin silenciador.** → **RESULTADO: PASA** (`ATA051_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
