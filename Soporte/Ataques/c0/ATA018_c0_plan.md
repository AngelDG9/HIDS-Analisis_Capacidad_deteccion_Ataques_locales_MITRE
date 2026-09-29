# C0 · pre-flight base-contra-base — ATA018 · T1056.001 (tee, logger)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA018).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica**. **No** se escriben reglas propias (D5). Comprobar además la
hipótesis del **punto ciego de journald** (`40700`, `level=0`): la persistencia vía `logger` **no**
debería alertar por sí sola.

## Comandos clave

`tee` (wrapper de captura de entrada), `logger` (persistencia en syslog).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima:**

```bash
# en victima-linux
echo hola | tee /tmp/tfg_c0_keylog.txt >/dev/null
logger -t tfg-c0 "prueba c0 ATA018"
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in tee logger; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo
  done'
```

**2.** `printf '%s\n' '<lineas>' | /var/ossec/bin/wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA018_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA018_preflight.md`.

## Resultado esperado (hipótesis)

- **`tee`** → **`80792`** level 3 → **SÍ avisa**.
- **`logger`** → **`80792`** level 3 (execve) → **SÍ avisa**; la **línea de journald** de `logger`
  cae en **`40700` (level 0)** → **NO alerta** (punto conocido, se documenta). El `logger` es un
  comando **de la técnica** (persistencia), así que la detección se apoya en su `execve`.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
