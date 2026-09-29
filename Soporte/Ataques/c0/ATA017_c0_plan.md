# C0 · pre-flight base-contra-base — ATA017 · T1657 (sed, cp)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA017).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica**. **No** se escriben reglas propias (D5).

## Comandos clave

`sed` (manipula el libro), `cp` (sustrae libro/cartera).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima:**

```bash
# en victima-linux
sed -n '1p' /etc/hostname >/dev/null
cp -f /etc/hostname /tmp/tfg_c0_ledger_copy
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in sed cp; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo
  done'
```

**2.** `printf '%s\n' '<lineas>' | /var/ossec/bin/wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA017_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA017_preflight.md`.

## Resultado esperado (hipótesis)

- Ganadoras **`80792`** (`sed`, `cp`), **`level 3` → SÍ avisan**. **Sin** silenciador.

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
