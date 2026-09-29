# C0 · pre-flight base-contra-base — ATA016 · T1213.006 (cp, grep)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA016).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica**. **No** se escriben reglas propias (D5). Nota: la **siembra**
de la BD usa `python3` (punto ciego conocido `92600`); el C0 aquí cubre los comandos de la
**colección** (`cp`, `grep`).

## Comandos clave

`cp` (copia de la BD), `grep` (extracción de registros).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima:**

```bash
# en victima-linux
cp -f /etc/hostname /tmp/tfg_c0_db_copy
grep -c root /etc/hostname
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in cp grep; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo
  done'
```

**2.** `printf '%s\n' '<lineas>' | /var/ossec/bin/wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA016_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA016_preflight.md`.

## Resultado esperado (hipótesis)

- Ganadoras **`80792`** (`cp`, `grep`), **`level 3` → SÍ avisan**. **Sin** silenciador.
- (`python3` **no** entra en el C0: ya está caracterizado — `92600` nivel 0 — y solo siembra la BD.)

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
