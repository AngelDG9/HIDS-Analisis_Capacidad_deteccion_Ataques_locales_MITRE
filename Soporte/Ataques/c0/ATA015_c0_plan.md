# C0 · pre-flight base-contra-base — ATA015 · T1114.003 (cat, cp, grep)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA015).
> **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base (p. ej. `92600` con `python3`). **No** se
escriben reglas propias (D5).

## Comandos clave

`cat` (crea la regla de reenvío), `cp` (copia la regla), `grep` (la lee).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima** (root solo para leer el log):

```bash
# en victima-linux (192.168.65.129)
cat /etc/hostname >/dev/null
cp -f /etc/hostname /tmp/tfg_c0_fwd_copy
grep -c root /etc/hostname
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in cat cp grep; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo
  done'
```

**2.** `printf '%s\n' '<lineas>' | /var/ossec/bin/wazuh-logtest -v` en el manager.
**3.** Guardar en `Soporte/Ataques/c0/ATA015_logtest.txt`.
**4.** `preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA015_preflight.md`.

## Resultado esperado (hipótesis)

- Ganadoras **`80792`** (*Audit: Command: /usr/bin/{cat,cp,grep}*), **`level 3` → SÍ avisan**.
- **Sin** silenciador esperado (ninguno figura entre `92600`/`92603`–`92606`).

## Si aparece un silenciador

Se **documenta**; la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
