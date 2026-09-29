# C0 · pre-flight base-contra-base — ATA014 · T1114 (grep, cp)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA014).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base (como `92600` con `python3` en ATA013): un
comando clave cuyo `execve` **no** alerta porque una regla **hermana** de nivel 0 lo suprime. **No**
se escriben reglas propias (D5).

## Comandos clave

`grep` (lector/extractor del buzón) y `cp` (copia de lo recolectado).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima** (root solo para leer el log):

```bash
# en victima-linux (192.168.65.129)
grep -c root /etc/hostname            # execve benigno de grep
cp -f /etc/hostname /tmp/tfg_c0_grep_copy   # execve benigno de cp
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in grep cp; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"
    echo
  done'
```

**2. Ejecutar `wazuh-logtest` en el manager** con esas líneas:

```bash
# en wazuh-server (192.168.65.128)
printf '%s\n' '<linea de audit (grep)>' '<linea de audit (cp)>' | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar la salida** en `Soporte/Ataques/c0/ATA014_logtest.txt` y **4.** generar el informe con
`_artefactos/scripts/preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA014_logtest.txt`
→ `Soporte/Ataques/c0/ATA014_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- Ganadora **`80792`** (*Audit: Command: /usr/bin/grep*, */usr/bin/cp*), **`level 3` → SÍ avisa**.
- **No** se espera silenciador: ni `grep` ni `cp` figuran entre las hermanas conocidas
  (`92600` python3, `92603` scp, `92604` ps, `92605` ls -R, `92606` lscpu).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
