# C0 · pre-flight base-contra-base — ATA019 · T1048.001 (openssl, cat)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA019).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base (como `92600` con `python3` en ATA013): un
comando clave cuyo `execve` **no** alerta porque una regla **hermana** de nivel 0 lo suprime. **No**
se escriben reglas propias (D5).

## Comandos clave

`openssl` (cifrado simétrico) y `cat` (envío del blob por TCP crudo).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima** (root solo para leer el log):

```bash
# en victima-linux (192.168.65.129)
openssl version                              # execve benigno de openssl
cat /etc/hostname >/dev/null                 # execve benigno de cat
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in openssl cat; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo
  done'
```

**2. Ejecutar `wazuh-logtest` en el manager** con esas líneas:

```bash
# en wazuh-server (192.168.65.128)
sudo -S /var/ossec/bin/wazuh-logtest -v < /tmp/ATA019_in.txt > /tmp/ATA019_logtest.txt 2>&1
```

**3. Guardar la salida** en `Soporte/Ataques/c0/ATA019_logtest.txt` y **4.** generar el informe con
`_artefactos/scripts/preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA019_logtest.txt`
→ `Soporte/Ataques/c0/ATA019_preflight.md`.

## Resultado (ejecutado)

- Ganadora **`80792`** (*Audit: Command: /usr/bin/openssl* y */usr/bin/cat*), **`level 3` → SÍ avisa**.
- **Sin silenciador**: ni `openssl` ni `cat` figuran entre las hermanas conocidas (`92600` python3,
  `92603` scp, `92604` ps, `92605` ls -R, `92606` lscpu).
- **RESULTADO: PASA** (`ATA019_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
