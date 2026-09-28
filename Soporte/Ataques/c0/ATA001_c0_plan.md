# C0 · pre-flight base-contra-base — ATA001 · T1486 (openssl)

> **Estado: PREPARADO · NO EJECUTADO** (al redactar este plan las VMs estaban **apagadas**;
> `vmrun list` = 0). Se ejecuta **antes del primer `t0`** de ATA001.
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base (como `92600` con `python3` en ATA013): un
comando clave cuyo `execve` **no** llega a alertar porque una regla **hermana** de nivel 0 lo
suprime. **No** se escriben reglas propias (D5).

## Comando clave

`openssl` (`execve` de `/usr/bin/openssl`, `key=audit-wazuh-c`).

## Pasos (cuando las VMs estén encendidas)

**1. Capturar una línea de audit REAL en la víctima** (necesita root solo para leer el log):

```bash
# en victima-linux (192.168.65.129)
openssl version        # genera un execve real y benigno de openssl
echo '<contrasena del laboratorio>' | sudo -S ausearch -ts recent -x openssl -i | tail -n 20
# alternativa: grep del audit.log (root)
echo '<contrasena del laboratorio>' | sudo -S grep -a 'exe="/usr/bin/openssl"' /var/log/audit/audit.log | tail -n 5
```

Seleccionar **una** línea `type=SYSCALL … syscall=59 … comm="openssl" exe="/usr/bin/openssl"
key="audit-wazuh-c"` (con su `type=EXECVE`, `type=CWD` y `type=PROCTITLE` si se pegan varias).

**2. Ejecutar `wazuh-logtest` en el manager** con esa línea:

```bash
# en wazuh-server (192.168.65.128)
echo '<linea de audit>' | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar la salida** en `Soporte/Ataques/c0/ATA001_logtest.txt` y **4.** generar el informe con
`_artefactos/scripts/preflight_enmascaramiento.py --logtest-base Soporte/Ataques/c0/ATA001_logtest.txt`
→ `Soporte/Ataques/c0/ATA001_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- Ganadora **`80792`** (*Audit: Command: /usr/bin/openssl*), **`level 3` → SÍ avisa**.
- **No** se espera silenciador: `openssl` **no** figura entre las hermanas conocidas del ruleset
  (`92600` python3, `92603` scp, `92604` ps, `92605` ls -R, `92606` lscpu).

## Si aparece un silenciador

Se **documenta** en la ficha de ATA001 y la detección se declara por el `rule_id` del `execve`; **no**
se escriben reglas RS3 (D5).
