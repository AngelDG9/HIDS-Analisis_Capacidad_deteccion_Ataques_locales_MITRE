# C0 · pre-flight base-contra-base — ATA023 · T1496.002 (head, curl)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA023).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`head` (generación del flujo acotado) y `curl` (transferencia masiva).

## Pasos (con las VMs encendidas)

**1. Capturar las líneas de audit REALES en la víctima** (root solo para leer el log):

```bash
# en victima-linux (192.168.65.129)
head -c 1 /etc/hostname >/dev/null            # execve benigno de head
curl --version                                # execve benigno de curl
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  for c in head curl; do
    eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
    grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo
  done'
```

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA023_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA023_logtest.txt`
→ `ATA023_preflight.md`.

## Resultado (ejecutado)

- Ganadoras **`80792`** (*Audit: Command: /usr/bin/head* y */usr/bin/curl*), **`level 3` → SÍ avisan**.
- **Sin silenciador**.
- **RESULTADO: PASA** (`ATA023_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
