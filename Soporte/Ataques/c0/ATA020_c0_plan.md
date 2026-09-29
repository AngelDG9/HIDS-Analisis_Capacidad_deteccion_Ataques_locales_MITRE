# C0 · pre-flight base-contra-base — ATA020 · T1020 (curl)

> **Estado: PREPARADO** (se ejecuta **antes del primer `t0`** de ATA020).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`curl` (cliente de la exfiltración automatizada).

## Pasos (con las VMs encendidas)

**1. Capturar una línea de audit REAL en la víctima** (root solo para leer el log):

```bash
# en victima-linux (192.168.65.129)
curl --version                               # execve benigno de curl
echo '<contrasena del laboratorio>' | sudo -S bash -c '
  c=curl; eid=$(grep -a "exe=\"/usr/bin/$c\"" /var/log/audit/audit.log | tail -n1 | sed -n "s/.*audit(\([0-9.]*:[0-9]*\)).*/\1/p")
  grep -a "audit($eid)" /var/log/audit/audit.log | tr -d "\n"; echo'
```

**2. Ejecutar `wazuh-logtest` en el manager** y **3.** guardar la salida en
`Soporte/Ataques/c0/ATA020_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA020_logtest.txt`
→ `ATA020_preflight.md`.

## Resultado (ejecutado)

- Ganadora **`80792`** (*Audit: Command: /usr/bin/curl*), **`level 3` → SÍ avisa**.
- **Sin silenciador** (ya se conocía de ATA009/ATA010; reconfirmado).
- **RESULTADO: PASA** (`ATA020_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
