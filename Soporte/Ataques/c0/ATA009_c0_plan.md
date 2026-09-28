# C0 · pre-flight base-contra-base — ATA009 · T1567 (curl)

> **Estado: PREPARADO · NO EJECUTADO** (VMs **apagadas** al redactar). Se ejecuta **antes del
> primer `t0`** de ATA009. **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** (como `92600` con `python3` en ATA013). **No** se escriben
reglas propias (D5).

## Comando clave

`curl` (`execve`, `key=audit-wazuh-c`).

## Pasos (cuando las VMs estén encendidas)

**1. Capturar una línea de audit REAL** en la víctima:

```bash
# en victima-linux (192.168.65.129)
curl --version >/dev/null
echo '<contrasena del laboratorio>' | sudo -S grep -a 'exe="/usr/bin/curl"' /var/log/audit/audit.log | tail -n 1
```

**2. `wazuh-logtest` en el manager** con la línea:

```bash
# en wazuh-server (192.168.65.128)
echo '<linea de audit de curl>' | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar** en `Soporte/Ataques/c0/ATA009_logtest.txt` y **4.** informe con
`preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA009_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- `curl` → **`80792` level 3 ⇒ SÍ avisa** (salvo silenciador; `curl` no figura entre las hermanas
  conocidas `92600` python3 / `92603` scp / `92604` ps / `92605` ls -R / `92606` lscpu).
- **No** se espera evento de fichero: la ruta del ataque **no está vigilada** y el efecto es de red.
- **Nota:** la exfiltración en sí (el POST al receptor del host) **no** genera alerta de host sin
  reglas de salida; la detección efectiva es el `execve` de `curl`.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
