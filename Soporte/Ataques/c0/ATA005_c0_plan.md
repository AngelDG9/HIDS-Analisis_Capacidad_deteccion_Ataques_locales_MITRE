# C0 · pre-flight base-contra-base — ATA005 · T1561 (dd / shred)

> **Estado: PREPARADO · NO EJECUTADO** (VMs **apagadas** al redactar; `vmrun list` = 0). Se ejecuta
> **antes del primer `t0`** de ATA005. **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** (como `92600` con `python3` en ATA013). **No** se escriben
reglas propias (D5).

## Comandos clave

`dd`, `shred` (`execve`, `key=audit-wazuh-c`).

## Pasos (cuando las VMs estén encendidas)

**1. Capturar una línea de audit REAL por cada binario** en la víctima:

```bash
# en victima-linux (192.168.65.129)
dd if=/dev/zero of=/tmp/_c0_ata005 bs=1 count=1 status=none
printf 'x' > /tmp/_c0_shred; shred -n 1 -u /tmp/_c0_shred
for b in dd shred; do
  echo '<contrasena del laboratorio>' | sudo -S grep -a "exe=\"/usr/bin/$b\"" /var/log/audit/audit.log | tail -n 1
done
```

**2. `wazuh-logtest` en el manager** con cada línea:

```bash
# en wazuh-server (192.168.65.128)
echo '<linea de audit de dd>'    | /var/ossec/bin/wazuh-logtest -v
echo '<linea de audit de shred>' | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar** en `Soporte/Ataques/c0/ATA005_logtest.txt` y **4.** informe con
`preflight_enmascaramiento.py --logtest-base …` → `ATA005_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- `dd` → **`80792` level 3 → SÍ avisa** (ya probado en ATA002).
- `shred` → **`80792` level 3 → SÍ avisa** (salvo silenciador; `shred` no figura entre las hermanas
  conocidas `92600` python3 / `92603` scp / `92604` ps / `92605` ls -R / `92606` lscpu).
- **No** se espera evento de fichero: la ruta del ataque **no está vigilada**.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
