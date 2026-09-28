# C0 · pre-flight base-contra-base — ATA011 · T1074 (mkdir / cp)

> **Estado: PREPARADO · NO EJECUTADO** (VMs **apagadas** al redactar). Se ejecuta **antes del
> primer `t0`** de ATA011. **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** (como `92600` con `python3` en ATA013). **No** se escriben
reglas propias (D5).

## Comandos clave

`mkdir`, `cp` (`execve`, `key=audit-wazuh-c`).

## Pasos (cuando las VMs estén encendidas)

**1. Capturar una línea de audit REAL por cada binario** en la víctima:

```bash
# en victima-linux (192.168.65.129)
mkdir -p /tmp/_c0_ata011 && printf 'x\n' > /tmp/_c0_ata011/src
cp /tmp/_c0_ata011/src /tmp/_c0_ata011/dst
for b in mkdir cp; do
  echo '<contrasena del laboratorio>' | sudo -S grep -a "exe=\"/usr/bin/$b\"" /var/log/audit/audit.log | tail -n 1
done
rm -rf /tmp/_c0_ata011
```

**2. `wazuh-logtest` en el manager** con cada línea:

```bash
# en wazuh-server (192.168.65.128)
echo '<linea de audit de mkdir>' | /var/ossec/bin/wazuh-logtest -v
echo '<linea de audit de cp>'    | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar** en `Soporte/Ataques/c0/ATA011_logtest.txt` y **4.** informe con
`preflight_enmascaramiento.py --logtest-base-c0 …` → `ATA011_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- `mkdir` → **`80792` level 3 ⇒ SÍ avisa** (salvo silenciador; `mkdir` no figura entre las hermanas
  conocidas `92600` python3 / `92603` scp / `92604` ps / `92605` ls -R / `92606` lscpu).
- `cp` → **`80792` level 3 ⇒ SÍ avisa** (el mismo `cp` ya alertó en ATA007/ATA012).
- **No** se espera evento de fichero: la ruta del ataque **no está vigilada**.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
