# C0 · pre-flight base-contra-base — ATA006 · T1565 (sed)

> **Estado: PREPARADO · NO EJECUTADO** (VMs **apagadas** al redactar; `vmrun list` = 0). Se ejecuta
> **antes del primer `t0`** de ATA006. **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** (como `92600` con `python3` en ATA013). **No** se escriben
reglas propias (D5).

## Comando clave

`sed` (`execve`, `key=audit-wazuh-c`).

> **Alcance (decisión humana 2026-09-28):** la técnica es el **cambio de contenido**; se han
> **retirado** `touch`/`chmod` del ataque (falsear fecha/modo = T1070.006 Timestomp, otra técnica),
> así que el C0 cubre **solo `sed`**.

## Pasos (cuando las VMs estén encendidas)

**1. Capturar una línea de audit REAL** en la víctima:

```bash
# en victima-linux (192.168.65.129)
sed --version >/dev/null
echo '<contrasena del laboratorio>' | sudo -S grep -a 'exe="/usr/bin/sed"' /var/log/audit/audit.log | tail -n 1
```

**2. `wazuh-logtest` en el manager** con la línea:

```bash
# en wazuh-server (192.168.65.128)
echo '<linea de audit de sed>' | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar** en `Soporte/Ataques/c0/ATA006_logtest.txt` y **4.** informe con
`preflight_enmascaramiento.py --logtest-base …` → `ATA006_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- `sed` → **`80792` level 3 → SÍ avisa** (salvo silenciador de fábrica; no figura entre las hermanas
  conocidas `92600` python3 / `92603` scp / `92604` ps / `92605` ls -R / `92606` lscpu).
- **Nota:** el **efecto** (escritura en `lab-legit`) produce además eventos **watch** (`80790`/
  `80781`), declarados **`ambigua`** en el `esperado`.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
