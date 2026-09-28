# C0 · pre-flight base-contra-base — ATA003 · T1490 (rm)

> **Estado: PREPARADO · NO EJECUTADO** (VMs **apagadas** al redactar; `vmrun list` = 0). Se ejecuta
> **antes del primer `t0`** de ATA003. **No contiene secretos.**

## Objetivo

Descubrir **silenciadores de fábrica** (como `92600` con `python3` en ATA013). **No** se escriben
reglas propias (D5).

## Comando clave

`rm` (`execve` de `/usr/bin/rm`, `key=audit-wazuh-c`).

> **Nota journald (lección de ATA004):** este ataque **no** usa `journald` (no hay `systemctl`), así
> que **no** se necesita una línea journald en el C0. Si en el futuro se añadiera la variante
> `systemctl`, el C0 **debería** incluir una **línea journald real** (la regla `40700` es
> `level="0"` → no alerta; ver `Soporte/Ataques/piloto_procedimiento.md` §8.3).

## Pasos (cuando las VMs estén encendidas)

**1. Capturar una línea de audit REAL** en la víctima:

```bash
# en victima-linux (192.168.65.129)
mkdir -p /tmp/_c0_ata003 && rm -rf /tmp/_c0_ata003
echo '<contrasena del laboratorio>' | sudo -S grep -a 'exe="/usr/bin/rm"' /var/log/audit/audit.log | tail -n 1
```

**2. `wazuh-logtest` en el manager**:

```bash
# en wazuh-server (192.168.65.128)
echo '<linea de audit de rm>' | /var/ossec/bin/wazuh-logtest -v
```

**3. Guardar** en `Soporte/Ataques/c0/ATA003_logtest.txt` y **4.** informe con
`preflight_enmascaramiento.py --logtest-base …` → `ATA003_preflight.md`.

## Resultado esperado (hipótesis a confirmar empíricamente)

- `rm` → **`80792` level 3 → SÍ avisa** (salvo silenciador de fábrica; `rm` no figura entre las
  hermanas conocidas `92600` python3 / `92603` scp / `92604` ps / `92605` ls -R / `92606` lscpu).
- El **borrado** bajo watch en `lab-legit` produce además eventos `80781`/`audit_watch_write`,
  declarados **`ambigua`** en el `esperado`.

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben RS3 (D5).
