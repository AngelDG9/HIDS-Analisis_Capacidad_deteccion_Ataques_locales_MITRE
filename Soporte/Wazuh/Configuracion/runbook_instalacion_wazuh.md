# Runbook — Instalación de Wazuh all-in-one (Fase 2, tarea 2.4 / T-05)

Documenta la instalación **real** del stack Wazuh (indexer + manager + Filebeat + dashboard)
en el host `wazuh-server`, las verificaciones, el smoke test del pipeline y el
**congelado de repositorios**. No incluye credenciales ni claves (ver §7).

- **Fecha de ejecución:** 2026-09-22
- **Host:** `wazuh-server` `192.168.65.128` (Ubuntu Server 24.04.5 LTS, 2 vCPU / 6 GB / 50 GB)
- **Acceso:** SSH desde el sobremesa por la red host-only (`VMnet1`)
- **Versión instalada:** **Wazuh 4.14.7-1** (línea 4.14.x, decisión G1)
- **Instalador:** `https://packages.wazuh.com/4.14/wazuh-install.sh`

> ⚠️ **Regla de oro:** durante la **baseline** y **cualquier ataque** el adaptador **NAT
> (`ens37`) debe estar DESCONECTADO**: solo activa la red **host-only (VMnet1)**. El NAT
> solo se conecta para instalar software / `apt update`.

---

## 1. Prerequisitos y comprobaciones previas

### 1.1 Espacio en disco (≥ 20 GB)

La VM tenía un **LV raíz de 24 G** sobre un disco de 50 G (quedaban ~16 G libres → por
debajo del mínimo del plan). Se amplió el LV al total del VG (operación online, sin
pérdida de datos):

```bash
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
df -h /
```

Resultado:

```
Filesystem                         Size  Used Avail Use% Mounted on
/dev/mapper/ubuntu--vg-ubuntu--lv   48G  6.7G   39G  15% /
```

### 1.2 RAM y CPU

```
free -h   -> Mem: 5.7Gi total (2.1Gi usados), Swap 4.0Gi
nproc     -> 2
```

### 1.3 Red (NAT temporal conectado)

`ens33` = host-only `192.168.65.128`; `ens37` = NAT `192.168.183.128` (DHCP) con salida a
internet (`ping -c2 8.8.8.8` → 0% pérdida). Ver `red_lab.md`.

---

## 2. Instalación all-in-one

```bash
cd /home/angel
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

- Duración real: ~11 min (21:41 → 21:52, hora local de la VM).
- El asistente detecta la versión y muestra: `Wazuh version: 4.14.7`.
- Genera `wazuh-install-files.tar` (certificados + **contraseñas**) en el directorio de
  ejecución (`/home/angel`), **fuera del repo**. Ver §7.
- Salida final: `Installation finished.` (`INSTALL_EXIT=0`).
- Log completo del asistente: `/var/log/wazuh-install.log` (en la VM).
- Log de la ejecución de este runbook: `/home/angel/tfg_wazuh_install.log` (en la VM).

Componentes instalados: `wazuh-indexer`, `wazuh-manager`, `filebeat`, `wazuh-dashboard`.

---

## 3. Ajuste del heap del indexer a 1 GB (decisión G1)

El instalador ya dejó `-Xms1024m`/`-Xmx1024m` (equivalente a 1 GB). Se normalizó a la
forma exacta acordada (`1g`) en `/etc/wazuh-indexer/jvm.options`:

```bash
sudo sed -i 's/^-Xms1024m/-Xms1g/;s/^-Xmx1024m/-Xmx1g/' /etc/wazuh-indexer/jvm.options
sudo systemctl restart wazuh-indexer
```

Estado final del fichero:

```
22:-Xms1g
23:-Xmx1g
```

---

## 4. Verificación de servicios y dashboard

```bash
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

```
active
active
active
active
```

Dashboard (HTTPS en el puerto 443 del host-only):

```bash
curl -k -o /dev/null -s -w '%{http_code}\n' https://192.168.65.128/   # -> 302 (redirige al login)
curl -k -L -o /dev/null -s -w '%{http_code}\n' https://192.168.65.128/ # -> 200
```

- URL: **`https://192.168.65.128/`**
- Usuario: **`admin`** (contraseña en `wazuh-passwords.txt`, ver §7).

> `wazuh-execd` queda **`inactive`** tras la instalación, **pero vuelve a arrancar** al reiniciar el
> `wazuh-manager` (o la VM) — y es **inerte** mientras no exista ningún `<active-response>`. El paso
> explícito de **modo detección-only** (R-06) se formaliza y verifica en la tarea **2.6 (T-07)**
> (ver `deteccion_only.md` §1.2 y `rulesets_diseno.md` §5.1).

---

## 5. Smoke test del pipeline

Se provocó **un único** login SSH fallido controlado contra el propio `wazuh-server`:

```bash
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 nonexistent_tfg@127.0.0.1 true
# -> Permission denied (publickey,password)
```

Alerta resultante en `/var/ossec/logs/alerts/alerts.json` (resumida):

```json
{"timestamp":"2026-09-22T21:56:34.678+0000",
 "rule":{"level":5,"id":"5710",
         "description":"sshd: Attempt to login using a non-existent user",
         "mitre":{"id":["T1110.001","T1021.004"]}},
 "agent":{"id":"000","name":"wazuh-server"},
 "data":{"srcip":"127.0.0.1","srcuser":"nonexistent_tfg"},
 "location":"journald"}
```

`rule.id` observado: **5710** (aceptado: 5710/5760). El pipeline extremo-a-extremo funciona.

---

## 6. Congelado de repositorios (reproducibilidad)

Tras instalar, se **comentan** las líneas `deb` del repo de Wazuh para evitar
actualizaciones accidentales:

```bash
# backup previo
sudo cp -a /etc/apt/sources.list.d/wazuh.list /etc/apt/sources.list.d/wazuh.list.tfg-backup
# congelar
sudo sed -i 's/^deb /#deb /' /etc/apt/sources.list.d/wazuh.list
```

Antes / después:

```
deb  [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
#deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
```

> Para reactivarlo temporalmente (p. ej. en Fase 3): quitar la `#` y `apt update`.
> La línea original sigue apuntando a `4.x`; la versión queda fijada por los paquetes ya
> instalados (4.14.7-1) y por el `dpkg` congelado, no por el repo.

**Nota:** `unattended-upgrades` está `enabled` en el sistema. El plan (`_fases/fase-02/plan.md` §7) contempla
deshabilitarlo como mitigación de reproducibilidad; **no** se ha tocado en esta tarea
(pendiente de decisión del orquestador).

---

## 7. Higiene: dónde están los secretos (NUNCA al repo)

- `wazuh-install-files.tar` y la carpeta `wazuh-install-files/` se generan en
  `/home/angel` **en la VM** (`wazuh-server`), no en el repo.
- Contiene `wazuh-passwords.txt` con las contraseñas de `admin` (dashboard),
  `wazuh` (API), etc. **No se registran aquí.**
- Patrones de secretos en `.gitignore`: `Soporte/Wazuh/Configuracion/*password*`,
  `wazuh-install-files.tar`, `wazuh-install-files/`, `*.pem`, `*.key`, `id_rsa*`,
  `id_ed25519*`.

---

## 8. Reversión (si hiciera falta)

```bash
# restaurar repo de Wazuh
sudo cp -a /etc/apt/sources.list.d/wazuh.list.tfg-backup /etc/apt/sources.list.d/wazuh.list
# reinstalar desde cero (borra config/datos):
#   sudo bash /home/angel/wazuh-install.sh -a -o   # -o = overlay (sobrescribe)
```
