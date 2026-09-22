# Red del laboratorio (Fase 2 — tarea 2.3)

Documenta la configuración de red de las dos VMs del laboratorio tras la tarea **2.3**
(parte de RED): adaptador **NAT temporal** para internet y **IPs estáticas** en la red
**host-only**. No incluye credenciales ni claves.

- **Fecha de ejecución:** 2026-09-22
- **Hipervisor:** VMware Workstation Pro (sobremesa Windows 10)
- **VMs:** `wazuh-server`, `victima-linux` (Ubuntu Server 24.04.5 LTS, usuario `angel`)
- **Acceso:** desde el sobremesa por red host-only (SSH a `192.168.65.128` / `.129`), `vmrun` local.

---

## 1. Estado inicial (antes de tocar nada)

| Elemento | Valor observado |
|---|---|
| Netplan existente | Solo `/etc/netplan/50-cloud-init.yaml` (modo `600 root:root`), gestionado por cloud-init |
| Contenido original | `ens33: dhcp4: true` (idéntico en ambas VMs) |
| `ens33` | Interfaz **host-only** (`VMnet1`, `192.168.65.0/24`). IP por DHCP: `.128` / `.129` |
| Gateway host-only | **No había** default route por VMnet1 (solo ruta `scope link` al DHCP `192.168.65.1`) |
| DNS host-only | `192.168.65.1` (entregado por DHCP), dominio `localdomain` |
| `ens37` | Interfaz **NAT** (`VMnet8`) ya presente en el `.vmx` (`ethernet1.connectionType="nat"`), **sin configurar por netplan** → estado `DOWN` |
| Renderer | `systemd-networkd` (activo); `NetworkManager` inactivo |

Al levantar `ens37` manualmente (`ip link set ens37 up`) el enlace pasa a `LOWER_UP`: el
adaptador NAT **sí está conectado** a nivel de hipervisor; solo faltaba la config del guest.

---

## 2. Interfaces finales

| VM | Interfaz | Rol | MAC | IP |
|---|---|---|---|---|
| `wazuh-server` | `ens33` | host-only VMnet1 (**estática**) | `00:0c:29:7b:f5:76` | `192.168.65.128/24` |
| `wazuh-server` | `ens37` | NAT VMnet8 (DHCP) | `00:0c:29:7b:f5:80` | `192.168.183.128/24` (DHCP) |
| `victima-linux` | `ens33` | host-only VMnet1 (**estática**) | `00:0c:29:7e:6d:03` | `192.168.65.129/24` |
| `victima-linux` | `ens37` | NAT VMnet8 (DHCP) | `00:0c:29:7e:6d:0d` | `192.168.183.129/24` (DHCP) |

- La ruta por defecto (internet) sale **solo** por `ens37` (NAT): `default via 192.168.183.2 dev ens37`.
- El tráfico `192.168.65.0/24` sale por `ens33` (host-only). La comunicación entre VMs **no cambia**.

---

## 3. Ficheros netplan creados / modificados

### 3.1 `/etc/netplan/50-cloud-init.yaml` (modificado — IP estática host-only)

Backup del original antes de modificar: `/etc/netplan/50-cloud-init.yaml.bak-<timestamp>`
(64 bytes, `600 root:root`). Contenido nuevo (modo `600 root:root`):

```yaml
# Host-only VMnet1 - IP estatica fijada en Fase 2 (tarea 2.3)
# No se define gateway: la red host-only no tenia default route.
network:
  version: 2
  ethernets:
    ens33:
      dhcp4: false
      dhcp6: false
      addresses:
        - 192.168.65.128/24        # <- .129 en victima-linux
      nameservers:
        addresses:
          - 192.168.65.1
```

### 3.2 `/etc/netplan/60-nat.yaml` (nuevo — NAT temporal, idéntico en ambas VMs)

```yaml
# NAT temporal (VMnet8) - internet solo para instalaciones (Fase 2, tarea 2.3)
# En operacion normal (baseline/ataques) este adaptador se deja DESCONECTADO.
network:
  version: 2
  ethernets:
    ens37:
      dhcp4: true
      dhcp6: false
      optional: true
```

### 3.3 `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg` (nuevo)

Evita que **cloud-init regenere** el `50-cloud-init.yaml` y revierta la IP estática a DHCP:

```yaml
# Evita que cloud-init regenere /etc/netplan/50-cloud-init.yaml (IP estatica, Fase 2)
network: {config: disabled}
```

### 3.4 Backups (en cada VM, `/etc/netplan/`)

| VM | Fichero de backup | Contenido |
|---|---|---|
| `wazuh-server` | `50-cloud-init.yaml.bak-20260922T232251Z` | **original** (64 B, `ens33 dhcp4: true`) |
| `victima-linux` | `50-cloud-init.yaml.bak-20260922T232334Z` | **original** (64 B, `ens33 dhcp4: true`) |

> En `wazuh-server` quedó además un backup intermedio (`...bak-20260922T232309Z`, 319 B) que es
> copia del fichero nuevo, no del original. **El backup válido del original es el de 64 B.**

**Revertir** (si fuera necesario) en una VM:

```bash
sudo cp -a /etc/netplan/50-cloud-init.yaml.bak-<TIMESTAMP> /etc/netplan/50-cloud-init.yaml
sudo rm -f /etc/netplan/60-nat.yaml /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
sudo netplan apply
```

---

## 4. Comandos de aplicación y verificación (y salida)

### 4.1 Aplicación

```bash
sudo cp -a /etc/netplan/50-cloud-init.yaml /etc/netplan/50-cloud-init.yaml.bak-<TIMESTAMP>
sudo install -m 600 -o root -g root <nuevo 50-cloud-init.yaml> /etc/netplan/50-cloud-init.yaml
sudo install -m 600 -o root -g root 60-nat.yaml /etc/netplan/60-nat.yaml
sudo install -m 600 -o root -g root 99-disable-network-config.cfg /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
sudo netplan generate
sudo netplan apply
```

### 4.2 Verificación (salida real)

**`ip -br a` — `wazuh-server` (192.168.65.128):**

```
lo               UNKNOWN        127.0.0.1/8 ::1/128
ens33            UP             192.168.65.128/24 fe80::20c:29ff:fe7b:f576/64
ens37            UP             192.168.183.128/24 metric 100 fe80::20c:29ff:fe7b:f580/64
```

**`ip -br a` — `victima-linux` (192.168.65.129):**

```
lo               UNKNOWN        127.0.0.1/8 ::1/128
ens33            UP             192.168.65.129/24 fe80::20c:29ff:fe7e:6d03/64
ens37            UP             192.168.183.129/24 metric 100 fe80::20c:29ff:fe7e:6d0d/64
```

**`ip route` (ambas):**

```
default via 192.168.183.2 dev ens37 proto dhcp src 192.168.183.<x> metric 100
192.168.65.0/24 dev ens33 proto kernel scope link src 192.168.65.<x>
192.168.183.0/24 dev ens37 proto kernel scope link src 192.168.183.<x> metric 100
192.168.183.2 dev ens37 proto dhcp scope link src 192.168.183.<x> metric 100
```

**Ping a internet (`ping -c2 8.8.8.8`) — ambas:**

```
2 packets transmitted, 2 received, 0% packet loss
```

**Ping cruzado host-only:**

- `wazuh-server` → `192.168.65.129`: `2 received, 0% packet loss`
- `victima-linux` → `192.168.65.128`: `2 received, 0% packet loss`

**DNS por nombre** (`getent ahostsv4 packages.wazuh.com`) → resuelve IPv4 (necesario para `apt`).

### 4.3 Prueba de reinicio (persistencia)

Se reiniciaron ambas VMs (`sudo systemctl reboot`) y se repitió la verificación:
las **IPs estáticas se mantuvieron**, el NAT volvió por DHCP, el **ping a internet** y el
**ping cruzado** siguen OK, y cloud-init **no** regeneró el `50-cloud-init.yaml`.

---

## 5. Acceso SSH no interactivo (soporte)

No había clave SSH configurada en el sobremesa (`~/.ssh` no existía) y el cliente `ssh.exe`
de Windows no estaba instalado (solo el servidor). Se generó una clave **ed25519 sin
passphrase** y se instaló su parte pública en `~/.ssh/authorized_keys` de `angel` en ambas VMs:

- Clave privada: `C:\Users\angel\.ssh\id_ed25519_tfg_lab` (**fuera del repo**, nunca a git)
- Cliente usado: `C:\Program Files\Git\usr\bin\ssh.exe`
- La instalación inicial de la clave se hizo con *guest operations* de `vmrun`
  (`-gu angel -gp <password>`), no versionada.

---

## 6. Notas y pendientes

> **✅ Estado actual (2026-09-23, tarea 2.9):** el NAT **ya está desconectado de forma persistente**
> (`ethernet1.startConnected = "FALSE"` en ambos `.vmx`, con backup `*.vmx.bak-20260923-010654-nat-off`).
> `ens37` aparece **DOWN** y no hay ruta por defecto: las VMs **no tienen internet**; solo VMnet1.
> Para reactivarlo (p. ej. Fase 3) y volver a desconectarlo, ver
> `../Laboratorio/README.md` **§3.1**.

- **NAT temporal:** `ens37` queda **presente** pero debe quedar **desconectado** en operación
  normal (baseline/ataques). Ver §3.6 del `plan.md`: regla de oro = **solo VMnet1 activa**.
- Las IPs de `ens37` (192.168.183.x) son DHCP de VMnet8 y pueden cambiar; solo se usan para
  instalar software.
- **No** se ejecutó `apt upgrade` ni se instaló Wazuh (eso es 2.4/2.5).
- Documento sin secretos: la contraseña de `angel` no se registra aquí.
