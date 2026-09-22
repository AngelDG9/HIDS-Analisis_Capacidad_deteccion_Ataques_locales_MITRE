# Laboratorio — TFG HIDS

> Laboratorio aislado donde se reproducen ataques locales (MITRE ATT&CK) y se
> evalúa la capacidad de detección de Wazuh.

## 1. Resumen
- **Objetivo:** entorno reproducible para ejecutar ataques locales y medir su detección con Wazuh.
- **TFG:** Análisis de la capacidad de detección de ataques locales de la matriz MITRE ATT&CK Enterprise mediante HIDS.
- **Fecha de montaje:** 2026-09-22

## 2. Equipo Anfitrión (host)
| Elemento | Valor |
|---|---|
| Equipo | PC sobremesa |
| SO | Windows 10 (64 bits) |
| RAM | 16 GB |
| Virtualización | VT-x habilitada (Hyper-V / WSL2 desactivados) |
| Hipervisor | VMware Workstation Pro 26H1 |
| Carpeta de VMs | `D:\TFG-VMs` |

## 3. Red
| Elemento | Valor |
|---|---|
| Tipo | Host-only (aislada) |
| Adaptador VMware | `VMnet1` |
| Subred | `192.168.65.0/24` |
| DHCP | Sí (VMware); las VMs usan **IP estática** `.128` / `.129` |
| Internet | **No.** El adaptador **NAT (VMnet8)** sigue presente (`ethernet1`) pero **desconectado al arrancar** (`ethernet1.startConnected = "FALSE"`) |

### 3.1 Adaptador NAT temporal — estado actual y reactivación

Desde la tarea **2.9** (2026-09-23) el NAT queda **desconectado de forma persistente**: el
adaptador `ethernet1` (VMnet8) **no se elimina** (en Fase 3 hará falta para instalar Atomic Red
Team) pero **no se conecta al encender** la VM. Consecuencia: las VMs **no tienen ruta por defecto
ni internet**; solo funciona la red interna `192.168.65.0/24` (host-only).

- **Ficheros `.vmx`** (fuera del repo, en `D:\TFG-VMs\...`): se añadió la línea
  `ethernet1.startConnected = "FALSE"`, con **backup** previo de cada `.vmx`:
  `*.vmx.bak-20260923-010654-nat-off`.
- **Reactivar el NAT** (para instalar software, p. ej. Fase 3):
  1. Con la VM **apagada**, editar el `.vmx` y poner `ethernet1.startConnected = "TRUE"`
     (o borrar esa línea).
  2. Arrancar la VM: el netplan `/etc/netplan/60-nat.yaml` ya trae `ens37: dhcp4: true`, así que
     recupera la IP NAT y la ruta por defecto automáticamente (`ip route` → `default via ... ens37`).
  3. **Volver a desconectar** (línea a `FALSE` y reiniciar) **antes** de cualquier baseline o
     ataque — **regla de oro: solo VMnet1 activa** durante el experimento.

## 4. Máquinas virtuales
| VM | Rol | SO | IP | vCPU | RAM | Disco | Usuario |
|---|---|---|---|---|---|---|---|
| `wazuh-server` | Servidor Wazuh (manager + indexer + dashboard) | Ubuntu Server 24.04.5 LTS | 192.168.65.128 | 2 | 6 GB | 50 GB | `angel` |
| `victima-linux` | Endpoint víctima (agente Wazuh) | Ubuntu Server 24.04.5 LTS | 192.168.65.129 | 2 | 3 GB | 20 GB | `angel` |

- **Snapshots:** `base-limpia` (S.O. recién instalado) y **`lab-listo`** (laboratorio listo para
  Fase 3 — ver §4.1) en **ambas** VMs.

### 4.1 Snapshot `lab-listo` (tarea 2.9, 2026-09-23)

Foto **limpia y congelada** del laboratorio; **cada ataque de Fase 3 parte de aquí**. Creado con
`vmrun -T ws snapshot <vmx> lab-listo` en **ambas** VMs con la VM **apagada** → **no guarda la
memoria RAM** (fichero `.vmsn` de 0 MB; snapshot ligero).

Contenido verificado del estado congelado:
- Wazuh **4.14.7** all-in-one en `wazuh-server` (`wazuh-manager`/`indexer`/`dashboard` **active**).
- Agente `victima-linux` (ID **001**) **Active**, apuntando a `192.168.65.128`.
- **Detección-only**: **0 `<active-response>`** en las 4 capas y en el `ossec.conf`;
  `wazuh-execd` puede estar **corriendo** tras un reinicio del manager, pero es **inerte**
  (no hay nada que disparar). Invariante verificable tras cada reinicio: checklist en
  `../Wazuh/Configuracion/rulesets_diseno.md` **§5.1**.
- **RS1..RS4** activas y clasificables por **fichero de origen** (`active_ruleset.txt`, sin
  colisiones; RS2 `auditd` operativo; **RS4 vacía** por decisión G2).
- **NAT desconectado** (`ens37` DOWN, sin ruta por defecto, sin internet); host-only OK.
- IPs estáticas `.128`/`.129`, zona **Europe/Madrid** y timesync de VMware Tools activo (§8).
- El **manager no se revierte** durante los ataques (así el baseline permanece en el indexer).
- `lab-listo` de `victima-linux` **no** contiene los ficheros que creará la baseline.
- `vmrun listSnapshots` muestra `base-limpia` y `lab-listo` en ambas VMs.

## 5. Plano de control
- Portátil Windows 11 (8 GB) → **SSH al sobremesa** (vía Tailscale); los **agentes (opencode) corren en el sobremesa** y acceden a las VMs por la red host-only.

## 6. Pendientes
- [x] Añadir adaptador NAT (internet) para instalar Wazuh — hecho y **desconectado** en 2.9 (§3.1).
- [x] Documentar los RuleSets — `../Wazuh/Configuracion/rulesets_diseno.md` + `active_ruleset.txt`.
- [ ] Baseline legítimo ~4 h (**tarea 2.10**) y hito H2.
- [ ] Cerrar la documentación de acceso (`ssh_setup.md`, `vmrun_config.md`) — tarea 2.11.

## 7. Actualizaciones automáticas deshabilitadas (decisión de laboratorio)

**Decisión (aprobada por el humano):** deshabilitar las actualizaciones automáticas del S.O. en
**ambas** VMs para garantizar la **reproducibilidad** del laboratorio: que ningún parche se
aplique solo y cambie versiones o binarios a mitad de la baseline o de los ataques.

Aplicado el **2026-09-22** en `wazuh-server` (`192.168.65.128`) y `victima-linux`
(`192.168.65.129`):

```bash
sudo systemctl disable --now unattended-upgrades.service
sudo systemctl disable --now apt-daily.timer
sudo systemctl disable --now apt-daily-upgrade.timer
```

> `apt-daily.service` y `apt-daily-upgrade.service` son unidades **static** (no se pueden
> `disable`); las lanzaban los *timers* anteriores. Al deshabilitar los timers quedan sin
> lanzador y `inactive`, por lo que **no procede** deshabilitarlas aparte.

Estado verificado en **las dos** VMs:

| Unidad | `is-enabled` | `is-active` |
|---|---|---|
| `unattended-upgrades.service` | `disabled` | `inactive` |
| `apt-daily.timer` | `disabled` | `inactive` |
| `apt-daily-upgrade.timer` | `disabled` | `inactive` |

**Reversión** (volver a permitir parcheo automático):

```bash
sudo systemctl enable --now unattended-upgrades.service
sudo systemctl enable --now apt-daily.timer
sudo systemctl enable --now apt-daily-upgrade.timer
```

## 8. Reloj y zona horaria (ajuste 2026-09-23)

- **Estado final en ambas VMs:** zona **`Europe/Madrid` (CEST, +0200)**, hora **NTP activa**
  (`systemd-timesyncd`, `System clock synchronized: yes`) y **timesync de VMware Tools habilitado**
  (`vmware-toolbox-cmd timesync enable`; `tools.syncTime = "TRUE"` en el `.vmx`). Esto permite que
  la hora se mantenga sincronizada con el **host** **sin internet** (relevante tras desconectar el NAT).
- **Verificación (2026-09-23 ~01:06 +0200):** host = VMs (epoch UTC `1790118384` vs `1790118385`;
  diferencia de 1 s por ejecución secuencial).
- **Qué pasaba antes:** las VMs estaban en **`Etc/UTC`**. La hora **absoluta era correcta**, pero al
  mostrarse en UTC parecía del día anterior (`2026-09-22`) respecto a la hora local del host
  (`2026-09-23`). Se alineó la **zona** con el host, no se corrigió la hora (no estaba desviada).
- Comandos aplicados (por VM):

```bash
sudo timedatectl set-timezone Europe/Madrid
sudo vmware-toolbox-cmd timesync enable
# verificación
timedatectl                     # Local time ... CEST ; Time zone Europe/Madrid (CEST, +0200)
vmware-toolbox-cmd timesync status   # Enabled
```

- **Alineación de `/etc/timezone` (corrección 2026-09-23 ~01:21 +0200).** `timedatectl
  set-timezone` ya había fijado la **zona efectiva**, pero `/etc/timezone` seguía diciendo
  `Etc/UTC` en **ambas** VMs (incoherencia entre ficheros). Se escribió a mano para que las tres
  fuentes coincidan. **Evidencia (idéntica en `wazuh-server` `.128` y `victima-linux` `.129`):**

```bash
$ cat /etc/timezone
Europe/Madrid
$ readlink -f /etc/localtime
/usr/share/zoneinfo/Europe/Madrid
$ timedatectl | sed -n '1,7p'
               Local time: Wed 2026-09-23 01:21:47 CEST
           Universal time: Tue 2026-09-22 23:21:47 UTC
                 RTC time: Tue 2026-09-22 23:21:47
                Time zone: Europe/Madrid (CEST, +0200)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

> **⚠️ Timestamps de Wazuh en UTC.** Aunque la VM está en Europe/Madrid, Wazuh **sella las alertas
> en UTC** (`/var/ossec/logs/alerts/alerts.json`, p. ej. `"timestamp":"2026-09-22T23:11:28.363+0000"`
> = `01:11:28 CEST`). Al registrar `t0`/`t1` para el baseline (2.10) hay que usar **UTC** (o
> convertir) para que el filtro `timestamp ∈ [t0, t1]` de `extraer_alertas.py` cuadre.

## 9. Referencias
- Contexto del TFG: `context.md`
- Modo detección-only: `../Wazuh/Configuracion/deteccion_only.md`