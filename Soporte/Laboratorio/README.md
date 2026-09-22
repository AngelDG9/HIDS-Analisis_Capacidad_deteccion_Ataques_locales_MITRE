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
| DHCP | Sí (VMware) |
| Internet | No (se añade adaptador NAT temporal solo para instalar software) |

## 4. Máquinas virtuales
| VM | Rol | SO | IP | vCPU | RAM | Disco | Usuario |
|---|---|---|---|---|---|---|---|
| `wazuh-server` | Servidor Wazuh (manager + indexer + dashboard) | Ubuntu Server 24.04.5 LTS | 192.168.65.128 | 2 | 6 GB | 50 GB | `angel` |
| `victima-linux` | Endpoint víctima (agente Wazuh) | Ubuntu Server 24.04.5 LTS | 192.168.65.129 | 2 | 3 GB | 20 GB | `angel` |

- **Snapshot base:** `base-limpia` en ambas (recién instaladas, sin Wazuh ni ataques).

## 5. Plano de control
- Portátil Windows 11 (8 GB) → **SSH al sobremesa** (vía Tailscale); los **agentes (opencode) corren en el sobremesa** y acceden a las VMs por la red host-only.

## 6. Pendientes
- [ ] Añadir adaptador NAT (internet) para instalar Wazuh.
- [ ] Documentar los RuleSets y el baseline (Fase 2).

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

## 8. Referencias
- Contexto del TFG: `context.md`
- Modo detección-only: `../Wazuh/Configuracion/deteccion_only.md`