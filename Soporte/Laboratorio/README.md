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
- Portátil Windows 11 (8 GB) → control remoto por **SSH** de las VMs del equipo anfitrión.

## 6. Pendientes
- [ ] Añadir adaptador NAT (internet) para instalar Wazuh.
- [ ] Documentar los RuleSets y el baseline (Fase 2).

## 7. Referencias
- Contexto del TFG: `context.md`