---
fase: 2b — Laboratorio Windows
bloque: fase-02b-construccion
nombre: Montaje del laboratorio Windows (agente Wazuh + Sysmon + limpieza + snapshots)
version: 1
status: approved_by_human
fecha: 2026-10-06
fecha_aprobacion: 2026-10-06
aprobado_por: humano
autor: tfg-orchestrator (micro-plan)
gate: **APROBADO por el humano (2026-10-06)**. Los pasos son los ya diseñados y aceptados en `Soporte/Laboratorio/windows/pasos_montaje.md` (+ `defender_off.md`) del bloque `fase-02b-diseno`, más el "adelante" explícito del humano para ejecutarlos. **La LÍNEA BASE queda FUERA** (otro paso).
---

# Micro-plan — `fase-02b-construccion`: montaje del laboratorio Windows

> **Naturaleza:** ejecución **en la VM Windows** (`D:\TFG-VMs\victima-windows\victima-windows.vmx`).
> **NO entra:** la **línea base** (queda para después) · los ataques (`fase-03b`) · nada de Linux.
> Los **pasos detallados** están en `Soporte/Laboratorio/windows/pasos_montaje.md` y `defender_off.md`.

## 0. Entorno
- **Manager** `wazuh-server` `192.168.65.128` (arrancar) · **Víctima** `victima-windows` `192.168.65.130` (ya creada: Win10 Pro, IP fija, VMnet1, **NAT desconectado**, SSH, VMware Tools).
- `vmrun`: `C:\Program Files\VMware\VMware Workstation\vmrun.exe`.
- **Material** en el HOST (`D:\TFG-VMs\material-windows\`): `wazuh-agent-4.14.7-1.msi` (5,66 MB) · `Sysmon.zip` (2,8 MB) · `sysmonconfig-export.xml` (0,12 MB).
 - URLs oficiales: `packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi` · `download.sysinternals.com/files/Sysmon.zip` · `raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml`
- **Sin SSH**: se trabaja con **`vmrun` + VMware Tools** (`copyFileFromHostToGuest`, `runProgramInGuest`). ⚠️ Comprobar **privilegios elevados** ("High Mandatory Level"); si no → PARAR.

## 1. Pasos
| # | Paso | Verificación |
|---|---|---|
| **1** | Arrancar **las dos VMs** | la víctima responde en `.130` |
| **2** | **Registrar el material** (pre-staging) | `Soporte/Laboratorio/windows/prestaging_material.md` con **URL + tamaño + `sha256` completo** |
| **3** | **Copiar** los 3 ficheros a `C:\Users\angel\material\` | existen en la VM |
| **4** | **Windows Update OFF** (servicio + política) | servicio `Disabled` |
| **5** | **Defender OFF** (Tamper → tiempo real → nube), según `defender_off.md` | `Get-MpComputerStatus`. ⚠️ **Si Tamper lo impide → PARAR y reportar** (paso manual del humano) |
| **6** | **Telemetría al mínimo** (`AllowTelemetry=0`) | valor del registro |
| **7** | **Snapshot `base-limpia`** (con la VM **apagada**) | `vmrun listSnapshots` |
| **8** | **Sysmon** (`Sysmon64.exe -accepteula -i sysmonconfig-export.xml`) | genera eventos (`Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational"`) |
| **9** | **Agente Wazuh** (MSI en silencio → `WAZUH_MANAGER=192.168.65.128`, nombre `victima-windows`) + config de logs (**Security, Sysmon, PowerShell 4104, FIM**) | agente **`active`** en el manager |
| **10** | **Prueba de telemetría**: ejecutar algo inocuo en la víctima | **la alerta llega al manager** (evidencia) |
| **11** | **Snapshot `lab-listo-windows`** (VM apagada) | `vmrun listSnapshots` |

## 2. Criterios de aceptación
| # | Criterio |
|---|---|
| **CA1** | El **agente aparece `active`** en el manager con el nombre `victima-windows` |
| **CA2** | **Llegan eventos** de la víctima al manager (evidencia pegada) |
| **CA3** | **Defender OFF**, **Update OFF**, **telemetría mínima** — con su evidencia |
| **CA4** | **Snapshots `base-limpia` y `lab-listo-windows`** creados |
| **CA5** | **NAT sigue desconectado** y la VM sigue aislada |
| **CA6** | Material registrado con **URL + `sha256`**; **sin secretos** en el repo; **sin commit** |
| **CA7** | Nada de Linux tocado; `_recursos/` intacto |

## 3. Reglas
- **Contraseña** de las VMs: **solo en memoria**; **nunca** en ficheros.
- **NO commitees** · **NO `git push`** · redacción neutra.
- **Si algo no cuadra: PARAR y reportar** (no improvisar).
- **NO** se hace la **línea base** en este bloque.
