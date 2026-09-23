# Control de las VMs — `vmrun` (local)

> Documento de cierre de la tarea **2.11 (T-08)**. Redactado el **2026-09-23**.
> `vmrun` se ejecuta **en el sobremesa** y **en local** (sin `-h`).

## 1. Binario y versión

| Elemento | Valor |
|---|---|
| Ruta real | `C:\Program Files\VMware\VMware Workstation\vmrun.exe` |
| Versión | `vmrun version 1.17.0.25388281` |
| Hipervisor | VMware Workstation Pro 26H1 |

> ⚠️ **Nota:** la ruta de `vmrun.exe` **varía según la instalación** de VMware. En muchas
> instalaciones de Windows aparece bajo `C:\Program Files (x86)\VMware\...`; en **este host**
> **no existe** esa ruta `(x86)` — está **verificada** la de la tabla, en `C:\Program Files`
> (sin `(x86)`).

## 2. Rutas reales de las VMs

| VM | Fichero `.vmx` |
|---|---|
| `wazuh-server` | `D:\TFG-VMs\wazuh-server\wazuh-server.vmx` |
| `victima-linux` | `D:\TFG-VMs\victima-linux\victima-linux.vmx` |

## 3. Sintaxis (local, sin `-h`)

`-T ws` = VMware Workstation. `nogui` = arranca sin ventana. `soft` = apagado ordenado (ACPI);
`hard` = corte de corriente.

```powershell
vmrun -T ws list                                              # VMs en marcha
vmrun -T ws start  "<vmx>" nogui                              # encender sin GUI
vmrun -T ws stop   "<vmx>" soft                               # apagar ordenadamente
vmrun -T ws listSnapshots    "<vmx>"                          # listar snapshots
vmrun -T ws snapshot         "<vmx>" "<nombre>"               # crear snapshot
vmrun -T ws revertToSnapshot "<vmx>" "<nombre>"               # revertir a un snapshot
vmrun -T ws deleteSnapshot   "<vmx>" "<nombre>"               # borrar snapshot
```

Ejemplos copiables:

```powershell
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$victima = "D:\TFG-VMs\victima-linux\victima-linux.vmx"
$wazuh   = "D:\TFG-VMs\wazuh-server\wazuh-server.vmx"

& $vmrun -T ws list
& $vmrun -T ws start $victima nogui
& $vmrun -T ws listSnapshots $victima
```

## 4. Inventario de snapshots

| Snapshot | VM(s) | Para qué sirve |
|---|---|---|
| `base-limpia` | ambas | S.O. recién instalado (fallback / reconstrucción) |
| **`lab-listo`** | ambas | Estado del laboratorio **listo**: Wazuh 4.14.7 all-in-one + agente `victima-linux` (ID 001) + **detección-only** + **RS1..RS4 activas** + **NAT desconectado**. **Punto de partida de cada ataque (Fase 3)** |

- **Antes de cada ataque** (Fase 3) se revierte **solo la víctima** al estado limpio:

```powershell
& $vmrun -T ws revertToSnapshot "D:\TFG-VMs\victima-linux\victima-linux.vmx" "lab-listo"
```

- **`wazuh-server` NO se revierte** durante los ataques: conserva las **alertas** en el indexer
  (si se revirtiera, se perderían las alertas capturadas). Solo se usaría `base-limpia`/`lab-listo`
  del manager para reconstruir el laboratorio, no en el ciclo de ataque.

## 5. Reactivar / desactivar el NAT (internet temporal)

El adaptador NAT (`ethernet1` = VMnet8) se controla con la línea del `.vmx`:

```text
ethernet1.startConnected = "FALSE"   # NAT desconectado al arrancar (estado actual)
ethernet1.startConnected = "TRUE"    # NAT conectado al arrancar
```

**Con la VM apagada**, editar el `.vmx` y poner `"TRUE"` (o borrar la línea); al arrancar, el
netplan `/etc/netplan/60-nat.yaml` de la VM ya trae `ens37: dhcp4: true`, así que recupera IP NAT y
ruta por defecto automáticamente (`ip route` → `default via ... ens37`).

> **Regla de oro:** durante baseline y ataques el NAT debe estar **desconectado**
> (`ethernet1.startConnected = "FALSE"`). Se reactiva **solo** para instalar software
> (p. ej. Atomic Red Team en Fase 3) y se vuelve a desconectar **antes** de cualquier captura.

Backups previos de los `.vmx` (al desactivar el NAT el 2026-09-23):
`victima-linux.vmx.bak-20260923-010654-nat-off` y `wazuh-server.vmx.bak-20260923-010654-nat-off`.

## 6. Prueba real (2026-09-23, VMs apagadas)

Las VMs están **apagadas a propósito**; `listSnapshots` funciona igualmente con la VM apagada.

```text
> vmrun -T ws list
Total running VMs: 0

> vmrun -T ws listSnapshots "D:\TFG-VMs\victima-linux\victima-linux.vmx"
Total snapshots: 2
base-limpia
lab-listo

> vmrun -T ws listSnapshots "D:\TFG-VMs\wazuh-server\wazuh-server.vmx"
Total snapshots: 2
base-limpia
lab-listo
```

## 7. Lección aprendida: no fiarse de procesos en segundo plano

Programar tareas con hora fija mediante un **proceso en segundo plano** es frágil: un `Start-Sleep`
largo que debía lanzar el **apagado programado** murió al **reiniciarse el servicio de OpenCode** y
el apagado **no se ejecutó**. Para tareas con hora fija, ejecutarlas **con alguien delante** (o usar
el **Programador de tareas de Windows**), nunca un proceso en segundo plano que pueda morir.

## 8. Referencias

- Acceso SSH: `ssh_setup.md`.
- Snapshot `lab-listo` (contenido y verificación): `README.md` §4.1.
- Plan: `plan.md` §3.7 (snapshots) y §3.9 (acceso remoto).
