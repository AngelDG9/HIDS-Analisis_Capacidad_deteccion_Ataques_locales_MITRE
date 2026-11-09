# Bóveda v3.1 — addendum B2 (servicios y material)

> **`boveda_version_windows = 3.1`.** Addendum de la bóveda v3
> (`Soporte/Laboratorio/windows/ataques/boveda_v3.md`), **sin sustituirla** y **sin tocar**
> `Soporte/Metrica/`. **Sin cambio de telemetría**: no se habilita Sysmon, agente, ruleset,
> auditoría SMB (`5140/5145`) ni SMTP. **Sin secretos.**

## 1. Material pre-staged (fuera del repo)

| Elemento | Origen / versión | Ruta | Bytes | `sha256` |
|---|---|---|---|---|
| `Inveigh.ps1` | URL pin `https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/82be2377ade47a4e325217b4144878a59595e750/Inveigh.ps1` | `D:\TFG-VMs\material-windows\b2\Inveigh.ps1` | 303194 | `cc7dd1d68dc3cc41f385afd000a516145cee2284b2526ee79dfd5e72278e2a23` |
| `T1056.004x64.dll` | clon ART `388942ad`, `atomics/T1056.004/bin/T1056.004x64.dll` | `D:\TFG-VMs\material-windows\b2\T1056.004x64.dll` | 127488 | `e728be21c6f362b6cc1f7ed392afed93e75305c775dc98de3d0563776fd4504c` |
| `labdisk100.vhd` | `diskpart create vdisk maximum=100 type=fixed` | `D:\TFG-VMs\material-windows\b2\vhd\labdisk100.vhd` | 104858112 | `04c8899c5c95aaab1455500a513c192cd6f1568700ef1d26b4faced8ce9f9aad` |

- **Inveigh**: commit pin `82be2377ade47a4e325217b4144878a59595e750`; no se guarda el hash NTLM
  capturado. `where`/versión: fichero PowerShell sin versión embebida; se sella por URL+`sha256`.
- **DLL**: binario nativo del clon ART (`T1056.004`); sin `VersionInfo`; se sella por `sha256`.
- **VHD**: 100 MiB fijos; **no se monta** en el sistema real; solo se usará en
  `C:\lab-attack\ATA<NNN>\` y se desmontará al cerrar.

## 2. Servicios B2 (loopback del invitado)

| Servicio | Endpoint | Estado | Prueba |
|---|---|---|---|
| SMB share | `\\127.0.0.1\labshare` | OK | 1 fichero; share eliminado |
| SMTP sink | `127.0.0.1:2525` | OK | `220`/`250` |
| Proxy | `127.0.0.1:9095` | OK | `HTTP/1.1 200 OK` |
| App | `127.0.0.1:9093` | OK | `200 APP-OK` |
| UDP amplificador | `127.0.0.1:5353` | OK | 63 B → 252 B (4×); `ReuseAddress` por mDNS |
| UDP DHCP | `127.0.0.1:67` | OK | `DHCP-OFFER-TFG` |
| Portal | `127.0.0.1:8081` | OK | `200` |

- Evidencia y apagado: `Soporte/Laboratorio/windows/ataques/servicios_host_b2.md` y
  `servicios_host_b2_evidencia.txt`.
- **Host sinks** 9090/9091/9092: sin cambios (B1, `servicios_host.md`).

## 3. Snapshots

| Snapshot | Uso B2 | Estado |
|---|---|---|
| `lab-listo-windows-ataques-ssh` | casos no interactivos | reutilizado; revertido |
| `lab-listo-windows-ataques-gui` | ATA104 (GUI) | reutilizado; revertido |

No se crea snapshot nuevo. `base-limpia`, `lab-listo-windows`, `lab-listo-windows-baseline`
y `lab-listo-windows-ataques` **no se tocan**.

## 4. Guardarraíles (B2)

- **Ruta**: todo bajo `C:\lab-attack\ATA<NNN>\`; si no, aborta.
- **Destructivas**: solo el **VHD de 100 MB**; nunca `PhysicalDrive*`, `C:`, ni el disco del
  sistema; `Dismount-DiskImage` al cerrar.
- **Red**: solo `192.168.65.0/24` y loopback; nunca internet; nunca el manager.
- **Credenciales**: el hash de Inveigh es de `angel` (laboratorio) y **no se guarda**.
- **Procesos**: inyección (`T1056.004`) y `WriteProcessMemory` (`T1565.003`) **solo** sobre
  procesos de juguete; nunca `lsass`, `winlogon`, `services`.
- **Cierre**: VHD desmontado, share eliminado, servicios parados, 0 tareas, 0 VMs.

## 5. Lo que **no** cambia

- Sysmon, agente Wazuh, ruleset, extractor (27 columnas), métrica v1 y catálogo provisional v1.
- `Soporte/Metrica/` (sellado Linux) y el corpus Linux.
- La telemetría SMB/SMTP **no** se habilita (v4 queda descartada por KISS).
