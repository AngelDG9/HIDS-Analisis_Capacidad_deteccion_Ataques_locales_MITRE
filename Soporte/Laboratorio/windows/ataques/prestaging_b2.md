# Pre-staging B2 — Inveigh, DLL y VHD

> **B2.0 (prep)**. Material fuera del repo en `D:\TFG-VMs\material-windows\b2\`.
> **Sin secretos**; el hash NTLM de Inveigh no se guarda.

## 1. Material

| Elemento | Ruta | Bytes | `sha256` | Verificación |
|---|---|---|---|---|
| `Inveigh.ps1` | `D:\TFG-VMs\material-windows\b2\Inveigh.ps1` | 303194 | `cc7dd1d68dc3cc41f385afd000a516145cee2284b2526ee79dfd5e72278e2a23` | URL pin `82be2377…` |
| `T1056.004x64.dll` | `D:\TFG-VMs\material-windows\b2\T1056.004x64.dll` | 127488 | `e728be21c6f362b6cc1f7ed392afed93e75305c775dc98de3d0563776fd4504c` | clon ART `388942ad` |
| `labdisk100.vhd` | `D:\TFG-VMs\material-windows\b2\vhd\labdisk100.vhd` | 104858112 | `04c8899c5c95aaab1455500a513c192cd6f1568700ef1d26b4faced8ce9f9aad` | `diskpart` fixed 100 MB; **no montado** |

- **Inveigh**: `where`/versión: fichero PowerShell sin versión embebida; se sella por URL+`sha256`.
  El commit pin es `82be2377ade47a4e325217b4144878a59595e750`.
- **DLL**: binario nativo de `atomics/T1056.004/bin/`; sin `VersionInfo`; se sella por `sha256`.
  La copia está **fuera del repo** (`D:\TFG-VMs`), no se añade a `Dataset/`.
- **VHD**: creado con `diskpart create vdisk file=… maximum=100 type=fixed`; **no se ha
  montado** en el sistema real. Se usará solo bajo `C:\lab-attack\ATA<NNN>\` y se desmontará.

## 2. Uso previsto

- **ATA091** (T1557.001): `Inveigh.ps1` en el invitado; ambos roles en el mismo host; el hash
  capturado es de `angel` y **no se guarda**.
- **ATA106** (T1056.004): DLL del clon ART; inyección **solo** en un proceso PowerShell de
  juguete; si el hook TLS local no dispara, `efecto_parcial`.
- **ATA098/099/100/101/102** (T1561.x, T1025, T1052.001): VHD de 100 MB; **nunca** el disco del
  sistema; `Dismount-DiskImage` al cerrar.

## 3. Cierre

- VHD **no montado**; material en `D:\TFG-VMs` (excluido de Defender; **no** se desactiva).
- Sin secretos en el repo.
