# Bóveda v3 — sellado del laboratorio Windows (canal SSH)

> **`boveda_version = 3`.** Creada en **B1.0-SSH.1** (2026-11-08). Complementa —no
> sustituye— el sellado Linux (`Soporte/Metrica/boveda_congelacion.md`, que **no se toca**).
> **Sin secretos**: aquí solo van versiones, `sha256` y **claves públicas**.

---

## 1. Identidad del canal

| Elemento | Valor |
|---|---|
| `canal` | **`ssh`** |
| Invitado | `victima-windows` (`DESKTOP-BTMCFA5`), `192.168.65.130`, agente `002` |
| Host del operador | `192.168.65.1` (VMnet1) |
| Usuario | `angel` (Administradores) |
| Puerto | **TCP 22** |
| Servicio | `sshd` — **Automatic / Running**, cuenta `LocalSystem` |
| Firewall | `TFG-ssh-22`: Inbound TCP 22 **Allow**, `RemoteAddress = 192.168.65.0/24`; regla del sistema `OpenSSH Server (sshd)` **deshabilitada** |

## 2. Versiones y `sha256`

| Fichero / elemento | Versión | `sha256` |
|---|---|---|
| `C:\Windows\System32\OpenSSH\sshd.exe` | **OpenSSH_7.7p1 for Windows** | `7D4F44FC14E9096032A4966FBE804E8827F7DDF8BB72687E0763D16D01FE949D` |
| `C:\Windows\System32\OpenSSH\ssh-keygen.exe` | 7.7p1 | `731BEFCB1A1655FE46EF91B3A02982B71D841E439DE362EF3B1ECA5644FC8DAE` |
| `C:\ProgramData\ssh\sshd_config` (13 líneas) | — | `83FBDA407AC4ADF58A1A71566B9BF2FBDB17FC9379A8652C81951625CCCDB3E1` |
| `C:\Users\angel\.ssh\authorized_keys` | — | `781C5A28667AF925A8E5A4237B1976C3D89BB057A50BD929ECFEBB872C560E00` |
| `ssh_host_ed25519_key.pub` | — | `7671F608B99AD79EE03621C3DD27511CEB2BD4EFE5EC13F539B86F4CBCE63CD3` |

> **Instalación**: la capacidad `OpenSSH.Server~~~~0.0.1.0` **ya estaba `Installed`** en el
> snapshot `lab-listo-windows-ataques`; **no** se instaló ningún zip ni se descargó nada.
> Por eso no hay `sha256` de “zip”: el binario sellado es el de la capacidad del sistema.

## 3. Configuración sellada (`sshd_config`)

```text
Port 22
AddressFamily any
ListenAddress 0.0.0.0
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
PubkeyAuthentication yes
PasswordAuthentication no
PermitRootLogin no
AllowUsers angel
AuthorizedKeysFile .ssh/authorized_keys
StrictModes yes
LogLevel INFO
Subsystem sftp sftp-server.exe
```

## 4. Claves (solo material **público**)

| Clave | Valor |
|---|---|
| Cliente (privada) | `C:\Users\angel\.ssh\id_ed25519_tfg_win` — **fuera del repo**, sin passphrase (BatchMode) |
| Cliente (pública) | `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKvEw252lvDIUzeKJKfKmb8IIeKRrHBpSjsesXS9SE6s tfg-windows-lab` |
| Fingerprint cliente | `SHA256:qw6bBtB4tsL1UXYXETHuNYAvz6u5lMAXYyp5y0cDDR4` |
| Host key ed25519 (pública) | `SHA256:dDcDlKwmGZhArPtPlo6Gq2mwBfh3TRuENaKTBPYALto` |

## 5. Snapshots

| Snapshot | Uso | Estado |
|---|---|---|
| `lab-listo-windows-ataques-ssh` | **canal SSH** (todos los casos no interactivos) | VM apagada; verificado |
| `lab-listo-windows-ataques-gui` | **S1** (ATA071/072/073: autologon + tarea `InteractiveToken`) | VM apagada; verificado (`autologon=1`, sesión 1) |

Los snapshots `base-limpia`, `lab-listo-windows`, `lab-listo-windows-baseline` y
`lab-listo-windows-ataques` **no se tocan**.

## 6. Lo que **no** está en esta bóveda (declarado)

- La **contraseña** del invitado y la **clave privada** SSH (fuera del repo).
- La contraseña del **autologon** (`Winlogon\DefaultPassword`, solo en el invitado `-gui`).
- El contenido de `Soporte/Metrica/` (sellado Linux, congelado).
