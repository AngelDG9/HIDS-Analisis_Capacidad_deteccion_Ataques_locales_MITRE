# Acceso remoto al laboratorio — SSH

> Documento de cierre de la tarea **2.11 (T-08)**. Redactado el **2026-09-23**.
> Describe **cómo se entra** al laboratorio en sus **dos niveles**.
> **No contiene contraseñas ni claves privadas**: solo **dónde** están.

## 0. Esquema

```text
Portátil Windows 11 ──Tailscale──▶ Sobremesa Windows 10 ──host-only (VMnet1)──▶ VMs Ubuntu
  (cliente SSH)      100.82.127.119   desktop-oiolopo        192.168.65.0/24     .128 / .129
                                      usuario: angel
                                      │
                                      └─ vmrun (local, sin -h) controla las VMs  →  vmrun_config.md
```

- **Nivel 1:** portátil → sobremesa, por **SSH sobre Tailscale**.
- **Nivel 2:** sobremesa → VMs, por la **red host-only** (`VMnet1`, `192.168.65.0/24`).

Los **agentes (opencode) corren en el sobremesa**, junto a las VMs: por eso el salto a las VMs es
**local** (host-only) y `vmrun` se ejecuta **en local** (sin `-h`). **No hay ProxyJump.**

---

## 1. Nivel 1 — Portátil → Sobremesa (SSH sobre Tailscale)

| Elemento | Valor |
|---|---|
| Cliente | Portátil Windows 11 (8 GB) |
| Servidor SSH | Sobremesa Windows 10 (16 GB) |
| Nombre del equipo | `desktop-oiolopo` |
| IP Tailscale | `100.82.127.119` |
| Usuario | `angel` |
| Servicio | `sshd` (OpenSSH Server) — `Running`, `Automatic` |
| Firewall | Reglas de entrada **habilitadas**: `OpenSSH Server (sshd)` y `OpenSSH SSH Server (sshd)` (TCP 22, todos los perfiles) |
| Tailscale | v1.102.4 (ambos equipos en la misma tailnet) |

### Prueba de conexión

Desde el **portátil**:

```powershell
ssh angel@100.82.127.119
```

Comprobación tras entrar (debe devolver `DESKTOP-OIOLOPO` y `desktop-oiolopo\angel`):

```powershell
hostname
whoami
```

### Autenticación por clave

La autenticación de referencia es **por clave** (sin contraseña). La clave **privada vive solo en
el cliente** (portátil), en `C:\Users\<usuario>\.ssh\`; en el sobremesa solo va la **pública**.

En el sobremesa, el usuario `angel` pertenece al grupo **Administradores**, por lo que el bloque
`Match Group administrators` de `C:\ProgramData\ssh\sshd_config` hace que el fichero efectivo de
claves públicas sea:

```text
C:\ProgramData\ssh\administrators_authorized_keys
```

Para dejar el acceso **solo por clave**, colocar la **clave pública del portátil** en ese fichero
(en el sobremesa, PowerShell como administrador) y fijar permisos:

```powershell
# 1) Añadir la clave pública del portátil (contenido del .pub; NO la privada)
Add-Content -Path "C:\ProgramData\ssh\administrators_authorized_keys" -Value "<contenido de id_*.pub>"

# 2) Permisos exigidos por sshd (solo Administradores y SYSTEM)
icacls "C:\ProgramData\ssh\administrators_authorized_keys" /inheritance:r `
  /grant "Administrators:F" /grant "SYSTEM:F"

# 3) (Opcional) deshabilitar login por contraseña y reiniciar
#    Editar C:\ProgramData\ssh\sshd_config  ->  PasswordAuthentication no
Restart-Service sshd
```

> **Estado verificado (2026-09-23).** La conexión `ssh angel@100.82.127.119` funciona (confirmada
> por el humano). Al redactar este documento **no existía** `administrators_authorized_keys` en el
> sobremesa, por lo que el login **sin contraseña** hay que habilitarlo con los pasos de arriba.
> **No se documenta ninguna contraseña.**

### Si falla (Nivel 1)

- `Get-Service sshd` en el sobremesa → debe estar `Running`.
- Si el portátil **pide contraseña** al usar clave → la pública no está en `administrators_authorized_keys`.
- Tailscale (en el sobremesa): `tailscale status` → `desktop-oiolopo 100.82.127.119`.
- Firewall: comprobar que las dos reglas de entrada de OpenSSH están `Habilitada: Sí` y escuchan en TCP 22.

---

## 2. Nivel 2 — Sobremesa → VMs (red host-only)

| Elemento | Valor |
|---|---|
| Red | Host-only `VMnet1`, `192.168.65.0/24` (sin internet) |
| `wazuh-server` | `192.168.65.128` |
| `victima-linux` | `192.168.65.129` |
| Usuario | `angel` (en ambas VMs) |
| Clave | `C:\Users\angel\.ssh\id_ed25519_tfg_lab` (privada) + `.pub` (`ssh-ed25519`) |
| Cliente `ssh` | `C:\Program Files\Git\usr\bin\ssh.exe` (**no está en el PATH**) |

> ⚠️ **Dato importante:** el binario `ssh` **no está en el PATH** del sobremesa. Se usa el de Git
> (`C:\Program Files\Git\usr\bin\ssh.exe`, `OpenSSH_10.5p1`). Por eso los ejemplos usan la **ruta
> completa** (o una variable `$ssh`).

La **clave pública** (`id_ed25519_tfg_lab.pub`) está en `~/.ssh/authorized_keys` de cada VM; la
**privada** se queda en el sobremesa y **no** se versiona. `known_hosts` ya contiene las entradas de
`192.168.65.128` y `192.168.65.129`.

### Ejemplos reales y copiables (en el sobremesa, PowerShell)

```powershell
$ssh = "C:\Program Files\Git\usr\bin\ssh.exe"
$key = "C:\Users\angel\.ssh\id_ed25519_tfg_lab"

# Wazuh (manager + indexer + dashboard)
& $ssh -i $key angel@192.168.65.128

# Víctima
& $ssh -i $key angel@192.168.65.129
```

Comando puntual sin shell interactiva:

```powershell
& $ssh -i $key angel@192.168.65.129 "hostname; ip -4 addr show ens33 | grep inet"
```

### Si falla (Nivel 2)

- Las VMs deben estar **encendidas** (ver `vmrun_config.md`):
  `vmrun -T ws list` → deben aparecer; si no, `vmrun -T ws start "<vmx>" nogui`.
- `ping 192.168.65.129` desde el sobremesa → comprueba la red host-only.
- Si pide contraseña → revisar `authorized_keys` en la VM y que se pasa `-i $key`.
- La ruta de la clave debe ir **entre comillas** (contiene `\`).

---

## 3. Resumen de pruebas

| Nivel | Prueba | Dónde |
|---|---|---|
| 1 | `ssh angel@100.82.127.119` abre shell en el sobremesa | Portátil |
| 2 | `& $ssh -i $key angel@192.168.65.129` abre shell en la víctima | Sobremesa (VM encendida) |

## 4. Higiene

- **Nunca** versionar claves privadas ni contraseñas; este repo solo guarda **dónde** están.
- No se toca `_recursos/`.
- Referencias: `README.md` (laboratorio), `vmrun_config.md` (control de VMs), `_fases/fase-02/plan.md` §3.9.
