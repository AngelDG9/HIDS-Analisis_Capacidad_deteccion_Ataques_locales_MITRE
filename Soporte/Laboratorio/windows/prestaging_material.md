# Pre-staging del material — laboratorio Windows (`fase-02b-construccion`)

> **Sidecar de fijación del material** (los **binarios no entran al repo**; solo este
> sidecar con **URL + tamaño + `sha256`**). Material descargado por el humano **con NAT on**
> y guardado **fuera del repo** en `D:\TFG-VMs\material-windows\`; el NAT se **desconecta**
> antes de baseline/ataques. Hashes **recalculados** en el host el **2026-10-06** con
> `Get-FileHash -Algorithm SHA256`.

---

## 1. Ficheros fijados

| Material | URL oficial | Tamaño (bytes) | `sha256` |
|---|---|---|---|
| **Agente Wazuh 4.14.7-1 (MSI)** | `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.7-1.msi` | `5 935 104` | `E967F36B75589D6210244FD58239C7021FA53A77C38D92315C3B3BD115002EDE` |
| **Sysmon (Sysinternals)** — v15.22 | `https://download.sysinternals.com/files/Sysmon.zip` | `2 938 038` | `00ECF1B46AEC99299D3AE0BCA79DC621458BD014B20B509D7C5C8E8C8611AA54` |
| **Config Sysmon curada** (`sysmonconfig-export.xml`) — SwiftOnSecurity, source version 74 (2021-07-08) | `https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml` | `123 257` | `055FEBC600E6D7448CDF3812307275912927A62B1F94D0D933B64B294BC87162` |

- **Ruta en el host:** `D:\TFG-VMs\material-windows\`.
- **Destino en la VM:** `C:\Users\angel\material\`.
- **Versión del agente:** `4.14.7-1` (sincronía con el manager `wazuh-server`).
- **Versión de Sysmon:** `15.22` (`Sysmon64.exe`, Sysinternals).

> **Nota de trazabilidad:** `pasos_montaje.md` §2 citaba `olafhartong/sysmon-modular`
> como config curada, pero el fichero materializado es `sysmonconfig-export.xml`
> (**SwiftOnSecurity/sysmon-config**), que es la URL fijada en el plan aprobado (`plan.md`
> §0). La cita de `pasos_montaje.md` §2 se **corrigió** el **2026-10-07** a la fuente real
> (`SwiftOnSecurity/sysmon-config`, *source version 74*). El binario y la config son
> **consistentes entre sí** (Sysmon ≥ 13, requisito de la config); se registra la procedencia
> **real** para no falsear la huella.

---

## 2. Cómo se fijó

- `sha256` recalculado en el host: `Get-FileHash <fichero> -Algorithm SHA256`.
- Los hashes **dependen del binario exacto** descargado (Sysmon/release y MSI); **no se
  inventan** (`pasos_montaje.md` §2).
- **Sin secretos** en este documento.

---

## 3. Pre-staging de B1.0 (ataques Windows)

> Material **fuera del repo** en **`D:\TFG-VMs\material-windows\ataques\`**. Descargado y
> verificado en el host el **2026-11-08**. Los binarios **no** entran al repo; solo este
> sidecar con **URL + tamaño + `sha256`**. El material se copia a la VM **antes de `t0`**
> (nunca dentro de `C:\lab-attack`, que debe quedar vacío en el snapshot).

| Material | URL oficial | Tamaño (bytes) | `sha256` |
|---|---|---|---|
| **rclone** v1.68.1 (Windows amd64) | `https://downloads.rclone.org/v1.68.1/rclone-v1.68.1-windows-amd64.zip` | `22 431 048` | `35E550EA373D90ED65AC1E2202420923584EC0501CF143AE27BDCFF580A7C51F` |
| **PortableGit** 2.47.1 (64-bit) | `https://github.com/git-for-windows/git/releases/download/v2.47.1.windows.1/PortableGit-2.47.1-64-bit.7z.exe` | `62 954 096` | `4F3F21F4EFFCB659566883EE1ED3AE403E5B3D7A0699CEE455F6CD765E1AC39C` |
| **sqlite3** (tools 3.46.1, win-x64) | `https://www.sqlite.org/2024/sqlite-tools-win-x64-3460100.zip` | `5 036 925` | `C86C0FE0B0B46CFAAC40812A26C958BBF2378B6EF9D784D6354D9F5BD66E566B` |

### 3.1 Verificación en el host (`where` + versión)

```text
> where rclone
D:\TFG-VMs\material-windows\ataques\rclone\rclone-v1.68.1-windows-amd64\rclone.exe
> where sqlite3
D:\TFG-VMs\material-windows\ataques\sqlite\sqlite3.exe
> where git
D:\TFG-VMs\material-windows\ataques\PortableGit\cmd\git.exe
C:\Program Files\Git\cmd\git.exe
```

| Herramienta | Versión verificada |
|---|---|
| `rclone.exe` | `rclone v1.68.1` |
| `PortableGit\cmd\git.exe` | `git version 2.47.1.windows.1` |
| `PortableGit\bin\bash.exe` | `GNU bash, version 5.2.37(1)-release` |
| `sqlite3.exe` | `3.46.1 2024-08-13 09:16:08 c9c2ab54ba1f5f46360f1b4f35d849cd3f080e6fc2b6c60e91b16c63f69a1e33 (64-bit)` |

> **Nota:** el `where git` del host encuentra **primero** el PortableGit pre-staged y después
> el Git instalado en `C:\Program Files\Git`. En la VM se usará **solo** el PortableGit
> pre-staged, copiado antes de `t0`.

### 3.2 Destino previsto en la VM

- `C:\Users\angel\material\ataques\rclone\rclone.exe`
- `C:\Users\angel\material\ataques\PortableGit\` (carpeta completa)
- `C:\Users\angel\material\ataques\sqlite\sqlite3.exe`

> **B1.0 no copia estos binarios al snapshot** (para no inflar la imagen y mantener
> `C:\lab-attack` vacío). Se copian **por caso** antes de `t0`, como dice `plan.md` §6.3.
> Si en B1.1 se decide incluirlos en el snapshot, se hará con `sha256` verificado y sin
> tocar `C:\lab-attack`.
