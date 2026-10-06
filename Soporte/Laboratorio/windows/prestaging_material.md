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
