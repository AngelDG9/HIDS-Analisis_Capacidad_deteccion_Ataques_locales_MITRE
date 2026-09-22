# Lista de técnicas válidas (host-eligible) — MITRE ATT&CK Enterprise v19.1

> Generado automáticamente por `_artefactos/scripts/extraer_tecnicas_host.py` el **2026-09-19**.
> Fuente: `_artefactos/mitre/enterprise-attack-v19.1.json` (STIX v19.1).

## 1. Método (filtro inverso host, R-03)

- Se recorre la cadena de detección de ATT&CK v19: `attack-pattern ←detects— Detection Strategy → Analytics → Data Components`.
- Los Data Components de red pura (`Network Connection Creation`, `Network Traffic Content`, `Network Traffic Flow`) y los descartados (`Network Share Access`, `Response Content`, `Response Metadata`) **no** otorgan elegibilidad.
- **Interpretación amplia (fijada):** una técnica es `host_eligible=YES` si tiene **≥1 Data Component endpoint**; los DC de red **no anulan** una técnica con telemetría host. Solo es `NO` si todos sus DC son de red.
- Las subtécnicas sin telemetría propia **heredan** la del padre (`heredado_padre=si`).

## 2. Resumen del corpus

- Técnicas/subtécnicas activas analizadas: **697** (excluidas deprecated/revoked).
- `host_eligible=YES`: **625** · `NO`: **72**.
- Prioridad (host-eligible): **P1=89**, **P2=459**, **P3=77**.

### Cobertura por táctica (host-eligible)

| Táctica | Técnicas |
|---|---|
| Collection | 39 |
| Command and Control | 41 |
| Credential Access | 66 |
| Defense Impairment | 54 |
| Discovery | 49 |
| Execution | 64 |
| Exfiltration | 17 |
| Impact | 33 |
| Initial Access | 22 |
| Lateral Movement | 23 |
| Persistence | 113 |
| Privilege Escalation | 96 |
| Reconnaissance | 6 |
| Resource Development | 28 |
| Stealth | 148 |

## 3. Técnicas priorizadas (P1 → P3)

### P1 — Ransomware / Exfiltración / Sabotaje

| ID | Nombre | Subtéc. | Tácticas | Plataformas | DC host | DC red | Prio | Justificación R/E/S |
|---|---|---|---|---|---|---|---|---|
| T1005 | Data from Local System | no | Collection | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Access, File Creation, Process Creation | 0 | P1 | Recolección/preparación |
| T1011 | Exfiltration Over Other Network Medium | no | Exfiltration | Linux;macOS;Windows | Command Execution, File Creation, Host Status, Process Creation | 3 | P1 | Exfiltración |
| T1011.001 | Exfiltration Over Bluetooth | sí | Exfiltration | Linux;macOS;Windows | Command Execution, File Access, File Creation, Process Creation | 1 | P1 | Exfiltración |
| T1020 | Automated Exfiltration | no | Exfiltration | Linux;macOS;Network Devices;Windows | Process Creation, Scheduled Job Creation | 1 | P1 | Exfiltración |
| T1025 | Data from Removable Media | no | Collection | Linux;macOS;Windows | Drive Creation, File Access, Process Creation | 0 | P1 | Recolección/preparación |
| T1029 | Scheduled Transfer | no | Exfiltration | Linux;macOS;Windows | Process Creation, Scheduled Job Metadata | 2 | P1 | Exfiltración |
| T1039 | Data from Network Shared Drive | no | Collection | Linux;macOS;Windows | Drive Access, File Access, File Creation | 1 | P1 | Recolección/preparación |
| T1041 | Exfiltration Over C2 Channel | no | Exfiltration | ESXi;Linux;macOS;Windows | File Access, Process Creation | 3 | P1 | Exfiltración |
| T1048 | Exfiltration Over Alternative Protocol | no | Exfiltration | ESXi;IaaS;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | Cloud Storage Access, Command Execution, File Access, File Creation, File Modification, Process Creation | 3 | P1 | Exfiltración |
| T1048.001 | Exfiltration Over Symmetric Encrypted Non-C2 Protocol | sí | Exfiltration | Linux;macOS;Windows;ESXi | Command Execution, Process Creation | 3 | P1 | Exfiltración |
| T1048.002 | Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | sí | Exfiltration | ESXi;Linux;macOS;Windows | Command Execution, File Access, Process Creation | 3 | P1 | Exfiltración |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | sí | Exfiltration | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Access, Process Creation | 3 | P1 | Exfiltración |
| T1052 | Exfiltration Over Physical Medium | no | Exfiltration | Linux;macOS;Windows | Command Execution, Drive Creation, File Access, File Creation, Process Creation | 0 | P1 | Exfiltración |
| T1052.001 | Exfiltration over USB | sí | Exfiltration | Linux;Windows;macOS | Drive Creation, File Access, File Creation, Process Creation | 0 | P1 | Exfiltración |
| T1056 | Input Capture | no | Collection;Credential Access | Linux;macOS;Network Devices;Windows | File Access, File Modification, OS API Execution, Process Access, Process Creation, Process Metadata | 2 | P1 | Recolección/preparación |
| T1056.001 | Keylogging | sí | Collection;Credential Access | Linux;macOS;Network Devices;Windows | File Access, Firmware Modification, OS API Execution, Process Access, Process Creation, Process Metadata, Service Creation, Windows Registry Key Modification | 1 | P1 | Recolección/preparación |
| T1056.002 | GUI Input Capture | sí | Collection;Credential Access | Linux;macOS;Windows | Command Execution, Process Creation, Script Execution | 0 | P1 | Recolección/preparación |
| T1056.003 | Web Portal Capture | sí | Collection;Credential Access | Linux;macOS;Windows | File Creation, File Modification | 1 | P1 | Recolección/preparación |
| T1056.004 | Credential API Hooking | sí | Collection;Credential Access | Windows;Linux;macOS | File Access, Module Load, Process Access, Process Creation, Process Modification | 0 | P1 | Recolección/preparación |
| T1074 | Data Staged | no | Collection | ESXi;IaaS;Linux;macOS;Windows | Cloud Storage Access, Command Execution, File Access, File Creation, Process Creation | 0 | P1 | Recolección/preparación |
| T1074.001 | Local Data Staging | sí | Collection | ESXi;Linux;macOS;Windows | Command Execution, File Access, File Creation, Process Creation, Snapshot Creation | 0 | P1 | Recolección/preparación |
| T1074.002 | Remote Data Staging | sí | Collection | ESXi;IaaS;Linux;macOS;Windows | Cloud Storage Access, Command Execution, File Access, File Creation, Process Creation | 2 | P1 | Recolección/preparación |
| T1113 | Screen Capture | no | Collection | Linux;macOS;Windows | Module Load, Process Creation | 0 | P1 | Recolección/preparación |
| T1114 | Email Collection | no | Collection | Windows;macOS;Linux;Office Suite | Application Log Content, Command Execution, File Access, Logon Session Creation, Process Creation | 2 | P1 | Recolección/preparación |
| T1114.001 | Local Email Collection | sí | Collection | Windows | File Access, File Creation, Process Creation | 1 | P1 | Recolección/preparación |
| T1114.002 | Remote Email Collection | sí | Collection | Office Suite;Windows | Application Log Content, Command Execution, Logon Session Creation | 1 | P1 | Recolección/preparación |
| T1114.003 | Email Forwarding Rule | sí | Collection | Linux;macOS;Office Suite;Windows | Application Log Content, Cloud Service Metadata, Command Execution, File Modification, Process Creation | 0 | P1 | Recolección/preparación |
| T1115 | Clipboard Data | no | Collection | Linux;macOS;Windows | Process Access, Process Creation | 0 | P1 | Recolección/preparación |
| T1119 | Automated Collection | no | Collection | IaaS;Linux;macOS;Office Suite;SaaS;Windows | File Access, File Creation, Process Creation, Script Execution, User Account Authentication | 0 | P1 | Recolección/preparación |
| T1123 | Audio Capture | no | Collection | Linux;macOS;Windows | File Access, File Creation, OS API Execution, Process Access, Process Creation | 0 | P1 | Recolección/preparación |
| T1125 | Video Capture | no | Collection | Linux;macOS;Windows | Command Execution, File Access, File Creation, Module Load, OS API Execution, Process Creation, Process Metadata | 2 | P1 | Recolección/preparación |
| T1185 | Browser Session Hijacking | no | Collection | Windows | Logon Session Creation, Logon Session Metadata, Module Load, Process Access, Process Modification, User Account Metadata | 1 | P1 | Recolección/preparación |
| T1213 | Data from Information Repositories | no | Collection | Linux;Windows;macOS;SaaS;IaaS;Office Suite | Application Log Content, Cloud Service Modification, Cloud Storage Access, Command Execution, File Access, Process Creation | 2 | P1 | Recolección/preparación |
| T1213.001 | Confluence | sí | Collection | SaaS | Application Log Content, Logon Session Creation | 1 | P1 | Recolección/preparación |
| T1213.002 | Sharepoint | sí | Collection | Office Suite;Windows | Application Log Content, Cloud Service Metadata, Logon Session Creation | 0 | P1 | Recolección/preparación |
| T1213.003 | Code Repositories | sí | Collection | SaaS | Application Log Content, Cloud Service Metadata, Logon Session Creation | 0 | P1 | Recolección/preparación |
| T1213.004 | Customer Relationship Management Software | sí | Collection | SaaS | Application Log Content, Logon Session Creation | 0 | P1 | Recolección/preparación |
| T1213.005 | Messaging Applications | sí | Collection | Office Suite;SaaS | Application Log Content, Logon Session Creation | 0 | P1 | Recolección/preparación |
| T1213.006 | Databases | sí | Collection | IaaS;Linux;macOS;SaaS;Windows | Application Log Content, Cloud Service Metadata, Cloud Storage Access, File Access, File Creation, Process Creation | 2 | P1 | Recolección/preparación |
| T1485 | Data Destruction | no | Impact | Containers;ESXi;IaaS;Linux;macOS;Windows | Cloud Storage Deletion, Command Execution, File Creation, File Deletion, Process Creation, Process Termination, Volume Deletion | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1485.001 | Lifecycle-Triggered Deletion | sí | Impact | IaaS | Cloud Storage Modification | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1486 | Data Encrypted for Impact | no | Impact | ESXi;IaaS;Linux;macOS;Windows | Cloud Storage Modification, Command Execution, File Creation, File Modification, Process Creation | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1489 | Service Stop | no | Impact | ESXi;IaaS;Linux;macOS;Windows | File Deletion, Logon Session Metadata, Process Creation, Process Termination, Service Creation, Service Metadata | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1490 | Inhibit System Recovery | no | Impact | Containers;ESXi;IaaS;Linux;macOS;Network Devices;Windows | Cloud Storage Deletion, Command Execution, File Deletion, Process Creation, Service Metadata, Snapshot Deletion, Windows Registry Key Modification | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1491 | Defacement | no | Impact | Windows;IaaS;Linux;macOS;ESXi | Application Log Content, Cloud Storage Access, File Creation, File Modification, Process Creation | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1491.001 | Internal Defacement | sí | Impact | ESXi;Linux;macOS;Windows | Command Execution, File Access, File Creation, File Modification, Process Creation, Script Execution, User Account Modification | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1491.002 | External Defacement | sí | Impact | Windows;IaaS;Linux;macOS | Cloud Storage Access, Cloud Storage Enumeration, File Creation, File Modification, Logon Session Metadata, Process Creation | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1495 | Firmware Corruption | no | Impact | Linux;macOS;Network Devices;Windows | Driver Load, Firmware Modification, Process Creation | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1496 | Resource Hijacking | no | Impact | Windows;IaaS;Linux;macOS;Containers;SaaS | Application Log Content, Cloud Service Modification, Host Status, Instance Start, Process Creation | 3 | P1 | Ransomware/Sabotaje (Impact) |
| T1496.001 | Compute Hijacking | sí | Impact | Windows;IaaS;Linux;macOS;Containers | Container Creation, Host Status, Instance Start, Process Creation, Scheduled Job Creation | 3 | P1 | Ransomware/Sabotaje (Impact) |
| T1496.002 | Bandwidth Hijacking | sí | Impact | Linux;Windows;macOS;IaaS;Containers | Instance Start, Process Creation | 3 | P1 | Ransomware/Sabotaje (Impact) |
| T1496.003 | SMS Pumping | sí | Impact | SaaS | Application Log Content, User Account Authentication | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1496.004 | Cloud Service Hijacking | sí | Impact | SaaS | Application Log Content, Cloud Service Modification, User Account Metadata | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1498 | Network Denial of Service | no | Impact | Windows;IaaS;Linux;macOS;Containers | Process Creation | 2 | P1 | Ransomware/Sabotaje (Impact) |
| T1498.001 | Direct Network Flood | sí | Impact | Windows;IaaS;Linux;macOS | Host Status, Process Creation | 2 | P1 | Ransomware/Sabotaje (Impact) |
| T1498.002 | Reflection Amplification | sí | Impact | Windows;IaaS;Linux;macOS | Command Execution, Firewall Rule Modification, Host Status, Process Creation | 2 | P1 | Ransomware/Sabotaje (Impact) |
| T1499 | Endpoint Denial of Service | no | Impact | Windows;Linux;macOS;Containers;IaaS | Application Log Content, Host Status, Instance Start, Process Creation | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1499.001 | OS Exhaustion Flood | sí | Impact | Linux;macOS;Windows | Host Status, Process Creation | 2 | P1 | Ransomware/Sabotaje (Impact) |
| T1499.002 | Service Exhaustion Flood | sí | Impact | Windows;IaaS;Linux;macOS | Application Log Content, Firewall Rule Modification, Host Status, Process Access | 3 | P1 | Ransomware/Sabotaje (Impact) |
| T1499.003 | Application Exhaustion Flood | sí | Impact | Windows;IaaS;Linux;macOS | Application Log Content, Cloud Service Metadata, Host Status, Process Creation | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1499.004 | Application or System Exploitation | sí | Impact | Windows;IaaS;Linux;macOS | Application Log Content, Instance Stop, Process Creation, Process Termination, Service Creation | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1529 | System Shutdown/Reboot | no | Impact | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Host Status, Process Creation | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1530 | Data from Cloud Storage | no | Collection | IaaS;Office Suite;SaaS | Cloud Storage Access, User Account Authentication, User Account Metadata | 1 | P1 | Recolección/preparación |
| T1531 | Account Access Removal | no | Impact | Linux;macOS;Windows;SaaS;IaaS;Office Suite;ESXi | Command Execution, Process Creation, User Account Authentication, User Account Deletion, User Account Modification | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1537 | Transfer Data to Cloud Account | no | Exfiltration | IaaS;Office Suite;SaaS | Application Log Content, Cloud Storage Metadata, Cloud Storage Modification, Snapshot Creation, Snapshot Metadata, Snapshot Modification | 1 | P1 | Exfiltración |
| T1557 | Adversary-in-the-Middle | no | Credential Access;Collection | Linux;macOS;Network Devices;Windows | Application Log Content, File Modification, Windows Registry Key Modification | 3 | P1 | Recolección/preparación |
| T1557.001 | Name Resolution Poisoning and SMB Relay | sí | Credential Access;Collection | Windows | Service Creation, Windows Registry Key Modification | 2 | P1 | Recolección/preparación |
| T1557.003 | DHCP Spoofing | sí | Credential Access;Collection | Linux;Windows;macOS | Application Log Content | 2 | P1 | Recolección/preparación |
| T1557.004 | Evil Twin | sí | Credential Access;Collection | Network Devices | Application Log Content | 2 | P1 | Recolección/preparación |
| T1560 | Archive Collected Data | no | Collection | Linux;macOS;Windows | Command Execution, File Creation, Module Load, Process Creation | 0 | P1 | Recolección/preparación |
| T1560.001 | Archive via Utility | sí | Collection | Linux;macOS;Windows | Command Execution, File Creation, Module Load, Process Creation | 0 | P1 | Recolección/preparación |
| T1560.002 | Archive via Library | sí | Collection | Linux;macOS;Windows | Command Execution, File Creation, Module Load, Process Creation | 0 | P1 | Recolección/preparación |
| T1560.003 | Archive via Custom Method | sí | Collection | Linux;macOS;Windows | Command Execution, File Creation, Process Access, Process Creation, Process Modification | 0 | P1 | Recolección/preparación |
| T1561 | Disk Wipe | no | Impact | Linux;macOS;Windows;Network Devices | Command Execution, Drive Access, Drive Modification, Driver Load, Process Creation, User Account Authentication, User Account Metadata | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1561.001 | Disk Content Wipe | sí | Impact | Linux;macOS;Network Devices;Windows | Command Execution, Drive Access, Drive Modification, Driver Load, Process Creation, User Account Authentication, User Account Metadata | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1561.002 | Disk Structure Wipe | sí | Impact | Linux;macOS;Network Devices;Windows | Command Execution, Drive Access, Drive Modification, Driver Load, Process Creation, User Account Authentication, User Account Metadata | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1565 | Data Manipulation | no | Impact | Linux;macOS;Windows | File Access, File Creation, File Metadata, File Modification, OS API Execution | 1 | P1 | Ransomware/Sabotaje (Impact) |
| T1565.001 | Stored Data Manipulation | sí | Impact | Linux;macOS;Windows | File Creation, File Deletion, File Metadata, File Modification | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1565.002 | Transmitted Data Manipulation | sí | Impact | Linux;macOS;Windows | File Metadata, OS API Execution | 3 | P1 | Ransomware/Sabotaje (Impact) |
| T1565.003 | Runtime Data Manipulation | sí | Impact | Linux;macOS;Windows | File Creation, File Metadata, File Modification, OS API Execution, Windows Registry Key Modification | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1567 | Exfiltration Over Web Service | no | Exfiltration | ESXi;Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Command Execution, File Access, File Creation, Process Creation | 3 | P1 | Exfiltración |
| T1567.001 | Exfiltration to Code Repository | sí | Exfiltration | ESXi;Linux;macOS;Windows | Command Execution, File Access, Process Creation | 3 | P1 | Exfiltración |
| T1567.002 | Exfiltration to Cloud Storage | sí | Exfiltration | ESXi;Linux;macOS;Windows | Command Execution, File Access, Process Creation | 3 | P1 | Exfiltración |
| T1567.003 | Exfiltration to Text Storage Sites | sí | Exfiltration | Linux;macOS;Windows;ESXi | Command Execution, File Access, Process Creation | 3 | P1 | Exfiltración |
| T1567.004 | Exfiltration Over Webhook | sí | Exfiltration | ESXi;Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Command Execution, File Access, Process Creation | 3 | P1 | Exfiltración |
| T1602.001 | SNMP (MIB Dump) | sí | Collection | Network Devices | File Modification | 2 | P1 | Recolección/preparación |
| T1602.002 | Network Device Configuration Dump | sí | Collection | Network Devices | Command Execution, User Account Authentication | 2 | P1 | Recolección/preparación |
| T1657 | Financial Theft | no | Impact | Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Command Execution, File Modification, Logon Session Creation, Process Creation | 0 | P1 | Ransomware/Sabotaje (Impact) |
| T1667 | Email Bombing | no | Impact | Linux;Office Suite;Windows;macOS | Application Log Content, File Creation | 0 | P1 | Ransomware/Sabotaje (Impact) |

### P2 — Habilitadoras directas

| ID | Nombre | Subtéc. | Tácticas | Plataformas | DC host | DC red | Prio | Justificación R/E/S |
|---|---|---|---|---|---|---|---|---|
| T1001 | Data Obfuscation | no | Command and Control | ESXi;Linux;macOS;Windows | Process Creation | 2 | P2 | Habilitadora |
| T1001.001 | Junk Data | sí | Command and Control | ESXi;Linux;macOS;Windows | Process Access, Process Creation | 2 | P2 | Habilitadora |
| T1001.002 | Steganography | sí | Command and Control | Linux;macOS;Windows;ESXi | File Creation, File Metadata, Process Creation | 2 | P2 | Habilitadora |
| T1001.003 | Protocol or Service Impersonation | sí | Command and Control | ESXi;Linux;macOS;Windows | Process Creation, Process Metadata | 2 | P2 | Habilitadora |
| T1003 | OS Credential Dumping | no | Credential Access | Linux;macOS;Windows | Active Directory Object Access, File Access, Process Access, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1003.001 | LSASS Memory | sí | Credential Access | Windows | File Creation, Process Access, Process Creation, User Account Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1003.002 | Security Account Manager | sí | Credential Access | Windows | File Creation, File Modification, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1003.003 | NTDS | sí | Credential Access | Windows | File Creation, File Modification, Process Creation, Volume Creation | 0 | P2 | Habilitadora |
| T1003.004 | LSA Secrets | sí | Credential Access | Windows | File Modification, Module Load, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1003.005 | Cached Domain Credentials | sí | Credential Access | Windows;Linux | File Access, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1003.006 | DCSync | sí | Credential Access | Windows | Active Directory Object Access, Active Directory Object Deletion | 1 | P2 | Habilitadora |
| T1003.007 | Proc Filesystem | sí | Credential Access | Linux | File Access, File Modification, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1003.008 | /etc/passwd and /etc/shadow | sí | Credential Access | Linux | File Access, Process Creation | 0 | P2 | Habilitadora |
| T1006 | Direct Volume Access | no | Stealth | Network Devices;Windows | Command Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1014 | Rootkit | no | Stealth | Linux;macOS;Windows | Driver Load, File Creation, File Modification, Module Load, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1021 | Remote Services | no | Lateral Movement | Linux;macOS;Windows;IaaS;ESXi | Command Execution, Logon Session Creation, Process Creation | 1 | P2 | Habilitadora |
| T1021.001 | Remote Desktop Protocol | sí | Lateral Movement | Windows | Logon Session Creation, Logon Session Metadata, Process Creation | 1 | P2 | Habilitadora |
| T1021.002 | SMB/Windows Admin Shares | sí | Lateral Movement | Windows | Logon Session Creation, Process Creation | 1 | P2 | Habilitadora |
| T1021.003 | Distributed Component Object Model | sí | Lateral Movement | Windows | Logon Session Creation, Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1021.004 | SSH | sí | Lateral Movement | ESXi;Linux;macOS | Command Execution, Logon Session Creation, Logon Session Metadata, Process Creation | 2 | P2 | Habilitadora |
| T1021.005 | VNC | sí | Lateral Movement | Linux;Windows;macOS | Logon Session Creation, Logon Session Metadata, Process Creation | 1 | P2 | Habilitadora |
| T1021.006 | Windows Remote Management | sí | Lateral Movement | Windows | Logon Session Creation, Process Creation, Service Metadata | 1 | P2 | Habilitadora |
| T1021.007 | Cloud Services | sí | Lateral Movement | IaaS;Identity Provider;Office Suite;SaaS | Command Execution, File Access, Logon Session Creation | 0 | P2 | Habilitadora |
| T1021.008 | Direct Cloud VM Connections | sí | Lateral Movement | IaaS | Logon Session Creation, Process Creation | 0 | P2 | Habilitadora |
| T1027 | Obfuscated Files or Information | no | Stealth | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Creation, File Metadata, File Modification, OS API Execution, Process Creation | 1 | P2 | Habilitadora |
| T1027.001 | Binary Padding | sí | Stealth | Linux;macOS;Windows | File Access, File Creation, Process Creation | 0 | P2 | Habilitadora |
| T1027.002 | Software Packing | sí | Stealth | Linux;macOS;Windows | Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1027.003 | Steganography | sí | Stealth | Linux;macOS;Windows | File Access, Process Creation | 1 | P2 | Habilitadora |
| T1027.004 | Compile After Delivery | sí | Stealth | Linux;macOS;Windows | File Creation, Process Creation | 1 | P2 | Habilitadora |
| T1027.005 | Indicator Removal from Tools | sí | Stealth | Linux;macOS;Windows | Application Log Content, File Creation, File Metadata, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1027.006 | HTML Smuggling | sí | Stealth | Linux;macOS;Windows | File Creation, File Metadata, Process Creation | 1 | P2 | Habilitadora |
| T1027.007 | Dynamic API Resolution | sí | Stealth | Windows | Module Load, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1027.008 | Stripped Payloads | sí | Stealth | Linux;macOS;Network Devices;Windows | File Creation, File Metadata, File Modification, Process Creation | 1 | P2 | Habilitadora |
| T1027.009 | Embedded Payloads | sí | Stealth | Linux;macOS;Windows | File Access, File Creation, File Metadata, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1027.010 | Command Obfuscation | sí | Stealth | Linux;macOS;Windows | Command Execution, Process Creation | 0 | P2 | Habilitadora |
| T1027.011 | Fileless Storage | sí | Stealth | Linux;Windows | File Creation, File Metadata, WMI Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1027.012 | LNK Icon Smuggling | sí | Stealth | Windows | File Metadata, Process Creation | 1 | P2 | Habilitadora |
| T1027.013 | Encrypted/Encoded File | sí | Stealth | Linux;macOS;Windows | Command Execution, Module Load, Process Access, Process Creation, Process Modification | 1 | P2 | Habilitadora |
| T1027.014 | Polymorphic Code | sí | Stealth | Linux;macOS;Windows | File Creation, File Modification, Module Load, Process Access, Process Creation, Process Metadata, Process Modification | 0 | P2 | Habilitadora |
| T1027.015 | Compression | sí | Stealth | Linux;macOS;Windows | File Access, File Creation, File Metadata, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1027.016 | Junk Code Insertion | sí | Stealth | Linux;macOS;Windows | File Creation, Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1027.017 | SVG Smuggling | sí | Stealth | Linux;macOS;Windows | File Creation, File Modification, Process Creation | 2 | P2 | Habilitadora |
| T1027.018 | Invisible Unicode | sí | Stealth | Linux;macOS;Windows | Command Execution, File Access, File Creation, File Metadata, Module Load, Process Creation, Script Execution | 1 | P2 | Habilitadora |
| T1036 | Masquerading | no | Stealth | Containers;ESXi;Linux;macOS;Windows | Command Execution, File Metadata, File Modification, Image Metadata, Process Creation, Process Metadata, Service Creation, Service Metadata | 0 | P2 | Habilitadora |
| T1036.001 | Invalid Code Signature | sí | Stealth | macOS;Windows | Command Execution, File Metadata, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1036.002 | Right-to-Left Override | sí | Stealth | Linux;macOS;Windows | Command Execution, File Access, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1036.003 | Rename Legitimate Utilities | sí | Stealth | Linux;macOS;Windows | Command Execution, File Creation, File Metadata, File Modification, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1036.004 | Masquerade Task or Service | sí | Stealth | Linux;macOS;Windows | Process Creation, Scheduled Job Creation, Scheduled Job Metadata, Scheduled Job Modification, Service Creation, Service Metadata | 0 | P2 | Habilitadora |
| T1036.005 | Match Legitimate Resource Name or Location | sí | Stealth | Containers;ESXi;Linux;macOS;Windows | File Access, File Creation, File Metadata, Image Metadata, Module Load, Process Creation, Process Metadata, Process Modification, Scheduled Job Creation, Service Metadata | 0 | P2 | Habilitadora |
| T1036.006 | Space after Filename | sí | Stealth | Linux;macOS | File Access, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1036.007 | Double File Extension | sí | Stealth | Windows | File Creation, Process Creation | 0 | P2 | Habilitadora |
| T1036.008 | Masquerade File Type | sí | Stealth | Linux;macOS;Windows | File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1036.009 | Break Process Trees | sí | Stealth | Linux;macOS | OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1036.010 | Masquerade Account Name | sí | Stealth | Containers;IaaS;Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | User Account Creation, User Account Metadata, User Account Modification | 0 | P2 | Habilitadora |
| T1036.011 | Overwrite Process Arguments | sí | Stealth | Linux | Process Metadata, Process Modification | 0 | P2 | Habilitadora |
| T1036.012 | Browser Fingerprint | sí | Stealth | Linux;macOS;Windows | OS API Execution, Process Creation | 2 | P2 | Habilitadora |
| T1037 | Boot or Logon Initialization Scripts | no | Persistence;Privilege Escalation | ESXi;Linux;macOS;Network Devices;Windows | File Access, File Metadata, File Modification, Process Creation, Scheduled Job Creation, Script Execution, Service Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1037.001 | Logon Script (Windows) | sí | Persistence;Privilege Escalation | Windows | File Access, Logon Session Creation, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1037.002 | Login Hook | sí | Persistence;Privilege Escalation | macOS | File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1037.003 | Network Logon Script | sí | Persistence;Privilege Escalation | Windows | Process Creation, Script Execution | 1 | P2 | Habilitadora |
| T1037.004 | RC Scripts | sí | Persistence;Privilege Escalation | macOS;Linux;Network Devices;ESXi | Command Execution, File Creation, File Modification, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1037.005 | Startup Items | sí | Persistence;Privilege Escalation | macOS | File Creation, Process Creation | 0 | P2 | Habilitadora |
| T1040 | Network Sniffing | no | Credential Access;Discovery | IaaS;Linux;macOS;Network Devices;Windows | Cloud Service Modification, Command Execution, Process Creation, Service Creation, User Account Authentication | 1 | P2 | Habilitadora |
| T1047 | Windows Management Instrumentation | no | Execution | Windows | Process Creation, WMI Creation | 1 | P2 | Habilitadora |
| T1053 | Scheduled Task/Job | no | Execution;Persistence;Privilege Escalation | Containers;ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Creation, File Modification, Process Creation, Scheduled Job Creation | 0 | P2 | Habilitadora |
| T1053.002 | At | sí | Execution;Persistence;Privilege Escalation | Windows;Linux;macOS | Command Execution, File Modification, Process Creation, Scheduled Job Creation | 0 | P2 | Habilitadora |
| T1053.003 | Cron | sí | Execution;Persistence;Privilege Escalation | Linux;macOS;ESXi | File Modification, Process Creation, Scheduled Job Creation | 0 | P2 | Habilitadora |
| T1053.005 | Scheduled Task | sí | Execution;Persistence;Privilege Escalation | Windows | File Creation, Process Creation, Scheduled Job Creation, Scheduled Job Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1053.006 | Systemd Timers | sí | Execution;Persistence;Privilege Escalation | Linux | File Creation, Process Creation, Scheduled Job Creation | 0 | P2 | Habilitadora |
| T1053.007 | Container Orchestration Job | sí | Execution;Persistence;Privilege Escalation | Containers | Container Creation, Scheduled Job Creation | 1 | P2 | Habilitadora |
| T1055 | Process Injection | no | Stealth;Privilege Escalation | Linux;macOS;Windows | File Access, Module Load, OS API Execution, Process Access, Process Creation, Process Metadata, Process Modification | 0 | P2 | Habilitadora |
| T1055.001 | Dynamic-link Library Injection | sí | Stealth;Privilege Escalation | Windows | Module Load, Named Pipe Metadata, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1055.002 | Portable Executable Injection | sí | Stealth;Privilege Escalation | Windows | File Creation, Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1055.003 | Thread Execution Hijacking | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1055.004 | Asynchronous Procedure Call | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1055.005 | Thread Local Storage | sí | Stealth;Privilege Escalation | Windows | Module Load, OS API Execution, Process Access, Process Modification | 0 | P2 | Habilitadora |
| T1055.008 | Ptrace System Calls | sí | Stealth;Privilege Escalation | Linux | OS API Execution, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1055.009 | Proc Memory | sí | Stealth;Privilege Escalation | Linux | File Access, File Modification, OS API Execution | 0 | P2 | Habilitadora |
| T1055.011 | Extra Window Memory Injection | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1055.012 | Process Hollowing | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1055.013 | Process Doppelgänging | sí | Stealth;Privilege Escalation | Windows | File Creation, OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1055.014 | VDSO Hijacking | sí | Stealth;Privilege Escalation | Linux | Module Load, OS API Execution, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1055.015 | ListPlanting | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Access, Process Creation, Process Modification | 0 | P2 | Habilitadora |
| T1059 | Command and Scripting Interpreter | no | Execution | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | Command Execution, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1059.001 | PowerShell | sí | Execution | Windows | Command Execution, Module Load, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1059.002 | AppleScript | sí | Execution | macOS | Process Creation | 0 | P2 | Habilitadora |
| T1059.003 | Windows Command Shell | sí | Execution | Windows | Module Load, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1059.004 | Unix Shell | sí | Execution | ESXi;Linux;macOS;Network Devices | Command Execution, Logon Session Creation, Process Creation, Script Execution | 2 | P2 | Habilitadora |
| T1059.005 | Visual Basic | sí | Execution | Linux;macOS;Windows | Command Execution, Module Load, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1059.006 | Python | sí | Execution | ESXi;Linux;macOS;Windows | Command Execution, Process Creation, Script Execution | 1 | P2 | Habilitadora |
| T1059.007 | JavaScript | sí | Execution | Linux;macOS;Windows | Command Execution, Module Load, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1059.008 | Network Device CLI | sí | Execution | Network Devices | Command Execution, User Account Authentication | 1 | P2 | Habilitadora |
| T1059.009 | Cloud API | sí | Execution | IaaS;Identity Provider;Office Suite;SaaS | Cloud Service Modification, Command Execution, User Account Authentication | 0 | P2 | Habilitadora |
| T1059.010 | AutoHotKey & AutoIT | sí | Execution | Windows | File Creation, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1059.011 | Lua | sí | Execution | Linux;Network Devices;Windows;macOS | Command Execution, File Creation, File Metadata, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1059.012 | Hypervisor CLI | sí | Execution | ESXi | Command Execution, User Account Authentication | 0 | P2 | Habilitadora |
| T1059.013 | Container CLI/API | sí | Execution | Containers | Command Execution, Container Creation, Container Start, Pod Creation, Process Creation | 0 | P2 | Habilitadora |
| T1068 | Exploitation for Privilege Escalation | no | Privilege Escalation | Containers;Linux;macOS;Windows | Container Enumeration, Driver Load, Logon Session Creation, Logon Session Metadata, Module Load, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1070 | Indicator Removal | no | Stealth | Containers;ESXi;Linux;macOS;Network Devices;Office Suite;Windows | Application Log Content, File Deletion, File Metadata, File Modification, Scheduled Job Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1070.003 | Clear Command History | sí | Stealth | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Deletion, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1070.004 | File Deletion | sí | Stealth | ESXi;Linux;macOS;Windows | Command Execution, File Access, File Deletion, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1070.005 | Network Share Connection Removal | sí | Stealth | Windows | Command Execution, Logon Session Creation, Process Creation | 1 | P2 | Habilitadora |
| T1070.006 | Timestomp | sí | Stealth | ESXi;Linux;macOS;Windows | Command Execution, File Access, File Metadata, File Modification, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1070.007 | Clear Network Connection History and Configurations | sí | Stealth | Linux;macOS;Windows;Network Devices | Command Execution, File Modification, Firewall Rule Modification, Process Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1070.008 | Clear Mailbox Data | sí | Stealth | Linux;macOS;Office Suite;Windows | Application Log Content, Command Execution, File Deletion, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1070.009 | Clear Persistence | sí | Stealth | ESXi;Linux;macOS;Windows | Command Execution, File Deletion, Process Creation, Scheduled Job Creation, User Account Deletion, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1070.010 | Relocate Malware | sí | Stealth | Linux;macOS;Network Devices;Windows | Command Execution, File Creation, File Deletion, File Modification | 0 | P2 | Habilitadora |
| T1071 | Application Layer Protocol | no | Command and Control | Linux;macOS;Windows;Network Devices;ESXi | Command Execution, Process Creation | 3 | P2 | Habilitadora |
| T1071.001 | Web Protocols | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Process Creation | 3 | P2 | Habilitadora |
| T1071.002 | File Transfer Protocols | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Process Creation | 3 | P2 | Habilitadora |
| T1071.003 | Mail Protocols | sí | Command and Control | Linux;macOS;Network Devices;Windows | Process Creation | 3 | P2 | Habilitadora |
| T1071.004 | DNS | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Process Creation | 3 | P2 | Habilitadora |
| T1071.005 | Publish/Subscribe Protocols | sí | Command and Control | macOS;Linux;Windows;Network Devices | Process Creation | 3 | P2 | Habilitadora |
| T1072 | Software Deployment Tools | no | Execution;Lateral Movement | Linux;macOS;Network Devices;SaaS;Windows | Application Log Content, Command Execution, Process Creation | 1 | P2 | Habilitadora |
| T1078 | Valid Accounts | no | Stealth;Persistence;Privilege Escalation;Initial Access | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | Logon Session Creation, Logon Session Metadata, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1078.001 | Default Accounts | sí | Stealth;Persistence;Privilege Escalation;Initial Access | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | Logon Session Creation, Logon Session Metadata, User Account Authentication | 0 | P2 | Habilitadora |
| T1078.002 | Domain Accounts | sí | Stealth;Persistence;Privilege Escalation;Initial Access | ESXi;Linux;macOS;Windows | Logon Session Metadata, Process Creation, User Account Authentication | 1 | P2 | Habilitadora |
| T1078.003 | Local Accounts | sí | Stealth;Persistence;Privilege Escalation;Initial Access | Containers;ESXi;Linux;macOS;Network Devices;Windows | Logon Session Creation, Logon Session Metadata, User Account Authentication | 0 | P2 | Habilitadora |
| T1078.004 | Cloud Accounts | sí | Stealth;Persistence;Privilege Escalation;Initial Access | IaaS;Identity Provider;Office Suite;SaaS | Logon Session Creation, Logon Session Metadata, User Account Authentication | 0 | P2 | Habilitadora |
| T1080 | Taint Shared Content | no | Lateral Movement | Windows;SaaS;Linux;macOS;Office Suite | File Creation, File Modification | 1 | P2 | Habilitadora |
| T1090 | Proxy | no | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Firewall Rule Modification, Process Creation | 2 | P2 | Habilitadora |
| T1090.001 | Internal Proxy | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Firewall Rule Modification, Process Creation, Service Creation | 3 | P2 | Habilitadora |
| T1090.002 | External Proxy | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Firewall Rule Modification, Process Creation | 3 | P2 | Habilitadora |
| T1090.003 | Multi-hop Proxy | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Firmware Modification, Process Creation | 3 | P2 | Habilitadora |
| T1090.004 | Domain Fronting | sí | Command and Control | Linux;macOS;Windows;ESXi | Process Creation | 2 | P2 | Habilitadora |
| T1091 | Replication Through Removable Media | no | Lateral Movement;Initial Access | Windows | Drive Creation, File Access, File Creation, Process Creation | 0 | P2 | Habilitadora |
| T1092 | Communication Through Removable Media | no | Command and Control | Linux;macOS;Windows | Drive Creation, File Creation, Process Creation | 0 | P2 | Habilitadora |
| T1098 | Account Manipulation | no | Persistence;Privilege Escalation | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | Active Directory Object Modification, File Modification, Process Creation, User Account Modification | 0 | P2 | Habilitadora |
| T1098.001 | Additional Cloud Credentials | sí | Persistence;Privilege Escalation | IaaS;Identity Provider;SaaS | Active Directory Object Creation, Active Directory Object Modification, User Account Modification | 0 | P2 | Habilitadora |
| T1098.002 | Additional Email Delegate Permissions | sí | Persistence;Privilege Escalation | Windows;Office Suite | Application Log Content, Process Creation, User Account Modification | 0 | P2 | Habilitadora |
| T1098.003 | Additional Cloud Roles | sí | Persistence;Privilege Escalation | IaaS;Identity Provider;Office Suite;SaaS | User Account Modification | 0 | P2 | Habilitadora |
| T1098.004 | SSH Authorized Keys | sí | Persistence;Privilege Escalation | ESXi;IaaS;Linux;macOS;Network Devices | Command Execution, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1098.005 | Device Registration | sí | Persistence;Privilege Escalation | Windows;Identity Provider | Active Directory Object Creation, Application Log Content, User Account Modification | 0 | P2 | Habilitadora |
| T1098.006 | Additional Container Cluster Roles | sí | Persistence;Privilege Escalation | Containers | User Account Modification | 0 | P2 | Habilitadora |
| T1098.007 | Additional Local or Domain Groups | sí | Persistence;Privilege Escalation | Windows;macOS;Linux | User Account Modification | 0 | P2 | Habilitadora |
| T1102.002 | Bidirectional Communication | sí | Command and Control | ESXi;Linux;macOS;Windows | Process Creation | 3 | P2 | Habilitadora |
| T1102.003 | One-Way Communication | sí | Command and Control | Linux;macOS;Windows;ESXi | Process Creation | 3 | P2 | Habilitadora |
| T1104 | Multi-Stage Channels | no | Command and Control | Linux;macOS;Windows;ESXi | Process Creation | 2 | P2 | Habilitadora |
| T1105 | Ingress Tool Transfer | no | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Creation, Process Creation | 2 | P2 | Habilitadora |
| T1106 | Native API | no | Execution | Linux;macOS;Windows | Module Load, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1110 | Brute Force | no | Credential Access | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | User Account Authentication | 0 | P2 | Habilitadora |
| T1110.001 | Password Guessing | sí | Credential Access | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | User Account Authentication | 0 | P2 | Habilitadora |
| T1110.002 | Password Cracking | sí | Credential Access | Identity Provider;Linux;macOS;Network Devices;Office Suite;Windows | File Access, File Creation, Process Access, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1110.003 | Password Spraying | sí | Credential Access | Containers;ESXi;IaaS;Identity Provider;Linux;Network Devices;Office Suite;SaaS;Windows;macOS | User Account Authentication | 0 | P2 | Habilitadora |
| T1110.004 | Credential Stuffing | sí | Credential Access | Containers;ESXi;IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | User Account Authentication | 0 | P2 | Habilitadora |
| T1111 | Multi-Factor Authentication Interception | no | Credential Access | Linux;macOS;Windows | Driver Load, Logon Session Creation, OS API Execution, Process Access, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1112 | Modify Registry | no | Defense Impairment;Persistence | Windows | Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1127 | Trusted Developer Utilities Proxy Execution | no | Stealth;Execution | Windows | File Creation, Module Load, Process Creation, Process Metadata | 1 | P2 | Habilitadora |
| T1127.001 | MSBuild | sí | Stealth;Execution | Windows | File Creation, Module Load, Process Access, Process Creation, Process Metadata, Process Modification, Script Execution | 1 | P2 | Habilitadora |
| T1127.002 | ClickOnce | sí | Stealth;Execution | Windows | Module Load, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1127.003 | JamPlus | sí | Stealth;Execution | Windows | File Creation, Process Creation, Process Metadata | 1 | P2 | Habilitadora |
| T1129 | Shared Modules | no | Execution | Linux;macOS;Windows | File Access, File Creation, Module Load, Process Creation, Process Metadata | 2 | P2 | Habilitadora |
| T1132 | Data Encoding | no | Command and Control | ESXi;Linux;macOS;Windows | Command Execution, Process Creation, User Account Authentication | 2 | P2 | Habilitadora |
| T1132.001 | Standard Encoding | sí | Command and Control | ESXi;Linux;macOS;Windows | Application Log Content, Process Creation, Script Execution | 3 | P2 | Habilitadora |
| T1132.002 | Non-Standard Encoding | sí | Command and Control | ESXi;Linux;macOS;Windows | Application Log Content, Process Creation, Script Execution | 3 | P2 | Habilitadora |
| T1133 | External Remote Services | no | Persistence;Initial Access | Containers;Linux;macOS;Windows | Application Log Content, Logon Session Metadata, User Account Authentication | 2 | P2 | Habilitadora |
| T1134 | Access Token Manipulation | no | Stealth;Privilege Escalation | Windows | Active Directory Object Modification, Logon Session Metadata, OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1134.001 | Token Impersonation/Theft | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1134.002 | Create Process with Token | sí | Stealth;Privilege Escalation | Windows | Active Directory Object Modification, Logon Session Metadata, OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1134.003 | Make and Impersonate Token | sí | Stealth;Privilege Escalation | Windows | Logon Session Metadata, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1134.004 | Parent PID Spoofing | sí | Stealth;Privilege Escalation | Windows | OS API Execution, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1134.005 | SID-History Injection | sí | Stealth;Privilege Escalation | Windows | Active Directory Object Modification, OS API Execution, User Account Metadata | 0 | P2 | Habilitadora |
| T1136 | Create Account | no | Persistence | Windows;IaaS;Linux;macOS;Network Devices;Containers;SaaS;Office Suite;Identity Provider;ESXi | Command Execution, File Modification, Process Creation, User Account Creation, User Account Modification | 0 | P2 | Habilitadora |
| T1136.001 | Local Account | sí | Persistence | Containers;ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Modification, Process Creation, User Account Creation | 0 | P2 | Habilitadora |
| T1136.002 | Domain Account | sí | Persistence | Linux;macOS;Windows | Command Execution, Logon Session Creation, Process Creation, User Account Authentication, User Account Creation | 0 | P2 | Habilitadora |
| T1136.003 | Cloud Account | sí | Persistence | IaaS;SaaS;Office Suite;Identity Provider | Group Modification, User Account Authentication, User Account Creation, User Account Modification | 0 | P2 | Habilitadora |
| T1137 | Office Application Startup | no | Persistence | Windows;Office Suite | Application Log Content, File Creation, Process Creation, User Account Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1137.001 | Office Template Macros | sí | Persistence | Office Suite;Windows | Command Execution, File Creation, File Metadata, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1137.002 | Office Test | sí | Persistence | Windows;Office Suite | Command Execution, File Creation, Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1137.003 | Outlook Forms | sí | Persistence | Windows;Office Suite | Application Log Content, Command Execution, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1137.004 | Outlook Home Page | sí | Persistence | Windows;Office Suite | Application Log Content, Command Execution, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1137.005 | Outlook Rules | sí | Persistence | Windows;Office Suite | Application Log Content, Command Execution, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1137.006 | Add-ins | sí | Persistence | Windows;Office Suite | Application Log Content, Command Execution, File Creation, File Modification, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1140 | Deobfuscate/Decode Files or Information | no | Stealth | ESXi;Linux;macOS;Windows | Command Execution, File Creation, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1176 | Software Extensions | no | Persistence | Linux;macOS;Windows | Command Execution, File Creation, Process Creation, Windows Registry Key Modification | 2 | P2 | Habilitadora |
| T1176.001 | Browser Extensions | sí | Persistence | Linux;Windows;macOS | Command Execution, File Access, File Creation, Process Creation, Windows Registry Key Modification | 2 | P2 | Habilitadora |
| T1176.002 | IDE Extensions | sí | Persistence | Linux;macOS;Windows | File Creation, Process Creation | 2 | P2 | Habilitadora |
| T1187 | Forced Authentication | no | Credential Access | Windows | File Creation, File Modification | 2 | P2 | Habilitadora |
| T1189 | Drive-by Compromise | no | Initial Access | Identity Provider;Linux;macOS;Windows | Application Log Content, File Creation, Logon Session Creation, Process Creation, Process Modification, User Account Authentication, User Account Metadata | 2 | P2 | Habilitadora |
| T1190 | Exploit Public-Facing Application | no | Initial Access | Containers;ESXi;IaaS;Linux;macOS;Network Devices;Windows | Application Log Content, Module Load, Process Creation | 3 | P2 | Habilitadora |
| T1195 | Supply Chain Compromise | no | Initial Access | Linux;Windows;macOS;SaaS | File Creation, File Metadata, File Modification, Module Load, Process Creation, Process Modification | 1 | P2 | Habilitadora |
| T1195.001 | Compromise Software Dependencies and Development Tools | sí | Initial Access | Linux;macOS;Windows | File Creation, File Metadata, Module Load, Process Creation, Process Modification, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1195.002 | Compromise Software Supply Chain | sí | Initial Access | Linux;Windows;macOS | Driver Load, File Creation, File Metadata, Module Load, Process Creation, Windows Registry Key Modification | 2 | P2 | Habilitadora |
| T1195.003 | Compromise Hardware Supply Chain | sí | Initial Access | Linux;macOS;Windows | Driver Load, File Metadata, Host Status, Module Load, Process Access | 0 | P2 | Habilitadora |
| T1197 | BITS Jobs | no | Stealth;Persistence;Execution | Windows | Command Execution, Process Creation, Service Creation | 1 | P2 | Habilitadora |
| T1199 | Trusted Relationship | no | Initial Access | IaaS;Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Logon Session Creation, Logon Session Metadata | 2 | P2 | Habilitadora |
| T1200 | Hardware Additions | no | Initial Access | Windows;Linux;macOS | Application Log Content, Drive Creation, Driver Load, File Creation, Module Load, Process Creation | 2 | P2 | Habilitadora |
| T1202 | Indirect Command Execution | no | Stealth | Windows | File Creation, Process Creation | 1 | P2 | Habilitadora |
| T1203 | Exploitation for Client Execution | no | Execution | Linux;macOS;Windows | Application Log Content, File Access, File Creation, File Modification, Process Creation | 2 | P2 | Habilitadora |
| T1204 | User Execution | no | Execution | Linux;Windows;macOS;IaaS;Containers | Application Log Content, Container Creation, Container Start, File Access, File Creation, File Modification, Instance Creation, Instance Start, Process Creation | 2 | P2 | Habilitadora |
| T1204.001 | Malicious Link | sí | Execution | Linux;macOS;Windows | File Creation, Process Creation | 2 | P2 | Habilitadora |
| T1204.002 | Malicious File | sí | Execution | Linux;macOS;Windows | File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1204.003 | Malicious Image | sí | Execution | IaaS;Containers | Command Execution, Container Creation, Container Start, Image Creation, Instance Creation, Instance Start, Process Creation | 1 | P2 | Habilitadora |
| T1204.004 | Malicious Copy and Paste | sí | Execution | Linux;macOS;Windows | Command Execution, File Creation, Process Creation | 2 | P2 | Habilitadora |
| T1204.005 | Malicious Library | sí | Execution | Linux;macOS;Windows | File Creation, File Metadata, Process Creation | 2 | P2 | Habilitadora |
| T1205 | Traffic Signaling | no | Stealth;Persistence;Command and Control | Linux;macOS;Network Devices;Windows | Command Execution, Process Creation | 3 | P2 | Habilitadora |
| T1205.001 | Port Knocking | sí | Stealth;Persistence;Command and Control | Linux;macOS;Network Devices;Windows | Process Creation | 2 | P2 | Habilitadora |
| T1205.002 | Socket Filters | sí | Stealth;Persistence;Command and Control | Linux;macOS;Windows | Driver Load, Module Load, Process Creation, Service Creation | 2 | P2 | Habilitadora |
| T1207 | Rogue Domain Controller | no | Defense Impairment | Windows | Active Directory Credential Request, Active Directory Object Access, Active Directory Object Creation, Active Directory Object Modification | 1 | P2 | Habilitadora |
| T1210 | Exploitation of Remote Services | no | Lateral Movement | Linux;Windows;macOS;ESXi | Application Log Content, File Creation, Module Load, Process Access, Process Creation | 2 | P2 | Habilitadora |
| T1211 | Exploitation for Stealth | no | Stealth | Linux;Windows;macOS;SaaS;IaaS | Application Log Content, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1212 | Exploitation for Credential Access | no | Credential Access | Linux;Windows;macOS;Identity Provider | Application Log Content, Process Access, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1216 | System Script Proxy Execution | no | Stealth | Windows | Command Execution, File Creation, Module Load, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1216.001 | PubPrn | sí | Stealth | Windows | Command Execution, Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1216.002 | SyncAppvPublishingServer | sí | Stealth | Windows | Command Execution, Module Load, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1218 | System Binary Proxy Execution | no | Stealth | Linux;macOS;Windows | Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1218.001 | Compiled HTML File | sí | Stealth | Windows | File Creation, Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1218.002 | Control Panel | sí | Stealth | Windows | File Creation, Module Load, Process Creation, Windows Registry Key Creation | 0 | P2 | Habilitadora |
| T1218.003 | CMSTP | sí | Stealth | Windows | Command Execution, File Creation, Process Access, Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1218.004 | InstallUtil | sí | Stealth | Windows | Command Execution, File Creation, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1218.005 | Mshta | sí | Stealth | Windows | File Creation, Process Creation | 1 | P2 | Habilitadora |
| T1218.007 | Msiexec | sí | Stealth | Windows | Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1218.008 | Odbcconf | sí | Stealth | Windows | Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1218.009 | Regsvcs/Regasm | sí | Stealth | Windows | Command Execution, File Creation, Module Load, Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1218.010 | Regsvr32 | sí | Stealth | Windows | Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1218.011 | Rundll32 | sí | Stealth | Windows | File Creation, Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1218.012 | Verclsid | sí | Stealth | Windows | Module Load, Process Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1218.013 | Mavinject | sí | Stealth | Windows | Command Execution, File Creation, Module Load, Process Access, Process Creation | 1 | P2 | Habilitadora |
| T1218.014 | MMC | sí | Stealth | Windows | Command Execution, File Creation, Module Load, OS API Execution, Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1218.015 | Electron Applications | sí | Stealth | Linux;macOS;Windows | File Creation, Module Load, Process Creation | 1 | P2 | Habilitadora |
| T1219 | Remote Access Tools | no | Command and Control | Linux;macOS;Windows | File Creation, Process Creation, Service Creation, Windows Registry Key Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1219.001 | IDE Tunneling | sí | Command and Control | Linux;macOS;Windows | File Creation, Process Creation | 1 | P2 | Habilitadora |
| T1219.002 | Remote Desktop Software | sí | Command and Control | Linux;macOS;Windows | File Creation, Firewall Rule Modification, Process Creation | 1 | P2 | Habilitadora |
| T1219.003 | Remote Access Hardware | sí | Command and Control | Linux;macOS;Windows | Drive Creation | 0 | P2 | Habilitadora |
| T1220 | XSL Script Processing | no | Stealth | Windows | Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1221 | Template Injection | no | Stealth | Windows | Process Creation | 1 | P2 | Habilitadora |
| T1222 | File and Directory Permissions Modification | no | Defense Impairment | ESXi;Linux;macOS;Windows | Active Directory Object Modification, Command Execution, File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1222.001 | Windows Permissions | sí | Defense Impairment | Windows | Active Directory Object Modification, Command Execution, File Creation, File Metadata, Process Creation, WMI Creation | 0 | P2 | Habilitadora |
| T1222.002 | Linux and Mac Permissions | sí | Defense Impairment | Linux;macOS | Command Execution, File Metadata, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1480 | Execution Guardrails | no | Stealth | ESXi;Linux;macOS;Windows | Command Execution, File Access, File Creation, Logon Session Creation, Module Load, Process Creation, Process Modification, User Account Authentication, WMI Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1480.001 | Environmental Keying | sí | Stealth | Linux;Windows;macOS | Command Execution, File Access, Logon Session Creation, Module Load, Process Access, Process Creation, WMI Creation | 1 | P2 | Habilitadora |
| T1480.002 | Mutual Exclusion | sí | Stealth | Linux;macOS;Windows | File Access, File Creation, OS API Execution, Process Creation, Process Termination | 0 | P2 | Habilitadora |
| T1484 | Domain or Tenant Policy Modification | no | Defense Impairment;Privilege Escalation | Windows;Identity Provider | Active Directory Object Modification, Application Log Content, File Modification, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1484.001 | Group Policy Modification | sí | Defense Impairment;Privilege Escalation | Windows | Active Directory Object Modification, File Creation, File Modification, Process Creation, User Account Modification | 0 | P2 | Habilitadora |
| T1484.002 | Trust Modification | sí | Defense Impairment;Privilege Escalation | Identity Provider;Windows | Active Directory Object Modification, Application Log Content, Command Execution, Process Creation, User Account Modification | 0 | P2 | Habilitadora |
| T1497 | Virtualization/Sandbox Evasion | no | Stealth;Discovery | Linux;macOS;Windows | Command Execution, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1497.001 | System Checks | sí | Stealth;Discovery | Linux;macOS;Windows | Module Load, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1497.002 | User Activity Based Checks | sí | Stealth;Discovery | Linux;macOS;Windows | Command Execution, File Access, Logon Session Metadata, OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1497.003 | Time Based Checks | sí | Stealth;Discovery | Linux;macOS;Windows | File Metadata, Module Load, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1505 | Server Software Component | no | Persistence | Windows;Linux;macOS;Network Devices;ESXi | Application Log Content, Command Execution, Process Creation, Scheduled Job Creation | 2 | P2 | Habilitadora |
| T1505.001 | SQL Stored Procedures | sí | Persistence | Windows;Linux | Module Load, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1505.002 | Transport Agent | sí | Persistence | Linux;Windows | Application Log Content, Command Execution, File Creation, File Modification, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1505.003 | Web Shell | sí | Persistence | Linux;macOS;Network Devices;Windows | File Creation, File Modification, Logon Session Creation, Process Creation | 1 | P2 | Habilitadora |
| T1505.004 | IIS Components | sí | Persistence | Windows | Application Log Content, File Creation, File Modification, Module Load, Process Creation, Service Modification | 0 | P2 | Habilitadora |
| T1505.005 | Terminal Services DLL | sí | Persistence | Windows | File Creation, Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1505.006 | vSphere Installation Bundles | sí | Persistence | ESXi | Application Log Content, Command Execution, File Modification | 0 | P2 | Habilitadora |
| T1525 | Implant Internal Image | no | Persistence | IaaS;Containers | Image Creation, Image Modification, Instance Start | 0 | P2 | Habilitadora |
| T1528 | Steal Application Access Token | no | Credential Access | Containers;IaaS;Identity Provider;Office Suite;SaaS | Application Log Content, Cloud Service Enumeration, Cloud Service Modification, Cloud Storage Access, File Access, User Account Authentication | 0 | P2 | Habilitadora |
| T1534 | Internal Spearphishing | no | Lateral Movement | Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Command Execution, Logon Session Creation, Logon Session Metadata, Process Creation, User Account Authentication | 1 | P2 | Habilitadora |
| T1535 | Unused/Unsupported Cloud Regions | no | Stealth | IaaS | Cloud Storage Creation, Instance Start, User Account Metadata | 1 | P2 | Habilitadora |
| T1539 | Steal Web Session Cookie | no | Credential Access | Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, File Access, File Modification, Logon Session Creation, Process Access, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1542 | Pre-OS Boot | no | Stealth;Persistence | Linux;macOS;Network Devices;Windows | Command Execution, Drive Access, Drive Modification, File Creation, File Modification, Firmware Modification, Process Creation | 0 | P2 | Habilitadora |
| T1542.001 | System Firmware | sí | Stealth;Persistence | Network Devices;Windows | Drive Access, Drive Modification, File Creation, Firmware Modification, Process Creation | 0 | P2 | Habilitadora |
| T1542.002 | Component Firmware | sí | Stealth;Persistence | Windows;Linux;macOS | Driver Load, Firmware Modification | 0 | P2 | Habilitadora |
| T1542.003 | Bootkit | sí | Stealth;Persistence | Linux;Windows | Drive Access, Drive Modification, File Creation, File Modification | 0 | P2 | Habilitadora |
| T1542.004 | ROMMONkit | sí | Stealth;Persistence | Network Devices | Firmware Modification, OS API Execution | 1 | P2 | Habilitadora |
| T1542.005 | TFTP Boot | sí | Stealth;Persistence | Network Devices | Command Execution, Firmware Modification | 1 | P2 | Habilitadora |
| T1543 | Create or Modify System Process | no | Persistence;Privilege Escalation | Containers;Linux;macOS;Windows | Command Execution, Container Creation, File Modification, Process Creation, Service Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1543.001 | Launch Agent | sí | Persistence;Privilege Escalation | macOS | Command Execution, File Creation, File Modification, Service Creation | 0 | P2 | Habilitadora |
| T1543.002 | Systemd Service | sí | Persistence;Privilege Escalation | Linux | Command Execution, File Creation, File Modification, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1543.003 | Windows Service | sí | Persistence;Privilege Escalation | Windows | Driver Load, Process Creation, Service Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1543.004 | Launch Daemon | sí | Persistence;Privilege Escalation | macOS | File Creation, File Modification, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1543.005 | Container Service | sí | Persistence;Privilege Escalation | Containers | Container Creation, Pod Creation, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1546 | Event Triggered Execution | no | Privilege Escalation;Persistence | Linux;macOS;Windows;SaaS;IaaS;Office Suite | Cloud Service Modification, Command Execution, File Metadata, File Modification, Process Creation, Scheduled Job Creation, Script Execution, WMI Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1546.001 | Change Default File Association | sí | Privilege Escalation;Persistence | Windows | Logon Session Metadata, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.002 | Screensaver | sí | Privilege Escalation;Persistence | Windows | Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.003 | Windows Management Instrumentation Event Subscription | sí | Privilege Escalation;Persistence | Windows | Module Load, Process Creation, WMI Creation | 0 | P2 | Habilitadora |
| T1546.004 | Unix Shell Configuration Modification | sí | Privilege Escalation;Persistence | Linux;macOS | File Modification, Process Creation | 1 | P2 | Habilitadora |
| T1546.005 | Trap | sí | Privilege Escalation;Persistence | macOS;Linux | File Access, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1546.006 | LC_LOAD_DYLIB Addition | sí | Privilege Escalation;Persistence | macOS | File Metadata, File Modification, Module Load | 0 | P2 | Habilitadora |
| T1546.007 | Netsh Helper DLL | sí | Privilege Escalation;Persistence | Windows | Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.008 | Accessibility Features | sí | Privilege Escalation;Persistence | Windows | File Creation, File Metadata, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.009 | AppCert DLLs | sí | Privilege Escalation;Persistence | Windows | Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.010 | AppInit DLLs | sí | Privilege Escalation;Persistence | Windows | Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.011 | Application Shimming | sí | Privilege Escalation;Persistence | Windows | File Creation, Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.012 | Image File Execution Options Injection | sí | Privilege Escalation;Persistence | Windows | Process Access, Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.013 | PowerShell Profile | sí | Privilege Escalation;Persistence | Windows | Command Execution, File Creation, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1546.014 | Emond | sí | Privilege Escalation;Persistence | macOS | Command Execution, File Creation, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1546.015 | Component Object Model Hijacking | sí | Privilege Escalation;Persistence | Windows | Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1546.016 | Installer Packages | sí | Privilege Escalation;Persistence | Linux;macOS;Windows | File Creation, Process Creation | 0 | P2 | Habilitadora |
| T1546.017 | Udev Rules | sí | Persistence;Privilege Escalation | Linux | Command Execution, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1546.018 | Python Startup Hooks | sí | Persistence;Privilege Escalation | Linux;macOS;Windows | File Metadata, File Modification, Process Creation | 1 | P2 | Habilitadora |
| T1547 | Boot or Logon Autostart Execution | no | Persistence;Privilege Escalation | Linux;macOS;Windows;Network Devices | File Creation, File Modification, Process Creation, Service Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.001 | Registry Run Keys / Startup Folder | sí | Persistence;Privilege Escalation | Windows | File Creation, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.002 | Authentication Package | sí | Persistence;Privilege Escalation | Windows | Module Load, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.003 | Time Providers | sí | Persistence;Privilege Escalation | Windows | File Creation, Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.004 | Winlogon Helper DLL | sí | Persistence;Privilege Escalation | Windows | Module Load, Process Creation, Windows Registry Key Access, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.005 | Security Support Provider | sí | Persistence;Privilege Escalation | Windows | Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.006 | Kernel Modules and Extensions | sí | Persistence;Privilege Escalation | macOS;Linux | Command Execution, File Creation, File Modification, Kernel Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1547.007 | Re-opened Applications | sí | Persistence;Privilege Escalation | macOS | File Metadata, File Modification, Logon Session Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1547.008 | LSASS Driver | sí | Persistence;Privilege Escalation | Windows | Driver Load, File Creation, File Modification, Module Load, Windows Registry Key Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.009 | Shortcut Modification | sí | Persistence;Privilege Escalation | Windows | File Creation, File Metadata, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1547.010 | Port Monitors | sí | Persistence;Privilege Escalation | Windows | File Creation, Module Load, OS API Execution, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.012 | Print Processors | sí | Persistence;Privilege Escalation | Windows | File Creation, Module Load, Process Access, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.013 | XDG Autostart Entries | sí | Persistence;Privilege Escalation | Linux | File Access, File Creation, File Metadata, Logon Session Creation, Process Creation | 0 | P2 | Habilitadora |
| T1547.014 | Active Setup | sí | Persistence;Privilege Escalation | Windows | Logon Session Metadata, Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1547.015 | Login Items | sí | Persistence;Privilege Escalation | macOS | File Modification, OS API Execution, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1548 | Abuse Elevation Control Mechanism | no | Privilege Escalation | Linux;macOS;Windows;IaaS;Office Suite;Identity Provider | File Metadata, Logon Session Metadata, OS API Execution, Process Creation, Process Metadata, User Account Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1548.001 | Setuid and Setgid | sí | Privilege Escalation | Linux;macOS | Command Execution, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1548.002 | Bypass User Account Control | sí | Privilege Escalation | Windows | Logon Session Metadata, Module Load, Process Access, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1548.003 | Sudo and Sudo Caching | sí | Privilege Escalation | Linux;macOS | Command Execution, File Modification, Process Metadata, Process Termination | 0 | P2 | Habilitadora |
| T1548.004 | Elevated Execution with Prompt | sí | Privilege Escalation | macOS | OS API Execution, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1548.005 | Temporary Elevated Cloud Access | sí | Privilege Escalation | IaaS;Office Suite;Identity Provider | Application Log Content, User Account Authentication, User Account Metadata | 0 | P2 | Habilitadora |
| T1548.006 | TCC Manipulation | sí | Privilege Escalation | macOS | Command Execution, File Modification, Host Status, Process Creation | 0 | P2 | Habilitadora |
| T1550 | Use Alternate Authentication Material | no | Lateral Movement | Containers;IaaS;Identity Provider;Linux;Office Suite;SaaS;Windows | Application Log Content, Logon Session Creation, Process Creation, User Account Authentication, User Account Metadata, Web Credential Usage | 0 | P2 | Habilitadora |
| T1550.001 | Application Access Token | sí | Lateral Movement | Containers;IaaS;Identity Provider;Office Suite;SaaS | User Account Authentication, Web Credential Usage | 0 | P2 | Habilitadora |
| T1550.002 | Pass the Hash | sí | Lateral Movement | Windows | Active Directory Credential Request, Logon Session Creation, Process Creation | 1 | P2 | Habilitadora |
| T1550.003 | Pass the Ticket | sí | Lateral Movement | Windows | Active Directory Credential Request, Logon Session Creation, Module Load, Process Access, User Account Authentication | 0 | P2 | Habilitadora |
| T1550.004 | Web Session Cookie | sí | Lateral Movement | IaaS;Office Suite;SaaS | Logon Session Creation, User Account Authentication, Web Credential Usage | 0 | P2 | Habilitadora |
| T1552 | Unsecured Credentials | no | Credential Access | Windows;SaaS;IaaS;Linux;macOS;Containers;Network Devices;Office Suite;Identity Provider | Application Log Content, Cloud Service Metadata, Command Execution, File Access, File Creation, Process Creation, User Account Authentication, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1552.001 | Credentials In Files | sí | Credential Access | Containers;IaaS;Linux;macOS;Windows | Command Execution, File Access, File Creation, Logon Session Creation, Process Creation | 1 | P2 | Habilitadora |
| T1552.002 | Credentials in Registry | sí | Credential Access | Windows | Process Creation, Windows Registry Key Access, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1552.003 | Shell History | sí | Credential Access | Linux;macOS;Windows | File Access, File Creation, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1552.004 | Private Keys | sí | Credential Access | Linux;macOS;Network Devices;Windows | Command Execution, File Access, File Creation, Process Creation | 1 | P2 | Habilitadora |
| T1552.005 | Cloud Instance Metadata API | sí | Credential Access | IaaS | Cloud Service Metadata | 2 | P2 | Habilitadora |
| T1552.006 | Group Policy Preferences | sí | Credential Access | Windows | File Creation, Process Creation, Script Execution | 1 | P2 | Habilitadora |
| T1552.007 | Container API | sí | Credential Access | Containers | Application Log Content, Command Execution, Process Creation, User Account Authentication | 0 | P2 | Habilitadora |
| T1552.008 | Chat Messages | sí | Credential Access | SaaS;Office Suite | Application Log Content, User Account Authentication | 0 | P2 | Habilitadora |
| T1553 | Subvert Trust Controls | no | Defense Impairment | Linux;macOS;Windows | Command Execution, File Creation, File Metadata, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1553.001 | Gatekeeper Bypass | sí | Defense Impairment | macOS | File Metadata, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1553.002 | Code Signing | sí | Defense Impairment | macOS;Windows | File Metadata, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1553.003 | SIP and Trust Provider Hijacking | sí | Defense Impairment | Windows | File Modification, Module Load, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1553.004 | Install Root Certificate | sí | Defense Impairment | Linux;macOS;Windows | Command Execution, File Modification, Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1553.005 | Mark-of-the-Web Bypass | sí | Defense Impairment | Windows | File Access, File Creation, File Metadata | 0 | P2 | Habilitadora |
| T1553.006 | Code Signing Policy Modification | sí | Defense Impairment | macOS;Windows | Command Execution, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1554 | Compromise Host Software Binary | no | Persistence | ESXi;Linux;macOS;Windows | File Creation, File Modification, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1555 | Credentials from Password Stores | no | Credential Access | IaaS;Linux;macOS;Windows | Cloud Service Enumeration, File Access, OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1555.001 | Keychain | sí | Credential Access | macOS | File Access, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1555.002 | Securityd Memory | sí | Credential Access | Linux;macOS | Command Execution, File Access, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1555.003 | Credentials from Web Browsers | sí | Credential Access | Linux;macOS;Windows | File Access, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1555.004 | Windows Credential Manager | sí | Credential Access | Windows | File Metadata, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1555.005 | Password Managers | sí | Credential Access | Linux;macOS;Windows | File Access, File Metadata, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1555.006 | Cloud Secrets Management Stores | sí | Credential Access | IaaS | Cloud Service Enumeration | 0 | P2 | Habilitadora |
| T1556 | Modify Authentication Process | no | Defense Impairment;Persistence;Credential Access | IaaS;Identity Provider;Linux;macOS;Network Devices;Office Suite;SaaS;Windows | Cloud Service Modification, File Modification, Module Load, Process Access, Process Creation, User Account Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1556.001 | Domain Controller Authentication | sí | Defense Impairment;Persistence;Credential Access | Windows | File Modification, Logon Session Creation, Module Load, Process Access | 0 | P2 | Habilitadora |
| T1556.002 | Password Filter DLL | sí | Defense Impairment;Persistence;Credential Access | Windows | File Creation, Module Load, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1556.003 | Pluggable Authentication Modules | sí | Defense Impairment;Persistence;Credential Access | Linux;macOS | File Modification, Logon Session Creation, Process Creation | 0 | P2 | Habilitadora |
| T1556.004 | Network Device Authentication | sí | Defense Impairment;Persistence;Credential Access | Network Devices | File Modification, User Account Authentication | 0 | P2 | Habilitadora |
| T1556.005 | Reversible Encryption | sí | Defense Impairment;Persistence;Credential Access | Windows | Active Directory Object Modification, Command Execution, Process Creation | 0 | P2 | Habilitadora |
| T1556.006 | Multi-Factor Authentication | sí | Defense Impairment;Persistence;Credential Access | IaaS;Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | Active Directory Object Modification, Application Log Content, Cloud Service Modification, File Modification, Script Execution, User Account Authentication, User Account Modification | 0 | P2 | Habilitadora |
| T1556.007 | Hybrid Identity | sí | Defense Impairment;Persistence;Credential Access | IaaS;Identity Provider;Office Suite;SaaS;Windows | Active Directory Object Modification, Application Log Content, Cloud Service Modification, Logon Session Creation, Module Load, User Account Modification | 0 | P2 | Habilitadora |
| T1556.008 | Network Provider DLL | sí | Defense Impairment;Persistence;Credential Access | Windows | File Creation, Module Load, Process Access, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1556.009 | Conditional Access Policies | sí | Defense Impairment;Persistence;Credential Access | IaaS;Identity Provider | Active Directory Object Modification, Application Log Content, Cloud Service Modification | 0 | P2 | Habilitadora |
| T1558 | Steal or Forge Kerberos Tickets | no | Credential Access | Linux;macOS;Windows | Active Directory Credential Request, File Access, Logon Session Metadata, Process Access | 0 | P2 | Habilitadora |
| T1558.001 | Golden Ticket | sí | Credential Access | Windows | Active Directory Credential Request, Logon Session Metadata, Process Access | 0 | P2 | Habilitadora |
| T1558.002 | Silver Ticket | sí | Credential Access | Windows | Active Directory Credential Request, Logon Session Metadata, Process Access | 0 | P2 | Habilitadora |
| T1558.003 | Kerberoasting | sí | Credential Access | Windows | Active Directory Credential Request, Logon Session Creation, Logon Session Metadata, Process Access | 0 | P2 | Habilitadora |
| T1558.004 | AS-REP Roasting | sí | Credential Access | Windows | Active Directory Credential Request, Process Creation | 0 | P2 | Habilitadora |
| T1558.005 | Ccache Files | sí | Credential Access | Linux;macOS | File Access, Process Creation | 0 | P2 | Habilitadora |
| T1559 | Inter-Process Communication | no | Execution | Linux;macOS;Windows | File Access, Named Pipe Metadata, Process Access, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1559.001 | Component Object Model | sí | Execution | Windows | Module Load, Process Creation, Windows Registry Key Access | 0 | P2 | Habilitadora |
| T1559.002 | Dynamic Data Exchange | sí | Execution | Windows | Module Load, Process Creation, Windows Registry Key Access | 0 | P2 | Habilitadora |
| T1559.003 | XPC Services | sí | Execution | macOS | Named Pipe Metadata, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1563 | Remote Service Session Hijacking | no | Lateral Movement | Linux;macOS;Windows | Command Execution, Logon Session Creation, Process Creation | 3 | P2 | Habilitadora |
| T1563.001 | SSH Hijacking | sí | Lateral Movement | Linux;macOS | Logon Session Creation, Process Creation, Process Metadata | 1 | P2 | Habilitadora |
| T1563.002 | RDP Hijacking | sí | Lateral Movement | Windows | Logon Session Creation, Process Creation, Service Creation | 1 | P2 | Habilitadora |
| T1564 | Hide Artifacts | no | Stealth | ESXi;Linux;macOS;Office Suite;Windows | Application Log Content, Command Execution, File Creation, File Metadata, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1564.001 | Hidden Files and Directories | sí | Stealth | Linux;macOS;Windows | Command Execution, File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1564.002 | Hidden Users | sí | Stealth | Linux;macOS;Windows | Command Execution, File Modification, User Account Creation, User Account Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1564.003 | Hidden Window | sí | Stealth | Linux;macOS;Windows | Command Execution, File Modification, Process Creation, Process Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1564.004 | NTFS File Attributes | sí | Stealth | Windows | File Creation, File Metadata, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1564.005 | Hidden File System | sí | Stealth | Linux;macOS;Windows | Command Execution, File Modification, Firmware Modification, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1564.006 | Run Virtual Instance | sí | Stealth | ESXi;Linux;macOS;Windows | Command Execution, File Creation, File Modification, Image Metadata, Process Creation, Service Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1564.007 | VBA Stomping | sí | Stealth | Linux;macOS;Windows | File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1564.008 | Email Hiding Rules | sí | Stealth | Windows;Linux;macOS;Office Suite | Application Log Content, Command Execution, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1564.009 | Resource Forking | sí | Stealth | macOS | Command Execution, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1564.010 | Process Argument Spoofing | sí | Stealth | Windows | Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1564.011 | Ignore Process Interrupts | sí | Stealth | Linux;macOS;Windows | Command Execution, Process Creation | 0 | P2 | Habilitadora |
| T1564.012 | File/Path Exclusions | sí | Stealth | Linux;macOS;Windows | File Access, File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1564.013 | Bind Mounts | sí | Stealth | Linux | File Creation, OS API Execution, Process Metadata | 0 | P2 | Habilitadora |
| T1564.014 | Extended Attributes | sí | Stealth | Linux;macOS | Command Execution, File Metadata | 0 | P2 | Habilitadora |
| T1566 | Phishing | no | Initial Access | Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, File Creation, Logon Session Creation, Process Creation | 0 | P2 | Habilitadora |
| T1566.001 | Spearphishing Attachment | sí | Initial Access | Linux;macOS;Windows | Application Log Content, File Creation, Process Creation | 2 | P2 | Habilitadora |
| T1566.002 | Spearphishing Link | sí | Initial Access | Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Process Creation | 3 | P2 | Habilitadora |
| T1566.003 | Spearphishing via Service | sí | Initial Access | Linux;macOS;Windows | Application Log Content, File Creation, Process Creation | 3 | P2 | Habilitadora |
| T1566.004 | Spearphishing Voice | sí | Initial Access | Linux;macOS;Windows;Identity Provider | Application Log Content | 0 | P2 | Habilitadora |
| T1568 | Dynamic Resolution | no | Command and Control | ESXi;Linux;macOS;Windows | Process Creation | 3 | P2 | Habilitadora |
| T1568.001 | Fast Flux DNS | sí | Command and Control | Linux;macOS;Windows;ESXi | Process Creation | 2 | P2 | Habilitadora |
| T1568.002 | Domain Generation Algorithms | sí | Command and Control | ESXi;Linux;macOS;Windows | Process Creation | 3 | P2 | Habilitadora |
| T1568.003 | DNS Calculation | sí | Command and Control | ESXi;Linux;macOS;Windows | Process Creation | 3 | P2 | Habilitadora |
| T1569 | System Services | no | Execution | Windows;macOS;Linux | File Modification, Process Creation, Service Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1569.001 | Launchctl | sí | Execution | macOS | Command Execution, File Modification, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1569.002 | Service Execution | sí | Execution | Windows | Process Creation, Service Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1569.003 | Systemctl | sí | Execution | Linux | Command Execution, File Modification, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1570 | Lateral Tool Transfer | no | Lateral Movement | ESXi;Linux;macOS;Windows | Command Execution, File Creation, File Metadata, Process Creation | 1 | P2 | Habilitadora |
| T1571 | Non-Standard Port | no | Command and Control | ESXi;Linux;macOS;Windows | Application Log Content, Process Creation | 3 | P2 | Habilitadora |
| T1572 | Protocol Tunneling | no | Command and Control | ESXi;Linux;macOS;Windows | Application Log Content, Process Creation | 3 | P2 | Habilitadora |
| T1573 | Encrypted Channel | no | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Application Log Content, Module Load, Process Creation | 3 | P2 | Habilitadora |
| T1573.001 | Symmetric Cryptography | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Application Log Content, Module Load, Process Creation | 3 | P2 | Habilitadora |
| T1573.002 | Asymmetric Cryptography | sí | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Application Log Content, Module Load, Process Creation | 3 | P2 | Habilitadora |
| T1574 | Hijack Execution Flow | no | Stealth;Execution | Linux;macOS;Windows | File Creation, File Modification, Module Load, Process Creation, Service Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1574.001 | DLL | sí | Stealth;Execution | Windows | File Creation, File Metadata, Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1574.004 | Dylib Hijacking | sí | Stealth;Execution | macOS | File Creation, File Modification, Module Load | 0 | P2 | Habilitadora |
| T1574.005 | Executable Installer File Permissions Weakness | sí | Stealth;Execution | Windows | File Creation, File Metadata, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1574.006 | Dynamic Linker Hijacking | sí | Stealth;Execution | Linux;macOS | File Creation, File Modification, Module Load, Process Creation, Process Metadata | 0 | P2 | Habilitadora |
| T1574.007 | Path Interception by PATH Environment Variable | sí | Stealth;Execution | Linux;macOS;Windows | File Creation, File Modification, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1574.008 | Path Interception by Search Order Hijacking | sí | Stealth;Execution | Windows | File Creation, File Metadata, Process Creation | 0 | P2 | Habilitadora |
| T1574.009 | Path Interception by Unquoted Path | sí | Stealth;Execution | Windows | File Creation, File Metadata, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1574.010 | Services File Permissions Weakness | sí | Stealth;Execution | Windows | File Creation, File Metadata, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1574.011 | Services Registry Permissions Weakness | sí | Stealth;Execution | Windows | Process Creation, Service Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1574.012 | COR_PROFILER | sí | Stealth;Execution | Windows | File Creation, Module Load, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1574.013 | KernelCallbackTable | sí | Stealth;Execution | Windows | OS API Execution, Process Access, Process Creation | 0 | P2 | Habilitadora |
| T1574.014 | AppDomainManager | sí | Stealth;Execution | Windows | File Creation, Module Load, Process Creation | 0 | P2 | Habilitadora |
| T1578 | Modify Cloud Compute Infrastructure | no | Defense Impairment | IaaS | Cloud Service Metadata, Instance Start, Instance Stop, Snapshot Creation, Snapshot Deletion, Snapshot Modification, Volume Creation, Volume Deletion, Volume Modification | 0 | P2 | Habilitadora |
| T1578.001 | Create Snapshot | sí | Defense Impairment | IaaS | Snapshot Creation, Snapshot Metadata | 0 | P2 | Habilitadora |
| T1578.002 | Create Cloud Instance | sí | Defense Impairment | IaaS | Instance Creation, Instance Metadata, Instance Start | 0 | P2 | Habilitadora |
| T1578.003 | Delete Cloud Instance | sí | Defense Impairment | IaaS | Instance Deletion, Instance Metadata, Instance Stop | 0 | P2 | Habilitadora |
| T1578.004 | Revert Cloud Instance | sí | Defense Impairment | IaaS | Instance Modification, Instance Start, Instance Stop | 0 | P2 | Habilitadora |
| T1578.005 | Modify Cloud Compute Configurations | sí | Defense Impairment | IaaS | Cloud Service Modification | 0 | P2 | Habilitadora |
| T1600 | Weaken Encryption | no | Defense Impairment | Network Devices | File Modification, Module Load | 1 | P2 | Habilitadora |
| T1600.001 | Reduce Key Space | sí | Defense Impairment | Network Devices | Command Execution, File Modification | 1 | P2 | Habilitadora |
| T1600.002 | Disable Crypto Hardware | sí | Defense Impairment | Network Devices | Command Execution, File Modification | 1 | P2 | Habilitadora |
| T1601 | Modify System Image | no | Defense Impairment | Network Devices | Command Execution, File Modification | 0 | P2 | Habilitadora |
| T1601.001 | Patch System Image | sí | Defense Impairment | Network Devices | Command Execution, File Modification, Firmware Modification | 0 | P2 | Habilitadora |
| T1601.002 | Downgrade System Image | sí | Defense Impairment | Network Devices | Command Execution, File Metadata, File Modification | 0 | P2 | Habilitadora |
| T1606 | Forge Web Credentials | no | Credential Access | SaaS;Windows;macOS;Linux;IaaS;Office Suite;Identity Provider | File Access, Logon Session Creation, Process Access, Web Credential Creation, Web Credential Usage | 1 | P2 | Habilitadora |
| T1606.001 | Web Cookies | sí | Credential Access | Linux;macOS;Windows;SaaS;IaaS | File Access, File Creation, Logon Session Creation, Web Credential Usage | 1 | P2 | Habilitadora |
| T1606.002 | SAML Tokens | sí | Credential Access | SaaS;Windows;IaaS;Office Suite;Identity Provider | Logon Session Creation, Logon Session Metadata, User Account Authentication, Web Credential Creation, Web Credential Usage | 0 | P2 | Habilitadora |
| T1609 | Container Administration Command | no | Execution | Containers | Command Execution, Process Creation | 0 | P2 | Habilitadora |
| T1610 | Deploy Container | no | Execution | Containers | Application Log Content, Container Start, Process Creation | 1 | P2 | Habilitadora |
| T1611 | Escape to Host | no | Privilege Escalation | Windows;Linux;Containers;ESXi | Container Creation, File Creation, Kernel Module Load, OS API Execution, Process Creation, Volume Modification | 0 | P2 | Habilitadora |
| T1612 | Build Image on Host | no | Stealth | Containers | Image Creation | 1 | P2 | Habilitadora |
| T1620 | Reflective Code Loading | no | Stealth | Linux;macOS;Windows | Module Load, OS API Execution, Process Access, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1621 | Multi-Factor Authentication Request Generation | no | Credential Access | Windows;Linux;macOS;IaaS;SaaS;Office Suite;Identity Provider | Application Log Content, Logon Session Metadata, User Account Authentication | 0 | P2 | Habilitadora |
| T1622 | Debugger Evasion | no | Stealth;Discovery | Linux;macOS;Windows | File Access, OS API Execution, Process Creation | 0 | P2 | Habilitadora |
| T1647 | Plist File Modification | no | Defense Impairment | macOS | Command Execution, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1648 | Serverless Execution | no | Execution | SaaS;IaaS;Office Suite | Application Log Content, Cloud Service Modification | 0 | P2 | Habilitadora |
| T1649 | Steal or Forge Authentication Certificates | no | Credential Access | Windows;Linux;macOS;Identity Provider | Active Directory Credential Request, Active Directory Object Modification, Application Log Content, Command Execution, File Access, Windows Registry Key Access | 0 | P2 | Habilitadora |
| T1651 | Cloud Administration Command | no | Execution | IaaS | Command Execution, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1653 | Power Settings | no | Persistence | Windows;Linux;macOS;Network Devices | Command Execution, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1659 | Content Injection | no | Initial Access;Command and Control | Linux;macOS;Windows | Command Execution, File Creation, Process Creation | 1 | P2 | Habilitadora |
| T1665 | Hide Infrastructure | no | Command and Control | ESXi;Linux;macOS;Network Devices;Windows | Domain Registration, Process Creation | 4 | P2 | Habilitadora |
| T1666 | Modify Cloud Resource Hierarchy | no | Defense Impairment | IaaS | Cloud Service Modification | 0 | P2 | Habilitadora |
| T1668 | Exclusive Control | no | Persistence | Linux;macOS;Windows | Command Execution, Process Creation, Process Termination | 0 | P2 | Habilitadora |
| T1669 | Wi-Fi Networks | no | Initial Access | Linux;Network Devices;Windows;macOS | Firewall Rule Modification, User Account Authentication | 3 | P2 | Habilitadora |
| T1671 | Cloud Application Integration | no | Persistence | Office Suite;SaaS | Active Directory Object Modification, Application Log Content, Cloud Service Modification | 0 | P2 | Habilitadora |
| T1674 | Input Injection | no | Execution | Windows;macOS;Linux | Command Execution, Drive Creation, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1675 | ESXi Administration Command | no | Execution | ESXi | Application Log Content | 0 | P2 | Habilitadora |
| T1677 | Poisoned Pipeline Execution | no | Execution | SaaS | Cloud Service Metadata, Cloud Service Modification, Cloud Storage Access, Command Execution, File Metadata | 0 | P2 | Habilitadora |
| T1678 | Delay Execution | no | Stealth | Linux;macOS;Windows | Module Load, Process Creation, Script Execution | 0 | P2 | Habilitadora |
| T1679 | Selective Exclusion | no | Stealth | Windows | Command Execution, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1684 | Social Engineering | no | Stealth | Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Command Execution, File Access, File Creation, File Modification, Logon Session Creation, Process Creation, User Account Authentication | 1 | P2 | Habilitadora |
| T1684.001 | Impersonation | sí | Stealth | Linux;macOS;Office Suite;SaaS;Windows | Application Log Content, Command Execution, Logon Session Creation | 0 | P2 | Habilitadora |
| T1684.002 | Email Spoofing | sí | Stealth | Linux;macOS;Office Suite;Windows | Application Log Content | 0 | P2 | Habilitadora |
| T1685 | Disable or Modify Tools | no | Defense Impairment | Containers;ESXi;IaaS;Linux;macOS;Network Devices;Windows | Cloud Service Modification, Command Execution, Host Status, Process Creation, Process Termination, Service Creation, Service Metadata, Service Modification, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1685.001 | Disable or Modify Windows Event Log | sí | Defense Impairment | Windows | Application Log Content, Process Creation, Service Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1685.002 | Disable or Modify Cloud Log | sí | Defense Impairment | IaaS;SaaS;Identity Provider;Office Suite | Cloud Service Disable, Cloud Service Modification, User Account Modification | 0 | P2 | Habilitadora |
| T1685.003 | Modify or Spoof Tool UI | sí | Defense Impairment | Linux;macOS;Windows | Host Status, Process Creation, Service Creation | 0 | P2 | Habilitadora |
| T1685.004 | Disable or Modify Linux Audit System Log | sí | Defense Impairment | Linux | Command Execution, File Modification, Process Modification, Service Metadata | 0 | P2 | Habilitadora |
| T1685.005 | Clear Windows Event Logs | sí | Defense Impairment | Windows | Application Log Content, File Deletion, Process Creation | 0 | P2 | Habilitadora |
| T1685.006 | Clear Linux or Mac System Logs | sí | Defense Impairment | Linux;macOS | File Deletion, File Modification, Process Creation | 0 | P2 | Habilitadora |
| T1686 | Disable or Modify System Firewall | no | Defense Impairment | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Firewall Rule Modification, Process Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1686.001 | Cloud Firewall | sí | Defense Impairment | IaaS | Firewall Disable, Firewall Rule Modification | 0 | P2 | Habilitadora |
| T1686.002 | Network Device Firewall | sí | Defense Impairment | Network Devices | Command Execution, Firewall Rule Modification, Logon Session Creation | 1 | P2 | Habilitadora |
| T1686.003 | Windows Host Firewall | sí | Defense Impairment | Windows | Process Creation, Service Creation, Windows Registry Key Creation, Windows Registry Key Modification | 1 | P2 | Habilitadora |
| T1687 | Exploitation for Defense Impairment | no | Defense Impairment | IaaS;Linux;macOS;SaaS;Windows | Application Log Content, Cloud Service Disable, Command Execution, Driver Load, Driver Metadata, Firewall Rule Modification, Instance Modification, Process Creation, Process Metadata, Service Metadata | 1 | P2 | Habilitadora |
| T1688 | Safe Mode Boot | no | Defense Impairment | Windows | Process Creation, Windows Registry Key Creation, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1689 | Downgrade Attack | no | Defense Impairment | macOS;Windows;Linux | Command Execution, Process Creation, Process Metadata, Windows Registry Key Modification | 0 | P2 | Habilitadora |
| T1690 | Prevent Command History Logging | no | Defense Impairment | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Process Creation | 0 | P2 | Habilitadora |

### P3 — Resto host-eligible

| ID | Nombre | Subtéc. | Tácticas | Plataformas | DC host | DC red | Prio | Justificación R/E/S |
|---|---|---|---|---|---|---|---|---|
| T1007 | System Service Discovery | no | Discovery | Linux;macOS;Windows | Command Execution, Process Creation | 0 | P3 | Otras técnicas host |
| T1010 | Application Window Discovery | no | Discovery | Linux;macOS;Windows | Command Execution, OS API Execution, Process Access, Process Creation | 0 | P3 | Otras técnicas host |
| T1012 | Query Registry | no | Discovery | Windows | Command Execution, Process Creation, Windows Registry Key Modification | 0 | P3 | Otras técnicas host |
| T1016 | System Network Configuration Discovery | no | Discovery | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, Process Creation | 0 | P3 | Otras técnicas host |
| T1016.001 | Internet Connection Discovery | sí | Discovery | Windows;Linux;macOS;ESXi | Command Execution, Process Creation, Script Execution | 1 | P3 | Otras técnicas host |
| T1016.002 | Wi-Fi Discovery | sí | Discovery | Linux;Windows;macOS | Command Execution, File Access, Process Creation | 0 | P3 | Otras técnicas host |
| T1018 | Remote System Discovery | no | Discovery | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Access, Process Creation | 1 | P3 | Otras técnicas host |
| T1033 | System Owner/User Discovery | no | Discovery | Linux;macOS;Network Devices;Windows | Command Execution, OS API Execution, Process Creation | 0 | P3 | Otras técnicas host |
| T1046 | Network Service Discovery | no | Discovery | Containers;IaaS;Linux;macOS;Network Devices;Windows | Process Creation | 3 | P3 | Otras técnicas host |
| T1049 | System Network Connections Discovery | no | Discovery | ESXi;IaaS;Linux;macOS;Network Devices;Windows | Command Execution, OS API Execution, Process Creation | 1 | P3 | Otras técnicas host |
| T1057 | Process Discovery | no | Discovery | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Access, Process Access, Process Creation, Process Metadata | 0 | P3 | Otras técnicas host |
| T1069 | Permission Groups Discovery | no | Discovery | Containers;IaaS;Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | Command Execution, Process Creation | 0 | P3 | Otras técnicas host |
| T1069.001 | Local Groups | sí | Discovery | Linux;macOS;Windows | Process Creation | 0 | P3 | Otras técnicas host |
| T1069.002 | Domain Groups | sí | Discovery | Linux;macOS;Windows | Command Execution, Process Creation | 1 | P3 | Otras técnicas host |
| T1069.003 | Cloud Groups | sí | Discovery | SaaS;IaaS;Office Suite;Identity Provider | Command Execution, Group Enumeration, Group Metadata | 0 | P3 | Otras técnicas host |
| T1082 | System Information Discovery | no | Discovery | ESXi;IaaS;Linux;macOS;Network Devices;Windows | Command Execution, Instance Enumeration, Process Creation, Windows Registry Key Modification | 0 | P3 | Otras técnicas host |
| T1083 | File and Directory Discovery | no | Discovery | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Access, File Creation, Process Creation | 0 | P3 | Otras técnicas host |
| T1087 | Account Discovery | no | Discovery | ESXi;IaaS;Identity Provider;Linux;macOS;Office Suite;SaaS;Windows | Cloud Service Enumeration, Command Execution, File Access, Group Enumeration, Process Creation, Script Execution, User Account Metadata | 0 | P3 | Otras técnicas host |
| T1087.001 | Local Account | sí | Discovery | ESXi;Linux;macOS;Windows | File Access, Process Creation, User Account Metadata | 0 | P3 | Otras técnicas host |
| T1087.002 | Domain Account | sí | Discovery | Linux;macOS;Windows | Command Execution, Process Creation | 1 | P3 | Otras técnicas host |
| T1087.003 | Email Account | sí | Discovery | Windows;Office Suite | Application Log Content, Command Execution, Process Creation, User Account Authentication, User Account Metadata | 0 | P3 | Otras técnicas host |
| T1087.004 | Cloud Account | sí | Discovery | IaaS;Identity Provider;Office Suite;SaaS | Application Log Content, Command Execution, User Account Authentication, User Account Metadata | 0 | P3 | Otras técnicas host |
| T1120 | Peripheral Device Discovery | no | Discovery | Linux;macOS;Windows | Drive Access, File Access, Process Access, Process Creation | 0 | P3 | Otras técnicas host |
| T1124 | System Time Discovery | no | Discovery | ESXi;Linux;macOS;Network Devices;Windows | Command Execution, File Creation, File Modification, Module Load, OS API Execution, Process Access, Process Creation, Process Metadata, Scheduled Job Creation, Scheduled Job Metadata, User Account Authentication | 0 | P3 | Otras técnicas host |
| T1135 | Network Share Discovery | no | Discovery | Linux;macOS;Windows | Command Execution, Named Pipe Metadata, OS API Execution, Process Creation | 2 | P3 | Otras técnicas host |
| T1201 | Password Policy Discovery | no | Discovery | Windows;Linux;macOS;IaaS;Network Devices;Identity Provider;SaaS;Office Suite | Active Directory Object Access, Command Execution, Process Creation, User Account Metadata | 0 | P3 | Otras técnicas host |
| T1217 | Browser Information Discovery | no | Discovery | Linux;macOS;Windows | Command Execution, File Access, File Creation, Process Creation | 0 | P3 | Otras técnicas host |
| T1482 | Domain Trust Discovery | no | Discovery | Windows | Active Directory Object Access, Command Execution, Module Load, Process Access, Process Creation | 0 | P3 | Otras técnicas host |
| T1518 | Software Discovery | no | Discovery | ESXi;IaaS;Linux;macOS;Windows | Application Log Content, Cloud Service Enumeration, Command Execution, Process Creation | 0 | P3 | Otras técnicas host |
| T1518.001 | Security Software Discovery | sí | Discovery | IaaS;Linux;macOS;Windows | Command Execution, Module Load, Process Creation | 0 | P3 | Otras técnicas host |
| T1518.002 | Backup Software Discovery | sí | Discovery | Windows;macOS;Linux | File Access, File Creation, Process Creation, Windows Registry Key Modification | 0 | P3 | Otras técnicas host |
| T1526 | Cloud Service Discovery | no | Discovery | IaaS;Identity Provider;Office Suite;SaaS | Cloud Service Enumeration, Logon Session Creation, User Account Metadata | 0 | P3 | Otras técnicas host |
| T1538 | Cloud Service Dashboard | no | Discovery | IaaS;SaaS;Office Suite;Identity Provider | Application Log Content, Cloud Storage Metadata, Logon Session Creation, User Account Authentication | 0 | P3 | Otras técnicas host |
| T1580 | Cloud Infrastructure Discovery | no | Discovery | IaaS | Cloud Storage Enumeration, Instance Enumeration, Instance Metadata | 0 | P3 | Otras técnicas host |
| T1583 | Acquire Infrastructure | no | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 2 | P3 | Otras técnicas host |
| T1583.001 | Domains | sí | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 0 | P3 | Otras técnicas host |
| T1583.002 | DNS Server | sí | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 2 | P3 | Otras técnicas host |
| T1583.005 | Botnet | sí | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 2 | P3 | Otras técnicas host |
| T1584 | Compromise Infrastructure | no | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 2 | P3 | Otras técnicas host |
| T1584.001 | Domains | sí | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 0 | P3 | Otras técnicas host |
| T1584.002 | DNS Server | sí | Resource Development | PRE | Active DNS, Passive DNS | 0 | P3 | Otras técnicas host |
| T1584.005 | Botnet | sí | Resource Development | PRE | Active DNS, Domain Registration, Passive DNS | 2 | P3 | Otras técnicas host |
| T1585 | Establish Accounts | no | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1585.001 | Social Media Accounts | sí | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1585.002 | Email Accounts | sí | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1585.003 | Cloud Accounts | sí | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1586 | Compromise Accounts | no | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1586.001 | Social Media Accounts | sí | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1586.002 | Email Accounts | sí | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1586.003 | Cloud Accounts | sí | Resource Development | PRE | Social Media | 1 | P3 | Otras técnicas host |
| T1587 | Develop Capabilities | no | Resource Development | PRE | Malware Content, Malware Metadata | 1 | P3 | Otras técnicas host |
| T1587.001 | Malware | sí | Resource Development | PRE | Malware Content, Malware Metadata | 0 | P3 | Otras técnicas host |
| T1587.002 | Code Signing Certificates | sí | Resource Development | PRE | Malware Metadata | 0 | P3 | Otras técnicas host |
| T1587.004 | Exploits | sí | Resource Development | PRE | Malware Content, Malware Metadata | 1 | P3 | Otras técnicas host |
| T1588 | Obtain Capabilities | no | Resource Development | PRE | Certificate Registration, Malware Content, Malware Metadata | 1 | P3 | Otras técnicas host |
| T1588.001 | Malware | sí | Resource Development | PRE | Malware Content, Malware Metadata | 0 | P3 | Otras técnicas host |
| T1588.002 | Tool | sí | Resource Development | PRE | Malware Metadata | 0 | P3 | Otras técnicas host |
| T1588.003 | Code Signing Certificates | sí | Resource Development | PRE | Malware Metadata | 0 | P3 | Otras técnicas host |
| T1588.004 | Digital Certificates | sí | Resource Development | PRE | Certificate Registration | 1 | P3 | Otras técnicas host |
| T1588.005 | Exploits | sí | Resource Development | PRE | Certificate Registration, Malware Content, Malware Metadata | 1 | P3 | Otras técnicas host |
| T1588.006 | Vulnerabilities | sí | Resource Development | PRE | Certificate Registration, Malware Content, Malware Metadata | 1 | P3 | Otras técnicas host |
| T1588.007 | Artificial Intelligence | sí | Resource Development | PRE | Certificate Registration, Malware Content, Malware Metadata | 1 | P3 | Otras técnicas host |
| T1594 | Search Victim-Owned Websites | no | Reconnaissance | PRE | Application Log Content | 0 | P3 | Otras técnicas host |
| T1598 | Phishing for Information | no | Reconnaissance | PRE | Application Log Content | 2 | P3 | Otras técnicas host |
| T1598.001 | Spearphishing Service | sí | Reconnaissance | PRE | Application Log Content | 2 | P3 | Otras técnicas host |
| T1598.002 | Spearphishing Attachment | sí | Reconnaissance | PRE | Application Log Content | 2 | P3 | Otras técnicas host |
| T1598.003 | Spearphishing Link | sí | Reconnaissance | PRE | Application Log Content | 2 | P3 | Otras técnicas host |
| T1598.004 | Spearphishing Voice | sí | Reconnaissance | PRE | Application Log Content | 0 | P3 | Otras técnicas host |
| T1613 | Container and Resource Discovery | no | Discovery | Containers | Container Enumeration, Pod Enumeration | 0 | P3 | Otras técnicas host |
| T1614 | System Location Discovery | no | Discovery | IaaS;Linux;macOS;Windows | Command Execution, OS API Execution, Process Creation | 1 | P3 | Otras técnicas host |
| T1614.001 | System Language Discovery | sí | Discovery | Linux;macOS;Windows | Command Execution, OS API Execution, Process Creation, Windows Registry Key Access | 0 | P3 | Otras técnicas host |
| T1615 | Group Policy Discovery | no | Discovery | Windows | Active Directory Object Access, Command Execution, Process Creation | 1 | P3 | Otras técnicas host |
| T1619 | Cloud Storage Object Discovery | no | Discovery | IaaS | Cloud Storage Access, Cloud Storage Enumeration | 0 | P3 | Otras técnicas host |
| T1652 | Device Driver Discovery | no | Discovery | Linux;macOS;Windows | Command Execution, File Access, Process Creation, Windows Registry Key Modification | 0 | P3 | Otras técnicas host |
| T1654 | Log Enumeration | no | Discovery | ESXi;IaaS;Linux;macOS;Windows | Command Execution, File Access, Process Creation | 0 | P3 | Otras técnicas host |
| T1673 | Virtual Machine Discovery | no | Discovery | ESXi;Linux;macOS;Windows | Command Execution, Process Creation | 0 | P3 | Otras técnicas host |
| T1680 | Local Storage Discovery | no | Discovery | ESXi;IaaS;Linux;macOS;Windows | Command Execution, Process Creation, User Account Authentication | 0 | P3 | Otras técnicas host |

## 4. Top candidatas (apoyo a la selección)

Top ~20 candidatas host-eligible ordenadas por prioridad y riqueza de telemetría:

| # | ID | Nombre | Tácticas | Prio | DC host |
|---|---|---|---|---|---|
| 1 | T1485 | Data Destruction | Impact | P1 | 7 |
| 2 | T1490 | Inhibit System Recovery | Impact | P1 | 7 |
| 3 | T1561 | Disk Wipe | Impact | P1 | 7 |
| 4 | T1048 | Exfiltration Over Alternative Protocol | Exfiltration | P1 | 6 |
| 5 | T1489 | Service Stop | Impact | P1 | 6 |
| 6 | T1052 | Exfiltration Over Physical Medium | Exfiltration | P1 | 5 |
| 7 | T1074 | Data Staged | Collection | P1 | 5 |
| 8 | T1114 | Email Collection | Collection | P1 | 5 |
| 9 | T1119 | Automated Collection | Collection | P1 | 5 |
| 10 | T1486 | Data Encrypted for Impact | Impact | P1 | 5 |
| 11 | T1491 | Defacement | Impact | P1 | 5 |
| 12 | T1565 | Data Manipulation | Impact | P1 | 5 |
| 13 | T1567 | Exfiltration Over Web Service | Exfiltration | P1 | 5 |
| 14 | T1011 | Exfiltration Over Other Network Medium | Exfiltration | P1 | 4 |
| 15 | T1560 | Archive Collected Data | Collection | P1 | 4 |
| 16 | T1529 | System Shutdown/Reboot | Impact | P1 | 3 |
| 17 | T1041 | Exfiltration Over C2 Channel | Exfiltration | P1 | 2 |
| 18 | T1491.001 | Internal Defacement | Impact | P1 | 7 |
| 19 | T1561.001 | Disk Content Wipe | Impact | P1 | 7 |
| 20 | T1561.002 | Disk Structure Wipe | Impact | P1 | 7 |

## 5. Recomendación automática de corpus (13 técnicas)

> Propuesta de **apoyo**; la decisión final es humana (paso 1.5). Garantiza ≥1 técnica por familia R/E/S.

| ID | Nombre | Tácticas | Prio | Justificación |
|---|---|---|---|---|
| T1485 | Data Destruction | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | P1 | Exfiltración |
| T1074 | Data Staged | Collection | P1 | Recolección/preparación |
| T1490 | Inhibit System Recovery | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1561 | Disk Wipe | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1489 | Service Stop | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1052 | Exfiltration Over Physical Medium | Exfiltration | P1 | Exfiltración |
| T1114 | Email Collection | Collection | P1 | Recolección/preparación |
| T1119 | Automated Collection | Collection | P1 | Recolección/preparación |
| T1486 | Data Encrypted for Impact | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1491 | Defacement | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1565 | Data Manipulation | Impact | P1 | Ransomware/Sabotaje (Impact) |
| T1567 | Exfiltration Over Web Service | Exfiltration | P1 | Exfiltración |
