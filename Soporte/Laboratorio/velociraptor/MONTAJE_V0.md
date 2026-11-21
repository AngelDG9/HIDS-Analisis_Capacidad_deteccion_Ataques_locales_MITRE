# Velociraptor «virgen» sobre Linux — montaje V0 (2026-11-21)

> Estado: **servidor y cliente montados; falta UNA regla de cortafuegos del PC (necesita administrador) para que el cliente se inscriba.**
> Todo lo de aquí se comprobó en la máquina real (no se fía de la documentación). Sin secretos: las claves, la CA y el
> `client.config.yaml` viven en `D:\TFG-VMs\velociraptor-server\` (fuera del repo).

## 1. Material (V0a)
| Elemento | Valor |
|---|---|
| Versión | **v0.77.3** (estable más reciente; publicada 2026-10-05; 0.77.2 y 0.76.7 son anteriores) |
| Fuente | `https://github.com/Velocidex/velociraptor/releases/download/v0.77.3/` |
| Servidor (Windows) | `velociraptor-v0.77.3-windows-amd64.exe.gz` 28 350 845 B · sha256 `0b9cd957e5605da74994a6c29934da9af0e3af9c9b808f2274c826fba32dc3ae` → `velociraptor.exe` 73 422 840 B · sha256 `3d20a5a2d272e3eb2bccae4a80ebe469fc1a6f63eb4a8f8a586dbae356437d32` |
| Cliente (Linux) | `velociraptor-v0.77.3-linux-amd64.gz` 30 350 671 B · sha256 `c2c4eb585f16b622cd57de04995a7a13c076ee455bc2a828fd9243cec2ccfed8` → binario 78 329 008 B · sha256 `c216b7be6f104da551c302d707a7e5a7126e97db33d3f1fc9d2c3b76cfa00093` |
| Dónde | `D:\TFG-VMs\material-velociraptor\` (fuera del repo) |
| Nota de integridad | la release publica firmas `.sig` pero **no** un fichero de sumas; los `sha256` son los calculados tras descargar por HTTPS desde GitHub (no se verificó la firma GPG). |
| Elevación | `velociraptor.exe` pide administrador (manifiesto); sin elevar se arranca con la variable `__COMPAT_LAYER=RunAsInvoker` (comprobado: `version` → 0.77.3, go1.27.1). |

## 2. Servidor en el PC (V0b)
- Config generada con `velociraptor config generate` y ajustada: frontend `https://192.168.65.1:8000/` (IP del PC en VMnet1), GUI `https://127.0.0.1:8889/` (solo local), API `127.0.0.1:8001`, datastore `D:\TFG-VMs\velociraptor-server\datastore`.
- Arranque (sin administrador):
  `set __COMPAT_LAYER=RunAsInvoker` y `velociraptor.exe --config D:\TFG-VMs\velociraptor-server\server.config.yaml frontend -v`.
  Comprobado: escucha en `192.168.65.1:8000` y `127.0.0.1:8889`, «Frontend is ready to handle client TLS requests».
- Usuario de la GUI: **no creado** (no se guardan contraseñas). Se crea cuando se necesite con
  `velociraptor.exe --config …\server.config.yaml user add admin --role administrator`.

## 3. Cliente en la VM Linux (V0b)
- VM `victima-linux` partiendo de `lab-listo` (Ubuntu 24.04.5, kernel 6.8.0-139). Se **desinstaló el agente de Wazuh** (`dpkg --purge wazuh-agent`: 0 paquetes, sin `/var/ossec`, sin procesos).
- **auditd intacto**: las mismas 5 reglas que usaba Wazuh (`/etc/audit/rules.d/tfg.rules`, md5 `7b6f8396d13ff701990fff563aa43074`; claves `audit-wazuh-c/w`, el nombre se conserva para que la telemetría sea idéntica).
- Binario en `/usr/local/bin/velociraptor`, configuración en `/etc/velociraptor/client.config.yaml` (0600), servicio `velociraptor_client.service` (`Restart=always`, habilitado).
- El cliente arranca, genera su identidad (`C.dbc4d0ba705d6d27`), carga 422 artifacts y **intenta conectar a `https://192.168.65.1:8000/`**.
- Snapshot nuevo **`lab-listo-vr`** (no se tocó `lab-listo`). Probado: revertir a `lab-listo-vr` y arrancar deja el cliente y auditd activos y 0 paquetes de Wazuh.

## 4. LO QUE FALTA (necesita administrador)
Desde la VM, el puerto 8000 del PC **no es alcanzable** cuando lo escucha `velociraptor.exe` (conexión caduca), mientras que un `python.exe` en cualquier puerto sí lo es: el cortafuegos de Windows tiene reglas por programa y no hay ninguna para `velociraptor.exe`. Sin administrador no se pueden crear reglas, y **no se ha intentado eludirlo** (un reenvío desde `python.exe` se descartó por ser una forma de saltarse el control).
Orden para el humano (PowerShell **como administrador**), acotada a la red del laboratorio:
```
New-NetFirewallRule -DisplayName "TFG-velociraptor-8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -RemoteAddress 192.168.65.0/24 -Action Allow -Program "D:\TFG-VMs\material-velociraptor\velociraptor.exe"
```
Después: arrancar el servidor (§2) con la VM encendida; en ≤1 min el cliente aparece en
`velociraptor.exe --config …\server.config.yaml query "SELECT client_id, os_info.hostname FROM clients()"`.

## 5. Inventario real de artifacts (V0c, sin servidor)
`velociraptor artifacts list` en la VM: **441 artifacts** en total; `Linux.*` = 53, `Generic.*` = 33. Inventario clasificado en
`inventario_artifacts_linux.csv` (86 filas; script `_artefactos/scripts/inventario_artifacts_velociraptor.py`, clasificación por el texto de la definición y sus permisos requeridos):
telemetría **34** · otro **18** · forense **17** · **detección 8** · **respuesta 9** (ejecutan o cambian cosas: Remediation.Quarantine, Sys.BashShell, Utils.InstallDeb, Client.Rekey…).
*(Una primera versión clasificaba 9 como detección y solo 2 como «modifica el sistema»; la verificación independiente la corrigió: `Quarantine` y `BashShell` no son detección, y 11 artifacts modifican el sistema o ejecutan comandos.)*
Hallazgos que condicionan el diseño:
- **`Linux.Events.ProcessExecutions` lee auditd y además INSTALA una regla de auditoría propia** (`auditctl -a exit,always -F arch=b64 -S execve -k procmon`; es el único de los 86 que menciona `auditctl`): cambia la telemetría de partida respecto a Wazuh. Hay que decidir si se activa (y declararlo) o se evita.
- **11 artifacts modifican el sistema o ejecutan comandos** (campo `modifica_el_sistema`): ProcessExecutions, PacketCapture, Quarantine (crea una tabla nftables que corta el tráfico), BashShell (ejecución arbitraria como root), InstallDeb (instala paquetes), Rekey, CleanupTemp, FetchBinary, LocalLogs, LocalHashes.Init y DeadDiskRemapping. Ninguno debe lanzarse en ventanas de medida sin declararlo.
- Eventos continuos de Linux: `Events.{DNS, EBPF, HTTPConnections, Journal, ProcessExecutions, SSHBruteforce, SSHLogin, TrackProcesses}`.
- Muy poca detección «de fábrica» (8 artifacts de detección, casi todos Yara/hash que necesitan reglas o parámetros): coincide con lo esperado en el diseño (mucha visibilidad, poca detección).

## 6. Fuera de este montaje
Prueba de humo de colección (necesita el cliente inscrito), V0d (piloto de 6 casos), V1 (55×2) y V1-L (ventana de 72 h).
