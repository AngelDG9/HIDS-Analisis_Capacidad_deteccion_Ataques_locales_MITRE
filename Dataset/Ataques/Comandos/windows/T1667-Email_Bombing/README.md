# ATA083 - T1667 Email Bombing (Windows)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay servidor de correo real; se crea un **mailbox local de juguete** con
**25 `.eml`** (`bomb_01.eml` ... `bomb_25.eml`). Sin red.

## 2. Que hace

1. Crea `mailbox\` y escribe 25 `.eml` con cabeceras y cuerpo.
2. Cuenta los ficheros y los bytes totales.

**Guardarrail**: todo bajo `C:\lab-attack\ATA083\`; <=200 ficheros, <=64 MiB, <=120 s.
Sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `ficheros=25` y `bytes=<total>`.

## 4. `esperado`

`ATA083_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA083*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA083\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Mailbox sintetico; no se envia correo real.
