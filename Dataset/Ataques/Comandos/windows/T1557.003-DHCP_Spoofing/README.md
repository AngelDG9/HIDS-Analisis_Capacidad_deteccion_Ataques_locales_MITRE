# ATA092 - T1557.003 DHCP Spoofing (Windows)

> **B2.1 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se implementa un **servidor DHCP sintetico** en `127.0.0.1:67` y un **cliente
sintetico** que hace DISCOVER/REQUEST; el servidor responde OFFER/ACK con
`ip=192.168.65.200`, `gw=192.168.65.1`, `dns=192.168.65.1`. Se escribe `lease.txt` con la
concesion del atacante. **Sin NIC/lease real**; sin VMnet1.

## 2. Que hace

1. Arranca el servidor DHCP sintetico en loopback 67.
2. El cliente envia `DHCPDISCOVER` y `DHCPREQUEST`; recibe `DHCPOFFER`/`DHCPACK`.
3. Escribe `evidencias\lease.txt` con la concesion.

**Guardarrail**: loopback `127.0.0.1:67`; sin NIC/lease real; <=120 s.

## 3. Prueba de efecto

`evidencias\lease.txt` con `ip=192.168.65.200`, `gw=192.168.65.1`, `dns=192.168.65.1`;
`efecto_local.txt` con `ack_ok=True`.

## 4. `esperado`

`ATA092_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA092*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA092\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Lease **sintetico**; no se toca la NIC real ni VMnet1.
