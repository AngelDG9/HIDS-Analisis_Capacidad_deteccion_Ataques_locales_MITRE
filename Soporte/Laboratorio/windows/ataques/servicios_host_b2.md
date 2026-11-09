# Servicios locales B2 — prueba benigna y apagado

> **B2.0 (prep)**, 2026-11-09. **No es un ataque**: se levantan los servicios de B2 en
> **loopback del invitado**, se prueban y se apagan. Evidencia:
> `Soporte/Laboratorio/windows/ataques/servicios_host_b2_evidencia.txt`.
> **Sin cambio de telemetría**: no se habilita auditoría SMB (`5140/5145`) ni SMTP.

## 1. Servicios probados

| Servicio | Endpoint | Prueba | Resultado |
|---|---|---|---|
| SMB share | `\\127.0.0.1\labshare` | `Get-ChildItem` (1 fichero) | **OK**; share eliminado |
| SMTP sink | `127.0.0.1:2525` | `EHLO test` → `220`/`250` | **OK** |
| Proxy | `127.0.0.1:9095` | `GET http://example.local/` → `HTTP/1.1 200 OK` | **OK** |
| App | `127.0.0.1:9093` | `GET /` → `200 APP-OK` | **OK** |
| UDP amplificador | `127.0.0.1:5353` | 63 B → 252 B (4×) | **OK** |
| UDP DHCP sintético | `127.0.0.1:67` | DISCOVER → `DHCP-OFFER-TFG` | **OK** |
| Portal | `127.0.0.1:8081` | `GET /` → `200` (formulario) | **OK** |

- **SMB**: `New-SmbShare labshare` apuntando **solo** a `C:\lab-attack\labshare`; se elimina al
  cerrar. Sin auditoría SMB (declarado).
- **SMTP**: sink TCP mínimo en 2525; no hay correo real.
- **Proxy/app/portal**: `TcpListener`/`HttpListener` en loopback; sin tráfico real.
- **UDP 5353**: el sistema (mDNS, PID del servicio de red) ya ocupa `0.0.0.0:5353`; el
  amplificador se enlaza a `127.0.0.1:5353` con **`ReuseAddress` + `ExclusiveAddressUse=false`**.
  Sin ese ajuste, el bind falla. **Punto ciego/limitación**: el tráfico es **unicast loopback**,
  no broadcast en VMnet1.
- **UDP 67**: `UdpClient(67)` en loopback; lease **sintético**.
- **Host sinks** 9090/9091/9092: ya documentados en `servicios_host.md` (B1); no se tocan.

## 2. Apagado

- `Stop-Job`/`Remove-Job` de los seis servicios; `Remove-SmbShare labshare`; se borra
  `C:\lab-attack\labshare`.
- Evidencia final: `smb_delete=OK`, `fin servicios_b2` (2026-11-09T17:21:18Z).
- **0 servicios B2 activos** tras la prueba; 0 VMs al cierre de B2.0.

## 3. Notas para B2.1-B2.4

- El **share SMB** y los servicios loopback se crean **en el invitado** (no en el host).
- El **proxy 9095** y el **portal 8081** son desechables: el script de ataque los levanta y los
  para en la misma ventana.
- El **UDP 5353** requiere `ReuseAddress` por el mDNS del sistema; documentarlo en las fichas
  de ATA090.
- **No** se habilita SMB/SMTP audit: la telemetría sigue siendo la de B1 (proceso + FIM).
