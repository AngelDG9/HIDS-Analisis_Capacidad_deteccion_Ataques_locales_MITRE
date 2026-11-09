---
fase: 3b
bloque: B2
tanda: B2.1
ata_id: ATA092
tecnica: T1557.003
tactica: Credential Access
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA092 - T1557.003 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.1**. `esperado` **pre-registrado y sellado** en `06c0694`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA092** |
| Tecnica | **T1557.003** |
| Tactica | Credential Access |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | servidor DHCP sintetico 127.0.0.1:67 + cliente sintetico; lease.txt |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1557.003-DHCP_Spoofing/` |
| `sha256` ataque | `f8145c8d204b857ff0058f192a387c202d5a856f10a67f275613d4c174137cb9` |
| `sha256` esperado | `64231a6f6b56662b472d49cb3f9a91245f7a846076d06c49c86631959aa8dc3d` |
| C0 | `Soporte/Ataques/c0/windows/ATA092_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T18:46:22Z` | `2026-11-09T18:46:26Z` | 4 s | 24 | **6** | `67027,92027,92032,92052` | 6 |
| 2 | `2026-11-09T18:50:14Z` | `2026-11-09T18:50:21Z` | 7 s | 23 | **6** | `67027,92027,92032,92052` | 6 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA092\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA092_iter{1,2}/efecto.txt`: lease.txt con ip/gw/dns; ack_ok=True.

**Iter 1** (`sha256=55f6570126834a536b9e4b0b7b452683fd134c207a8f06004622dbebab680638`):

```text
# ATA092 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T18:46:22Z t0=2026-11-09T18:46:22Z run=cmd /c C:\lab-attack\ATA092\run.cmd
2026-11-09T18:46:26Z t1=2026-11-09T18:46:26Z

evidencia_local:
  ata=ATA092
  tecnica=T1557.003
  fuente=manual
  t0=2026-11-09T18:46:25Z
  t1=2026-11-09T18:46:25Z
  lease=C:\lab-attack\ATA092\evidencias\lease.txt
  ip=192.168.65.200
  gw=192.168.65.1
  dns=192.168.65.1
  ack_ok=True

VEREDICTO: EFECTO DEMOSTRADO (lease ip=192.168.65.200 gw=192.168.65.1 dns=192.168.65.1; ack_ok=True)
```

**Iter 2** (`sha256=4596a333f8119fa4999ba39de9a633d500a354333ebdd558e989f3d171507b3b`):

```text
# ATA092 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T18:50:14Z t0=2026-11-09T18:50:14Z run=cmd /c C:\lab-attack\ATA092\run.cmd
2026-11-09T18:50:21Z t1=2026-11-09T18:50:21Z

evidencia_local:
  ata=ATA092
  tecnica=T1557.003
  fuente=manual
  t0=2026-11-09T18:50:20Z
  t1=2026-11-09T18:50:20Z
  lease=C:\lab-attack\ATA092\evidencias\lease.txt
  ip=192.168.65.200
  gw=192.168.65.1
  dns=192.168.65.1
  ack_ok=True

VEREDICTO: EFECTO DEMOSTRADO (lease ip=192.168.65.200 gw=192.168.65.1 dns=192.168.65.1; ack_ok=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA092_iter1-Detalle.csv` | 24 | `8b9caefc854a91e95ef184c5f7c17e3816d2762cb02750796c73a006e4f0d9c3` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA092_iter2-Detalle.csv` | 23 | `93130abe50d30f0a9643e637248f3fda64ffa941e3760177d8569fbe8c425d7f` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 24 | **6** | 3 | 9 | **0** | 6 | 24 | 0 | 0 | 0 |
| 2 | 23 | **6** | 3 | 8 | **0** | 6 | 23 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T18:46:24.341Z` `rule_id=92052` |
| 2 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T18:50:15.956Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 6 vs 6;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA092** es **manual**: servidor DHCP sintetico en `127.0.0.1:67` + cliente sintetico; DISCOVER/REQUEST -> OFFER/ACK con `ip=192.168.65.200`, `gw=192.168.65.1`, `dns=192.168.65.1`.
2. El efecto es `lease.txt` con la concesion del atacante (`ack_ok=True`); lease sintetico, sin NIC/lease real.
