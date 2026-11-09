---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA074
tecnica: T1041
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA074 - T1041 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA074** |
| Tecnica | **T1041** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `d1253f6e-c29b-49dc-b466-2147a6191932` |
| Adaptacion | ART d1253f6e -> POST de payload.txt con curl.exe al sink local |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1041-Exfiltration_Over_C2_Channel/` |
| `sha256` ataque | `aef83658626397a780f40be13a8e80afcca7d05071acfd0fc6ffa4308ecd7709` |
| `sha256` esperado | `7b6c1fb2f8306960282ae1fd691be398e4af327ab578141151e7b106f51d548b` |
| C0 | `Soporte/Ataques/c0/windows/ATA074_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T11:58:17Z` | `2026-11-09T11:58:22Z` | 5 s | 44 | **6** | `67027,92032,92052` | 27 |
| 2 | `2026-11-09T12:02:39Z` | `2026-11-09T12:02:40Z` | 1 s | 41 | **6** | `67027,92032,92052` | 25 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA074\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA074_iter{1,2}/efecto.txt`: sink.log POST + sha256 del payload.

**Iter 1** (`sha256=268859e4949657aea45ac7cc2bf77e1c4e8cb38447cd4ae4905988da929be559`):

```text
# ATA074 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T11:58:17Z t0=2026-11-09T11:58:17Z run=cmd /c C:\lab-attack\ATA074\run.cmd
2026-11-09T11:58:22Z t1=2026-11-09T11:58:22Z

evidencia_local:
  ata=ATA074
  tecnica=T1041
  fuente=ART_adaptado
  guid=d1253f6e-c29b-49dc-b466-2147a6191932
  t0=2026-11-09T11:58:21Z
  t1=2026-11-09T11:58:21Z
  url=http://192.168.65.1:9090/upload/ATA074
  payload=C:\lab-attack\ATA074\payload.txt
  bytes=1571
  sha256=a676341a6be6711d9360160277713040be887ac0047006515d2482df0b39586b
  resultado=curl_rc=0 out=OK

sink.log (HOST):
  2026-11-09T11:58:21Z POST /upload/ATA074 from=192.168.65.130 len=1571 sha256=a676341a6be6711d9360160277713040be887ac0047006515d2482df0b39586b content_type=application/x-www-form-urlencoded

VEREDICTO: EFECTO DEMOSTRADO (POST /upload/ATA074; sha256 del payload en sink.log)
```

**Iter 2** (`sha256=5552f6f1e919b6f7f235bd1717f54edb5c51138f480b08d1804a43347a0a727e`):

```text
# ATA074 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T12:02:39Z t0=2026-11-09T12:02:39Z run=cmd /c C:\lab-attack\ATA074\run.cmd
2026-11-09T12:02:40Z t1=2026-11-09T12:02:40Z

evidencia_local:
  ata=ATA074
  tecnica=T1041
  fuente=ART_adaptado
  guid=d1253f6e-c29b-49dc-b466-2147a6191932
  t0=2026-11-09T12:02:40Z
  t1=2026-11-09T12:02:40Z
  url=http://192.168.65.1:9090/upload/ATA074
  payload=C:\lab-attack\ATA074\payload.txt
  bytes=1571
  sha256=a676341a6be6711d9360160277713040be887ac0047006515d2482df0b39586b
  resultado=curl_rc=0 out=OK

sink.log (HOST):
  2026-11-09T12:02:40Z POST /upload/ATA074 from=192.168.65.130 len=1571 sha256=a676341a6be6711d9360160277713040be887ac0047006515d2482df0b39586b content_type=application/x-www-form-urlencoded

VEREDICTO: EFECTO DEMOSTRADO (POST /upload/ATA074; sha256 del payload en sink.log)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA074_iter1-Detalle.csv` | 44 | `08754efc620ee4dcb3e33ed77abefa312293dc6f5397066a6a4f1fdd67e0a223` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA074_iter2-Detalle.csv` | 41 | `6daf752763c71ba0ebe78b80b61afeb079b6b0afeb049cb3f8f228f3b5610af7` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 44 | **6** | 3 | 9 | **0** | 26 | 44 | 0 | 0 | 0 |
| 2 | 41 | **6** | 3 | 7 | **0** | 25 | 41 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 3 -> `67027,92032,92052` | `2026-11-09T11:58:18.954Z` `rule_id=92052` |
| 2 | 6 | 3 -> `67027,92032,92052` | `2026-11-09T12:02:41.153Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 6 vs 6;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA074** es **ART_adaptado**: se cita el atomic T1041 `d1253f6e` (POST de un fichero al C2) y se cambia el executor de `Invoke-WebRequest` a **`curl.exe`** nativo de Windows 10 para anclar el proceso por `win_image`.
2. El sink 9090 registra `POST /upload/ATA074 ... sha256=<hash>`; el hash coincide con `payload.txt`.
