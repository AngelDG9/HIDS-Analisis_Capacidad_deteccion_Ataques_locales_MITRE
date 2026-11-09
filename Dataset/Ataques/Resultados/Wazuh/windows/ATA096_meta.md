---
fase: 3b
bloque: B2
tanda: B2.2
ata_id: ATA096
tecnica: T1565.002
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA096 - T1565.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.2**. `esperado` **pre-registrado y sellado** en `a2eca10`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA096** |
| Tecnica | **T1565.002** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | proxy loopback 127.0.0.1:9095 reescribe el body; sink host 192.168.65.1:9090 recibe sha distinto |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1565.002-Transmitted_Data_Manipulation/` |
| `sha256` ataque | `222435721992425bfaaae216834a180f6f2e10eb114f901f0ea9d9ebe3725817` |
| `sha256` esperado | `2ed0d8af52fcd84639348e4fb4806122e3622478b5f29c2c3b2d20c390617027` |
| C0 | `Soporte/Ataques/c0/windows/ATA096_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090` + proxy loopback `127.0.0.1:9095` (ATA096).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T19:44:39Z` | `2026-11-09T19:44:46Z` | 7 s | 23 | **6** | `67027,92027,92032,92052` | 6 |
| 2 | `2026-11-09T19:48:53Z` | `2026-11-09T19:48:57Z` | 4 s | 22 | **6** | `67027,92027,92032,92052` | 6 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA096\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA096_iter{1,2}/efecto.txt`: sink recibe sha256 distinto del fichero; proxy.log orig/mod; sink.log.

**Iter 1** (`sha256=0b4f56aafe99e4925961284f5f230695ede1da63a99c9af399c46b3b2b32158d`):

```text
# ATA096 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T19:44:39Z t0=2026-11-09T19:44:39Z run=cmd /c C:\lab-attack\ATA096\run.cmd
2026-11-09T19:44:46Z t1=2026-11-09T19:44:46Z

evidencia_local:
  ata=ATA096
  tecnica=T1565.002
  fuente=manual
  t0=2026-11-09T19:44:45Z
  t1=2026-11-09T19:44:46Z
  proxy=127.0.0.1:9095
  sink=192.168.65.1:9090
  sha256_original=2cb1215873ec94166552e21a700710cc14ddcb56ae1ceaf86a0c75dac5043520
  sha256_modified=69f9652a1f013d9e9ad199ca330734a2403860ff50868c0127b487ca012bb01c
  alterado=True

sink.log (HOST):
  2026-11-09T19:44:45Z POST /upload/ATA096 from=192.168.65.130 len=21 sha256=69f9652a1f013d9e9ad199ca330734a2403860ff50868c0127b487ca012bb01c content_type=text/plain

proxy.log (invitado):
  orig=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 mod=69f9652a1f013d9e9ad199ca330734a2403860ff50868c0127b487ca012bb01c

VEREDICTO: EFECTO DEMOSTRADO (sink recibe sha256=69f9652a1f01... distinto del original 2cb1215873ec...)
```

**Iter 2** (`sha256=30160b91bdeb61c592698d96c5b3fb57576d9b90b1b65a9cd95a25f0f67ffe17`):

```text
# ATA096 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T19:48:53Z t0=2026-11-09T19:48:53Z run=cmd /c C:\lab-attack\ATA096\run.cmd
2026-11-09T19:48:57Z t1=2026-11-09T19:48:57Z

evidencia_local:
  ata=ATA096
  tecnica=T1565.002
  fuente=manual
  t0=2026-11-09T19:48:56Z
  t1=2026-11-09T19:48:57Z
  proxy=127.0.0.1:9095
  sink=192.168.65.1:9090
  sha256_original=2cb1215873ec94166552e21a700710cc14ddcb56ae1ceaf86a0c75dac5043520
  sha256_modified=69f9652a1f013d9e9ad199ca330734a2403860ff50868c0127b487ca012bb01c
  alterado=True

sink.log (HOST):
  2026-11-09T19:48:57Z POST /upload/ATA096 from=192.168.65.130 len=21 sha256=69f9652a1f013d9e9ad199ca330734a2403860ff50868c0127b487ca012bb01c content_type=text/plain

proxy.log (invitado):
  orig=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 mod=69f9652a1f013d9e9ad199ca330734a2403860ff50868c0127b487ca012bb01c

VEREDICTO: EFECTO DEMOSTRADO (sink recibe sha256=69f9652a1f01... distinto del original 2cb1215873ec...)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA096_iter1-Detalle.csv` | 23 | `4a9fd5fd7da048d11b948b4da795446a5577f618bf8e1a8b27a58c7131accf0e` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA096_iter2-Detalle.csv` | 22 | `a155b19e335c6fdf467109db4162d7a8a36c1633b4f453c39fe988286335c86e` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 23 | **6** | 3 | 8 | **0** | 6 | 23 | 0 | 0 | 0 |
| 2 | 22 | **6** | 3 | 7 | **0** | 6 | 22 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T19:44:40.968Z` `rule_id=92052` |
| 2 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T19:48:55.080Z` `rule_id=92032` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 6 vs 6;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA096** es **manual**: proxy loopback `127.0.0.1:9095` que reescribe el body; sink del HOST `192.168.65.1:9090` recibe un `sha256` distinto del fichero original. Pareja Windows de **ATA026**.
2. **Caveat declarado**: el proxy lee la peticion con un solo `Read`; el body llego en un segmento posterior, por lo que `proxy.log` registra `orig=e3b0c442...` (sha del body vacio) y reenvia solo `MANIPULADO-POR-PROXY` (`len=21`). El efecto de manipulacion es valido (`sha256_original != sha256_modified`; `sink.log` con el sha alterado), pero **no se reenvia el body original**. Mejora propuesta para B2.5: leer `Content-Length` en bucle.
3. El efecto no es deteccion: se prueba en `efecto.txt`, `proxy.log` y `sink.log`.
