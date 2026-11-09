---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA085
tecnica: T1498.001
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA085 - T1498.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA085** |
| Tecnica | **T1498.001** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | 8 conexiones TCP de 8 MiB (64 MiB) al sink 192.168.65.1:9091 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1498.001-Direct_Network_Flood/` |
| `sha256` ataque | `462d6854ead9ecea56bf84a1a7271869abf208b85dac5d095f3b5efded7415aa` |
| `sha256` esperado | `1b3f71d8efe50cd1d39035fd1100fba5ed27b66d5548eb5993313c1da639600a` |
| C0 | `Soporte/Ataques/c0/windows/ATA085_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9091` (ATA085).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T14:50:23Z` | `2026-11-09T14:50:25Z` | 2 s | 18 | **5** | `67027,92032,92052` | 3 |
| 2 | `2026-11-09T14:54:21Z` | `2026-11-09T14:54:23Z` | 2 s | 18 | **5** | `67027,92032,92052` | 3 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA085\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA085_iter{1,2}/efecto.txt`: sink.log con 8 lineas TCP de 8 MiB.

**Iter 1** (`sha256=f14d1321ff17a22962d8d2542f8ade2376cbdbb96f9a9a7d210f2dd3fdcc5561`):

```text
# ATA085 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T14:50:23Z t0=2026-11-09T14:50:23Z run=cmd /c C:\lab-attack\ATA085\run.cmd
2026-11-09T14:50:25Z t1=2026-11-09T14:50:25Z

evidencia_local:
  ata=ATA085
  tecnica=T1498.001
  fuente=manual
  t0=2026-11-09T14:50:24Z
  t1=2026-11-09T14:50:24Z
  destino=192.168.65.1:9091
  conexiones=8
  bytes_conexion=8388608
  bytes_total=67108864

sink.log (HOST):
  2026-11-09T14:50:24Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:24Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:24Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:24Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:25Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:25Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:25Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:50:25Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388

VEREDICTO: EFECTO DEMOSTRADO (8 conexiones TCP de 8 MiB; 64 MiB total)
```

**Iter 2** (`sha256=4b8ad56586212cb233e9c98e26a95b3390a6f3602e557fb11be08906cea9f0ef`):

```text
# ATA085 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T14:54:21Z t0=2026-11-09T14:54:21Z run=cmd /c C:\lab-attack\ATA085\run.cmd
2026-11-09T14:54:23Z t1=2026-11-09T14:54:23Z

evidencia_local:
  ata=ATA085
  tecnica=T1498.001
  fuente=manual
  t0=2026-11-09T14:54:22Z
  t1=2026-11-09T14:54:22Z
  destino=192.168.65.1:9091
  conexiones=8
  bytes_conexion=8388608
  bytes_total=67108864

sink.log (HOST):
  2026-11-09T14:54:22Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:22Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:22Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:22Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:22Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:23Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:23Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388
  2026-11-09T14:54:23Z TCP from=192.168.65.130 len=8388608 sha256=b16bd32b101132fd0102461bc75ea65442c37293ac881ae953486c8ac26a7388

VEREDICTO: EFECTO DEMOSTRADO (8 conexiones TCP de 8 MiB; 64 MiB total)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA085_iter1-Detalle.csv` | 18 | `9e5db5c391dee8c26c6f8d93478005e1895c6db613a8a5bc51bf6f2a7f2a4b7b` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA085_iter2-Detalle.csv` | 18 | `37c4170cc9bd02d27becb9ad44a8a535d7a027a98a711879e4e8f06e8b895f58` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 18 | **5** | 3 | 7 | **0** | 3 | 18 | 0 | 0 | 0 |
| 2 | 18 | **5** | 3 | 7 | **0** | 3 | 18 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:50:24.999Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:54:22.929Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA085** es **manual**: **8 conexiones TCP de 8 MiB** (64 MiB total) al sink `192.168.65.1:9091`; `sink.log` con 8 lineas `len=8388608`.
2. El efecto es el `sink.log`; no es deteccion.
