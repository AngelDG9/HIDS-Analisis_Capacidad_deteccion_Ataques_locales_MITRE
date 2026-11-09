---
fase: 3b
bloque: B2
tanda: B2.1
ata_id: ATA088
tecnica: T1496.002
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA088 - T1496.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.1**. `esperado` **pre-registrado y sellado** en `06c0694`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA088** |
| Tecnica | **T1496.002** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | 32 MiB en 1 conexion TCP al sink 192.168.65.1:9091 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1496.002-Bandwidth_Hijacking/` |
| `sha256` ataque | `e1f1a7438be8d5720a720c75de85a7bf852d9a687f3a9bcbb823616c8bf6a0e1` |
| `sha256` esperado | `7e473999d89e32236841970ea6fd4f02fcca15b2b6ee700c1662e6def70db691` |
| C0 | `Soporte/Ataques/c0/windows/ATA088_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9091` (ATA088).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T18:04:28Z` | `2026-11-09T18:04:33Z` | 5 s | 19 | **5** | `67027,92032,92052` | 4 |
| 2 | `2026-11-09T18:08:25Z` | `2026-11-09T18:08:26Z` | 1 s | 18 | **5** | `67027,92032,92052` | 3 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA088\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA088_iter{1,2}/efecto.txt`: sink.log con 1 linea TCP len=33554432.

**Iter 1** (`sha256=1e5453358214413cd7bfbfe9e353ce5e03ea8918b80a6caabc0891e11eeec2c4`):

```text
# ATA088 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T18:04:28Z t0=2026-11-09T18:04:28Z run=cmd /c C:\lab-attack\ATA088\run.cmd
2026-11-09T18:04:33Z t1=2026-11-09T18:04:33Z

evidencia_local:
  ata=ATA088
  tecnica=T1496.002
  fuente=manual
  t0=2026-11-09T18:04:32Z
  t1=2026-11-09T18:04:33Z
  destino=192.168.65.1:9091
  conexiones=1
  bytes=33554432

sink.log (HOST):
  2026-11-09T18:04:33Z TCP from=192.168.65.130 len=33554432 sha256=e43b5a04ffeda208998180887510ba7bf75135a1e31d29b86f16f65e731dbc7b

VEREDICTO: EFECTO DEMOSTRADO (1 conexion TCP de 32 MiB; sink.log)
```

**Iter 2** (`sha256=01ef0cc8f9fcae20a0e8f59aa883f4923963f839ea2dd1b1dac8c15bc13393ff`):

```text
# ATA088 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T18:08:25Z t0=2026-11-09T18:08:25Z run=cmd /c C:\lab-attack\ATA088\run.cmd
2026-11-09T18:08:26Z t1=2026-11-09T18:08:26Z

evidencia_local:
  ata=ATA088
  tecnica=T1496.002
  fuente=manual
  t0=2026-11-09T18:08:26Z
  t1=2026-11-09T18:08:26Z
  destino=192.168.65.1:9091
  conexiones=1
  bytes=33554432

sink.log (HOST):
  2026-11-09T18:08:26Z TCP from=192.168.65.130 len=33554432 sha256=e43b5a04ffeda208998180887510ba7bf75135a1e31d29b86f16f65e731dbc7b

VEREDICTO: EFECTO DEMOSTRADO (1 conexion TCP de 32 MiB; sink.log)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA088_iter1-Detalle.csv` | 19 | `18cb6163590f7c056130b7bc57f2b35e74a7bb56575bfd466d974ad3ee8f4056` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA088_iter2-Detalle.csv` | 18 | `fcc5a0ffec73d6643a153a280edba6dc500c48bee8afe70be76e53a66ddae60e` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 19 | **5** | 3 | 7 | **0** | 4 | 19 | 0 | 0 | 0 |
| 2 | 18 | **5** | 3 | 7 | **0** | 3 | 18 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T18:04:30.769Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T18:08:26.675Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA088** es **manual**: 32 MiB en **una** conexion TCP al sink `192.168.65.1:9091`; `sink.log` con una linea `len=33554432`.
2. El efecto es el `sink.log`; no es deteccion.
