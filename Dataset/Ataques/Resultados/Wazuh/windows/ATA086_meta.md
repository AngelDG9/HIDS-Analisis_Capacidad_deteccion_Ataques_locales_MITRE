---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA086
tecnica: T1499.001
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA086 - T1499.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA086** |
| Tecnica | **T1499.001** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | 8 bloques de 64 MiB (512 MiB) retenidos 15 s; Available MBytes |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1499.001-OS_Exhaustion_Flood/` |
| `sha256` ataque | `3f58ce9d7117183c8fdaa8e01890b607fc0f8e6f428d35e4dcd37e92ced27664` |
| `sha256` esperado | `484c190482eb3ef20b166d6fe43df5133a831e7663591a72fb7da3de24f21ef0` |
| C0 | `Soporte/Ataques/c0/windows/ATA086_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sin red.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T15:02:20Z` | `2026-11-09T15:02:39Z` | 19 s | 21 | **5** | `67027,92032,92052` | 4 |
| 2 | `2026-11-09T15:06:12Z` | `2026-11-09T15:06:29Z` | 17 s | 20 | **5** | `67027,92032,92052` | 3 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA086\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA086_iter{1,2}/efecto.txt`: Available MBytes cae durante la presion de 512 MiB.

**Iter 1** (`sha256=84a8a38ee4e7f3469bb73b02bce80c38282ea252c4af7f6b5a32168b1498da3a`):

```text
# ATA086 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T15:02:20Z t0=2026-11-09T15:02:20Z run=cmd /c C:\lab-attack\ATA086\run.cmd
2026-11-09T15:02:39Z t1=2026-11-09T15:02:39Z

evidencia_local:
  ata=ATA086
  tecnica=T1499.001
  fuente=manual
  t0=2026-11-09T15:02:24Z
  t1=2026-11-09T15:02:39Z
  bloques=8
  bytes=536870912
  available_before_mb=3031.7
  available_during_mb=2504.9
  available_after_mb=2944.2

VEREDICTO: EFECTO DEMOSTRADO (Available MBytes 3031.7 -> 2504.9)
```

**Iter 2** (`sha256=0c03b324bd8d9a7ec78bb2c5ba8212dbb9049ac715fc2bd08b03bd0e68f88c97`):

```text
# ATA086 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T15:06:12Z t0=2026-11-09T15:06:12Z run=cmd /c C:\lab-attack\ATA086\run.cmd
2026-11-09T15:06:29Z t1=2026-11-09T15:06:29Z

evidencia_local:
  ata=ATA086
  tecnica=T1499.001
  fuente=manual
  t0=2026-11-09T15:06:13Z
  t1=2026-11-09T15:06:29Z
  bloques=8
  bytes=536870912
  available_before_mb=3115.1
  available_during_mb=2592
  available_after_mb=3040.4

VEREDICTO: EFECTO DEMOSTRADO (Available MBytes 3115.1 -> 2592)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA086_iter1-Detalle.csv` | 21 | `c2a7b007515593ac6660c24fd73818158daa38cd6d824475829a6b8613628314` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA086_iter2-Detalle.csv` | 20 | `afc4e4d52c896f0074b1f2a9e7264fd51c4f6a349721ca850a2bb69ed47ffdf5` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 21 | **5** | 3 | 10 | **0** | 3 | 21 | 0 | 0 | 0 |
| 2 | 20 | **5** | 3 | 9 | **0** | 3 | 20 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T15:02:22.173Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T15:06:14.308Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA086** es **manual**: **8 bloques de 64 MiB (512 MiB)** retenidos 15 s; se tocan las paginas para comprometer memoria fisica.
2. El efecto es la caida de `Available MBytes` durante la presion (p. ej. 3031.7 -> 2504.9 MB). **El HIDS no tiene capa de recursos**: la deteccion esperada es solo de proceso.
