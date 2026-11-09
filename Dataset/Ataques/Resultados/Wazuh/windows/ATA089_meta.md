---
fase: 3b
bloque: B2
tanda: B2.1
ata_id: ATA089
tecnica: T1499.003
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA089 - T1499.003 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.1**. `esperado` **pre-registrado y sellado** en `06c0694`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA089** |
| Tecnica | **T1499.003** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | app de juguete 127.0.0.1:9093 + 200 peticiones; latencia antes/durante |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1499.003-Application_Exhaustion_Flood/` |
| `sha256` ataque | `82be3fa48d22232b1267ed40dc660a2553e5994b321b8a6e6acb5f0f21af528c` |
| `sha256` esperado | `3ea2fbf13485ff0f93a44d6789b9d951bbd21c2112d7bcff7c3828c451437dba` |
| C0 | `Soporte/Ataques/c0/windows/ATA089_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T18:12:18Z` | `2026-11-09T18:13:37Z` | 79 s | 71 | **16** | `67027,92027,92032,92052` | 27 |
| 2 | `2026-11-09T18:17:44Z` | `2026-11-09T18:19:00Z` | 76 s | 93 | **16** | `67027,92027,92032,92052` | 26 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA089\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA089_iter{1,2}/efecto.txt`: during_ms >> before_ms; exhausted=True.

**Iter 1** (`sha256=f7b3da8caaa0ad81091c136680029e7c89d9022e9208f56a7448043ff12b26fa`):

```text
# ATA089 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T18:12:18Z t0=2026-11-09T18:12:18Z run=cmd /c C:\lab-attack\ATA089\run.cmd
2026-11-09T18:13:37Z t1=2026-11-09T18:13:37Z

evidencia_local:
  ata=ATA089
  tecnica=T1499.003
  fuente=manual
  t0=2026-11-09T18:12:24Z
  t1=2026-11-09T18:13:32Z
  endpoint=127.0.0.1:9093
  peticiones=200
  before_ms=0.3
  during_ms=5253
  after_ms=4997
  exhausted=True

VEREDICTO: EFECTO DEMOSTRADO (latencia 0.3 -> 5253 ms; exhausted=True)
```

**Iter 2** (`sha256=d04144b62023c39322c374c7d4afc86691e69461ae5b5f32ccacc931ba6a8487`):

```text
# ATA089 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T18:17:44Z t0=2026-11-09T18:17:44Z run=cmd /c C:\lab-attack\ATA089\run.cmd
2026-11-09T18:19:00Z t1=2026-11-09T18:19:00Z

evidencia_local:
  ata=ATA089
  tecnica=T1499.003
  fuente=manual
  t0=2026-11-09T18:17:47Z
  t1=2026-11-09T18:18:55Z
  endpoint=127.0.0.1:9093
  peticiones=200
  before_ms=0.3
  during_ms=5049
  after_ms=4990
  exhausted=True

VEREDICTO: EFECTO DEMOSTRADO (latencia 0.3 -> 5049 ms; exhausted=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA089_iter1-Detalle.csv` | 71 | `ef06af355a2e72553b271835e640e7c44aba6236c020bdbcf7b29adeefd3cdfe` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA089_iter2-Detalle.csv` | 93 | `0fb9d7eed403f866145a7272fdacd295aae7c911870903ac3e353269d6c98ced` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 71 | **16** | 3 | 27 | **0** | 25 | 71 | 0 | 0 | 0 |
| 2 | 93 | **16** | 3 | 49 | **0** | 25 | 93 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 16 | 4 -> `67027,92027,92032,92052` | `2026-11-09T18:12:19.946Z` `rule_id=92052` |
| 2 | 16 | 4 -> `67027,92027,92032,92052` | `2026-11-09T18:17:46.280Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 16 vs 16;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA089** es **manual**: app de juguete en `127.0.0.1:9093` (single-thread, `/slow` 200 ms) y **200 peticiones** con 10 workers.
2. El efecto es la latencia de `/health` antes/durante (`0.3 -> ~5.2 s`) y `exhausted=True`; la app se para al final.
