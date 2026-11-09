---
fase: 3b
bloque: B2
tanda: B2.1
ata_id: ATA090
tecnica: T1498.002
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA090 - T1498.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.1**. `esperado` **pre-registrado y sellado** en `06c0694`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA090** |
| Tecnica | **T1498.002** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | amplificador UDP 127.0.0.1:5353 + victima 127.0.0.2:5354; 100x64 B -> 4 KB |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1498.002-Reflection_Amplification/` |
| `sha256` ataque | `6d505982abd176444b54b8662c02dddec1af9a98fd033b215c4e6b73d50a8d61` |
| `sha256` esperado | `839e8d2f5c8e5bd1c9bcdab3b6a8b77bd719cf7f85c6fc53233bc4fe1e2175a9` |
| C0 | `Soporte/Ataques/c0/windows/ATA090_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T18:22:44Z` | `2026-11-09T18:22:48Z` | 4 s | 23 | **6** | `67027,92027,92032,92052` | 6 |
| 2 | `2026-11-09T18:26:33Z` | `2026-11-09T18:26:37Z` | 4 s | 22 | **6** | `67027,92027,92032,92052` | 5 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA090\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA090_iter{1,2}/efecto.txt`: sent_bytes=6400; recv_bytes=409600; ratio=64.

**Iter 1** (`sha256=9267fff8ae72694e6439da77f742421da1aab2ea926dc374f7c7dfbdd8cc8fc7`):

```text
# ATA090 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T18:22:44Z t0=2026-11-09T18:22:44Z run=cmd /c C:\lab-attack\ATA090\run.cmd
2026-11-09T18:22:48Z t1=2026-11-09T18:22:48Z

evidencia_local:
  ata=ATA090
  tecnica=T1498.002
  fuente=manual
  t0=2026-11-09T18:22:47Z
  t1=2026-11-09T18:22:48Z
  amplificador=127.0.0.1:5353
  victima=127.0.0.2:5354
  consultas=100
  sent_bytes=6400
  recv_bytes=409600
  ratio=64

VEREDICTO: EFECTO DEMOSTRADO (sent=6400 recv=409600 ratio=64)
```

**Iter 2** (`sha256=5d26ec60025476e411fa35e68a4c423fbaa33150f0dee4ce183b86fd76af70ec`):

```text
# ATA090 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T18:26:33Z t0=2026-11-09T18:26:33Z run=cmd /c C:\lab-attack\ATA090\run.cmd
2026-11-09T18:26:37Z t1=2026-11-09T18:26:37Z

evidencia_local:
  ata=ATA090
  tecnica=T1498.002
  fuente=manual
  t0=2026-11-09T18:26:37Z
  t1=2026-11-09T18:26:37Z
  amplificador=127.0.0.1:5353
  victima=127.0.0.2:5354
  consultas=100
  sent_bytes=6400
  recv_bytes=409600
  ratio=64

VEREDICTO: EFECTO DEMOSTRADO (sent=6400 recv=409600 ratio=64)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA090_iter1-Detalle.csv` | 23 | `5fcc8b00910d024fd042fc5e65b1b274a445648c7f632fbaf493b42318a58b64` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA090_iter2-Detalle.csv` | 22 | `170cd4e8eda6ac7550d98aa7b498e07744330f89fa8fea1f84ea8711187bc05b` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 23 | **6** | 3 | 8 | **0** | 6 | 23 | 0 | 0 | 0 |
| 2 | 22 | **6** | 3 | 8 | **0** | 5 | 22 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T18:22:46.096Z` `rule_id=67027` |
| 2 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T18:26:35.271Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 6 vs 6;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA090** es **manual**: amplificador UDP `127.0.0.1:5353` + victima `127.0.0.2:5354`; **100 consultas de 64 B -> 4 KB** (~400 KB).
2. **Sin spoofing**; el "tercero" es la 2.a direccion loopback. `ReuseAddress` por el mDNS del sistema.
