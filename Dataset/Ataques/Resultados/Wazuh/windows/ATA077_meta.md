---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA077
tecnica: T1048.003
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA077 - T1048.003 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA077** |
| Tecnica | **T1048.003** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | texto plano por TcpClient al sink TCP 9091 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1048.003-Exfiltration_Over_Unencrypted_Non-C2_Protocol/` |
| `sha256` ataque | `c76147bced619efd563fc089a18584b413e5a2a5279b26bbc54b8b119068a7c3` |
| `sha256` esperado | `06e91e99c966b1aecc07ac922244832fe1bc4365409591cce2bbc610b0c42856` |
| C0 | `Soporte/Ataques/c0/windows/ATA077_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T12:22:19Z` | `2026-11-09T12:22:20Z` | 1 s | 19 | **5** | `67027,92032,92052` | 4 |
| 2 | `2026-11-09T12:26:18Z` | `2026-11-09T12:26:19Z` | 1 s | 20 | **5** | `67027,92032,92052` | 4 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA077\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA077_iter{1,2}/efecto.txt`: sink.log TCP + sha256 del texto plano.

**Iter 1** (`sha256=a438f2ac396a2a9459b00c506a5d5bf4e0c4eaa85279f3cc1e4b683530b11a26`):

```text
# ATA077 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T12:22:19Z t0=2026-11-09T12:22:19Z run=cmd /c C:\lab-attack\ATA077\run.cmd
2026-11-09T12:22:20Z t1=2026-11-09T12:22:20Z

evidencia_local:
  ata=ATA077
  tecnica=T1048.003
  fuente=manual
  t0=2026-11-09T12:22:20Z
  t1=2026-11-09T12:22:20Z
  destino=192.168.65.1:9091
  bytes=1571
  sha256_plano=9ae8d77ff86721f1df2fae5726450e15ed701b6eb590f2bde1b2e2f7f379d431

sink.log (HOST):
  2026-11-09T12:22:20Z TCP from=192.168.65.130 len=1571 sha256=9ae8d77ff86721f1df2fae5726450e15ed701b6eb590f2bde1b2e2f7f379d431

VEREDICTO: EFECTO DEMOSTRADO (TCP 9091; 1571 bytes; sha256 del texto plano)
```

**Iter 2** (`sha256=a5debac156eec2e9c6b73f729bb55bf82f97d6d942a8aabf95851bb12e7c48f3`):

```text
# ATA077 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T12:26:18Z t0=2026-11-09T12:26:18Z run=cmd /c C:\lab-attack\ATA077\run.cmd
2026-11-09T12:26:19Z t1=2026-11-09T12:26:19Z

evidencia_local:
  ata=ATA077
  tecnica=T1048.003
  fuente=manual
  t0=2026-11-09T12:26:19Z
  t1=2026-11-09T12:26:19Z
  destino=192.168.65.1:9091
  bytes=1571
  sha256_plano=9ae8d77ff86721f1df2fae5726450e15ed701b6eb590f2bde1b2e2f7f379d431

sink.log (HOST):
  2026-11-09T12:26:19Z TCP from=192.168.65.130 len=1571 sha256=9ae8d77ff86721f1df2fae5726450e15ed701b6eb590f2bde1b2e2f7f379d431

VEREDICTO: EFECTO DEMOSTRADO (TCP 9091; 1571 bytes; sha256 del texto plano)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA077_iter1-Detalle.csv` | 19 | `983e248ed6898e6a02b51d08a1fc66134b7c14b91d18974a852ea180438c4a2d` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA077_iter2-Detalle.csv` | 20 | `f5b599916ce5d77adc6a1c964065bedf8dc180d8747a35da6c2dd42f38ce7108` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 19 | **5** | 3 | 7 | **0** | 4 | 19 | 0 | 0 | 0 |
| 2 | 20 | **5** | 3 | 8 | **0** | 4 | 20 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T12:22:20.959Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T12:26:20.131Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA077** es **manual (mismatch ART)**: las atomicas T1048.003 son Linux/ICMP; se implementa texto plano por `TcpClient` al sink 9091.
2. El sink registra `TCP ... len=1571 sha256=<hash>`; el hash coincide con `sha256_plano`.
