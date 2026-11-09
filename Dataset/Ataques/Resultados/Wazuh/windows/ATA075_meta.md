---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA075
tecnica: T1048.001
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA075 - T1048.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA075** |
| Tecnica | **T1048.001** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | AES-256 + TcpClient al sink TCP 9091 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1048.001-Exfiltration_Over_Symmetric_Encrypted_Non-C2_Protocol/` |
| `sha256` ataque | `a8e610831ee47bde3c1e051fffe18e562087f31382447787084ecb87b3573704` |
| `sha256` esperado | `e46cfdaa88a5aadd27f433796615c2828e021e8549c4701c89d713a347548887` |
| C0 | `Soporte/Ataques/c0/windows/ATA075_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T12:06:36Z` | `2026-11-09T12:06:37Z` | 1 s | 41 | **5** | `67027,92032,92052` | 25 |
| 2 | `2026-11-09T12:10:32Z` | `2026-11-09T12:10:33Z` | 1 s | 40 | **5** | `67027,92032,92052` | 25 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA075\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA075_iter{1,2}/efecto.txt`: sink.log TCP + sha256 del criptograma.

**Iter 1** (`sha256=c806a4ab7a27c78190a492d029ffe00376067aff363a019eea550b979fb1835a`):

```text
# ATA075 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T12:06:36Z t0=2026-11-09T12:06:36Z run=cmd /c C:\lab-attack\ATA075\run.cmd
2026-11-09T12:06:37Z t1=2026-11-09T12:06:37Z

evidencia_local:
  ata=ATA075
  tecnica=T1048.001
  fuente=manual
  t0=2026-11-09T12:06:36Z
  t1=2026-11-09T12:06:37Z
  destino=192.168.65.1:9091
  bytes=1536
  sha256_cifrado=b68ded5517ead943dd2e14264cd8e431cff42381efafc95be3547fe955615b76
  aes=256

sink.log (HOST):
  2026-11-09T12:06:37Z TCP from=192.168.65.130 len=1536 sha256=b68ded5517ead943dd2e14264cd8e431cff42381efafc95be3547fe955615b76

VEREDICTO: EFECTO DEMOSTRADO (TCP 9091; 1536 bytes; sha256 del criptograma)
```

**Iter 2** (`sha256=1b3b24c9c5fcb5455ff90e92d927942abbfdd26cb79d0d5803dd0810346029f9`):

```text
# ATA075 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T12:10:32Z t0=2026-11-09T12:10:32Z run=cmd /c C:\lab-attack\ATA075\run.cmd
2026-11-09T12:10:33Z t1=2026-11-09T12:10:33Z

evidencia_local:
  ata=ATA075
  tecnica=T1048.001
  fuente=manual
  t0=2026-11-09T12:10:33Z
  t1=2026-11-09T12:10:33Z
  destino=192.168.65.1:9091
  bytes=1536
  sha256_cifrado=b4d6fcd7eaf0972122084e4d1a52d733483cb9286ad2b90a1decfd6ba6c59d2a
  aes=256

sink.log (HOST):
  2026-11-09T12:10:33Z TCP from=192.168.65.130 len=1536 sha256=b4d6fcd7eaf0972122084e4d1a52d733483cb9286ad2b90a1decfd6ba6c59d2a

VEREDICTO: EFECTO DEMOSTRADO (TCP 9091; 1536 bytes; sha256 del criptograma)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA075_iter1-Detalle.csv` | 41 | `244ed725391f00873f5510cac380ce6186356b32f93584e30e52a5049a97d35d` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA075_iter2-Detalle.csv` | 40 | `99059819bff762b836e3e3c046fccef43a54d9f28ca4c1e150dca8be017c0ef5` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 41 | **5** | 3 | 8 | **0** | 25 | 41 | 0 | 0 | 0 |
| 2 | 40 | **5** | 3 | 7 | **0** | 25 | 40 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T12:06:37.648Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T12:10:33.695Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA075** es **manual**: el clon ART `388942ad` no trae una atomica Windows de AES + `TcpClient`; se implementa AES-256 con clave/IV efimeros (no persistidos) y TCP crudo al sink 9091.
2. El sink registra `TCP ... len=1536 sha256=<hash>`; el hash coincide con `sha256_cifrado`.
