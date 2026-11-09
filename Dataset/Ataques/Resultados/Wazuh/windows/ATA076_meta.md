---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA076
tecnica: T1048.002
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA076 - T1048.002 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA076** |
| Tecnica | **T1048.002** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | RSA-2048 OAEP-SHA256 + POST al sink 9090 + descifrado local |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1048.002-Exfiltration_Over_Asymmetric_Encrypted_Non-C2_Protocol/` |
| `sha256` ataque | `45233a0abbc60ccb5c279268dd0efe0f36ca350f22e39e8f42c7680ea341a236` |
| `sha256` esperado | `f95096f6d1abc1a2a259d103f21baec7dd473de392285140f71b000e7b545da9` |
| C0 | `Soporte/Ataques/c0/windows/ATA076_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T12:14:26Z` | `2026-11-09T12:14:28Z` | 2 s | 17 | **5** | `67027,92032,92052` | 3 |
| 2 | `2026-11-09T12:18:22Z` | `2026-11-09T12:18:23Z` | 1 s | 18 | **5** | `67027,92032,92052` | 3 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA076\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA076_iter{1,2}/efecto.txt`: sink.log POST + sha256_post + descifrado_ok=True.

**Iter 1** (`sha256=fceab0ffe13c3aff1b9395b5b764009c400107b7f8f4e0257297d5b847a9f6f1`):

```text
# ATA076 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T12:14:26Z t0=2026-11-09T12:14:26Z run=cmd /c C:\lab-attack\ATA076\run.cmd
2026-11-09T12:14:28Z t1=2026-11-09T12:14:28Z

evidencia_local:
  ata=ATA076
  tecnica=T1048.002
  fuente=manual
  t0=2026-11-09T12:14:27Z
  t1=2026-11-09T12:14:28Z
  url=http://192.168.65.1:9090/upload/ATA076
  bytes_cifrado=256
  sha256_post=1613a546aaa6bcb7c9e6b2225fc45e4e6ba89639fed26caf2b84f699bfbdfeac
  descifrado_ok=True
  resultado=HTTP=200

sink.log (HOST):
  2026-11-09T12:14:28Z POST /upload/ATA076 from=192.168.65.130 len=344 sha256=1613a546aaa6bcb7c9e6b2225fc45e4e6ba89639fed26caf2b84f699bfbdfeac content_type=application/octet-stream

VEREDICTO: EFECTO DEMOSTRADO (POST /upload/ATA076; sha256_post; descifrado_ok=True)
```

**Iter 2** (`sha256=5b7edb9f072702ddae9e05ef659cec04f9ee27f3e336f6a99734fc3405ca6e79`):

```text
# ATA076 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T12:18:22Z t0=2026-11-09T12:18:22Z run=cmd /c C:\lab-attack\ATA076\run.cmd
2026-11-09T12:18:23Z t1=2026-11-09T12:18:23Z

evidencia_local:
  ata=ATA076
  tecnica=T1048.002
  fuente=manual
  t0=2026-11-09T12:18:23Z
  t1=2026-11-09T12:18:23Z
  url=http://192.168.65.1:9090/upload/ATA076
  bytes_cifrado=256
  sha256_post=7f9d9d414c393112f19a2fbc8e3dbec6165fb0d0e4b77b1b0d58246f38fa3b4c
  descifrado_ok=True
  resultado=HTTP=200

sink.log (HOST):
  2026-11-09T12:18:23Z POST /upload/ATA076 from=192.168.65.130 len=344 sha256=7f9d9d414c393112f19a2fbc8e3dbec6165fb0d0e4b77b1b0d58246f38fa3b4c content_type=application/octet-stream

VEREDICTO: EFECTO DEMOSTRADO (POST /upload/ATA076; sha256_post; descifrado_ok=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA076_iter1-Detalle.csv` | 17 | `bda011ef52ee4d35368b2d59493d181d0d1e0669d4205ffcdf087efb2a7780ad` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA076_iter2-Detalle.csv` | 18 | `8d9cd03d0a7f5500ee10c5393cd15de5d394469d5b4dd0b6cb2b5890f3b90ed7` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 17 | **5** | 3 | 6 | **0** | 3 | 17 | 0 | 0 | 0 |
| 2 | 18 | **5** | 3 | 7 | **0** | 3 | 18 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T12:14:27.892Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T12:18:23.513Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA076** es **manual (mismatch ART)**: la atomica T1048.002 (`1cdf2fb0`) usa `curl -F` a `file.io` (internet) y no RSA; se implementa RSA-2048 OAEP-SHA256 + POST al sink 9090 y descifrado local.
2. El sink registra `POST /upload/ATA076 ... sha256=<hash>`; el hash coincide con `sha256_post` y `descifrado_ok=True`.
