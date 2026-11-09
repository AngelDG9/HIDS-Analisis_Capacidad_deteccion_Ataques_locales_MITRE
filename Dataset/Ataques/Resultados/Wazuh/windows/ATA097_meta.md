---
fase: 3b
bloque: B2
tanda: B2.2
ata_id: ATA097
tecnica: T1565.003
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA097 - T1565.003 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.2**. `esperado` **pre-registrado y sellado** en `a2eca10`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA097** |
| Tecnica | **T1565.003** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | WriteProcessMemory sobre proceso PowerShell de juguete (ATA097_toy.ps1); solo ese PID |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1565.003-Runtime_Data_Manipulation/` |
| `sha256` ataque | `acb8d9a627cc00bb368726110e4f1cb6dba646c9d21a83bdd5de79f65c901b56` |

| `sha256` toy | `c207f3c0a27a9dbe366d75cfba21f7a4698b6d748478cf260b323e62dfe58705` |
| `sha256` esperado | `08c2b0db2141947c3f56e142ccd4dfefa844b418d8f26b857ba21faba2916c34` |
| C0 | `Soporte/Ataques/c0/windows/ATA097_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T19:58:40Z` | `2026-11-09T19:58:43Z` | 3 s | 39 | **8** | `67027,92032,92052,92213` | 14 |
| 2 | `2026-11-09T20:02:31Z` | `2026-11-09T20:02:34Z` | 3 s | 39 | **8** | `67027,92032,92052,92213` | 14 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA097\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA097_iter{1,2}/efecto.txt`: cadena TFG-ORIGINAL-STRING -> TFG-MANIPULATED-STRING leida por el toy.

**Iter 1** (`sha256=c9fb2da19aa53f4fb5d46389c51cf2bbb201763f6d2d9c2e69241fed01f0deb5`):

```text
# ATA097 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T19:58:40Z t0=2026-11-09T19:58:40Z run=cmd /c C:\lab-attack\ATA097\run.cmd
2026-11-09T19:58:43Z t1=2026-11-09T19:58:43Z

evidencia_local:
  ata=ATA097
  tecnica=T1565.003
  fuente=manual
  t0=2026-11-09T19:58:41Z
  t1=2026-11-09T19:58:43Z
  pid=4796
  write_ok=True
  original=TFG-ORIGINAL-STRING
  manipulated=TFG-MANIPULATED-STRING
  ultima_lectura=TFG-MANIPULATED-STRING
  alterado=True

toy_out.txt (ultimas lecturas del proceso de juguete):
  TFG-MANIPULATED-STRING
  TFG-MANIPULATED-STRING
  TFG-MANIPULATED-STRING
  TFG-MANIPULATED-STRING

VEREDICTO: EFECTO DEMOSTRADO (WriteProcessMemory write_ok=True; ultima_lectura=TFG-MANIPULATED-STRING)
```

**Iter 2** (`sha256=6790a31d1ad08e5c2d8de07422c44a5faa6cbb1bda747517edd57a0a0d815b74`):

```text
# ATA097 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T20:02:31Z t0=2026-11-09T20:02:31Z run=cmd /c C:\lab-attack\ATA097\run.cmd
2026-11-09T20:02:34Z t1=2026-11-09T20:02:34Z

evidencia_local:
  ata=ATA097
  tecnica=T1565.003
  fuente=manual
  t0=2026-11-09T20:02:32Z
  t1=2026-11-09T20:02:34Z
  pid=2112
  write_ok=True
  original=TFG-ORIGINAL-STRING
  manipulated=TFG-MANIPULATED-STRING
  ultima_lectura=TFG-MANIPULATED-STRING
  alterado=True

toy_out.txt (ultimas lecturas del proceso de juguete):
  TFG-MANIPULATED-STRING
  TFG-MANIPULATED-STRING
  TFG-MANIPULATED-STRING
  TFG-MANIPULATED-STRING

VEREDICTO: EFECTO DEMOSTRADO (WriteProcessMemory write_ok=True; ultima_lectura=TFG-MANIPULATED-STRING)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA097_iter1-Detalle.csv` | 39 | `5444285eb9a60ece702f9ec493e4bdbc14002e4f413721a573d2f95b65aed9c8` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA097_iter2-Detalle.csv` | 39 | `cbce3f7bfd75e25a00894cf6c6126e6bf3617d33fca49addb7dfe432928421da` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 39 | **8** | 3 | 12 | **0** | 16 | 39 | 0 | 0 | 0 |
| 2 | 39 | **8** | 3 | 12 | **0** | 16 | 39 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 8 | 4 -> `67027,92032,92052,92213` | `2026-11-09T19:58:41.578Z` `rule_id=67027` |
| 2 | 8 | 4 -> `67027,92032,92052,92213` | `2026-11-09T20:02:32.435Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052', '92213'] == ['67027', '92032', '92052', '92213']`; recuento 8 vs 8;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA097** es **manual**: `WriteProcessMemory` (P/Invoke) sobre un **proceso PowerShell de juguete** (`ATA097_toy.ps1`); la cadena `TFG-ORIGINAL-STRING` se sobrescribe con `TFG-MANIPULATED-STRING` y el proceso la imprime. Pareja Windows de **ATA036**.
2. **Fix de ejecucion**: el primer intento de iter1 (19:52:42) fallo con `GUARDARRAIL: toy no arranco` porque `[UIntPtr]256` no es convertible en PowerShell 5.1; se corrigio el toy a `[UIntPtr]::new(256)` (y `::new(0)` en `VirtualFree`) y se archivo esa iteracion fuera del repo. Las iteraciones validas son las de **19:58:40** y **20:02:31**. El `esperado` no se toco.
3. Guardarrail: **solo** el PID del proceso de juguete (`powershell.exe` con `ATA097_toy.ps1`); nunca `lsass`, `winlogon`, `services`.
4. El efecto no es deteccion: se prueba en `efecto.txt` y `toy_out.txt`.
