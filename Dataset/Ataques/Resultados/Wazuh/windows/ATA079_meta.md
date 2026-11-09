---
fase: 3b
bloque: B1
tanda: B1.4
ata_id: ATA079
tecnica: T1029
tactica: Exfiltration
sistema: windows
canal: S1
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA079 - T1029 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.4**. `esperado` **pre-registrado y sellado** en `7e3e872`;
> `sha256` verificado antes de cada `t0`. Canal **S1** (tarea programada `TFG-Attack-ATA079`, `InteractiveToken`, `UserId=angel`, disparo `t0+30 s`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA079** |
| Tecnica | **T1029** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - S1 |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | schtasks /it + curl POST al sink 9090 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1029-Scheduled_Transfer/` |
| `sha256` ataque | `fe6c3db3d40f95b270d3624a7a9801edca996427af0b97fbda94e5b0683aa871` |
| `sha256` esperado | `e3ba78335ef4743d217dbee584444495f85782b08f37811ac7c5b76e78ddc05e` |
| C0 | `Soporte/Ataques/c0/windows/ATA079_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-gui`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- Sink del HOST `192.168.65.1:9090/9091` (excepto ATA078/080, sin red).

## 3.1 Canal S1 (tarea programada)

- Tarea `TFG-Attack-ATA079` creada **antes** de `t0` y borrada tras `t1`.
- Principal verificado: `LogonType: Interactive`, `UserId: angel` (`s1_task_principal.txt`).
- Accion: `cmd.exe /c C:\lab-attack\ATA079\run.cmd`; disparo `t0+30 s`.
- La tarea de transferencia `TFG-ATA079` se crea dentro del script y se borra al final.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T13:17:54Z` | `2026-11-09T13:19:01Z` | 67 s | 488 | **132** | `67027,92032,92052` | 31 |
| 2 | `2026-11-09T13:23:55Z` | `2026-11-09T13:25:00Z` | 65 s | 477 | **128** | `67027,92032,92052` | 34 |

## 5. Comando ejecutado (literal)

```text
S1: cmd.exe /c C:\lab-attack\ATA079\run.cmd (tarea TFG-Attack-ATA079)
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA079_iter{1,2}/efecto.txt`: sink.log POST + Last Run Time.

**Iter 1** (`sha256=b474191169c89f5975982859a0b7370861c563bc12fe77b9c69a1aa2f2472e41`):

```text
# ATA079 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T13:17:54Z t0=2026-11-09T13:17:54Z run=cmd /c C:\lab-attack\ATA079\run.cmd
2026-11-09T13:19:01Z t1=2026-11-09T13:19:01Z

evidencia_local:
  ata=ATA079
  tecnica=T1029
  fuente=manual
  t0=2026-11-09T13:18:24Z
  t1=2026-11-09T13:19:01Z
  task=TFG-ATA079
  trigger=14:19
  last_run=11/9/2026 2:19:00 PM
  post=C:\lab-attack\ATA079\post.cmd
  payload=C:\lab-attack\ATA079\payload.txt

sink.log (HOST):
  2026-11-09T13:19:00Z POST /upload/ATA079 from=192.168.65.130 len=1631 sha256=9418ce90f2d37772a51c6d0b0c354d39df1d8a9b169cd5500a4228186852c491 content_type=application/x-www-form-urlencoded

VEREDICTO: EFECTO DEMOSTRADO (POST /upload/ATA079; last_run=11/9/2026 2:19:00 PM)
```

**Iter 2** (`sha256=c1e483c0a9bc6a3f1ab2903c1a81edb279fa9944596499a0d022190767ae5458`):

```text
# ATA079 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T13:23:55Z t0=2026-11-09T13:23:55Z run=cmd /c C:\lab-attack\ATA079\run.cmd
2026-11-09T13:25:00Z t1=2026-11-09T13:25:00Z

evidencia_local:
  ata=ATA079
  tecnica=T1029
  fuente=manual
  t0=2026-11-09T13:24:25Z
  t1=2026-11-09T13:25:00Z
  task=TFG-ATA079
  trigger=14:25
  last_run=11/9/2026 2:25:00 PM
  post=C:\lab-attack\ATA079\post.cmd
  payload=C:\lab-attack\ATA079\payload.txt

sink.log (HOST):
  2026-11-09T13:25:00Z POST /upload/ATA079 from=192.168.65.130 len=1631 sha256=9418ce90f2d37772a51c6d0b0c354d39df1d8a9b169cd5500a4228186852c491 content_type=application/x-www-form-urlencoded

VEREDICTO: EFECTO DEMOSTRADO (POST /upload/ATA079; last_run=11/9/2026 2:25:00 PM)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA079_iter1-Detalle.csv` | 488 | `5cfcfc35bac5f9835893971396274851c81479c88afe313fbcbc99abf13f66c2` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA079_iter2-Detalle.csv` | 477 | `be75839f8afd496b16577513b5fc5f361b7db57d942ad00af87268806cebf908` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 488 | **132** | 96 | 233 | **0** | 27 | 488 | 0 | 0 | 0 |
| 2 | 477 | **128** | 93 | 229 | **0** | 27 | 477 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 132 | 3 -> `67027,92032,92052` | `2026-11-09T13:17:55.739Z` `rule_id=92052` |
| 2 | 128 | 3 -> `67027,92032,92052` | `2026-11-09T13:23:56.893Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt` (sink.log / git log / dump.sql).
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 132 vs 128;
margen `max(2, 10%*n1)=13.2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA079** es **manual**: el clon ART `388942ad` no trae T1029; se implementa `schtasks /create /it` + `post.cmd` con `curl.exe` POST al sink 9090.
2. Canal **S1**: tarea `TFG-Attack-ATA079` (`InteractiveToken`, `UserId=angel`, disparo `t0+30 s`), creada antes de `t0` y borrada tras `t1`; la tarea de transferencia `TFG-ATA079` se crea dentro y se borra al final. `Last Run Time` distinto de `N/A` y `sink.log` con `POST /upload/ATA079`.
3. El ruido de sesion/arranque S1 infla `#Alertas`; el conjunto de `rule_id` de deteccion se mantiene.
