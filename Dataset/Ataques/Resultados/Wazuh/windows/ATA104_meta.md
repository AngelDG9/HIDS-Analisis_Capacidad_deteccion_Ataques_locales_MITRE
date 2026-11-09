---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA104
tecnica: T1056.002
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA104 - T1056.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA104** |
| Tecnica | **T1056.002** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `2b162bfd-0928-4d4c-9ec3-4d9f88374b52` |
| Adaptacion | formulario WinForms + SendKeys TFG-GUI-TEXT + captura PNG (S1) |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1056.002-GUI_Input_Capture/` |
| `sha256` ataque | `a49d16327ff5ce2be4545a575437a64fe37fd3cefb9a63807bbee27c26bf5511` |
| `sha256` esperado | `6874c4a274f02a2acb66c469223a96d84438a1799ec8c0604cf6e2aaf02a22b3` |
| C0 | `Soporte/Ataques/c0/windows/ATA104_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-gui`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- S1: tarea `TFG-Attack-ATA104` (`InteractiveToken`, trigger `t0+30 s`).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T22:15:37Z` | `2026-11-09T22:16:16Z` | 39 s | 279 | **3** | `67027,92052` | 14 |
| 2 | `2026-11-09T22:22:19Z` | `2026-11-09T22:22:56Z` | 37 s | 271 | **3** | `67027,92052` | 14 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA104\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA104_iter{1,2}/efecto.txt`: PNG real + texto TFG-GUI-TEXT.

**Iter 1** (`sha256=983cb19a7dd0145c32c70983c8f5f7067870db37bb979028bea3d99c82919559`):

```text
# ATA104 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T22:15:37Z t0=2026-11-09T22:15:37Z run=cmd /c C:\lab-attack\ATA104\run.cmd
2026-11-09T22:16:16Z t1=2026-11-09T22:16:16Z

evidencia_local:
  ata=ATA104
  tecnica=T1056.002
  fuente=ART_adaptado
  t0=2026-11-09T22:16:12Z
  t1=2026-11-09T22:16:14Z
  png=C:\lab-attack\ATA104\captura.png
  png_bytes=137416
  texto=TFG-GUI-TEXT
  captura_ok=True

VEREDICTO: EFECTO DEMOSTRADO (png_bytes=137416; texto=TFG-GUI-TEXT)
```

**Iter 2** (`sha256=3c13e2e8456f3d3b84d36390c5a69cbb5e374c4b14af13b541bbe34acdafae52`):

```text
# ATA104 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T22:22:19Z t0=2026-11-09T22:22:19Z run=cmd /c C:\lab-attack\ATA104\run.cmd
2026-11-09T22:22:56Z t1=2026-11-09T22:22:56Z

evidencia_local:
  ata=ATA104
  tecnica=T1056.002
  fuente=ART_adaptado
  t0=2026-11-09T22:22:53Z
  t1=2026-11-09T22:22:55Z
  png=C:\lab-attack\ATA104\captura.png
  png_bytes=137409
  texto=TFG-GUI-TEXT
  captura_ok=True

VEREDICTO: EFECTO DEMOSTRADO (png_bytes=137409; texto=TFG-GUI-TEXT)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA104_iter1-Detalle.csv` | 279 | `194bdcb77a4dfba82d53b454a6b2c04182cbd864e1a168563c6441da3e567c80` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA104_iter2-Detalle.csv` | 271 | `39b47d8fb16d986861fba607b237e3d08e6c93d7dd6fb91c41e8646babc2b2aa` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 279 | **3** | 57 | 134 | **0** | 85 | 279 | 0 | 0 | 0 |
| 2 | 271 | **3** | 54 | 133 | **0** | 81 | 271 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 3 | 2 -> `67027,92052` | `2026-11-09T22:16:07.657Z` `rule_id=92052` |
| 2 | 3 | 2 -> `67027,92052` | `2026-11-09T22:22:49.930Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92052'] == ['67027', '92052']`; recuento 3 vs 3;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA104** es **ART adaptado**: `guid=2b162bfd-0928-4d4c-9ec3-4d9f88374b52`, `atomics/T1056.002/T1056.002.yaml`, commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. El atomic usa `PromptForCredential`; aqui un **formulario WinForms** + `SendKeys` `TFG-GUI-TEXT` + captura PNG (`png_bytes>0`, `texto=TFG-GUI-TEXT`). Pareja de **ATA053**.
2. **S1**: snapshot `lab-listo-windows-ataques-gui` (autologon); tarea `TFG-Attack-ATA104` (`InteractiveToken`, trigger `t0+30 s`) que ejecuta `cmd /c C:\lab-attack\ATA104\run.cmd`; el runner la crea/espera/borra. `preparar_tarea_s1.ps1` es el helper manual.
3. **Correccion de medicion**: el runner S1 sondea `efecto_local.txt` cada 2 s con `cmd /c if exist C:\lab-attack\ATA104\evidencias\efecto_local.txt echo OK`; ese comando casa el ancla `*lab-attack*ATA104*` y generaba 72/68 filas `deteccion` falsas. Se reclasificaron a `artefacto_ataque` (`motivo=poll_runner_s1`) en `-Audited.csv`; el `-Audited_raw.csv` conserva el conteo bruto. **Deteccion corregida: 3** (raw 75/71), `rule_id` `67027,92052`.
