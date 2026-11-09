---
fase: 3b
bloque: B1
tanda: B1.3
ata_id: ATA071
tecnica: T1113
tactica: Collection
sistema: windows
canal: S1
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA071 - T1113 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.3**. `esperado` **pre-registrado y sellado** en `c0c1058`;
> `sha256` verificado antes de cada `t0`. Canal **S1** (tarea programada `TFG-Attack-ATA071`, `InteractiveToken`, `UserId=angel`, disparo `t0+30 s`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA071** |
| Tecnica | **T1113** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - S1 |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `e9313014-985a-48ef-80d9-cde604ffc187` |
| Adaptacion | ART e9313014 -> CopyFromScreen a screen.png |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1113-Screen_Capture/` |
| `sha256` ataque | `953805b6c6c49d7a9e616747d0ae1d26c70e1f5a21c9b68b738ef8846dd3bf6c` |
| `sha256` esperado | `16477dd3d73f6203fa99a3c6cf82f75265a0d0197e1b31fc3a07e1ee9b1bb47d` |
| C0 | `Soporte/Ataques/c0/windows/ATA071_c0.md` (`sha256=5f03fa3cd0d2a7a0f20e4c3546b271fa775f1438e4e0e04869927ddfa9a736e0`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-gui`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- **Sin red**: no se levantan servicios del host.

## 3.1 Canal S1 (tarea programada)

- Tarea `TFG-Attack-ATA071` creada **antes** de `t0` y borrada tras `t1`.
- Principal verificado: `LogonType: Interactive`, `UserId: angel` (`s1_task_principal.txt`).
- Accion: `cmd.exe /c C:\lab-attack\ATA071\run.cmd`; disparo `t0+30 s`.
- Sesion 1 `console` con autologon `angel` confirmada antes de `t0`.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T09:42:53Z` | `2026-11-09T09:43:32Z` | 39 s | 304 | **75** | `67027,92032,92052` | 13 |
| 2 | `2026-11-09T09:48:40Z` | `2026-11-09T09:49:09Z` | 29 s | 224 | **59** | `67027,92032,92052` | 11 |

## 5. Comando ejecutado (literal)

```text
S1: cmd.exe /c C:\lab-attack\ATA071\run.cmd (tarea TFG-Attack-ATA071)
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA071_iter{1,2}/efecto.txt`: screen.png real (bytes>0, 1024x768).

**Iter 1** (`sha256=a50c3dcc73c24728ed01a77b04e608264a0f0aa9b7ec962923da48001096eaeb`):

```text
# ATA071 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T09:42:53Z t0=2026-11-09T09:42:53Z run=cmd /c C:\lab-attack\ATA071\run.cmd
2026-11-09T09:43:32Z t1=2026-11-09T09:43:32Z

evidencia_local:
  ata=ATA071
  tecnica=T1113
  fuente=ART_adaptado
  guid=e9313014-985a-48ef-80d9-cde604ffc187
  t0=2026-11-09T09:43:28Z
  t1=2026-11-09T09:43:30Z
  png=C:\lab-attack\ATA071\evidencias\screen.png
  bytes=136813
  width=1024
  height=768

VEREDICTO: EFECTO DEMOSTRADO (screen.png real 136813 bytes, 1024x768)
```

**Iter 2** (`sha256=003344f4722c374db1f3fe88abbff2055b9e0c828a711462c825f75e37ceed00`):

```text
# ATA071 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T09:48:40Z t0=2026-11-09T09:48:40Z run=cmd /c C:\lab-attack\ATA071\run.cmd
2026-11-09T09:49:09Z t1=2026-11-09T09:49:09Z

evidencia_local:
  ata=ATA071
  tecnica=T1113
  fuente=ART_adaptado
  guid=e9313014-985a-48ef-80d9-cde604ffc187
  t0=2026-11-09T09:49:09Z
  t1=2026-11-09T09:49:09Z
  png=C:\lab-attack\ATA071\evidencias\screen.png
  bytes=152829
  width=1024
  height=768

VEREDICTO: EFECTO DEMOSTRADO (screen.png real 152829 bytes, 1024x768)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA071_iter1-Detalle.csv` | 304 | `7cc454fdcaab2ee7a61f9ba6582b00c1fc99464cbcf498ac47151015a5856337` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA071_iter2-Detalle.csv` | 224 | `10d61638e15c3261de8f7500b7476080562bc9e2eb1efa1cb546555b9e33dba3` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 304 | **75** | 57 | 165 | **0** | 7 | 304 | 0 | 0 | 0 |
| 2 | 224 | **59** | 45 | 114 | **0** | 6 | 224 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 75 | 3 -> `67027,92032,92052` | `2026-11-09T09:42:54.662Z` `rule_id=92052` |
| 2 | 59 | 3 -> `67027,92032,92052` | `2026-11-09T09:48:41.721Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`review`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 75 vs 59;
margen `max(2, 10%*n1)=7.5` -> `criterio_recuento_ok=False`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5***: deteccion por proceso; sin capa de red ni de recursos.
2. **Canal**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
5. **S1**: el arranque/sesion interactiva genera ruido de proceso que infla `#Alertas`; el conjunto de `rule_id` de deteccion se mantiene y el TPR no cambia.
