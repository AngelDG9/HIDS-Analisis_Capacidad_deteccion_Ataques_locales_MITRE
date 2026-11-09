---
fase: 3b
bloque: B1
tanda: B1.3
ata_id: ATA072
tecnica: T1115
tactica: Collection
sistema: windows
canal: S1
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA072 - T1115 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.3**. `esperado` **pre-registrado y sellado** en `c0c1058`;
> `sha256` verificado antes de cada `t0`. Canal **S1** (tarea programada `TFG-Attack-ATA072`, `InteractiveToken`, `UserId=angel`, disparo `t0+30 s`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA072** |
| Tecnica | **T1115** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - S1 |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `d6dc21af-bec9-4152-be86-326b6babd416` |
| Adaptacion | ART d6dc21af -> Get-Clipboard con seed TFG-CLIP-2026-B1.3 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1115-Clipboard_Data/` |
| `sha256` ataque | `5aeb81897a583696015b197cc7f39ef25de13ccb2705e811d81091af560fdfb7` |
| `sha256` esperado | `0081c78befeda0943be41a2316cef7fb44489b4cf87edbd2f8cda431e58a03f8` |
| C0 | `Soporte/Ataques/c0/windows/ATA072_c0.md` (`sha256=09b6351ae0dfa4975d247ca9f5ab61032ec2e51fa327d2f26249089ab784956e`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-gui`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- **Sin red**: no se levantan servicios del host.

## 3.1 Canal S1 (tarea programada)

- Tarea `TFG-Attack-ATA072` creada **antes** de `t0` y borrada tras `t1`.
- Principal verificado: `LogonType: Interactive`, `UserId: angel` (`s1_task_principal.txt`).
- Accion: `cmd.exe /c C:\lab-attack\ATA072\run.cmd`; disparo `t0+30 s`.
- Sesion 1 `console` con autologon `angel` confirmada antes de `t0`.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T09:53:28Z` | `2026-11-09T09:53:59Z` | 31 s | 241 | **64** | `67027,91824,92032,92052` | 12 |
| 2 | `2026-11-09T09:58:38Z` | `2026-11-09T09:59:09Z` | 31 s | 241 | **64** | `67027,91824,92032,92052` | 12 |

## 5. Comando ejecutado (literal)

```text
S1: cmd.exe /c C:\lab-attack\ATA072\run.cmd (tarea TFG-Attack-ATA072)
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA072_iter{1,2}/efecto.txt`: clipboard leido == seed TFG-CLIP-2026-B1.3.

**Iter 1** (`sha256=58e2052a0cdc14941430fba669aa76fb1e122cbc8892fe84d0c14b3c97727307`):

```text
# ATA072 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T09:53:28Z t0=2026-11-09T09:53:28Z run=cmd /c C:\lab-attack\ATA072\run.cmd
2026-11-09T09:53:59Z t1=2026-11-09T09:53:59Z

evidencia_local:
  ata=ATA072
  tecnica=T1115
  fuente=ART_adaptado
  guid=d6dc21af-bec9-4152-be86-326b6babd416
  t0=2026-11-09T09:53:57Z
  t1=2026-11-09T09:53:58Z
  seed=TFG-CLIP-2026-B1.3
  leido=TFG-CLIP-2026-B1.3
  coincide=True

VEREDICTO: EFECTO DEMOSTRADO (clipboard leido == seed TFG-CLIP-2026-B1.3)
```

**Iter 2** (`sha256=edcc710d3cfb9de4a87ba7cd858f4a94f803a03a14fa5df08ada6c4130f1bf23`):

```text
# ATA072 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T09:58:38Z t0=2026-11-09T09:58:38Z run=cmd /c C:\lab-attack\ATA072\run.cmd
2026-11-09T09:59:09Z t1=2026-11-09T09:59:09Z

evidencia_local:
  ata=ATA072
  tecnica=T1115
  fuente=ART_adaptado
  guid=d6dc21af-bec9-4152-be86-326b6babd416
  t0=2026-11-09T09:59:07Z
  t1=2026-11-09T09:59:07Z
  seed=TFG-CLIP-2026-B1.3
  leido=TFG-CLIP-2026-B1.3
  coincide=True

VEREDICTO: EFECTO DEMOSTRADO (clipboard leido == seed TFG-CLIP-2026-B1.3)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA072_iter1-Detalle.csv` | 241 | `87e0ce6127928eff14477928b2e0fab14e7aac0a2418408f925f03e5198aefb5` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA072_iter2-Detalle.csv` | 241 | `4af8cc966def5c236b74108b69d9614ca517b1eccd6626e30396e4170a5d3f4a` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 241 | **64** | 48 | 123 | **0** | 6 | 241 | 0 | 0 | 0 |
| 2 | 241 | **64** | 48 | 123 | **0** | 6 | 241 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 64 | 4 -> `67027,91824,92032,92052` | `2026-11-09T09:53:29.378Z` `rule_id=92032` |
| 2 | 64 | 4 -> `67027,91824,92032,92052` | `2026-11-09T09:58:39.134Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '91824', '92032', '92052'] == ['67027', '91824', '92032', '92052']`; recuento 64 vs 64;
margen `max(2, 10%*n1)=6.4` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5***: deteccion por proceso; sin capa de red ni de recursos.
2. **Canal**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
5. **S1**: el arranque/sesion interactiva genera ruido de proceso que infla `#Alertas`; el conjunto de `rule_id` de deteccion se mantiene y el TPR no cambia.
