---
fase: 3b
bloque: B1
tanda: B1.2
ata_id: ATA062
tecnica: T1485
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA062 - T1485 Data Destruction (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.2**. `esperado` **pre-registrado y sellado** en `7bce82d`;
> `sha256` verificado antes de cada `t0`. Canal **SSH**; token **High** (`S-1-16-12288`).
> **Sin secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA062** |
| Técnica | **T1485 - Data Destruction** |
| Táctica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Vía | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `476419b5-aebf-4366-a131-ae3e8dae5fc2` |
| Adaptación | SDelete -> sobrescritura nativa con PowerShell + borrado de 5 ficheros de juguete |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1485-Data_Destruction/` |
| `sha256` ataque | `901f52a0685987110bb1324ac5030197322c34de7199da4819230df917e59ff7` |
| `sha256` esperado | `5944d1292c921631be5131e37d28542fcc0730dc06084d61ccee1ce666948d73` |
| C0 | `Soporte/Ataques/c0/windows/ATA062_c0.md` (`sha256=56f0d5c96cce6e5f38c9b03dd895ba5acc25d96b4bcbd7d32c486b526d0fa7c8`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteración; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | detección | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T21:58:37Z` | `2026-11-08T21:58:41Z` | 4 s | 30 | **5** | `67027,92032,92052` | 15 |
| 2 | `2026-11-08T22:02:39Z` | `2026-11-08T22:02:42Z` | 3 s | 29 | **5** | `67027,92032,92052` | 14 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA062\run.cmd"
```

## 6. Prueba de efecto (no es detección)

`Logs/ATA062_iter{1,2}/efecto.txt`: 5/5 ficheros sobrescritos con ceros y borrados; existe_after=0.

**Iter 1** (`sha256=4a4c10719a3d21020115cfdd77af9bb4f7e58ea1c6eb7a58fc5cfd2d0f1405d1`):

```text
  existe_after=0
  sha256_antes_toy_1.txt=2c932e9a8f578074adb6bc84ca0d6ebbc26707396c143c85d8099297c427f262
  sha256_antes_toy_2.txt=c209df8a4ca8541d3c8ad7944a2ac5f4fa2d8f79e716d82085b326fb032f2653
  sha256_antes_toy_3.txt=0966663c95f34302413b21a44f2359dbaa2309fcc240ea9be0fddb8b0aa72b1b
  sha256_antes_toy_4.txt=012bb124cdfbd01fb3388b138244a7825c27a70367d1ab0b0e4c40d13bc7a628
  sha256_antes_toy_5.txt=3604c34d7fd0d0b558c6146def3b73352be60cd09dae76c8c87c6da129a1af54

VEREDICTO: EFECTO DEMOSTRADO (5/5 sobrescritos, 5/5 borrados, existe_after=0)
```

**Iter 2** (`sha256=8027e845948baf3d9267a736cb74cbb8c40b248a419f68d198e59f8a1b7c4ebb`):

```text
  existe_after=0
  sha256_antes_toy_1.txt=2c932e9a8f578074adb6bc84ca0d6ebbc26707396c143c85d8099297c427f262
  sha256_antes_toy_2.txt=c209df8a4ca8541d3c8ad7944a2ac5f4fa2d8f79e716d82085b326fb032f2653
  sha256_antes_toy_3.txt=0966663c95f34302413b21a44f2359dbaa2309fcc240ea9be0fddb8b0aa72b1b
  sha256_antes_toy_4.txt=012bb124cdfbd01fb3388b138244a7825c27a70367d1ab0b0e4c40d13bc7a628
  sha256_antes_toy_5.txt=3604c34d7fd0d0b558c6146def3b73352be60cd09dae76c8c87c6da129a1af54

VEREDICTO: EFECTO DEMOSTRADO (5/5 sobrescritos, 5/5 borrados, existe_after=0)
```

## 7. Ventana extraída

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA062_iter1-Detalle.csv` | 30 | `84752f81a129844a67c81d13ddc06b7edc013cf33f2250e96a9a0320e55ab795` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA062_iter2-Detalle.csv` | 29 | `7966e17c4e3c3f567d9b768f6dfbddec453a783af21677922b725ae81e1fc4c8` |

## 8. Resultado (métrica v1)

| Iter | filas | detección | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 30 | **5** | 3 | 7 | **0** | 15 | 30 | 0 | 0 | 0 |
| 2 | 29 | **5** | 3 | 7 | **0** | 14 | 29 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T21:58:38.930Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:02:40.743Z` `rule_id=92052` |

- Detección principal: procesos del ataque anclados por `win_command_line` a la carpeta.
- **El efecto no es detección**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteración - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5′**: detección por proceso; sin capa de red ni de recursos.
2. **Canal SSH**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Elevación**: token SSH **High**; no se necesitó tarea `Highest`.
6. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
