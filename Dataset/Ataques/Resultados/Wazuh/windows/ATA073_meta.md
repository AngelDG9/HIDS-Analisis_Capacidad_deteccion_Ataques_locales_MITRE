---
fase: 3b
bloque: B1
tanda: B1.3
ata_id: ATA073
tecnica: T1056.001
tactica: Collection
sistema: windows
canal: S1
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA073 - T1056.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.3**. `esperado` **pre-registrado y sellado** en `c0c1058`;
> `sha256` verificado antes de cada `t0`. Canal **S1** (tarea programada `TFG-Attack-ATA073`, `InteractiveToken`, `UserId=angel`, disparo `t0+30 s`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA073** |
| Tecnica | **T1056.001** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - S1 |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `d9b633ca-8efb-45e6-b838-70f595c6ae26` |
| Adaptacion | ART d9b633ca -> GetAsyncKeyState + keybd_event con tfg-key-2026 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1056.001-Keylogging/` |
| `sha256` ataque | `33b36ed5d128e5281d6bd587521e6e2f689a37bb8f692dfbff139b313ebb1eeb` |
| `sha256` esperado | `2aebf1dffd10228f3e5204ac92b327a5249a8c76a2bbd0273ff49e88e07cc263` |
| C0 | `Soporte/Ataques/c0/windows/ATA073_c0.md` (`sha256=5fa8e14ecdc391c73583af41c50badaf0e8daa71a4d7b5b4499c5c2bd381f776`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-gui`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- **Sin red**: no se levantan servicios del host.

## 3.1 Canal S1 (tarea programada)

- Tarea `TFG-Attack-ATA073` creada **antes** de `t0` y borrada tras `t1`.
- Principal verificado: `LogonType: Interactive`, `UserId: angel` (`s1_task_principal.txt`).
- Accion: `cmd.exe /c C:\lab-attack\ATA073\run.cmd`; disparo `t0+30 s`.
- Sesion 1 `console` con autologon `angel` confirmada antes de `t0`.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T10:15:09Z` | `2026-11-09T10:16:00Z` | 51 s | 381 | **102** | `67027,92027,92032,92052,92213` | 17 |
| 2 | `2026-11-09T10:20:08Z` | `2026-11-09T10:21:00Z` | 52 s | 402 | **102** | `67027,92027,92032,92052,92213` | 17 |

## 5. Comando ejecutado (literal)

```text
S1: cmd.exe /c C:\lab-attack\ATA073\run.cmd (tarea TFG-Attack-ATA073)
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA073_iter{1,2}/efecto.txt`: key.log con secuencia completa; cadena_detectada=True.

**Iter 1** (`sha256=5f3ad5368ea2dce64bba694da047863d68eaa8876f9adafc420baa7b4d2bb814`):

```text
# ATA073 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T10:15:09Z t0=2026-11-09T10:15:09Z run=cmd /c C:\lab-attack\ATA073\run.cmd
2026-11-09T10:16:00Z t1=2026-11-09T10:16:00Z

evidencia_local:
  ata=ATA073
  tecnica=T1056.001
  fuente=ART_adaptado
  guid=d9b633ca-8efb-45e6-b838-70f595c6ae26
  t0=2026-11-09T10:15:38Z
  t1=2026-11-09T10:15:58Z
  seed=tfg-key-2026
  secuencia=54,46,47,BD,4B,45,59,BD,32,30,32,36
  cadena_detectada=True

VEREDICTO: EFECTO DEMOSTRADO (key.log con la secuencia completa; cadena_detectada=True)
```

**Iter 2** (`sha256=3076dc83bddc78b40c49b6f651a721b11670f4b76e847a1190df17dc22aa9f30`):

```text
# ATA073 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T10:20:08Z t0=2026-11-09T10:20:08Z run=cmd /c C:\lab-attack\ATA073\run.cmd
2026-11-09T10:21:00Z t1=2026-11-09T10:21:00Z

evidencia_local:
  ata=ATA073
  tecnica=T1056.001
  fuente=ART_adaptado
  guid=d9b633ca-8efb-45e6-b838-70f595c6ae26
  t0=2026-11-09T10:20:39Z
  t1=2026-11-09T10:20:59Z
  seed=tfg-key-2026
  secuencia=54,46,47,BD,4B,45,59,BD,32,30,32,36
  cadena_detectada=True

VEREDICTO: EFECTO DEMOSTRADO (key.log con la secuencia completa; cadena_detectada=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA073_iter1-Detalle.csv` | 381 | `5d78f42e7cc2c1746802b24658e086d5698e3919d012653d5b337da212611925` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA073_iter2-Detalle.csv` | 402 | `7d6095b0b7639a787ba7d96df8bd57cf8ee8dbebe4cf1fe516caa043b9ca3164` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 381 | **102** | 75 | 193 | **0** | 11 | 381 | 0 | 0 | 0 |
| 2 | 402 | **102** | 75 | 214 | **0** | 11 | 402 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 102 | 5 -> `67027,92027,92032,92052,92213` | `2026-11-09T10:15:10.429Z` `rule_id=92052` |
| 2 | 102 | 5 -> `67027,92027,92032,92052,92213` | `2026-11-09T10:20:09.532Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052', '92213'] == ['67027', '92027', '92032', '92052', '92213']`; recuento 102 vs 102;
margen `max(2, 10%*n1)=10.2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5***: deteccion por proceso; sin capa de red ni de recursos.
2. **Canal**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
5. **S1**: el arranque/sesion interactiva genera ruido de proceso que infla `#Alertas`; el conjunto de `rule_id` de deteccion se mantiene y el TPR no cambia.
