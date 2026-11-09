---
fase: 3b
bloque: B1
tanda: B1.3
ata_id: ATA069
tecnica: T1560.001
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA069 - T1560.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.3**. `esperado` **pre-registrado y sellado** en `c0c1058`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA069** |
| Tecnica | **T1560.001** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0` |
| Adaptacion | ART 02ea31cb -> Compress-Archive de 20 ficheros de juguete |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1560.001-Archive_via_Utility/` |
| `sha256` ataque | `088c5dd1bbb3c4c5c7320aaa56a4ca03a6fd253d58dcb56d1a330b1fbd428f5f` |
| `sha256` esperado | `6f3cbfa5673e5883037846b09cb21ce52cd4333e6c4bac3e5ac0654a73537c2b` |
| C0 | `Soporte/Ataques/c0/windows/ATA069_c0.md` (`sha256=03745073f184491eb45b2b62ec7db11808a003bf1b8bae09d14287c676c186d6`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T09:17:29Z` | `2026-11-09T09:17:32Z` | 3 s | 40 | **5** | `67027,92032,92052` | 25 |
| 2 | `2026-11-09T09:21:30Z` | `2026-11-09T09:21:32Z` | 2 s | 39 | **5** | `67027,92032,92052` | 24 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA069\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA069_iter{1,2}/efecto.txt`: datos.zip con 20 entradas, 2275 bytes.

**Iter 1** (`sha256=751c19f12bd0b20bdc83b48d08b954175d375e01d8780756ed078e7dd0171585`):

```text
# ATA069 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T09:17:29Z t0=2026-11-09T09:17:29Z run=cmd /c C:\lab-attack\ATA069\run.cmd
2026-11-09T09:17:32Z t1=2026-11-09T09:17:32Z

evidencia_local:
  ata=ATA069
  tecnica=T1560.001
  fuente=ART_adaptado
  guid=02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0
  t0=2026-11-09T09:17:30Z
  t1=2026-11-09T09:17:32Z
  zip=C:\lab-attack\ATA069\evidencias\datos.zip
  entradas=20
  bytes=2275

VEREDICTO: EFECTO DEMOSTRADO (datos.zip con 20 entradas, 2275 bytes)
```

**Iter 2** (`sha256=80dd7bc081d1c538987fff268b2b0dbffff93d64b0280bc0884bf79c750441e8`):

```text
# ATA069 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T09:21:30Z t0=2026-11-09T09:21:30Z run=cmd /c C:\lab-attack\ATA069\run.cmd
2026-11-09T09:21:32Z t1=2026-11-09T09:21:32Z

evidencia_local:
  ata=ATA069
  tecnica=T1560.001
  fuente=ART_adaptado
  guid=02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0
  t0=2026-11-09T09:21:31Z
  t1=2026-11-09T09:21:32Z
  zip=C:\lab-attack\ATA069\evidencias\datos.zip
  entradas=20
  bytes=2275

VEREDICTO: EFECTO DEMOSTRADO (datos.zip con 20 entradas, 2275 bytes)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA069_iter1-Detalle.csv` | 40 | `2832bcafc6d6e5123c4a222c536945452eb6083cf6b707938f049e1e5a3826c2` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA069_iter2-Detalle.csv` | 39 | `badfa5cab84d0ab53558fab348ba9536befa4d11b7e49d3fd709a6b64b8f50fd` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 40 | **5** | 3 | 7 | **0** | 25 | 40 | 0 | 0 | 0 |
| 2 | 39 | **5** | 3 | 7 | **0** | 24 | 39 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T09:17:31.149Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T09:21:32.511Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5***: deteccion por proceso; sin capa de red ni de recursos.
2. **Canal**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.

