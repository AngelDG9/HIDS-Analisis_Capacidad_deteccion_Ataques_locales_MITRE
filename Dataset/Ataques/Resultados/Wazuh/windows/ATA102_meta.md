---
fase: 3b
bloque: B2
tanda: B2.3
ata_id: ATA102
tecnica: T1052.001
tactica: Exfiltration
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA102 - T1052.001 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.3**. `esperado` **pre-registrado y sellado** en `312d9fe`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA102** |
| Tecnica | **T1052.001** |
| Tactica | Exfiltration |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM del VHD como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | 20 ficheros de botin copiados al VHD; desmonta/remonta y verifica |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1052.001-Exfiltration_over_USB/` |
| `sha256` ataque | `af20cb4e566e282f9f66c936d8fd89495941ed95741a96dba837c4d207e64215` |
| `sha256` esperado | `6603e264afe9e9abeb5f56f2c10fdffadf7a793347122d13039541367f448435` |
| C0 | `Soporte/Ataques/c0/windows/ATA102_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y del VHD **fuera** de `[t0,t1]`.
- **VHD**: `labdisk100.vhd` (100 MiB, `sha256=04c8899c…9f9aad`) copiado a `C:\lab-attack\ATA102\labdisk100.vhd` antes de `t0`.
- Sin red; solo el VHD del caso. Nunca `PhysicalDrive*`/`C:`/sistema.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T21:33:03Z` | `2026-11-09T21:33:40Z` | 37 s | 56 | **5** | `67027,92032,92052` | 34 |
| 2 | `2026-11-09T21:37:24Z` | `2026-11-09T21:38:01Z` | 37 s | 67 | **5** | `67027,92032,92052` | 35 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA102\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA102_iter{1,2}/efecto.txt`: 20 ficheros en el VHD; persistido tras remontar.

**Iter 1** (`sha256=a1f5a47510adb1ab12d6929978270c1e78dab569e3c5ad5df1805ad6b97f0b16`):

```text
# ATA102 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T21:33:03Z t0=2026-11-09T21:33:03Z run=cmd /c C:\lab-attack\ATA102\run.cmd
2026-11-09T21:33:40Z t1=2026-11-09T21:33:40Z

evidencia_local:
  ata=ATA102
  tecnica=T1052.001
  fuente=manual
  t0=2026-11-09T21:33:07Z
  t1=2026-11-09T21:33:39Z
  vhd=C:\lab-attack\ATA102\labdisk100.vhd
  bytes=104858112
  ficheros_en_vhd=20
  persistido=True
  exfil_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_en_vhd=20; persistido=True)
```

**Iter 2** (`sha256=3039d6823624275c83f34255b811ba0c90d4b41189e02a9adffb95a4b4ca25eb`):

```text
# ATA102 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T21:37:24Z t0=2026-11-09T21:37:24Z run=cmd /c C:\lab-attack\ATA102\run.cmd
2026-11-09T21:38:01Z t1=2026-11-09T21:38:01Z

evidencia_local:
  ata=ATA102
  tecnica=T1052.001
  fuente=manual
  t0=2026-11-09T21:37:28Z
  t1=2026-11-09T21:38:00Z
  vhd=C:\lab-attack\ATA102\labdisk100.vhd
  bytes=104858112
  ficheros_en_vhd=20
  persistido=True
  exfil_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_en_vhd=20; persistido=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA102_iter1-Detalle.csv` | 56 | `09c1a8409ccb17a17e05f12ee107ca55dcbc9e738e2185ae4a182c0178c79c31` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA102_iter2-Detalle.csv` | 67 | `d3e66d1c3b36d175232f01681c0e4079032600a4951e12cda82e066be5113a72` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 56 | **5** | 3 | 18 | **0** | 30 | 56 | 0 | 0 | 0 |
| 2 | 67 | **5** | 3 | 31 | **0** | 28 | 67 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T21:33:05.609Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T21:37:25.928Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA102** es **manual**: crea **20 ficheros de botin** en `botin\` y los copia a `exfil\` del VHD; desmonta, **remonta** y verifica que siguen (`ficheros_en_vhd=20`, `persistido=True`).
2. **Fix de ejecucion**: el primer intento fallo al remontar ("Not enough available capacity") porque `Get-Partition` no encontraba la particion a tiempo; se reintenta la busqueda y se ordena por tamano. Esa iteracion se archivo fuera del repo.
