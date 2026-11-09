---
fase: 3b
bloque: B2
tanda: B2.3
ata_id: ATA101
tecnica: T1025
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA101 - T1025 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.3**. `esperado` **pre-registrado y sellado** en `312d9fe`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA101** |
| Tecnica | **T1025** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM del VHD como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `0b29f7e3-a050-44b7-bf05-9fb86af1ec2e` |
| Adaptacion | ART adaptado: monta/formatea el VHD, crea 20 docs y los copia a copiados\ |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1025-Data_from_Removable_Media/` |
| `sha256` script usado (ventanas validas) | `97a5c70919fb0d7e1f26604bf1e9b16cbc5a24f2a6f7d0c72733d793f8d9d4be` |
| `sha256` script en `312d9fe` (no usado) | `5654ced35b2dea5c8aac47591841f50de1cfc0f65bb6921d2434a291281f4f46` |
| `sha256` script corregido (actual) | `0edc15d7a8d460f163ff5557a1f9a480b68aa860349a9e5f52aba592610b0d1a` |
| `sha256` esperado | `5dd2dd202dfacb1c5e964dab88f8c4631da1738c4adbd6c909d2d03ea6bbe6f3` |
| C0 | `Soporte/Ataques/c0/windows/ATA101_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y del VHD **fuera** de `[t0,t1]`.
- **VHD**: `labdisk100.vhd` (100 MiB, `sha256=04c8899c…9f9aad`) copiado a `C:\lab-attack\ATA101\labdisk100.vhd` antes de `t0`.
- Sin red; solo el VHD del caso. Nunca `PhysicalDrive*`/`C:`/sistema.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T21:19:05Z` | `2026-11-09T21:19:26Z` | 21 s | 47 | **5** | `67027,92032,92052` | 28 |
| 2 | `2026-11-09T21:23:24Z` | `2026-11-09T21:23:45Z` | 21 s | 46 | **5** | `67027,92032,92052` | 27 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA101\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA101_iter{1,2}/efecto.txt`: 20 ficheros copiados del VHD; sha256 coinciden.

**Iter 1** (`sha256=f93538a8eacb405bcd1e4f39d69fee9c0b7713fc56a90c5903c81a3a90ddfa98`):

```text
# ATA101 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T21:19:05Z t0=2026-11-09T21:19:05Z run=cmd /c C:\lab-attack\ATA101\run.cmd
2026-11-09T21:19:26Z t1=2026-11-09T21:19:26Z

evidencia_local:
  ata=ATA101
  tecnica=T1025
  fuente=ART_adaptado
  t0=2026-11-09T21:19:08Z
  t1=2026-11-09T21:19:25Z
  vhd=C:\lab-attack\ATA101\labdisk100.vhd
  bytes=104858112
  ficheros_copiados=20
  sha256_coinciden=True
  copiado_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_copiados=20; sha256_coinciden=True)
```

**Iter 2** (`sha256=4070b4278d0057d1376b515c4a327d9a33a56ad29fe427665e90ab23a9ae2b23`):

```text
# ATA101 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T21:23:24Z t0=2026-11-09T21:23:24Z run=cmd /c C:\lab-attack\ATA101\run.cmd
2026-11-09T21:23:45Z t1=2026-11-09T21:23:45Z

evidencia_local:
  ata=ATA101
  tecnica=T1025
  fuente=ART_adaptado
  t0=2026-11-09T21:23:27Z
  t1=2026-11-09T21:23:45Z
  vhd=C:\lab-attack\ATA101\labdisk100.vhd
  bytes=104858112
  ficheros_copiados=20
  sha256_coinciden=True
  copiado_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_copiados=20; sha256_coinciden=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA101_iter1-Detalle.csv` | 47 | `df94d736071115ee53a0e3dd26a99879f4202b84055ab7549885237c5790e94c` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA101_iter2-Detalle.csv` | 46 | `74dbc22fd82b9b263514fe34eee402e390bcc07ee2c3391a183fca38e26fecfc` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 47 | **5** | 3 | 12 | **0** | 27 | 47 | 0 | 0 | 0 |
| 2 | 46 | **5** | 3 | 12 | **0** | 26 | 46 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T21:19:07.348Z` `rule_id=67027` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T21:23:25.858Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA101** es **ART adaptado**: `guid=0b29f7e3-a050-44b7-bf05-9fb86af1ec2e`, fichero `atomics/T1025/T1025.yaml`, commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. El test original busca volumenes `DriveType -eq Removable`; en el lab se monta el VHD, se crean **20 documentos** y se copian a `copiados\` (`ficheros_copiados=20`, `sha256_coinciden=True`). Pareja de **ATA044**.
2. **Fix de ejecucion**: (i) el agente FIM bloquea el VHD recien copiado por `scp`; el runner copia localmente (`labdisk100_src.vhd` -> `labdisk100.vhd`) y el script reintenta la apertura; (ii) el disco montado se localiza por `BusType -eq File Backed Virtual` + `Location`; (iii) `Set-Disk` se llama en dos pasos (param sets distintos); (iv) se reintenta `Get-Partition` antes de crear. El primer intento fallo y se archivo fuera del repo.

- **Trazabilidad del script**: el fix de montaje (reintento de particion) tiene mtime `21:29:16` UTC, **posterior** a los `t0` validos (`21:19:05` / `21:23:24`). Las ventanas validas usan el **script intermedio** (`97a5c70919fb0d7e1f26604bf1e9b16cbc5a24f2a6f7d0c72733d793f8d9d4be`): fixes de disco/`Set-Disk`/volumen, sin el reintento de particion. El script de `312d9fe` (`5654ced35b2dea5c8aac47591841f50de1cfc0f65bb6921d2434a291281f4f46`) **no pudo** usarse: fallo en los intentos de 21:06 y 21:11. **No se repite** porque el efecto y la deteccion son reales.