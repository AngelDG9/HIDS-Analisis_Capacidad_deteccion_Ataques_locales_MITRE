---
fase: 3b
bloque: B2
tanda: B2.3
ata_id: ATA098
tecnica: T1561
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA098 - T1561 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.3**. `esperado` **pre-registrado y sellado** en `312d9fe`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA098** |
| Tecnica | **T1561** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM del VHD como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | VHD fijo 100 MiB; siembra 0xAA y sobrescribe el volumen con 0xFF; footer intacto |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1561-Disk_Wipe/` |
| `sha256` ataque | `13ee538408a71d6927e788e74ca5e1a3e56b9e8c621610ba58f7c096007d40df` |
| `sha256` esperado | `caf34939cbc0a0ee276db42a45d1f36c591e3f527e778f092c76c60ae56ed680` |
| C0 | `Soporte/Ataques/c0/windows/ATA098_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y del VHD **fuera** de `[t0,t1]`.
- **VHD**: `labdisk100.vhd` (100 MiB, `sha256=04c8899c…9f9aad`) copiado a `C:\lab-attack\ATA098\labdisk100.vhd` antes de `t0`.
- Sin red; solo el VHD del caso. Nunca `PhysicalDrive*`/`C:`/sistema.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T20:41:36Z` | `2026-11-09T20:41:39Z` | 3 s | 20 | **5** | `67027,92032,92052` | 5 |
| 2 | `2026-11-09T20:45:29Z` | `2026-11-09T20:45:32Z` | 3 s | 20 | **5** | `67027,92032,92052` | 5 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA098\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA098_iter{1,2}/efecto.txt`: VHD corrupto (0xFF en el volumen; footer conectix intacto).

**Iter 1** (`sha256=21845e35d3e13028e751f098176b2768d42250cae05d89247cb7ceb9f7f0a358`):

```text
# ATA098 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T20:41:36Z t0=2026-11-09T20:41:36Z run=cmd /c C:\lab-attack\ATA098\run.cmd
2026-11-09T20:41:39Z t1=2026-11-09T20:41:39Z

evidencia_local:
  ata=ATA098
  tecnica=T1561
  fuente=manual
  t0=2026-11-09T20:41:38Z
  t1=2026-11-09T20:41:38Z
  vhd=C:\lab-attack\ATA098\labdisk100.vhd
  bytes=104858112
  sha256_antes=3e2191efd493894a43c67adcc1159f8f45da71c6fef26483fca727487be5a70c
  sha256_despues=4b1c0921a110d01d364a92e91eacb0b4a503595283714e91d9e62dd2721d3ce8
  cabecera_ff=True
  footer_conectix=True
  vhd_corrupto=True

VEREDICTO: EFECTO DEMOSTRADO (vhd_corrupto=True; cabecera_ff=True; footer_conectix=True)
```

**Iter 2** (`sha256=185ba28113c0c743320041cb3aa24fb72ddbe5d83b52f04fa07b15585a396f91`):

```text
# ATA098 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T20:45:29Z t0=2026-11-09T20:45:29Z run=cmd /c C:\lab-attack\ATA098\run.cmd
2026-11-09T20:45:32Z t1=2026-11-09T20:45:32Z

evidencia_local:
  ata=ATA098
  tecnica=T1561
  fuente=manual
  t0=2026-11-09T20:45:31Z
  t1=2026-11-09T20:45:32Z
  vhd=C:\lab-attack\ATA098\labdisk100.vhd
  bytes=104858112
  sha256_antes=3e2191efd493894a43c67adcc1159f8f45da71c6fef26483fca727487be5a70c
  sha256_despues=4b1c0921a110d01d364a92e91eacb0b4a503595283714e91d9e62dd2721d3ce8
  cabecera_ff=True
  footer_conectix=True
  vhd_corrupto=True

VEREDICTO: EFECTO DEMOSTRADO (vhd_corrupto=True; cabecera_ff=True; footer_conectix=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA098_iter1-Detalle.csv` | 20 | `96c6ed39d3b60075af5780f584c26dca6832cbf942bbc0d1b5db836ddd64a7be` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA098_iter2-Detalle.csv` | 20 | `b2bb0d019afa18499c11c041fbc49e4c5c3222583ba8309d12122613192dbdc0` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 20 | **5** | 3 | 7 | **0** | 5 | 20 | 0 | 0 | 0 |
| 2 | 20 | **5** | 3 | 7 | **0** | 5 | 20 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T20:41:38.016Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T20:45:30.700Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA098** es **manual**: VHD fijo de 100 MiB; siembra `0xAA` y **sobrescribe el volumen con `0xFF`**; el footer `conectix` queda intacto (`vhd_corrupto=True`). Pareja Windows de **ATA005** (T1561, Linux).
2. El efecto no es deteccion: se prueba en `efecto.txt`.
