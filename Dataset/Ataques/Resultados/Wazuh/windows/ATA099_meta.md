---
fase: 3b
bloque: B2
tanda: B2.3
ata_id: ATA099
tecnica: T1561.001
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA099 - T1561.001 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.3**. `esperado` **pre-registrado y sellado** en `312d9fe`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA099** |
| Tecnica | **T1561.001** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM del VHD como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | VHD fijo 100 MiB; siembra 0xAA y pone a cero el contenido; footer intacto |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1561.001-Disk_Content_Wipe/` |
| `sha256` ataque | `f66a36636b389ee860f2d4d6192c168b7d1e29937197cbbf03249f84f5cfa062` |
| `sha256` esperado | `350be8e61c8e17575b26cba65984f7f3a984657addee5b11d9554479ea9f8388` |
| C0 | `Soporte/Ataques/c0/windows/ATA099_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y del VHD **fuera** de `[t0,t1]`.
- **VHD**: `labdisk100.vhd` (100 MiB, `sha256=04c8899c…9f9aad`) copiado a `C:\lab-attack\ATA099\labdisk100.vhd` antes de `t0`.
- Sin red; solo el VHD del caso. Nunca `PhysicalDrive*`/`C:`/sistema.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T20:49:23Z` | `2026-11-09T20:49:35Z` | 12 s | 24 | **5** | `67027,92032,92052` | 6 |
| 2 | `2026-11-09T20:53:23Z` | `2026-11-09T20:53:35Z` | 12 s | 23 | **5** | `67027,92032,92052` | 6 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA099\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA099_iter{1,2}/efecto.txt`: contenido del VHD borrado (ceros; footer intacto).

**Iter 1** (`sha256=c200e835cd92eaade7fc6e6d6c913ea5a3d983f1d56f8d4de87d5a3eede2034b`):

```text
# ATA099 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T20:49:23Z t0=2026-11-09T20:49:23Z run=cmd /c C:\lab-attack\ATA099\run.cmd
2026-11-09T20:49:35Z t1=2026-11-09T20:49:35Z

evidencia_local:
  ata=ATA099
  tecnica=T1561.001
  fuente=manual
  t0=2026-11-09T20:49:25Z
  t1=2026-11-09T20:49:26Z
  vhd=C:\lab-attack\ATA099\labdisk100.vhd
  bytes=104858112
  sha256_antes=3e2191efd493894a43c67adcc1159f8f45da71c6fef26483fca727487be5a70c
  sha256_despues=04c8899c5c95aaab1455500a513c192cd6f1568700ef1d26b4faced8ce9f9aad
  primero_cero=True
  ultimo_cero=True
  footer_conectix=True
  contenido_borrado=True

VEREDICTO: EFECTO DEMOSTRADO (contenido_borrado=True; primero_cero=True; ultimo_cero=True)
```

**Iter 2** (`sha256=75f81edec85cd296f8e5cba591fffdad1ded25521d7798771c808319e1052b65`):

```text
# ATA099 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T20:53:23Z t0=2026-11-09T20:53:23Z run=cmd /c C:\lab-attack\ATA099\run.cmd
2026-11-09T20:53:35Z t1=2026-11-09T20:53:35Z

evidencia_local:
  ata=ATA099
  tecnica=T1561.001
  fuente=manual
  t0=2026-11-09T20:53:25Z
  t1=2026-11-09T20:53:26Z
  vhd=C:\lab-attack\ATA099\labdisk100.vhd
  bytes=104858112
  sha256_antes=3e2191efd493894a43c67adcc1159f8f45da71c6fef26483fca727487be5a70c
  sha256_despues=04c8899c5c95aaab1455500a513c192cd6f1568700ef1d26b4faced8ce9f9aad
  primero_cero=True
  ultimo_cero=True
  footer_conectix=True
  contenido_borrado=True

VEREDICTO: EFECTO DEMOSTRADO (contenido_borrado=True; primero_cero=True; ultimo_cero=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA099_iter1-Detalle.csv` | 24 | `9ba0b5d6130111ab58a5a00041a28e56ad14ef072a508ab14db2cb6179dfa12c` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA099_iter2-Detalle.csv` | 23 | `647ef63997b3bebba5265c9eb1699b2c470a139df5ca5179e954334484c73268` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 24 | **5** | 3 | 11 | **0** | 5 | 24 | 0 | 0 | 0 |
| 2 | 23 | **5** | 3 | 10 | **0** | 5 | 23 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T20:49:25.091Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T20:53:25.290Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA099** es **manual**: siembra `0xAA` y **pone a cero el contenido** del VHD (primeros 1 MiB y ultimo bloque a cero); footer intacto (`contenido_borrado=True`). Pareja Windows de **ATA037**.
2. El efecto no es deteccion: se prueba en `efecto.txt`.
