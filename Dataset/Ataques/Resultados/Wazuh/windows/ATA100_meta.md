---
fase: 3b
bloque: B2
tanda: B2.3
ata_id: ATA100
tecnica: T1561.002
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA100 - T1561.002 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.3**. `esperado` **pre-registrado y sellado** en `312d9fe`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA100** |
| Tecnica | **T1561.002** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM del VHD como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | VHD fijo 100 MiB; siembra + MBR falso; ceros a primeros 1 MiB y footer |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1561.002-Disk_Structure_Wipe/` |
| `sha256` ataque | `472a5048f5925f4839e69cc8cc805fa482950b49dba756bd7df3e61b4ad2fdb6` |
| `sha256` esperado | `7a47905fb158d8858c100a59cef31384055a80fd37095b6790f80d5574a64394` |
| C0 | `Soporte/Ataques/c0/windows/ATA100_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y del VHD **fuera** de `[t0,t1]`.
- **VHD**: `labdisk100.vhd` (100 MiB, `sha256=04c8899c…9f9aad`) copiado a `C:\lab-attack\ATA100\labdisk100.vhd` antes de `t0`.
- Sin red; solo el VHD del caso. Nunca `PhysicalDrive*`/`C:`/sistema.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T20:57:28Z` | `2026-11-09T20:57:44Z` | 16 s | 25 | **5** | `67027,92032,92052` | 8 |
| 2 | `2026-11-09T21:01:52Z` | `2026-11-09T21:02:04Z` | 12 s | 25 | **5** | `67027,92032,92052` | 8 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA100\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA100_iter{1,2}/efecto.txt`: VHD no montable (footer destruido; Mount-DiskImage falla).

**Iter 1** (`sha256=72118c9b2a3c55c2ce66f2db056f2e49612bf6b2d2080db8dee956b74d3d14ca`):

```text
# ATA100 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T20:57:28Z t0=2026-11-09T20:57:28Z run=cmd /c C:\lab-attack\ATA100\run.cmd
2026-11-09T20:57:44Z t1=2026-11-09T20:57:44Z

evidencia_local:
  ata=ATA100
  tecnica=T1561.002
  fuente=manual
  t0=2026-11-09T20:57:34Z
  t1=2026-11-09T20:57:34Z
  vhd=C:\lab-attack\ATA100\labdisk100.vhd
  bytes=104858112
  sha256_antes=5ef856d1dfc2920832e5f53b2f587ae151482f223b3995f5a3af2f7b6b03646b
  sha256_despues=314059ed40d150948baf1b322ff66880e7eb3257dfaabb1cb0dad0fc358b2e87
  footer_conectix=False
  montable=False
  no_montable=True

VEREDICTO: EFECTO DEMOSTRADO (no_montable=True; footer_conectix=False; montable=False)
```

**Iter 2** (`sha256=c952a93d68b8f9e42d454828fa06c461f71228c59216be3cdf70098c9536ade1`):

```text
# ATA100 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T21:01:52Z t0=2026-11-09T21:01:52Z run=cmd /c C:\lab-attack\ATA100\run.cmd
2026-11-09T21:02:04Z t1=2026-11-09T21:02:04Z

evidencia_local:
  ata=ATA100
  tecnica=T1561.002
  fuente=manual
  t0=2026-11-09T21:01:57Z
  t1=2026-11-09T21:01:58Z
  vhd=C:\lab-attack\ATA100\labdisk100.vhd
  bytes=104858112
  sha256_antes=5ef856d1dfc2920832e5f53b2f587ae151482f223b3995f5a3af2f7b6b03646b
  sha256_despues=314059ed40d150948baf1b322ff66880e7eb3257dfaabb1cb0dad0fc358b2e87
  footer_conectix=False
  montable=False
  no_montable=True

VEREDICTO: EFECTO DEMOSTRADO (no_montable=True; footer_conectix=False; montable=False)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA100_iter1-Detalle.csv` | 25 | `01ec7adb1b16d8edc1673af96219bee82de9c4ac41210737799483c4d2c57ebc` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA100_iter2-Detalle.csv` | 25 | `824f903d2f37f0a406caff42229d5e7a4b14703a18ffd16cb8421c1319335d5a` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 25 | **5** | 3 | 10 | **0** | 7 | 25 | 0 | 0 | 0 |
| 2 | 25 | **5** | 3 | 10 | **0** | 7 | 25 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T20:57:30.512Z` `rule_id=67027` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T21:01:54.360Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA100** es **manual**: siembra `0xAA` + MBR falso (`0x55AA`), y **pone a cero los primeros 1 MiB y el footer**; `Mount-DiskImage` falla -> `no_montable=True`. Pareja Windows de **ATA027**.
2. El montaje fallido se captura y se desmonta por si acaso; no se toca ningun otro disco.
