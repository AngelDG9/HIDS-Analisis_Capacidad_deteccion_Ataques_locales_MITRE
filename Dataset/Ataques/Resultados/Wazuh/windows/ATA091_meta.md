---
fase: 3b
bloque: B2
tanda: B2.1
ata_id: ATA091
tecnica: T1557.001
tactica: Credential Access
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA091 - T1557.001 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.1**. `esperado` **pre-registrado y sellado** en `06c0694`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA091** |
| Tecnica | **T1557.001** |
| Tactica | Credential Access |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `deecd55f-afe0-4a62-9fba-4d1ba2deb321` |
| Adaptacion | Inveigh pre-staged + consulta local; sin relay; hash no guardado |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1557.001-LLMNR_NBT-NS_Poisoning/` |
| `sha256` ataque | `1b6e25dd8fb86e969c48c7c34ee8d317ef8beda46b0225d4e5d01e50c00634b8` |
| `sha256` esperado | `98eaceffff0484ecbc252cb36709c7ccb1457849ddea183a78767389a8504c53` |
| C0 | `Soporte/Ataques/c0/windows/ATA091_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T18:35:47Z` | `2026-11-09T18:36:00Z` | 13 s | 35 | **7** | `67027,92004,92027,92032,92052` | 16 |
| 2 | `2026-11-09T18:42:25Z` | `2026-11-09T18:42:34Z` | 9 s | 36 | **7** | `67027,92004,92027,92032,92052` | 17 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA091\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA091_iter{1,2}/efecto.txt`: capturado=False (co-locado); efecto parcial.

**Iter 1** (`sha256=e7ccc6598b6dd2146e34f54f6cc0182a2c400cf8c0a4681b6d62c3ff9156c8f8`):

```text
# ATA091 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T18:35:47Z t0=2026-11-09T18:35:47Z run=cmd /c C:\lab-attack\ATA091\run.cmd
2026-11-09T18:36:00Z t1=2026-11-09T18:36:00Z

evidencia_local:
  ata=ATA091
  tecnica=T1557.001
  fuente=ART_adaptado
  guid=deecd55f-afe0-4a62-9fba-4d1ba2deb321
  t0=2026-11-09T18:35:54Z
  t1=2026-11-09T18:35:59Z
  capturado=False
  longitud=0
  hash_guardado=False

VEREDICTO: EFECTO PARCIAL (capturado=False; Inveigh co-locado sin captura de hash; hash no guardado)
```

**Iter 2** (`sha256=0f78cadfa8e3a5fa6886ff8e15e0fc415432b0ab94c19aba7f9b855cf747d103`):

```text
# ATA091 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T18:42:25Z t0=2026-11-09T18:42:25Z run=cmd /c C:\lab-attack\ATA091\run.cmd
2026-11-09T18:42:34Z t1=2026-11-09T18:42:34Z

evidencia_local:
  ata=ATA091
  tecnica=T1557.001
  fuente=ART_adaptado
  guid=deecd55f-afe0-4a62-9fba-4d1ba2deb321
  t0=2026-11-09T18:42:29Z
  t1=2026-11-09T18:42:34Z
  capturado=False
  longitud=0
  hash_guardado=False

VEREDICTO: EFECTO PARCIAL (capturado=False; Inveigh co-locado sin captura de hash; hash no guardado)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA091_iter1-Detalle.csv` | 35 | `7fd9f4b75eb56f4827fd8ea171684e2ea59918cc516c4dc6ef03691a50ddc204` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA091_iter2-Detalle.csv` | 36 | `3f1a3f2f98a925605465e46c58f190f655e824e2c2c0e3d034b9bbb9dd49469a` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 35 | **7** | 3 | 10 | **0** | 15 | 35 | 0 | 0 | 0 |
| 2 | 36 | **7** | 3 | 10 | **0** | 16 | 36 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 7 | 5 -> `67027,92004,92027,92032,92052` | `2026-11-09T18:35:48.697Z` `rule_id=92052` |
| 2 | 7 | 5 -> `67027,92004,92027,92032,92052` | `2026-11-09T18:42:26.745Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92004', '92027', '92032', '92052'] == ['67027', '92004', '92027', '92032', '92052']`; recuento 7 vs 7;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA091** es **ART_adaptado**: Inveigh pre-staged; consulta LLMNR/NBT-NS solo del invitado; sin relay real; **hash NTLM no guardado**.
2. **EFECTO PARCIAL**: Inveigh arranca (elevado, LLMNR/NBNS/mDNS/SMB/HTTP enabled) pero **no captura** el hash en el escenario co-locado (el servidor SMB/HTTP del sistema ocupa 445/80 y no hay tercer host); `capturado=False`, `longitud=0`. No se inventa.
3. La deteccion esperada sigue siendo de proceso (script/Inveigh); el `efecto_parcial` es de la prueba de efecto, no del TPR.
