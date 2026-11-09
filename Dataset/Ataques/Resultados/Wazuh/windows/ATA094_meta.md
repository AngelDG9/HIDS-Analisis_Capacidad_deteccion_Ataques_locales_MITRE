---
fase: 3b
bloque: B2
tanda: B2.2
ata_id: ATA094
tecnica: T1560.003
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA094 - T1560.003 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.2**. `esperado` **pre-registrado y sellado** en `a2eca10`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA094** |
| Tecnica | **T1560.003** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | formato propio TFGARCH1 (cabecera + XOR 0x5A) con 20 ficheros; decodificado verificado |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1560.003-Archive_via_Custom_Method/` |
| `sha256` ataque | `5c5295007a08921fc2c33aa3f620a7b316a0ef85dbc88be470fa1312abbee6f4` |
| `sha256` esperado | `eaca0d53ba5715047e25a9c72735f942f1dfac227868e6a5e206857c7bdfda08` |
| C0 | `Soporte/Ataques/c0/windows/ATA094_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T19:29:13Z` | `2026-11-09T19:29:14Z` | 1 s | 60 | **5** | `67027,92032,92052` | 45 |
| 2 | `2026-11-09T19:32:48Z` | `2026-11-09T19:32:52Z` | 4 s | 61 | **5** | `67027,92032,92052` | 46 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA094\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA094_iter{1,2}/efecto.txt`: custom.tfg magic=TFGARCH1 ficheros=20; decodificado_ok=True.

**Iter 1** (`sha256=97c7073e1d55cc3f7e04f6d5520d320db7286f76d5735824558e0e12604ec000`):

```text
# ATA094 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T19:29:13Z t0=2026-11-09T19:29:13Z run=cmd /c C:\lab-attack\ATA094\run.cmd
2026-11-09T19:29:14Z t1=2026-11-09T19:29:14Z

evidencia_local:
  ata=ATA094
  tecnica=T1560.003
  fuente=manual
  t0=2026-11-09T19:29:13Z
  t1=2026-11-09T19:29:13Z
  archivo=C:\lab-attack\ATA094\custom.tfg
  magic=TFGARCH1
  ficheros=20
  custom_sha256=52a47564f3a94ec1fef3328feb9e0630f37ddc1823a4f2352abe7bf6adae5b3d
  decodificado_ok=True

VEREDICTO: EFECTO DEMOSTRADO (magic=TFGARCH1; ficheros=20; decodificado_ok=True; sha256=52a47564f3a94ec1fef3328feb9e0630f37ddc1823a4f2352abe7bf6adae5b3d)
```

**Iter 2** (`sha256=70d4bc8de1abbd3d22ec5b61ea266f190708eb87b7ae7375d2f0e4eb10339083`):

```text
# ATA094 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T19:32:48Z t0=2026-11-09T19:32:48Z run=cmd /c C:\lab-attack\ATA094\run.cmd
2026-11-09T19:32:52Z t1=2026-11-09T19:32:52Z

evidencia_local:
  ata=ATA094
  tecnica=T1560.003
  fuente=manual
  t0=2026-11-09T19:32:52Z
  t1=2026-11-09T19:32:52Z
  archivo=C:\lab-attack\ATA094\custom.tfg
  magic=TFGARCH1
  ficheros=20
  custom_sha256=52a47564f3a94ec1fef3328feb9e0630f37ddc1823a4f2352abe7bf6adae5b3d
  decodificado_ok=True

VEREDICTO: EFECTO DEMOSTRADO (magic=TFGARCH1; ficheros=20; decodificado_ok=True; sha256=52a47564f3a94ec1fef3328feb9e0630f37ddc1823a4f2352abe7bf6adae5b3d)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA094_iter1-Detalle.csv` | 60 | `a7ea2d60d1b8b954013e1d22138da7f63557d54294aeeccb0cd2af9567c9db0e` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA094_iter2-Detalle.csv` | 61 | `6e8befac29e94e0055fae482f430e7dfc3c5ca3dfc920ab217b39b256674abd5` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 60 | **5** | 3 | 7 | **0** | 45 | 60 | 0 | 0 | 0 |
| 2 | 61 | **5** | 3 | 7 | **0** | 46 | 61 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T19:29:14.344Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T19:32:50.279Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA094** es **manual**: formato propio **`TFGARCH1`** (cabecera + numero de ficheros + `nombre`/`tamano`/payload **XOR 0x5A**) con 20 ficheros; decodificado y verificado (`decodificado_ok=True`). Pareja Windows de **ATA034** (FN en Linux).
2. El efecto no es deteccion: se prueba en `efecto.txt`.
