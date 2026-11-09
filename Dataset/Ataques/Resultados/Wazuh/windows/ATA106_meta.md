---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA106
tecnica: T1056.004
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-parcial
fecha: 2026-11-09
---

# Ficha - ATA106 - T1056.004 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA106** |
| Tecnica | **T1056.004** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `de1934ea-1fbf-425b-8795-65fb27dd7e33` |
| Adaptacion | DLL T1056.004x64.dll inyectada con mavinject en PowerShell de juguete; TLS local 127.0.0.1:8443 |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1056.004-Credential_API_Hooking/` |
| `sha256` ataque | `417837d7504f006af2c8c9f952e95bf5b24c7799e0243d12826b3ef7fdb1d469` |
| `sha256` esperado | `5f7280a7b04260a2cbc6233b2a687b683e2815259249ec190af040fe35f64ef1` |
| C0 | `Soporte/Ataques/c0/windows/ATA106_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T22:35:26Z` | `2026-11-09T22:35:50Z` | 24 s | 39 | **7** | `67027,92027,92032,92052` | 14 |
| 2 | `2026-11-09T22:40:20Z` | `2026-11-09T22:40:45Z` | 25 s | 38 | **7** | `67027,92027,92032,92052` | 14 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA106\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA106_iter{1,2}/efecto.txt`: DLL inyectada; hook.log sin captura -> efecto_parcial.

**Iter 1** (`sha256=2e2fe3995b7480b4bcb878f5ae98d6bc23a6ddf5f75ce64e740decbf99dfc26a`):

```text
# ATA106 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T22:35:26Z t0=2026-11-09T22:35:26Z run=cmd /c C:\lab-attack\ATA106\run.cmd
2026-11-09T22:35:50Z t1=2026-11-09T22:35:50Z

evidencia_local:
  ata=ATA106
  tecnica=T1056.004
  fuente=ART_adaptado
  t0=2026-11-09T22:35:34Z
  t1=2026-11-09T22:35:49Z
  dll=C:\lab-attack\ATA106\T1056.004x64.dll
  toy=C:\lab-attack\ATA106\ATA106_toy.ps1
  inyectado=True
  hook_log=False
  efecto_parcial=True

hook.log:
  Ready To Roll Out!

VEREDICTO: EFECTO PARCIAL (inyectado=True; hook_log=False; DLL cargada pero sin captura TLS)
```

**Iter 2** (`sha256=4e4045891af47b4f71914c421fe6652c9d1f5a2134f9cad8f6ea4bc57c0ca8de`):

```text
# ATA106 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T22:40:20Z t0=2026-11-09T22:40:20Z run=cmd /c C:\lab-attack\ATA106\run.cmd
2026-11-09T22:40:45Z t1=2026-11-09T22:40:45Z

evidencia_local:
  ata=ATA106
  tecnica=T1056.004
  fuente=ART_adaptado
  t0=2026-11-09T22:40:31Z
  t1=2026-11-09T22:40:45Z
  dll=C:\lab-attack\ATA106\T1056.004x64.dll
  toy=C:\lab-attack\ATA106\ATA106_toy.ps1
  inyectado=True
  hook_log=False
  efecto_parcial=True

VEREDICTO: EFECTO PARCIAL (inyectado=True; hook_log=False; DLL cargada pero sin captura TLS)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA106_iter1-Detalle.csv` | 39 | `646f3324bd7a3e322e4933b7a6e9531465102d0d0498dcb8526d66f2f51a0a5e` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA106_iter2-Detalle.csv` | 38 | `49c909584b2b3e863aa2cb64c1c4bdee0c9aecd066dce46e6c64daeb2e36e81a` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 39 | **7** | 3 | 16 | **0** | 13 | 39 | 0 | 0 | 0 |
| 2 | 38 | **7** | 3 | 15 | **0** | 13 | 38 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 7 | 4 -> `67027,92027,92032,92052` | `2026-11-09T22:35:27.645Z` `rule_id=92052` |
| 2 | 7 | 4 -> `67027,92027,92032,92052` | `2026-11-09T22:40:22.441Z` `rule_id=67027` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 7 vs 7;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA106** es **ART adaptado**: `guid=de1934ea-1fbf-425b-8795-65fb27dd7e33`, `atomics/T1056.004/T1056.004.yaml`, commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`; DLL `T1056.004x64.dll` (`sha256=e728be21...`, 127488 B) pre-staged. Se inyecta con `mavinject` **solo** en el PowerShell de juguete; TLS local `127.0.0.1:8443`. Pareja de **ATA035**.
2. **EFECTO PARCIAL**: `inyectado=True` y `hook.log` contiene `Ready To Roll Out!` (DLL cargada), pero **no** aparece `***HOOKED CAPTURE LOG***` ni `EncryptMessage`/`DecryptMessage`; el hook TLS no captura. No se inventa; se declara `efecto_parcial=True`. La deteccion de proceso si es real (7 alertas).
