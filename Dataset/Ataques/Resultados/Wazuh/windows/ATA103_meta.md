---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA103
tecnica: T1039
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA103 - T1039 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA103** |
| Tecnica | **T1039** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `7762e120-5879-44ff-97f8-008b401b9a98` |
| Adaptacion | share loopback \\127.0.0.1\labshare con 20 ficheros; copia por UNC |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1039-Data_from_Network_Shared_Drive/` |
| `sha256` ataque | `3860b16329abf9ade2be073c0c9944f59e4019a28e81dbde0527ea9a6b758cee` |
| `sha256` esperado | `41896b26c94229e803738511967461361b0b95568ab24f35eefed5ad26e5a275` |
| C0 | `Soporte/Ataques/c0/windows/ATA103_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T22:06:56Z` | `2026-11-09T22:07:05Z` | 9 s | 60 | **5** | `67027,92032,92052` | 46 |
| 2 | `2026-11-09T22:11:48Z` | `2026-11-09T22:11:55Z` | 7 s | 61 | **5** | `67027,92032,92052` | 46 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA103\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA103_iter{1,2}/efecto.txt`: 20 ficheros copiados del share; sha256 coinciden.

**Iter 1** (`sha256=cb33f8c21f39ee744bb9c4a4ad626a755a7d7614fff1aa4338add784216bb370`):

```text
# ATA103 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T22:06:56Z t0=2026-11-09T22:06:56Z run=cmd /c C:\lab-attack\ATA103\run.cmd
2026-11-09T22:07:05Z t1=2026-11-09T22:07:05Z

evidencia_local:
  ata=ATA103
  tecnica=T1039
  fuente=ART_adaptado
  t0=2026-11-09T22:07:04Z
  t1=2026-11-09T22:07:05Z
  share=\\127.0.0.1\labshare
  copiados=C:\lab-attack\ATA103\copiados
  ficheros_copiados=20
  sha256_coinciden=True
  copia_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_copiados=20; sha256_coinciden=True)
```

**Iter 2** (`sha256=53ce511d943d2f02ad4aa9a6c46a74b348bd44ee78541e2576d4d6f88b5a5dd7`):

```text
# ATA103 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T22:11:48Z t0=2026-11-09T22:11:48Z run=cmd /c C:\lab-attack\ATA103\run.cmd
2026-11-09T22:11:55Z t1=2026-11-09T22:11:55Z

evidencia_local:
  ata=ATA103
  tecnica=T1039
  fuente=ART_adaptado
  t0=2026-11-09T22:11:54Z
  t1=2026-11-09T22:11:54Z
  share=\\127.0.0.1\labshare
  copiados=C:\lab-attack\ATA103\copiados
  ficheros_copiados=20
  sha256_coinciden=True
  copia_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_copiados=20; sha256_coinciden=True)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA103_iter1-Detalle.csv` | 60 | `4a2bfffb5a37204518168ac588f158e3b816e82b883b422ea3212018190d4a77` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA103_iter2-Detalle.csv` | 61 | `a7f31289dfc00356759a7dc19eb2afd9f67e6b23b8777492ac69323c5baa6aef` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 60 | **5** | 3 | 6 | **0** | 46 | 60 | 0 | 0 | 0 |
| 2 | 61 | **5** | 3 | 7 | **0** | 46 | 61 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T22:06:58.296Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T22:11:50.427Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA103** es **ART adaptado**: `guid=7762e120-5879-44ff-97f8-008b401b9a98`, `atomics/T1039/T1039.yaml`, commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. El atomic copia por `\\remote\C$\...`; en el lab se crea un **share loopback** `\\127.0.0.1\labshare` con 20 ficheros y se copian por UNC (`ficheros_copiados=20`, `sha256_coinciden=True`). Pareja de **ATA039**.
2. El share se elimina en `finally`; sin auditoria SMB (no 5140/5145).
