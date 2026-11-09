---
fase: 3b
bloque: B2
tanda: B2.4
ata_id: ATA108
tecnica: T1119
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA108 - T1119 (Windows / `victima-windows`)

> Bloque **B2**, tanda **B2.4**. `esperado` **pre-registrado y sellado** en `2af6ed0`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA108** |
| Tecnica | **T1119** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `cb379146-53f1-43e0-b884-7ce2c635ff5b` |
| Adaptacion | bucle sobre fuentes\ (20 docx) -> staging\ |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1119-Automated_Collection/` |
| `sha256` ataque | `a3246b8018b688cb216d3e4122e8f25912f38fcbc394e5de7807547f45beb413` |
| `sha256` esperado | `93a07b43170987099e7d6c5892d3895bf1cd7d8e175110f6fb9f6940c6d6866e` |
| C0 | `Soporte/Ataques/c0/windows/ATA108_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Loopback/local en el invitado; sin red externa.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T22:53:18Z` | `2026-11-09T22:53:22Z` | 4 s | 59 | **5** | `67027,92032,92052` | 44 |
| 2 | `2026-11-09T22:57:14Z` | `2026-11-09T22:57:18Z` | 4 s | 58 | **5** | `67027,92032,92052` | 43 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA108\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA108_iter{1,2}/efecto.txt`: 20 ficheros recolectados en staging\.

**Iter 1** (`sha256=01ace8a836a1f0eab9cbda149c9331947277e6d15e6ee59a2f8bc026ce3fa082`):

```text
# ATA108 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T22:53:18Z t0=2026-11-09T22:53:18Z run=cmd /c C:\lab-attack\ATA108\run.cmd
2026-11-09T22:53:22Z t1=2026-11-09T22:53:22Z

evidencia_local:
  ata=ATA108
  tecnica=T1119
  fuente=ART_adaptado
  t0=2026-11-09T22:53:22Z
  t1=2026-11-09T22:53:22Z
  fuentes=C:\lab-attack\ATA108\fuentes
  staging=C:\lab-attack\ATA108\staging
  ficheros_recolectados=20
  recoleccion_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_recolectados=20)
```

**Iter 2** (`sha256=77d8e8843bb23402251588f8e6852c7023cabfcce51a96dcd0076de4722850cb`):

```text
# ATA108 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T22:57:14Z t0=2026-11-09T22:57:14Z run=cmd /c C:\lab-attack\ATA108\run.cmd
2026-11-09T22:57:18Z t1=2026-11-09T22:57:18Z

evidencia_local:
  ata=ATA108
  tecnica=T1119
  fuente=ART_adaptado
  t0=2026-11-09T22:57:17Z
  t1=2026-11-09T22:57:17Z
  fuentes=C:\lab-attack\ATA108\fuentes
  staging=C:\lab-attack\ATA108\staging
  ficheros_recolectados=20
  recoleccion_ok=True

VEREDICTO: EFECTO DEMOSTRADO (ficheros_recolectados=20)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA108_iter1-Detalle.csv` | 59 | `3648e75acef8e7de6f8a02b44c9b4a84d8b7481c3ced4e9e36fd5b19402d6057` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA108_iter2-Detalle.csv` | 58 | `a6301ed1b6d213aa9048058cbe4f9bd47368adf9102f0e97c771e41643e0991b` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 59 | **5** | 3 | 7 | **0** | 44 | 59 | 0 | 0 | 0 |
| 2 | 58 | **5** | 3 | 7 | **0** | 43 | 58 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T22:53:19.867Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T22:57:16.179Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA108** es **ART adaptado**: `guid=cb379146-53f1-43e0-b884-7ce2c635ff5b`, `atomics/T1119/T1119.yaml`, commit `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`. El atomic recorre `c:\`; aqui se parametriza a `fuentes\` (20 `doc_XX.docx`) -> `staging\` (`ficheros_recolectados=20`). Pareja de **ATA012**.
