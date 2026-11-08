---
fase: 3b
bloque: B1
tanda: B1.2
ata_id: ATA064
tecnica: T1489
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA064 - T1489 Service Stop (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.2**. `esperado` **pre-registrado y sellado** en `7bce82d`;
> `sha256` verificado antes de cada `t0`. Canal **SSH**; token **High** (`S-1-16-12288`).
> **Sin secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA064** |
| Técnica | **T1489 - Service Stop** |
| Táctica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Vía | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `21dfb440-830d-4c86-a3e5-2a491d5a8d04` |
| Adaptación | spooler -> servicio de juguete TFG-Svc-1489 (ToyService.exe compilado en el caso) creado/parado/borrado |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1489-Service_Stop/` |
| `sha256` ataque | `033439c6255e2ec6ddfce1d0a40acbf7787550d767844fcef963d1dfa5501c66` |
| `sha256` esperado | `35187eb5f4dafb411a4cf7fe8049b3968c93ff985e1bb98350e94007530c2263` |
| C0 | `Soporte/Ataques/c0/windows/ATA064_c0.md` (`sha256=55c07019325db60186bcad3aabac50ada4c2630044592b6be17250b84cfe3bb6`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteración; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | detección | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T22:30:50Z` | `2026-11-08T22:31:07Z` | 17 s | 32 | **6** | `67027,92032,92052,92307` | 12 |
| 2 | `2026-11-08T22:34:29Z` | `2026-11-08T22:34:45Z` | 16 s | 36 | **6** | `67027,92032,92052,92307` | 15 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA064\run.cmd"
```

## 6. Prueba de efecto (no es detección)

`Logs/ATA064_iter{1,2}/efecto.txt`: servicio creado, Running -> Stopped, borrado=True.

**Iter 1** (`sha256=86be83173d1691d2153d216f1657e7501387b9ba225186a5adcf725a9205f36e`):

```text
  binario=C:\lab-attack\ATA064\ToyService.exe
  creado=True
  estado_antes=Running
  estado_despues=Stopped
  borrado=True
  error=

VEREDICTO: EFECTO DEMOSTRADO (servicio creado, Running->Stopped, borrado=True)
```

**Iter 2** (`sha256=56e7f01c447b7bf95b7601fbbd21452a386628676f1f3e35133d3066f9bd4c3d`):

```text
  binario=C:\lab-attack\ATA064\ToyService.exe
  creado=True
  estado_antes=Running
  estado_despues=Stopped
  borrado=True
  error=

VEREDICTO: EFECTO DEMOSTRADO (servicio creado, Running->Stopped, borrado=True)
```

## 7. Ventana extraída

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA064_iter1-Detalle.csv` | 32 | `9a1684ce6f45ea1fd39562672c0fe44d7a0a7c7610fa3c0651d7c1bbb18a42be` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA064_iter2-Detalle.csv` | 36 | `c72dff2b71e07b04c7ecb41b2e1f8594d8ad722bac6ab46af8b231dd44e0f2e1` |

## 8. Resultado (métrica v1)

| Iter | filas | detección | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 32 | **6** | 3 | 8 | **0** | 15 | 32 | 0 | 0 | 0 |
| 2 | 36 | **6** | 3 | 10 | **0** | 17 | 36 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 4 -> `67027,92032,92052,92307` | `2026-11-08T22:30:51.683Z` `rule_id=92052` |
| 2 | 6 | 4 -> `67027,92032,92052,92307` | `2026-11-08T22:34:31.761Z` `rule_id=92052` |

- Detección principal: procesos del ataque anclados por `win_command_line` a la carpeta.
- **El efecto no es detección**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteración - veredicto **`iguales`**

`{67027,92032,92052,92307} == {67027,92032,92052,92307}`; recuento 6 vs 6; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5′**: detección por proceso; sin capa de red ni de recursos.
2. **Canal SSH**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Elevación**: token SSH **High**; no se necesitó tarea `Highest`.
5. **Servicio de juguete**: `ToyService.exe` compilado en el caso; el `sc.exe`/binario del sistema no es service-aware.
6. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
