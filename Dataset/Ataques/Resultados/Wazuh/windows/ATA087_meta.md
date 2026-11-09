---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA087
tecnica: T1499.002
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA087 - T1499.002 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA087** |
| Tecnica | **T1499.002** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | servicio TCP desechable en loopback 9094 + 200 peticiones |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1499.002-Service_Exhaustion_Flood/` |
| `sha256` ataque | `75e9ccabd7d673e1826bf3bd98a8e931c390547d0792f25080dd959522979136` |
| `sha256` esperado | `024a36f034b067089e0dc49a8c20ff2d9186eb24492be3d3cbdf876ad6225159` |
| C0 | `Soporte/Ataques/c0/windows/ATA087_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sin red externa; loopback permitido (ATA087).

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T15:10:14Z` | `2026-11-09T15:11:01Z` | 47 s | 43 | **6** | `67027,92027,92032,92052` | 7 |
| 2 | `2026-11-09T15:14:53Z` | `2026-11-09T15:15:41Z` | 48 s | 48 | **6** | `67027,92027,92032,92052` | 7 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA087\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA087_iter{1,2}/efecto.txt`: 200 peticiones; servicio_responde=False.

**Iter 1** (`sha256=268518fcf3191701667a28075c72f1c233cb794abaf3dad015f2ca1afb5819bd`):

```text
# ATA087 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T15:10:14Z t0=2026-11-09T15:10:14Z run=cmd /c C:\lab-attack\ATA087\run.cmd
2026-11-09T15:11:01Z t1=2026-11-09T15:11:01Z

evidencia_local:
  ata=ATA087
  tecnica=T1499.002
  fuente=manual
  t0=2026-11-09T15:10:19Z
  t1=2026-11-09T15:11:01Z
  endpoint=127.0.0.1:9094
  peticiones=200
  ok=10
  fail=190
  servicio_responde=False

VEREDICTO: EFECTO DEMOSTRADO (200 peticiones; servicio_responde=False)
```

**Iter 2** (`sha256=caaba1b69b96d5a130f7ff8e09920b063ac39e5575f0cb15f36766370eac454b`):

```text
# ATA087 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T15:14:53Z t0=2026-11-09T15:14:53Z run=cmd /c C:\lab-attack\ATA087\run.cmd
2026-11-09T15:15:41Z t1=2026-11-09T15:15:41Z

evidencia_local:
  ata=ATA087
  tecnica=T1499.002
  fuente=manual
  t0=2026-11-09T15:14:59Z
  t1=2026-11-09T15:15:40Z
  endpoint=127.0.0.1:9094
  peticiones=200
  ok=10
  fail=190
  servicio_responde=False

VEREDICTO: EFECTO DEMOSTRADO (200 peticiones; servicio_responde=False)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA087_iter1-Detalle.csv` | 43 | `4bd240cc0b36d89dea44179ab39a4610f188aeb4257c95e95d0644903c791cb3` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA087_iter2-Detalle.csv` | 48 | `22af8e71c77e864001a882f18778af2aa12a9391d816be50ee31bdf2ed55dc09` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 43 | **6** | 3 | 29 | **0** | 5 | 43 | 0 | 0 | 0 |
| 2 | 48 | **6** | 3 | 35 | **0** | 4 | 48 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T15:10:15.706Z` `rule_id=92052` |
| 2 | 6 | 4 -> `67027,92027,92032,92052` | `2026-11-09T15:14:55.278Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92027', '92032', '92052'] == ['67027', '92027', '92032', '92052']`; recuento 6 vs 6;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA087** es **manual**: servicio TCP desechable en loopback `127.0.0.1:9094` (backlog 1, atiende una conexion cada 5 s) y **200 peticiones**; la sonda final da `servicio_responde=False`.
2. El efecto es el agotamiento del servicio desechable; se para al final.
