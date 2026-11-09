---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA083
tecnica: T1667
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA083 - T1667 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA083** |
| Tecnica | **T1667** |
| Tactica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **manual** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `manual` |
| `guid` ART | `n/a` |
| Adaptacion | mailbox local de juguete con 25 .eml |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1667-Email_Bombing/` |
| `sha256` ataque | `cd3c10d1362bb8b8c21f31a8c3437fc61a4700f0d18dd66bb0c443c3d37a9a4b` |
| `sha256` esperado | `5f586049a427c89578f665786c5365a390a4e17c2303d18aa1ad05ba1a9f7212` |
| C0 | `Soporte/Ataques/c0/windows/ATA083_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sin red.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T14:34:57Z` | `2026-11-09T14:34:58Z` | 1 s | 44 | **5** | `67027,92032,92052` | 29 |
| 2 | `2026-11-09T14:38:51Z` | `2026-11-09T14:38:52Z` | 1 s | 44 | **5** | `67027,92032,92052` | 29 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA083\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA083_iter{1,2}/efecto.txt`: 25 .eml en mailbox local.

**Iter 1** (`sha256=d43d0204aae556bb5085aacd6a8031d4ebf46e1f748784fba4ccf682bf519d5f`):

```text
# ATA083 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T14:34:57Z t0=2026-11-09T14:34:57Z run=cmd /c C:\lab-attack\ATA083\run.cmd
2026-11-09T14:34:58Z t1=2026-11-09T14:34:58Z

evidencia_local:
  ata=ATA083
  tecnica=T1667
  fuente=manual
  t0=2026-11-09T14:34:58Z
  t1=2026-11-09T14:34:58Z
  mailbox=C:\lab-attack\ATA083\mailbox
  ficheros=25
  bytes=2932

VEREDICTO: EFECTO DEMOSTRADO (25 .eml en mailbox local)
```

**Iter 2** (`sha256=99db84ede18c710efaffe4c2f877393b6147eaaef743b93084e8deff77166618`):

```text
# ATA083 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T14:38:51Z t0=2026-11-09T14:38:51Z run=cmd /c C:\lab-attack\ATA083\run.cmd
2026-11-09T14:38:52Z t1=2026-11-09T14:38:52Z

evidencia_local:
  ata=ATA083
  tecnica=T1667
  fuente=manual
  t0=2026-11-09T14:38:52Z
  t1=2026-11-09T14:38:52Z
  mailbox=C:\lab-attack\ATA083\mailbox
  ficheros=25
  bytes=2932

VEREDICTO: EFECTO DEMOSTRADO (25 .eml en mailbox local)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA083_iter1-Detalle.csv` | 44 | `9bea0a1ec6188b42ca2d9e19b304a6d3a74c6ca128d0f7d783100b3029f226da` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA083_iter2-Detalle.csv` | 44 | `5ea100ff8841c537ae6ba1e3a7a9b6cfe645125b87d4f193c3d992e7c4847df4` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 44 | **5** | 3 | 7 | **0** | 29 | 44 | 0 | 0 | 0 |
| 2 | 44 | **5** | 3 | 7 | **0** | 29 | 44 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:34:58.857Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:38:53.003Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA083** es **manual**: mailbox local de juguete con **25 `.eml`**; sin red.
2. El efecto son los 25 ficheros y sus bytes.
