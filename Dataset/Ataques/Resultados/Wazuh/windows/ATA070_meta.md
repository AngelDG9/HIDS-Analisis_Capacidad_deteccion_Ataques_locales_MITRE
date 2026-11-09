---
fase: 3b
bloque: B1
tanda: B1.3
ata_id: ATA070
tecnica: T1074.001
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA070 - T1074.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.3**. `esperado` **pre-registrado y sellado** en `c0c1058`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA070** |
| Tecnica | **T1074.001** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `a57fbe4b-3440-452a-88a7-943531ac872a` |
| Adaptacion | ART a57fbe4b -> robocopy de 30 ficheros a staging\ |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1074.001-Local_Data_Staging/` |
| `sha256` ataque | `fdff1bd0476d14ad8b29ea28b6f721aad74d66e1b18a27ea124d3cf9e1d55d5b` |
| `sha256` esperado | `ff97a9064d13852f2b0aaa74f177ee508b26e9bf5b231329c2c7e2792be5e212` |
| C0 | `Soporte/Ataques/c0/windows/ATA070_c0.md` (`sha256=8e267ab12d209fbc9aa9d971271d3a5922c41290919cb3df66b4acd78b61cb7c`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T09:25:17Z` | `2026-11-09T09:25:18Z` | 1 s | 51 | **5** | `67027,92032,92052` | 35 |
| 2 | `2026-11-09T09:29:23Z` | `2026-11-09T09:29:24Z` | 1 s | 82 | **5** | `67027,92032,92052` | 66 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA070\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA070_iter{1,2}/efecto.txt`: staging con 30 ficheros; robocopy_rc=1.

**Iter 1** (`sha256=8e64753be6e165bd500fd2ed29463e80244042ce4cf75612b5a564a835cd4a37`):

```text
# ATA070 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T09:25:17Z t0=2026-11-09T09:25:17Z run=cmd /c C:\lab-attack\ATA070\run.cmd
2026-11-09T09:25:18Z t1=2026-11-09T09:25:18Z

evidencia_local:
  ata=ATA070
  tecnica=T1074.001
  fuente=ART_adaptado
  guid=a57fbe4b-3440-452a-88a7-943531ac872a
  t0=2026-11-09T09:25:18Z
  t1=2026-11-09T09:25:18Z
  staging=C:\lab-attack\ATA070\staging
  ficheros=30
  robocopy_rc=1

VEREDICTO: EFECTO DEMOSTRADO (staging con 30 ficheros; robocopy_rc=1)
```

**Iter 2** (`sha256=39f7830a254e8f8af9a176add8fe64b022822e3b73f1a6ff7f52eedfa89b3574`):

```text
# ATA070 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T09:29:23Z t0=2026-11-09T09:29:23Z run=cmd /c C:\lab-attack\ATA070\run.cmd
2026-11-09T09:29:24Z t1=2026-11-09T09:29:24Z

evidencia_local:
  ata=ATA070
  tecnica=T1074.001
  fuente=ART_adaptado
  guid=a57fbe4b-3440-452a-88a7-943531ac872a
  t0=2026-11-09T09:29:24Z
  t1=2026-11-09T09:29:24Z
  staging=C:\lab-attack\ATA070\staging
  ficheros=30
  robocopy_rc=1

VEREDICTO: EFECTO DEMOSTRADO (staging con 30 ficheros; robocopy_rc=1)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA070_iter1-Detalle.csv` | 51 | `f05291a062f8cc6a641b19c0f7bab4d7377333dfc290eab02770264e37736857` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA070_iter2-Detalle.csv` | 82 | `d52e28fef086cc2942f672247ab2c255cebbf3d1cd168be905d6baf3dc471034` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 51 | **5** | 3 | 7 | **0** | 36 | 51 | 0 | 0 | 0 |
| 2 | 82 | **5** | 3 | 7 | **0** | 67 | 82 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T09:25:19.601Z` `rule_id=67027` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T09:29:25.003Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5***: deteccion por proceso; sin capa de red ni de recursos.
2. **Canal**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.

