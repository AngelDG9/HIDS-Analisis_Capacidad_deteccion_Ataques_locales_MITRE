---
fase: 3b
bloque: B1
tanda: B1.5
ata_id: ATA081
tecnica: T1114.001
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA081 - T1114.001 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.5**. `esperado` **pre-registrado y sellado** en `4e41f38`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA081** |
| Tecnica | **T1114.001** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `3f1b5096-0139-4736-9b78-19bcb02bb1cb` |
| Adaptacion | ART 3f1b5096 -> perfil de correo sintetico (.eml/.pst) + copia a evidencias\mail |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1114.001-Local_Email_Collection/` |
| `sha256` ataque | `a8c87713622ee0dcf8fc4763a5288a37507563fa6edf736a186abc120dfb0438` |
| `sha256` esperado | `1a69bcbfe451ef6505ac190d7ded0c6d4b97fa9d852f7e668b0ceeed63c830a4` |
| C0 | `Soporte/Ataques/c0/windows/ATA081_c0.md` (`sha256=`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso **fuera** de `[t0,t1]`.
- Sin red.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T14:19:18Z` | `2026-11-09T14:19:23Z` | 5 s | 63 | **5** | `67027,92032,92052` | 46 |
| 2 | `2026-11-09T14:23:11Z` | `2026-11-09T14:23:12Z` | 1 s | 60 | **5** | `67027,92032,92052` | 45 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA081\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA081_iter{1,2}/efecto.txt`: 21 ficheros copiados (20 .eml + 1 .pst) + mail.csv.

**Iter 1** (`sha256=bfdceb3461cdba33e0f7daa4f214c6f2a6b88aaf40769764a73e459f1b376e2e`):

```text
# ATA081 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T14:19:18Z t0=2026-11-09T14:19:18Z run=cmd /c C:\lab-attack\ATA081\run.cmd
2026-11-09T14:19:23Z t1=2026-11-09T14:19:23Z

evidencia_local:
  ata=ATA081
  tecnica=T1114.001
  fuente=ART_adaptado
  guid=3f1b5096-0139-4736-9b78-19bcb02bb1cb
  t0=2026-11-09T14:19:22Z
  t1=2026-11-09T14:19:23Z
  eml=20
  pst=1
  copiados=21
  inventario=C:\lab-attack\ATA081\evidencias\mail.csv

VEREDICTO: EFECTO DEMOSTRADO (21 ficheros: 20 .eml + 1 .pst; mail.csv)
```

**Iter 2** (`sha256=934ddebeb11045b8886b9314e2ef2aa12caa1e80b81f32ff520305294bc00de0`):

```text
# ATA081 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T14:23:11Z t0=2026-11-09T14:23:11Z run=cmd /c C:\lab-attack\ATA081\run.cmd
2026-11-09T14:23:12Z t1=2026-11-09T14:23:12Z

evidencia_local:
  ata=ATA081
  tecnica=T1114.001
  fuente=ART_adaptado
  guid=3f1b5096-0139-4736-9b78-19bcb02bb1cb
  t0=2026-11-09T14:23:12Z
  t1=2026-11-09T14:23:12Z
  eml=20
  pst=1
  copiados=21
  inventario=C:\lab-attack\ATA081\evidencias\mail.csv

VEREDICTO: EFECTO DEMOSTRADO (21 ficheros: 20 .eml + 1 .pst; mail.csv)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA081_iter1-Detalle.csv` | 63 | `07b54da7dfe5ccdddea85b82c4cfee225e8ddeb6ba738776e53046c9535e4ba5` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA081_iter2-Detalle.csv` | 60 | `9a2156ab9f7df66b67ebd1d49f6b9acd8e84dd88cb00c1d57f58609156c1221e` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 63 | **5** | 3 | 9 | **0** | 46 | 63 | 0 | 0 | 0 |
| 2 | 60 | **5** | 3 | 7 | **0** | 45 | 60 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:19:20.130Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T14:23:12.630Z` `rule_id=92052` |

- Deteccion principal: procesos del ataque anclados por `win_image`/`win_command_line` a la carpeta.
- **El efecto no es deteccion**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteracion - veredicto **`iguales`**

`['67027', '92032', '92052'] == ['67027', '92032', '92052']`; recuento 5 vs 5;
margen `max(2, 10%*n1)=2` -> `criterio_recuento_ok=True`; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **ATA081** es **ART_adaptado**: se cita T1114.001 `3f1b5096` y se sustituye Outlook/`Get-Inbox.ps1` por un **perfil de correo sintetico** (20 `.eml` + `outlook.pst`) copiado a `evidencias\mail\` con `mail.csv`.
2. El efecto es 21 ficheros copiados; no es deteccion.
