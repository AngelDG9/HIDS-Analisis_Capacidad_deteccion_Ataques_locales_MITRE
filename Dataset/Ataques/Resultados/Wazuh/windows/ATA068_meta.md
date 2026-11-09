---
fase: 3b
bloque: B1
tanda: B1.3
ata_id: ATA068
tecnica: T1005
tactica: Collection
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-09
---

# Ficha - ATA068 - T1005 (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.3**. `esperado` **pre-registrado y sellado** en `c0c1058`;
> `sha256` verificado antes de cada `t0`. Canal **SSH** (token **High**, `S-1-16-12288`). **Sin secretos.**

## 1. Identificacion

| Campo | Valor |
|---|---|
| ATA | **ATA068** |
| Tecnica | **T1005** |
| Tactica | Collection |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Via | **ART_adaptado** - ssh |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `d3d9af44-b8ad-4375-8b0a-4bff4b7e419c` |
| Adaptacion | ART d3d9af44 -> inventario de C:\Users\angel\Documents con PowerShell |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1005-Data_from_Local_System/` |
| `sha256` ataque | `cd27d325ecd1445f002acb45bc710660678d85a516d60fc6af8d4310a4734e8f` |
| `sha256` esperado | `90ace9fe97f92f87b18f89c65271451cdebc7657375d4cd64243fc6ece23d2e6` |
| C0 | `Soporte/Ataques/c0/windows/ATA068_c0.md` (`sha256=73b0dcc4cae5e651284b87b47d4f5b0d1a48d2cc9be6c987c94fdd76290565ec`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteracion; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]`.
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | deteccion | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-09T09:07:40Z` | `2026-11-09T09:07:44Z` | 4 s | 43 | **5** | `67027,92032,92052` | 26 |
| 2 | `2026-11-09T09:13:42Z` | `2026-11-09T09:13:43Z` | 1 s | 40 | **5** | `67027,92032,92052` | 25 |

## 5. Comando ejecutado (literal)

```text
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA068\run.cmd"
```

## 6. Prueba de efecto (no es deteccion)

`Logs/ATA068_iter{1,2}/efecto.txt`: inventario.txt con 20 ficheros.

**Iter 1** (`sha256=8838daa5142ab6ffa2f47d479d76b9bc620c402bdae872dc28508b9d47afc9be`):

```text
# ATA068 iter1 - prueba de efecto (NO es deteccion)

2026-11-09T09:07:40Z t0=2026-11-09T09:07:40Z run=cmd /c C:\lab-attack\ATA068\run.cmd
2026-11-09T09:07:44Z t1=2026-11-09T09:07:44Z

evidencia_local:
  ata=ATA068
  tecnica=T1005
  fuente=ART_adaptado
  guid=d3d9af44-b8ad-4375-8b0a-4bff4b7e419c
  t0=2026-11-09T09:07:44Z
  t1=2026-11-09T09:07:44Z
  ficheros=20
  inventario=C:\lab-attack\ATA068\evidencias\inventario.txt

VEREDICTO: EFECTO DEMOSTRADO (inventario.txt con 20 ficheros)
```

**Iter 2** (`sha256=aa32132ea9df5ff24c84722ad7f7d17f16beaa0672cd3f6b6f17dad26856a0bc`):

```text
# ATA068 iter2 - prueba de efecto (NO es deteccion)

2026-11-09T09:13:42Z t0=2026-11-09T09:13:42Z run=cmd /c C:\lab-attack\ATA068\run.cmd
2026-11-09T09:13:43Z t1=2026-11-09T09:13:43Z

evidencia_local:
  ata=ATA068
  tecnica=T1005
  fuente=ART_adaptado
  guid=d3d9af44-b8ad-4375-8b0a-4bff4b7e419c
  t0=2026-11-09T09:13:43Z
  t1=2026-11-09T09:13:43Z
  ficheros=20
  inventario=C:\lab-attack\ATA068\evidencias\inventario.txt

VEREDICTO: EFECTO DEMOSTRADO (inventario.txt con 20 ficheros)
```

## 7. Ventana extraida

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA068_iter1-Detalle.csv` | 43 | `ecc8171fa22a136f0a49eb15005880d47b90f19a13b8aee9d6a839b2b7a55192` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA068_iter2-Detalle.csv` | 40 | `9e7c0fc85cf0a7a0e57c49dd50a89df90d4c33b31fe75fc59c2bdaef17fa809c` |

## 8. Resultado (metrica v1)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 43 | **5** | 3 | 9 | **0** | 26 | 43 | 0 | 0 | 0 |
| 2 | 40 | **5** | 3 | 7 | **0** | 25 | 40 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T09:07:42.426Z` `rule_id=92032` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-09T09:13:43.713Z` `rule_id=92052` |

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

