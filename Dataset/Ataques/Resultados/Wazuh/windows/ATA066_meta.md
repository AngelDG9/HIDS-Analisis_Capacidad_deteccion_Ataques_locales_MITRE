---
fase: 3b
bloque: B1
tanda: B1.2
ata_id: ATA066
tecnica: T1491.001
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA066 - T1491.001 Internal Defacement (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.2**. `esperado` **pre-registrado y sellado** en `7bce82d`;
> `sha256` verificado antes de cada `t0`. Canal **SSH**; token **High** (`S-1-16-12288`).
> **Sin secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA066** |
| Técnica | **T1491.001 - Internal Defacement** |
| Táctica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Vía | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `30558d53-9d76-41c4-9267-a7bd5184bed3` |
| Adaptación | wallpaper -> web/index.html de juguete; reemplazo de contenido visible |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1491.001-Internal_Defacement/` |
| `sha256` ataque | `20a853716ea5d6218d667ea1048ab6a7f15e4ae40ab8e023e87de23ec78626f8` |
| `sha256` esperado | `de471b5ea64b62471af5181b58ced787cf6f81ddd5899433264e559175fcc6c1` |
| C0 | `Soporte/Ataques/c0/windows/ATA066_c0.md` (`sha256=a75790ca8bff26161cf709162684045f123b63ce54e6cf61cbd8ced567836f3d`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteración; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | detección | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T22:45:01Z` | `2026-11-08T22:45:06Z` | 5 s | 21 | **5** | `67027,92032,92052` | 6 |
| 2 | `2026-11-08T22:48:08Z` | `2026-11-08T22:48:13Z` | 5 s | 30 | **5** | `67027,92032,92052` | 7 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA066\run.cmd"
```

## 6. Prueba de efecto (no es detección)

`Logs/ATA066_iter{1,2}/efecto.txt`: sha256(index.html) antes != después; contiene TFG-DEFACED.

**Iter 1** (`sha256=14658851abf98a770609611e0e00be323304f040f95d572c2f055064f5e95e68`):

```text
  sha256_antes=20c783c28128d1d606474c887dcf6d0123068bcc1a4a4700936915a4b35cc123
  sha256_despues=725323c28b69fc74af64f2ecd4d1cbff82b375d35f6f1573af6ee05986e5470a
  cambiado=
  True
  contiene_deface=
  True

VEREDICTO: EFECTO DEMOSTRADO (sha256 antes != despues; contiene_deface=True)
```

**Iter 2** (`sha256=fb69052a5d8e182390dbc68042f905b91b221ace6474ad953d487bd15cd6e3e9`):

```text
  sha256_antes=20c783c28128d1d606474c887dcf6d0123068bcc1a4a4700936915a4b35cc123
  sha256_despues=725323c28b69fc74af64f2ecd4d1cbff82b375d35f6f1573af6ee05986e5470a
  cambiado=
  True
  contiene_deface=
  True

VEREDICTO: EFECTO DEMOSTRADO (sha256 antes != despues; contiene_deface=True)
```

## 7. Ventana extraída

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA066_iter1-Detalle.csv` | 21 | `51b42ac86008a2d8fc8582ba1d236236e4a50fcb11b75c19f1ea0fd1c023eb72` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA066_iter2-Detalle.csv` | 30 | `6c4bc1e18ccc3f58311ec160dc7cff1ca08e32ffa6737b274b9558d557b07a5d` |

## 8. Resultado (métrica v1)

| Iter | filas | detección | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 21 | **5** | 3 | 7 | **0** | 6 | 21 | 0 | 0 | 0 |
| 2 | 30 | **5** | 3 | 15 | **0** | 7 | 30 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:45:03.095Z` `rule_id=92032` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:48:10.106Z` `rule_id=92052` |

- Detección principal: procesos del ataque anclados por `win_command_line` a la carpeta.
- **El efecto no es detección**: se prueba en `efecto.txt`.
- `dudosa=0`: las FIM `ambigua` (D-5) y los eventos de servicio/cuenta/registro se resolvieron antes de T2.

## 9. Doble iteración - veredicto **`iguales`**

`{67027,92032,92052} == {67027,92032,92052}`; recuento 5 vs 5; `dudosa=0`.

## 10. Limitaciones y hallazgos

1. **H-B1-5′**: detección por proceso; sin capa de red ni de recursos.
2. **Canal SSH**: filas del canal son `operador`/`auto_ruido`; 0 filas del ataque en ruido (candado).
3. **D-5**: `syscheck_path` es `ambigua`; las FIM se resuelven como `artefacto_ataque`.
4. **Elevación**: token SSH **High**; no se necesitó tarea `Highest`.
6. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
