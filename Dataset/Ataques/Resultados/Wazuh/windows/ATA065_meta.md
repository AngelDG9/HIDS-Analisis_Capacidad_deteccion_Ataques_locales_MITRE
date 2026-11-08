---
fase: 3b
bloque: B1
tanda: B1.2
ata_id: ATA065
tecnica: T1531
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA065 - T1531 Account Access Removal (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.2**. `esperado` **pre-registrado y sellado** en `7bce82d`;
> `sha256` verificado antes de cada `t0`. Canal **SSH**; token **High** (`S-1-16-12288`).
> **Sin secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA065** |
| Técnica | **T1531 - Account Access Removal** |
| Táctica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Vía | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `f21a1d7d-a62f-442a-8c3a-2440d43b19e5` |
| Adaptación | net user AtomicUser -> New-LocalUser -NoPassword + Remove-LocalUser (sin credenciales) |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1531-Account_Access_Removal/` |
| `sha256` ataque | `fce37897c649583fad8f5f90a8528e2be20d3bbf0925976c34a5a2dc27658a6f` |
| `sha256` esperado | `a680722513689fb740f5d2e9261bffa1a23a9941935867b85d03ff14b0426ecc` |
| C0 | `Soporte/Ataques/c0/windows/ATA065_c0.md` (`sha256=2dc3d094722d3e115435caa2e3670c3dd9ccdc2826f6acab4dbf05c052e2c397`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteración; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | detección | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T22:38:04Z` | `2026-11-08T22:38:09Z` | 5 s | 28 | **5** | `67027,92032,92052` | 13 |
| 2 | `2026-11-08T22:41:40Z` | `2026-11-08T22:41:45Z` | 5 s | 28 | **5** | `67027,92032,92052` | 13 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA065\run.cmd"
```

## 6. Prueba de efecto (no es detección)

`Logs/ATA065_iter{1,2}/efecto.txt`: tfg_toy_1531 creado; existe_antes=True; existe_despues=False.

**Iter 1** (`sha256=0b9990046f3789db9d7056cbc3aefee437f04ca813080031854ca9ad3b3c55df`):

```text
  t1=2026-11-08T22:38:08Z
  usuario=tfg_toy_1531
  creado=True
  existe_antes=True
  existe_despues=False
  error=

VEREDICTO: EFECTO DEMOSTRADO (usuario creado, existe_antes=True, existe_despues=False)
```

**Iter 2** (`sha256=afc9afc6d12dc664fb10eedace7cff84faf84ade6a78c4ddc849b84d48fe1749`):

```text
  t1=2026-11-08T22:41:45Z
  usuario=tfg_toy_1531
  creado=True
  existe_antes=True
  existe_despues=False
  error=

VEREDICTO: EFECTO DEMOSTRADO (usuario creado, existe_antes=True, existe_despues=False)
```

## 7. Ventana extraída

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA065_iter1-Detalle.csv` | 28 | `50809167692e2da8af1ce9b607c082d675b8c7b30cdeaecbcfb17b942dedb596` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA065_iter2-Detalle.csv` | 28 | `846014a1ea4ee965aa919980a9fc6df0114158b00b016288c86cde711607be28` |

## 8. Resultado (métrica v1)

| Iter | filas | detección | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 28 | **5** | 3 | 7 | **0** | 13 | 28 | 0 | 0 | 0 |
| 2 | 28 | **5** | 3 | 7 | **0** | 13 | 28 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:38:05.648Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:41:42.084Z` `rule_id=92052` |

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
