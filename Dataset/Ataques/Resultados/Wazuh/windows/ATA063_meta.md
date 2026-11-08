---
fase: 3b
bloque: B1
tanda: B1.2
ata_id: ATA063
tecnica: T1490
tactica: Impact
sistema: windows
canal: ssh
version: 1
status: piloto-ok
fecha: 2026-11-08
---

# Ficha - ATA063 - T1490 Inhibit System Recovery (Windows / `victima-windows`)

> Bloque **B1**, tanda **B1.2**. `esperado` **pre-registrado y sellado** en `7bce82d`;
> `sha256` verificado antes de cada `t0`. Canal **SSH**; token **High** (`S-1-16-12288`).
> **Sin secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA063** |
| Técnica | **T1490 - Inhibit System Recovery** |
| Táctica | Impact |
| Sistema | Windows 10 Pro (`victima-windows`, agente `002`) |
| Vía | **ART_adaptado** - SSH |
| Capa | proceso (`4688`/Sysmon 1/4104); FIM como ambigua (D-5) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART_adaptado` |
| `guid` ART | `43819286-91a9-4369-90ed-d31fb4da2c01+cf21060a-80b3-4238-a595-22525de4ab81` |
| Adaptación | vssadmin delete shadows + bcdedit recoveryenabled/bootstatuspolicy + reagentc /disable (copia local de herramientas) |
| Artefacto | `Dataset/Ataques/Comandos/windows/T1490-Inhibit_System_Recovery/` |
| `sha256` ataque | `50f90b64946b94324b81df550855f853b6b1444a07bfb890e9f0f92b51cd7e35` |
| `sha256` esperado | `b87cc83429885a851e8752b760c84cd411a35708c79a7b62c60bb11570ddce3e` |
| C0 | `Soporte/Ataques/c0/windows/ATA063_c0.md` (`sha256=9362c70b857d864b5baa2d117c21aaa066bf8c12518f446266654daf21fc7db3`) |

## 3. Snapshot, red y servicios

- Snapshot **`lab-listo-windows-ataques-ssh`** revertido por iteración; VM apagada entre tandas.
- `t0` >= 90 s tras `Agent Active`; copia del caso y pre-staging **fuera** de `[t0,t1]` (gap de 15 s).
- **Sin red**: no se levantan servicios del host.

## 4. Iteraciones

| Iter | `t0` (UTC) | `t1` (UTC) | Dur | filas | detección | `rule_id` | dudosas resueltas |
|---|---|---|---|---|---|---|---|
| 1 | `2026-11-08T22:11:07Z` | `2026-11-08T22:11:15Z` | 8 s | 44 | **5** | `67027,92032,92052` | 19 |
| 2 | `2026-11-08T22:15:01Z` | `2026-11-08T22:15:11Z` | 10 s | 44 | **5** | `67027,92032,92052` | 19 |

## 5. Comando ejecutado (literal)

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA063\run.cmd"
```

## 6. Prueba de efecto (no es detección)

`Logs/ATA063_iter{1,2}/efecto.txt`: bcdedit recoveryenabled=No y bootstatuspolicy=IgnoreAllFailures; reagentc /disable parcial (sin salida).

**Iter 1** (`sha256=c8b15624f24ff0d25811cdf087c4fb732ba2ec50b4fe56cd972dc19659a6608f`):

```text
  vssadmin_list_antes_len=
  92

bcdedit_despues.txt:
  recoveryenabled         No
  bootstatuspolicy        IgnoreAllFailures

VEREDICTO: EFECTO DEMOSTRADO (bcdedit recoveryenabled=No: True; bootstatuspolicy=IgnoreAllFailures: True; reagentc /disable: parcial, sin salida)
```

**Iter 2** (`sha256=061caa8831b623e4e388cadcd5c93b722adc169a68b7902f43cd71f668ec5f16`):

```text
  vssadmin_list_antes_len=
  92

bcdedit_despues.txt:
  recoveryenabled         No
  bootstatuspolicy        IgnoreAllFailures

VEREDICTO: EFECTO DEMOSTRADO (bcdedit recoveryenabled=No: True; bootstatuspolicy=IgnoreAllFailures: True; reagentc /disable: parcial, sin salida)
```

## 7. Ventana extraída

| Iter | Detalle | filas | `sha256` |
|---|---|---|---|
| 1 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA063_iter1-Detalle.csv` | 44 | `3962a9a576430325f58241778cef123ce5f966b5b5565e40ef67b8d905d0a0e5` |
| 2 | `Dataset/Ataques/Resultados/Wazuh/windows/CSV/ATA063_iter2-Detalle.csv` | 44 | `1101876a4e1112eebb9e794ad822a54004885f520f32d4a8d976dc5f07588d6e` |

## 8. Resultado (métrica v1)

| Iter | filas | detección | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 44 | **5** | 3 | 8 | **0** | 28 | 44 | 0 | 0 | 0 |
| 2 | 44 | **5** | 3 | 8 | **0** | 28 | 44 | 0 | 0 | 0 |

### 8.1 Detecciones

| Iter | alertas | `rule_id` distintos | primera evidencia |
|---|---|---|---|
| 1 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:11:08.532Z` `rule_id=92052` |
| 2 | 5 | 3 -> `67027,92032,92052` | `2026-11-08T22:15:02.907Z` `rule_id=92052` |

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
5. **`reagentc /disable` parcial**: la copia local no devolvió salida; el efecto principal lo da `bcdedit` (No/IgnoreAllFailures).
6. **Realismo acotado**: rutas conocidas por el analista; entorno limpio; red host-only.
