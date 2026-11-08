# ATA067 - T1529 System Shutdown/Reboot (Windows, `victima-windows`)

> **B1.2 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1529 — System Shutdown/Reboot** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1529/T1529.yaml` |
| Commit | `388942ad` |
| Prueba | **Restart System - Windows** |
| `guid` | `f4648f0d-bf78-483c-bafc-3ec99cd1c302` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic usa `shutdown /r /t 1`; se adapta a `shutdown /r /t 5 /f` como última acción. El script escribe `boot_before` y el comando antes de reiniciar; el efecto se cierra en el host con `boot_after` (LastBootUpTime) tras el reinicio.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA067\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA067`. Sin red; nada fuera de `192.168.65.0/24`.
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`LastBootUpTime` después > antes; el equipo reinicia y el agente `002` vuelve a `Active`. La ventana `[t0,t1]` se cierra con el reinicio.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA067_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA067_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA067*`.
- `syscheck_path` `C:\lab-attack\ATA067\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id` (no se declara ninguna regla no probada).

`sha256` del `esperado`: ver `ATA067_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA067\run.cmd"
```

## 6. Notas

- **No modificar** `ATA067_esperado.csv` después del sello.
- ATA067 reinicia la VM como **última** acción; el efecto se cierra en el host con
  `LastBootUpTime` (`boot_after`).
