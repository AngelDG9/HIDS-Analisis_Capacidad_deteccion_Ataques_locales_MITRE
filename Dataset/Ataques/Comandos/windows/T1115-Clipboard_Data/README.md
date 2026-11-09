# ATA072 - T1115 Clipboard Data (Windows, `victima-windows`)

> **B1.3 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **S1 GUI** (tarea InteractiveToken). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1115 — Clipboard Data** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1115/T1115.yaml` |
| Commit | `388942ad` |
| Prueba | **Execute Commands from Clipboard using PowerShell** |
| `guid` | `d6dc21af-bec9-4152-be86-326b6babd416` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic usa `Get-Clipboard | iex`; se adapta a leer una cadena sembrada (`TFG-CLIP-2026-B1.3`) sin ejecutarla. **S1**: sesión 1.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA072\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA072`. Sin red (salvo loopback si aplica).
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`clipboard.txt` contiene exactamente la cadena sembrada (`coincide=True`).

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA072_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA072_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA072*`.
- `syscheck_path` `C:\lab-attack\ATA072\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id`.

`sha256` del `esperado`: ver `ATA072_pre_registro.sha256`.

## 5. S1 — tarea `InteractiveToken` (ATA072)

- Snapshot **`lab-listo-windows-ataques-gui`** (autologon `angel`, sesión 1).
- **Antes de `t0`** (fuera de la ventana), crear la tarea con:
  ```powershell
  powershell -NoProfile -File C:\lab-attack\ATA072\preparar_tarea_s1.ps1 `
    -TriggerLocal (t0+30s).ToLocalTime() -Ata ATA072
  ```
- La tarea se llama **`TFG-Attack-ATA072`**, `InteractiveToken` de `angel`, acción
  `cmd.exe /c C:\lab-attack\ATA072\run.cmd`, disparo **`t0+30 s`**.
- **Después de `t1`**: `Unregister-ScheduledTask -TaskName "TFG-Attack-ATA072" -Confirm:$false`.
- XML equivalente (resumen): `Principal/LogonType=InteractiveToken`, `UserId=DESKTOP-BTMCFA5\angel`,
  `Actions/Exec/Command=cmd.exe`, `Arguments=/c C:\lab-attack\ATA072\run.cmd`,
  `Triggers/TimeTrigger/StartBoundary=t0+30s`.
- El autologon genera un `4624` tipo 2 **al arrancar**, fuera de `[t0,t1]`; se mide en el C0.

## 6. Notas

- **No modificar** `ATA072_esperado.csv` después del sello.
- ATA071/072/073 requieren **S1** (sesión 1); sin escritorio interactivo el PNG/clipboard/keylog
  pueden salir vacíos y se declarará `efecto_parcial`, no se maquilla.
