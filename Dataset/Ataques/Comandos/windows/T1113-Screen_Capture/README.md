# ATA071 - T1113 Screen Capture (Windows, `victima-windows`)

> **B1.3 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **S1 GUI** (tarea InteractiveToken). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1113 — Screen Capture** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1113/T1113.yaml` |
| Commit | `388942ad` |
| Prueba | **Windows Screen Capture (CopyFromScreen)** |
| `guid` | `e9313014-985a-48ef-80d9-cde604ffc187` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic usa `Graphics.CopyFromScreen`; se adapta la ruta de salida a `evidencias\screen.png`. **S1**: tarea `InteractiveToken` en sesión 1 (autologon).

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA071\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA071`. Sin red (salvo loopback si aplica).
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

PNG real (`screen.png`) con bytes > 0 y dimensiones de la pantalla.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA071_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA071_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA071*`.
- `syscheck_path` `C:\lab-attack\ATA071\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id`.

`sha256` del `esperado`: ver `ATA071_pre_registro.sha256`.

## 5. S1 — tarea `InteractiveToken` (ATA071)

- Snapshot **`lab-listo-windows-ataques-gui`** (autologon `angel`, sesión 1).
- **Antes de `t0`** (fuera de la ventana), crear la tarea con:
  ```powershell
  powershell -NoProfile -File C:\lab-attack\ATA071\preparar_tarea_s1.ps1 `
    -TriggerLocal (t0+30s).ToLocalTime() -Ata ATA071
  ```
- La tarea se llama **`TFG-Attack-ATA071`**, `InteractiveToken` de `angel`, acción
  `cmd.exe /c C:\lab-attack\ATA071\run.cmd`, disparo **`t0+30 s`**.
- **Después de `t1`**: `Unregister-ScheduledTask -TaskName "TFG-Attack-ATA071" -Confirm:$false`.
- XML equivalente (resumen): `Principal/LogonType=InteractiveToken`, `UserId=DESKTOP-BTMCFA5\angel`,
  `Actions/Exec/Command=cmd.exe`, `Arguments=/c C:\lab-attack\ATA071\run.cmd`,
  `Triggers/TimeTrigger/StartBoundary=t0+30s`.
- El autologon genera un `4624` tipo 2 **al arrancar**, fuera de `[t0,t1]`; se mide en el C0.

## 6. Notas

- **No modificar** `ATA071_esperado.csv` después del sello.
- ATA071/072/073 requieren **S1** (sesión 1); sin escritorio interactivo el PNG/clipboard/keylog
  pueden salir vacíos y se declarará `efecto_parcial`, no se maquilla.
