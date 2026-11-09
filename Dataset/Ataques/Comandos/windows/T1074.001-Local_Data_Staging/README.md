# ATA070 - T1074.001 Local Data Staging (Windows, `victima-windows`)

> **B1.3 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (SSH). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1074.001 — Local Data Staging** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1074.001/T1074.001.yaml` |
| Commit | `388942ad` |
| Prueba | **Zip a Folder with PowerShell for Staging in Temp** |
| `guid` | `a57fbe4b-3440-452a-88a7-943531ac872a` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic comprime para staging; se adapta a `robocopy` de una carpeta de 30 ficheros de juguete a `staging\`. Mecanismo: reunir datos localmente.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA070\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA070`. Sin red (salvo loopback si aplica).
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`staging\` con 30 ficheros; `robocopy_rc` 0–7.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA070_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA070_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA070*`.
- `syscheck_path` `C:\lab-attack\ATA070\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id`.

`sha256` del `esperado`: ver `ATA070_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA070\run.cmd"
```

## 6. Notas

- **No modificar** `ATA070_esperado.csv` después del sello.
- ATA071/072/073 requieren **S1** (sesión 1); sin escritorio interactivo el PNG/clipboard/keylog
  pueden salir vacíos y se declarará `efecto_parcial`, no se maquilla.
