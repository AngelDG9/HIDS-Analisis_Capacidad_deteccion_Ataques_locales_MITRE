# ATA065 - T1531 Account Access Removal (Windows, `victima-windows`)

> **B1.2 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1531 — Account Access Removal** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1531/T1531.yaml` |
| Commit | `388942ad` |
| Prueba | **Delete User - Windows** |
| `guid` | `f21a1d7d-a62f-442a-8c3a-2440d43b19e5` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic crea `AtomicUser` con `net user ... /add` (requiere contraseña). Se adapta a `New-LocalUser -NoPassword` + `Remove-LocalUser` sobre `tfg_toy_1531` para no escribir credenciales en el repo. Mecanismo: alta + borrado de cuenta.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA065\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA065`. Sin red; nada fuera de `192.168.65.0/24`.
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`Get-LocalUser tfg_toy_1531` existe tras crearla y deja de existir tras borrarla (`existe_despues=False`).

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA065_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA065_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA065*`.
- `syscheck_path` `C:\lab-attack\ATA065\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id` (no se declara ninguna regla no probada).

`sha256` del `esperado`: ver `ATA065_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA065\run.cmd"
```

## 6. Notas

- **No modificar** `ATA065_esperado.csv` después del sello.
- ATA063/064/065 requieren **elevación** (bcdedit/vssadmin/reagentc, servicios y cuentas). Si el
  token SSH no es elevado, el efecto será **parcial** y se declarará; no se maquilla.
- ATA067 reinicia la VM como **última** acción; el efecto se cierra en el host con
  `LastBootUpTime` (`boot_after`).
