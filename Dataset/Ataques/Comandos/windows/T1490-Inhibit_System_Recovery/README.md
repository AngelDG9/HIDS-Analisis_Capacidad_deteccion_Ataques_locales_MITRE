# ATA063 - T1490 Inhibit System Recovery (Windows, `victima-windows`)

> **B1.2 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1490 — Inhibit System Recovery** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1490/T1490.yaml` |
| Commit | `388942ad` |
| Prueba | **Windows - Delete Volume Shadow Copies + Windows - Disable Windows Recovery Console Repair** |
| `guid` | `43819286-91a9-4369-90ed-d31fb4da2c01 + cf21060a-80b3-4238-a595-22525de4ab81` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

Se combinan dos atomics (vssadmin delete shadows; bcdedit recoveryenabled/bootstatuspolicy) y se añade `reagentc /disable` como cobertura local del componente de recuperación (no está en el atomic). No se crean sombras; solo se borran si existen.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA063\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA063`. Sin red; nada fuera de `192.168.65.0/24`.
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`bcdedit /enum {default}` muestra `recoveryenabled No` y `bootstatuspolicy IgnoreAllFailures`; `reagentc /info` queda deshabilitado; `vssadmin list shadows` se registra antes/después. El revert de la VM lo deshace.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA063_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA063_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA063*`.
- `syscheck_path` `C:\lab-attack\ATA063\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id` (no se declara ninguna regla no probada).

`sha256` del `esperado`: ver `ATA063_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA063\run.cmd"
```

## 6. Notas

- **No modificar** `ATA063_esperado.csv` después del sello.
- ATA063/064/065 requieren **elevación** (bcdedit/vssadmin/reagentc, servicios y cuentas). Si el
  token SSH no es elevado, el efecto será **parcial** y se declarará; no se maquilla.
- ATA067 reinicia la VM como **última** acción; el efecto se cierra en el host con
  `LastBootUpTime` (`boot_after`).
