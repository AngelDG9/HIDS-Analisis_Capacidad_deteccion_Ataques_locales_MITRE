# ATA062 - T1485 Data Destruction (Windows, `victima-windows`)

> **B1.2 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1485 — Data Destruction** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1485/T1485.yaml` |
| Commit | `388942ad` |
| Prueba | **Windows - Overwrite file with SysInternals SDelete** |
| `guid` | `476419b5-aebf-4366-a131-ae3e8dae5fc2` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

SDelete no está pre-staged y exige EULA; se sustituye por sobrescritura nativa con PowerShell ([IO.File]::WriteAllBytes con ceros) y borrado de 5 ficheros de juguete. Mecanismo: sobrescribir + borrar.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA062\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA062`. Sin red; nada fuera de `192.168.65.0/24`.
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

5/5 ficheros sobrescritos con ceros y borrados; `existe_after=0`.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA062_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA062_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA062*`.
- `syscheck_path` `C:\lab-attack\ATA062\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id` (no se declara ninguna regla no probada).

`sha256` del `esperado`: ver `ATA062_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA062\run.cmd"
```

## 6. Notas

- **No modificar** `ATA062_esperado.csv` después del sello.
- Sin red; el efecto se comprueba en `efecto_local.txt`/`efecto.txt`.
