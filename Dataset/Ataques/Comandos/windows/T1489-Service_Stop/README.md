# ATA064 - T1489 Service Stop (Windows, `victima-windows`)

> **B1.2 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1489 — Service Stop** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1489/T1489.yaml` |
| Commit | `388942ad` |
| Prueba | **Windows - Stop service using Service Controller** |
| `guid` | `21dfb440-830d-4c86-a3e5-2a491d5a8d04` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic para `spooler`; se adapta a un servicio de juguete `TFG-Svc-1489` creado y borrado por el propio script, para no parar servicios reales. Mecanismo: `sc.exe stop` sobre un servicio.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA064\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA064`. Sin red; nada fuera de `192.168.65.0/24`.
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`sc query TFG-Svc-1489` pasa de RUNNING a STOPPED; tras `sc.exe delete`, la consulta devuelve 1060 (no existe).

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA064_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA064_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA064*`.
- `syscheck_path` `C:\lab-attack\ATA064\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id` (no se declara ninguna regla no probada).

`sha256` del `esperado`: ver `ATA064_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA064\run.cmd"
```

## 6. Notas

- **No modificar** `ATA064_esperado.csv` después del sello.
- ATA063/064/065 requieren **elevación** (bcdedit/vssadmin/reagentc, servicios y cuentas). Si el
  token SSH no es elevado, el efecto será **parcial** y se declarará; no se maquilla.
- ATA067 reinicia la VM como **última** acción; el efecto se cierra en el host con
  `LastBootUpTime` (`boot_after`).
