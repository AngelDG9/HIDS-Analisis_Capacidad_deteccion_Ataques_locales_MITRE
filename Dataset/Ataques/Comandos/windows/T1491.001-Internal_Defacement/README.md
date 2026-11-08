# ATA066 - T1491.001 Internal Defacement (Windows, `victima-windows`)

> **B1.2 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (`lab-listo-windows-ataques-ssh`). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1491.001 — Internal Defacement** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1491.001/T1491.001.yaml` |
| Commit | `388942ad` |
| Prueba | **Replace Desktop Wallpaper** |
| `guid` | `30558d53-9d76-41c4-9267-a7bd5184bed3` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic sustituye el fondo de escritorio; se adapta el objetivo a un `web\index.html` de juguete (defacement interno). Se conserva el mecanismo: reemplazar contenido visible por otro con mensaje.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA066\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA066`. Sin red; nada fuera de `192.168.65.0/24`.
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`sha256(index.html)` antes != después y el contenido contiene `TFG-DEFACED`.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA066_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA066_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA066*`.
- `syscheck_path` `C:\lab-attack\ATA066\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id` (no se declara ninguna regla no probada).

`sha256` del `esperado`: ver `ATA066_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA066\run.cmd"
```

## 6. Notas

- **No modificar** `ATA066_esperado.csv` después del sello.
- Sin red; el efecto se comprueba en `efecto_local.txt`/`efecto.txt`.
