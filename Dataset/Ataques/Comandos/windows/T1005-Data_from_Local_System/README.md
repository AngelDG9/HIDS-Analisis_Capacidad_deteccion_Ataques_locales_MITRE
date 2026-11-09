# ATA068 - T1005 Data from Local System (Windows, `victima-windows`)

> **B1.3 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (SSH). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1005 — Data from Local System** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1005/T1005.yaml` |
| Commit | `388942ad` |
| Prueba | **Search files of interest and save them to a single zip file (Windows)** |
| `guid` | `d3d9af44-b8ad-4375-8b0a-4bff4b7e419c` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic busca por extensión y comprime; aquí se conserva la búsqueda y se escribe un inventario (`dir`/`Get-ChildItem` + tamaño/fecha) en `inventario.txt`. El archivo se mide en ATA069 (T1560.001).

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA068\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA068`. Sin red (salvo loopback si aplica).
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`inventario.txt` con 20 líneas (ruta|tamaño|mtime) de 20 ficheros de juguete.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA068_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA068_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA068*`.
- `syscheck_path` `C:\lab-attack\ATA068\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id`.

`sha256` del `esperado`: ver `ATA068_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA068\run.cmd"
```

## 6. Notas

- **No modificar** `ATA068_esperado.csv` después del sello.
- ATA071/072/073 requieren **S1** (sesión 1); sin escritorio interactivo el PNG/clipboard/keylog
  pueden salir vacíos y se declarará `efecto_parcial`, no se maquilla.
