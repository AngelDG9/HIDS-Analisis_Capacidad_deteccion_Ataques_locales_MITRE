# ATA069 - T1560.001 Archive via Utility (Windows, `victima-windows`)

> **B1.3 — preparación.** Caso **pre-registrado** y sellado; **no ejecutado** todavía.
> Canal previsto: **SSH** (SSH). Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Técnica | **T1560.001 — Archive via Utility** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1560.001/T1560.001.yaml` |
| Commit | `388942ad` |
| Prueba | **Compress Data for Exfiltration With Rar** |
| `guid` | `02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0` |
| Fuente normalizada | `ART_adaptado` |

## 2. Qué hace y qué se adapta

El atomic usa WinRAR (no pre-staged); se sustituye por `Compress-Archive` nativo sobre 20 ficheros de juguete. Mecanismo: archivar con utilidad.

**Guardarraíl de ruta**: todo se escribe bajo `C:\lab-attack\ATA069\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA069`. Sin red (salvo loopback si aplica).
Cotas: ≤200 ficheros, ≤120 s.

## 3. Prueba de efecto (no es detección)

`datos.zip` con 20 entradas; tamaño > 0.

Se escribe `evidencias/efecto_local.txt` en el invitado; el `efecto.txt` canónico se compone en
`Logs/ATA069_iter<N>/`.

## 4. `esperado` (pre-registrado)

`ATA069_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA069*`.
- `syscheck_path` `C:\lab-attack\ATA069\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id`.

`sha256` del `esperado`: ver `ATA069_pre_registro.sha256`.

## 5. Ejecución prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA069\run.cmd"
```

## 6. Notas

- **No modificar** `ATA069_esperado.csv` después del sello.
- ATA071/072/073 requieren **S1** (sesión 1); sin escritorio interactivo el PNG/clipboard/keylog
  pueden salir vacíos y se declarará `efecto_parcial`, no se maquilla.
