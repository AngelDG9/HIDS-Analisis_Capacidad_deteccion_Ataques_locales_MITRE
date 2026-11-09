# ATA081 - T1114.001 Local Email Collection (Windows, `victima-windows`)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Tecnica | **T1114.001 - Local Email Collection** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1114.001/T1114.001.yaml` |
| Commit | `388942ad` |
| Prueba | **Email Collection with PowerShell Get-Inbox** |
| `guid` | `3f1b5096-0139-4736-9b78-19bcb02bb1cb` |
| Fuente normalizada | `ART_adaptado` |

## 2. Que hace y que se adapta

El atomic usa Outlook y `Get-Inbox.ps1` (descarga de internet). Aqui no hay Outlook ni
internet: se crea un **perfil de correo sintetico** con 20 `.eml` y un `outlook.pst` de
juguete, y se copia a `evidencias\mail\` con un inventario `mail.csv` (nombre|tamano|sha256).
La accion (recoger correo local) es la misma; el executor se adapta al laboratorio.

**Guardarrail**: todo bajo `C:\lab-attack\ATA081\`; <=200 ficheros, <=64 MiB, <=120 s.
Sin red.

## 3. Prueba de efecto (no es deteccion)

`evidencias\mail\` con 21 ficheros (20 `.eml` + 1 `.pst`) y `mail.csv` con 21 lineas
`nombre|tamano|sha256`.

## 4. `esperado`

`ATA081_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA081*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA081\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Sin Outlook ni red; perfil sintetico declarado.
