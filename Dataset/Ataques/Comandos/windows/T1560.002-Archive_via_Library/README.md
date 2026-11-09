# ATA093 - T1560.002 Archive via Library (Windows)

> **B2.2 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se implementa un `.zip` con la **libreria .NET**
(`System.IO.Compression.ZipFile`), **no** `Compress-Archive`. Es la pareja Windows de
**ATA013** (FN en Linux).

## 2. Que hace

1. Crea 20 ficheros de juguete en `datos\`.
2. `ZipFile::CreateFromDirectory` -> `archivo.zip`.
3. Cuenta entradas, calcula `sha256` y extrae a `extraido\`.
4. Verifica que cada fichero extraido tiene el mismo `sha256` que el original.

**Guardarrail**: todo bajo `C:\lab-attack\ATA093\`; <=200 ficheros; <=64 MiB; <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `entradas=20`, `zip_sha256`, `extraido_ok=True`.

## 4. `esperado`

`ATA093_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA093*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA093\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- La extraccion se verifica por `sha256`, no solo por numero de entradas.
