# ATA094 - T1560.003 Archive via Custom Method (Windows)

> **B2.2 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se implementa un **formato propio** `TFGARCH1`: cabecera magica, numero de
ficheros, por fichero `nombre` + `tamano` + payload **XOR 0x5A**; el decodificador invierte
el XOR y verifica `sha256`. Es la pareja Windows de **ATA034** (FN en Linux).

## 2. Que hace

1. Crea 20 ficheros de juguete.
2. Construye `custom.tfg` con el formato propio.
3. Lo decodifica a `extraido\` y compara `sha256` con los originales.

**Guardarrail**: todo bajo `C:\lab-attack\ATA094\`; <=200 ficheros; <=64 MiB; <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `magic=TFGARCH1`, `ficheros=20`, `custom_sha256`,
`decodificado_ok=True`.

## 4. `esperado`

`ATA094_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA094*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA094\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El formato es propio; no hay herramienta externa.
