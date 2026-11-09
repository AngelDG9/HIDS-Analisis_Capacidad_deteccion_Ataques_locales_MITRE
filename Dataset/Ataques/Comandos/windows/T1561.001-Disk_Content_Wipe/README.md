# ATA099 - T1561.001 Disk Content Wipe (Windows)

> **B2.3 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Pareja Windows de **ATA037** (T1561.001, Linux). No hay test ART para T1561.001.

## 2. Que hace

1. Verifica el VHD del caso (`conectix`, 100 MiB).
2. Siembra el area de datos con `0xAA`.
3. `t0`: pone a **cero** el contenido (area de datos); footer intacto.
4. `t1`: verifica primeros 1 MiB y ultimo bloque a cero; `sha256` cambiado.

**Guardarrail**: solo `C:\lab-attack\ATA099\labdisk100.vhd`; aborta con otra ruta.
Nunca `PhysicalDrive*`, `C:`, `\\.\PhysicalDrive*` ni el disco del sistema. <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `primero_cero=True`, `ultimo_cero=True`, `footer_conectix=True`,
`sha256_antes != sha256_despues`, `contenido_borrado=True`.

## 4. `esperado`

`ATA099_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA099*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA099\run.cmd"
```

## 6. Notas

- El VHD se copia **antes de `t0`**.
- No se monta: el borrado es a nivel de bytes. El sistema no se toca.
