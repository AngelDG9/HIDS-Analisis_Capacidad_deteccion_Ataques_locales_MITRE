# ATA100 - T1561.002 Disk Structure Wipe (Windows)

> **B2.3 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Pareja Windows de **ATA027** (T1561.002, Linux). No hay test ART para T1561.002.

## 2. Que hace

1. Verifica el VHD del caso (`conectix`, 100 MiB).
2. Siembra `0xAA` y un MBR falso (`0x55AA` en el offset 510).
3. `t0`: pone a **cero** los primeros 1 MiB (cabecera/particion) y el footer (ultimos 512 B).
4. `t1`: comprueba que `Mount-DiskImage` falla -> `no_montable=True`.

**Guardarrail**: solo `C:\lab-attack\ATA100\labdisk100.vhd`; aborta con otra ruta.
Nunca `PhysicalDrive*`, `C:`, `\\.\PhysicalDrive*` ni el disco del sistema. <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `footer_conectix=False`, `montable=False`, `no_montable=True`,
`sha256_antes != sha256_despues`.

## 4. `esperado`

`ATA100_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA100*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA100\run.cmd"
```

## 6. Notas

- El VHD se copia **antes de `t0`**.
- El montaje fallido se captura; no se toca ningun otro disco.
