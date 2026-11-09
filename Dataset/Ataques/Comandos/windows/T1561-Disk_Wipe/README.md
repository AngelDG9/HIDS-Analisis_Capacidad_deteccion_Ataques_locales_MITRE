# ATA098 - T1561 Disk Wipe (Windows)

> **B2.3 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Pareja Windows de **ATA005** (T1561, Linux). No hay test ART para T1561.

## 2. Que hace

1. Verifica que el VHD del caso es valido (`conectix`) y de 100 MiB.
2. Siembra el area de datos con `0xAA` (contenido de juguete).
3. `t0`: sobrescribe **todo el volumen** con `0xFF` (corrupcion).
4. `t1`: verifica cabecera `0xFF`, footer `conectix` intacto y `sha256` cambiado.

**Guardarrail**: solo `C:\lab-attack\ATA098\labdisk100.vhd`; aborta con cualquier otra ruta.
Nunca `PhysicalDrive*`, `C:`, `\\.\PhysicalDrive*` ni el disco del sistema. <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `sha256_antes != sha256_despues`, `cabecera_ff=True`,
`footer_conectix=True`, `vhd_corrupto=True`.

## 4. `esperado`

`ATA098_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA098*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA098\run.cmd"
```

## 6. Notas

- El VHD se copia a `C:\lab-attack\ATA098\labdisk100.vhd` **antes de `t0`**.
- No se monta: la corrupcion es a nivel de bytes. El sistema no se toca.
