# ATA102 - T1052.001 Exfiltration over USB (Windows)

> **B2.3 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay test ART para T1052.001 en el clon. Se adapta el escenario USB al VHD
del laboratorio. Tactica **Exfiltration**.

## 2. Que hace

1. Crea 20 ficheros de botin en `C:\lab-attack\ATA102\botin\`.
2. Monta el VHD (`Mount-DiskImage`), lo inicializa/formatea si hace falta (MBR + NTFS).
3. Copia el botin a `exfil\` dentro del VHD.
4. **Desmonta**, vuelve a montar y verifica que los 20 ficheros siguen en el VHD.
5. **Desmonta** de nuevo.

**Guardarrail**: solo `C:\lab-attack\ATA102\labdisk100.vhd`; aborta con otra ruta.
Comprueba que el disco montado no es `IsSystem`/`IsBoot` y mide 100 MiB.
Nunca `PhysicalDrive*`, `C:`, `\\.\PhysicalDrive*` ni el disco del sistema. <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `ficheros_en_vhd=20`, `persistido=True`, `exfil_ok=True`.

## 4. `esperado`

`ATA102_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA102*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA102\run.cmd"
```

## 6. Notas

- El VHD se copia **antes de `t0`**; el montaje/desmontaje ocurre dentro de la ventana.
- No se usa USB real; el VHD hace de medio removible.
