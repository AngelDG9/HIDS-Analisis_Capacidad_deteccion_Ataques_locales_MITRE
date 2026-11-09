# ATA101 - T1025 Data from Removable Media (Windows)

> **B2.3 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**ART adaptado**. Test #1 "Identify Documents on USB and Removable Media via PowerShell":

| Campo | Valor |
|---|---|
| `guid` | `0b29f7e3-a050-44b7-bf05-9fb86af1ec2e` |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1025/T1025.yaml` |
| Commit | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |

**Adaptacion**: el test original busca volumenes `DriveType -eq 'Removable'` y lista
`*.doc*/*.xls*/*.txt/*.pdf`. En el laboratorio no hay USB; se monta el VHD del caso
(`labdisk100.vhd`, 100 MiB) y se copian **20 documentos de juguete** desde el volumen a
`C:\lab-attack\ATA101\copiados\`. Pareja Windows de **ATA044** (T1025, Linux).

## 2. Que hace

1. Monta el VHD (`Mount-DiskImage`), lo inicializa/formatea si hace falta (MBR + NTFS).
2. Crea `media\doc_01.txt` ... `doc_20.txt` en el volumen.
3. Copia los 20 ficheros a `C:\lab-attack\ATA101\copiados\`.
4. Verifica 20 ficheros y `sha256` identicos.
5. **Desmonta** el VHD (`Dismount-DiskImage`) en `finally`.

**Guardarrail**: solo `C:\lab-attack\ATA101\labdisk100.vhd`; aborta con otra ruta.
Comprueba que el disco montado no es `IsSystem`/`IsBoot` y mide 100 MiB.
Nunca `PhysicalDrive*`, `C:`, `\\.\PhysicalDrive*` ni el disco del sistema. <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `ficheros_copiados=20`, `sha256_coinciden=True`, `copiado_ok=True`.

## 4. `esperado`

`ATA101_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA101*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA101\run.cmd"
```

## 6. Notas

- El VHD se copia **antes de `t0`**; el montaje/desmontaje ocurre dentro de la ventana.
- No se usa USB real; el VHD hace de medio removible.
