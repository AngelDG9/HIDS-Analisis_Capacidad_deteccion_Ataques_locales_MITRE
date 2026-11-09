# ATA080 - T1213.006 Data from Information Repositories: Databases (Windows)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. El clon ART `388942ad` **no** trae `T1213.006`. Se implementa una extraccion
local con `sqlite3 .dump` sobre una BD de juguete.

## 2. Que hace

1. Crea una BD SQLite `datos.db` con una tabla `clientes` y 20 filas.
2. Ejecuta `sqlite3 datos.db .dump` y guarda `dump.sql`.
3. Cuenta las filas y escribe `efecto_local.txt` (filas, sha256).

**Guardarrail**: todo bajo `C:\lab-attack\ATA080\`. `sqlite3.exe` debe estar pre-staged en
`C:\lab-attack\sqlite3\sqlite3.exe` (fuera del repo); si no existe, aborta. Sin red.

## 3. Prueba de efecto

`dump.sql` con el `CREATE TABLE` + 20 `INSERT`; `filas=20` y `sha256` en
`efecto_local.txt`. No es deteccion.

## 4. `esperado`

`ATA080_esperado.csv` (v5, field-first): `powershell.exe`, `sqlite3.exe` y `cmd.exe` + ancla
`*lab-attack*ATA080*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA080\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- `sqlite3.exe` se prepara **fuera** de `[t0,t1]`.
