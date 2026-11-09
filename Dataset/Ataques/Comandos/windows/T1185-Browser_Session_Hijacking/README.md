# ATA082 - T1185 Browser Session Hijacking (Windows)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay navegador real en el laboratorio; se crea un **perfil de navegador
sintetico** (`perfil\Default\Cookies` y `Login Data`) con cabecera **`SQLite format 3`**
(16 bytes) y 512 bytes de relleno. Se copian a `evidencias\browser\` y se comprueba la
cabecera.

## 2. Que hace

1. Crea `Cookies` y `Login Data` con cabecera SQLite valida.
2. Los copia a `evidencias\browser\`.
3. Verifica que la cabecera copiada empieza por `SQLite format 3` + NUL.

**Guardarrail**: todo bajo `C:\lab-attack\ATA082\`; <=64 MiB, <=120 s. Sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `cookies=<bytes>`, `login=<bytes>`, `cabecera=SQLite format 3`,
`cabecera_null=True`.

## 4. `esperado`

`ATA082_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA082*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA082\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Perfil sintetico; no se toca ningun navegador real.
