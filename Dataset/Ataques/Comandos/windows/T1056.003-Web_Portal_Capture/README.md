# ATA105 - T1056.003 Web Portal Capture (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay test ART para T1056.003 en el clon. Pareja Windows de **ATA028** (Linux).

## 2. Que hace

1. Levanta un portal `HttpListener` en **`127.0.0.1:8081`**.
2. `t0`: envia un POST de juguete (`username=tfg_user&password=TFG-DUMMY-PASS`).
3. El portal captura el cuerpo y lo guarda en `creds.txt`.
4. Verifica `creds_capturadas=True`, `usuario=tfg_user`, `password_longitud`.

**Guardarrail**: solo `127.0.0.1:8081`; <=64 MiB; <=120 s; sin red externa.
Las credenciales son **de juguete** (`TFG-DUMMY-PASS`), no secretos reales.

## 3. Prueba de efecto

`efecto_local.txt` con `creds_capturadas=True`, `usuario=tfg_user`,
`password_longitud=14`; `creds.txt` con el cuerpo del POST.

## 4. `esperado`

`ATA105_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA105*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA105\run.cmd"
```

## 6. Notas

- Portal local; no es una web real.
- Si el puerto 8081 esta ocupado o el POST falla, `efecto_parcial` declarado.
