# ATA084 - T1657 Financial Theft (Windows)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay sistema financiero real; se crea un **libro local de juguete**
(`libro.csv` con cuentas A/B) y se simula una **transferencia de 1500** de A a B.
Sin red.

## 2. Que hace

1. Crea `libro.csv` (`A=5000`, `B=1000`).
2. Transfiere 1500 de A a B y escribe `libro_after.csv`.
3. Comprueba los saldos (`A=3500`, `B=2500`).

**Guardarrail**: todo bajo `C:\lab-attack\ATA084\`; <=64 MiB, <=120 s. Sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `importe=1500`, `saldo_A=3500`, `saldo_B=2500`,
`alterado=True`.

## 4. `esperado`

`ATA084_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA084*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA084\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Libro sintetico; no se toca ningun sistema financiero.
