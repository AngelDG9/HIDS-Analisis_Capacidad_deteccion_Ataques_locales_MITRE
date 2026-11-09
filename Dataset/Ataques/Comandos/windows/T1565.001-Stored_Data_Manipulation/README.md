# ATA095 - T1565.001 Stored Data Manipulation (Windows)

> **B2.2 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se altera **in situ** un `libro.csv` de juguete (saldo de A: 5000 -> 9999) y se
comparan los `sha256` antes/despues. Pareja Windows de **ATA032**.

## 2. Que hace

1. Crea `libro.csv` (`A=5000`, `B=1000`, `C=250`) y calcula `sha256_antes`.
2. Modifica la fila A a `9999` y reescribe el fichero.
3. Calcula `sha256_despues` y comprueba que difiere.

**Guardarrail**: solo `libro.csv` bajo `C:\lab-attack\ATA095\`; <=64 MiB; <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `sha256_antes`, `sha256_despues`, `alterado=True`.

## 4. `esperado`

`ATA095_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA095*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA095\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- FIM `550`/`554` es la huella del fichero; el efecto es el `sha256` cambiado.
