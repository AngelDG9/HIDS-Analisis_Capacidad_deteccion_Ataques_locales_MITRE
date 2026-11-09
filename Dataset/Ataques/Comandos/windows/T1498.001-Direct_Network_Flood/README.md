# ATA085 - T1498.001 Direct Network Flood (Windows)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se implementa un **flood TCP directo** contra el sink del HOST
`192.168.65.1:9091`: **8 conexiones de 8 MiB** (64 MiB total). Sin internet.

## 2. Que hace

1. Abre 8 conexiones TCP al sink 9091.
2. Envia 8 MiB por conexion (buffer de 64 KiB).
3. Cierra cada conexion y anota el total.

**Guardarrail**: destino `192.168.65.*`; <=64 MiB; <=120 s. Sin internet.

## 3. Prueba de efecto

`sink.log` del HOST con **8 lineas** `TCP from=... len=8388608 sha256=...` (64 MiB total).

## 4. `esperado`

`ATA085_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA085*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA085\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink 9091 se levanta en el HOST antes de `t0` y se para tras `t1`.
