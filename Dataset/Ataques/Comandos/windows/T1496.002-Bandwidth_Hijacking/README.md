# ATA088 - T1496.002 Bandwidth Hijacking (Windows)

> **B2.1 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay atomica ART que encaje con el laboratorio; se implementa un envio
**TCP crudo de 32 MiB en una conexion** al sink del HOST `192.168.65.1:9091`.

## 2. Que hace

1. Abre **una** conexion TCP al sink 9091.
2. Envia **32 MiB** (buffer de 64 KiB, 512 escrituras).
3. Cierra y anota `bytes=33554432`.

**Guardarrail**: destino `192.168.65.*`; 32 MiB; <=120 s. Sin internet.

## 3. Prueba de efecto

`sink.log` del HOST con **una linea** `TCP from=... len=33554432 sha256=...`.

## 4. `esperado`

`ATA088_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA088*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA088\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink 9091 se levanta en el HOST antes de `t0` y se para tras `t1`.
