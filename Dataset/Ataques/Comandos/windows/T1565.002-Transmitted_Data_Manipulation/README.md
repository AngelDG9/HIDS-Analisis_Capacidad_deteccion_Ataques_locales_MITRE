# ATA096 - T1565.002 Transmitted Data Manipulation (Windows)

> **B2.2 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se interpone un **proxy local** `127.0.0.1:9095` que **reescribe el body** en
transito y lo reenvia al sink `192.168.65.1:9090`; el sink recibe un `sha256` distinto del
original. Pareja Windows de **ATA026**.

## 2. Que hace

1. Crea `payload.txt` y calcula `sha256_original`.
2. Levanta el proxy 9095; el cliente envia el payload al sink via proxy.
3. El proxy anade `MANIPULADO-POR-PROXY` y reenvia al sink; registra `orig`/`mod`.
4. El efecto es `sha256_original != sha256_modified`; el `sink.log` del HOST tiene el `mod`.

**Guardarrail**: loopback 9095; destino `192.168.65.*`; <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `sha256_original`, `sha256_modified`, `alterado=True`; `proxy.log`
con `orig=... mod=...`; `sink.log` con el `sha256` alterado.

## 4. `esperado`

`ATA096_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA096*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA096\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink 9090 se levanta en el HOST antes de `t0` y se para tras `t1`.
