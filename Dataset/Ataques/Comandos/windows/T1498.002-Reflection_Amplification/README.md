# ATA090 - T1498.002 Reflection Amplification (Windows)

> **B2.1 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se implementa una **amplificacion por reflexion UDP** en loopback:
amplificador `127.0.0.1:5353`, victima `127.0.0.2:5354` (2.a direccion loopback).
La victima envia **100 consultas de 64 B** y recibe **100 respuestas de 4 KB** (~400 KB).
**Sin spoofing**; el "tercero" es la 2.a direccion loopback.

## 2. Que hace

1. Arranca el amplificador UDP 5353 (`ReuseAddress` por el mDNS del sistema).
2. La victima se enlaza a `127.0.0.2:5354` y envia 100 consultas de 64 B.
3. El amplificador responde 4 KB a la victima; se mide `sent_bytes`/`recv_bytes`.

**Guardarrail**: loopback; 100 consultas; 64 B -> 4 KB; <=120 s. Sin red externa.

## 3. Prueba de efecto

`efecto_local.txt` con `sent_bytes=6400`, `recv_bytes=409600`, `ratio=64`.

## 4. `esperado`

`ATA090_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA090*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA090\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- `127.0.0.2` es loopback valido en Windows; no se toca VMnet1.
