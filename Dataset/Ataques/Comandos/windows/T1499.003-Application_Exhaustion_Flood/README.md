# ATA089 - T1499.003 Application Exhaustion Flood (Windows)

> **B2.1 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se levanta una **app de juguete** en `127.0.0.1:9093` (single-thread,
`/slow` duerme 200 ms, `/health` responde rapido) y se envian **200 peticiones** con
10 workers. No se toca ningun servicio del host.

## 2. Que hace

1. Arranca la app en loopback 9093.
2. Mide latencia de `/health` antes (3 muestras).
3. Lanza 200 peticiones a `/slow` (10 workers x 20).
4. Mide `/health` durante el flood y despues; para la app.

**Guardarrail**: loopback `127.0.0.1:9093`; 200 peticiones; <=120 s. Sin red externa.

## 3. Prueba de efecto

`efecto_local.txt` con `before_ms`, `during_ms`, `after_ms`, `peticiones=200` y
`exhausted=True` (durante > max(1000 ms, 2 x antes)).

## 4. `esperado`

`ATA089_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA089*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA089\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- La app es desechable y se para al final; no se toca el servicio del host.
