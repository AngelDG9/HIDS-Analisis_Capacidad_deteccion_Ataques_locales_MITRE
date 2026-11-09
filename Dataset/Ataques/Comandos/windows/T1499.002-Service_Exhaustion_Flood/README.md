# ATA087 - T1499.002 Service Exhaustion Flood (Windows)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se levanta un **servicio TCP desechable** en loopback `127.0.0.1:9094`
(backlog 1, atiende una conexion cada 5 s) y se envian **200 peticiones**. El servicio
deja de responder; la sonda final mide `servicio_responde=False`.

## 2. Que hace

1. Arranca el servicio desechable en `127.0.0.1:9094`.
2. Envia 200 conexiones con timeout de 200 ms.
3. Sonda final con timeout de 1 s; anota `servicio_responde`.
4. Para el servicio.

**Guardarrail**: loopback `127.0.0.1:9094`; 200 peticiones; <=120 s. Sin red externa.

## 3. Prueba de efecto

`efecto_local.txt` con `peticiones=200`, `ok`, `fail`, `servicio_responde=False`
(servicio no responde).

## 4. `esperado`

`ATA087_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA087*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA087\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Servicio desechable en loopback; se para al final.
