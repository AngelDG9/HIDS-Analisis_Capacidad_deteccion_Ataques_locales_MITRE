# ATA086 - T1499.001 OS Exhaustion Flood (Windows)

> **B1.5 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se reservan **8 bloques de 64 MiB = 512 MiB** y se retienen **15 s**.
El efecto se mide con `Available MBytes` (`FreePhysicalMemory`). **El HIDS no tiene capa de
recursos**; la deteccion esperada es de proceso (4688/Sysmon 1).

## 2. Que hace

1. Mide `Available MBytes` antes.
2. Reserva 8 bloques de 64 MiB (512 MiB).
3. Mide durante y espera 15 s.
4. Libera y mide despues.

**Guardarrail**: todo bajo `C:\lab-attack\ATA086\`; <=512 MiB; <=120 s. Sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `available_before_mb`, `available_during_mb`, `available_after_mb`
y `bytes=536870912`. No es deteccion.

## 4. `esperado`

`ATA086_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA086*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA086\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Sin capa de recursos en el HIDS: se declara el punto ciego.
