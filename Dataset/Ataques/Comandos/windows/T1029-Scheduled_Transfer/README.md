# ATA079 - T1029 Scheduled Transfer (Windows)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. El clon ART `388942ad` **no** trae `T1029`. Se implementa con `schtasks.exe`:
crea una tarea que ejecuta un POST al sink local. La deteccion esperada es de **proceso**
(4688/Sysmon 1, `schtasks.exe`); `4698`/`106` es **ciego** en el C0.

## 2. Que hace

1. Crea `payload.txt` (20 lineas de juguete) y `post.cmd` (curl POST al sink).
2. `schtasks /create /tn TFG-ATA079 /tr "cmd.exe /c post.cmd" /sc once /st <t+1min> /f /it`.
3. Espera a que la tarea se ejecute y lee `Last Run Time`.
4. Borra la tarea (`schtasks /delete`) y escribe `efecto_local.txt`.

**Guardarrail**: todo bajo `C:\lab-attack\ATA079\`; destino `192.168.65.*`; <=64 MiB;
<=120 s. Sin internet.

**Requisito de sesion**: `/it` requiere que `angel` tenga sesion iniciada. Ejecutar sobre el
snapshot GUI con autologon (o S1). Si no hay sesion, la tarea no corre y el efecto sera
`parcial` (se declara, no se maquilla).

## 3. Prueba de efecto

`sink.log`: `POST /upload/ATA079 ... sha256=<hash>` + `Last Run Time` distinto de `N/A`
en `efecto_local.txt`.

## 4. `esperado`

`ATA079_esperado.csv` (v5, field-first): `powershell.exe`, `schtasks.exe`, `curl.exe` y
`cmd.exe` + ancla `*lab-attack*ATA079*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA079\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink 9090 se levanta en el HOST antes de `t0` y se para tras `t1`.
