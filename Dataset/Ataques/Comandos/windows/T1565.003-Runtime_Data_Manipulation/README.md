# ATA097 - T1565.003 Runtime Data Manipulation (Windows)

> **B2.2 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. Se usa `WriteProcessMemory` (P/Invoke) sobre un **proceso PowerShell de
juguete**: el proceso reserva memoria con `VirtualAlloc`, escribe `TFG-ORIGINAL-STRING` y la
imprime en bucle; el ataque sobrescribe la cadena con `TFG-MANIPULATED-STRING` y el proceso
imprime la cadena alterada. Pareja Windows de **ATA036**.

## 2. Que hace

1. Crea `toy.ps1` y lo arranca como proceso PowerShell separado.
2. Espera a que el juguete publique la direccion de memoria (`toy_addr.txt`).
3. `OpenProcess` + `WriteProcessMemory` de la cadena manipulada.
4. Lee la ultima salida del juguete (`toy_out.txt`) y comprueba `TFG-MANIPULATED-STRING`.

**Guardarrail**: **solo** el PID del proceso de juguete (`powershell.exe` con `toy.ps1`);
nunca `lsass`, `winlogon`, `services`. Todo bajo `C:\lab-attack\ATA097\`; <=120 s.

## 3. Prueba de efecto

`efecto_local.txt` con `write_ok=True`, `original=TFG-ORIGINAL-STRING`,
`manipulated=TFG-MANIPULATED-STRING`, `ultima_lectura=TFG-MANIPULATED-STRING`,
`alterado=True`.

## 4. `esperado`

`ATA097_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA097*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA097\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- Si `OpenProcess`/`WriteProcessMemory` fallan, `efecto_parcial` declarado.
