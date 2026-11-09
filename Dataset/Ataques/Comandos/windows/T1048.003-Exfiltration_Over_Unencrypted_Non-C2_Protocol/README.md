# ATA077 - T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol (Windows)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual** (mismatch ART). Las atomicas `T1048.003` del clon `388942ad` son Linux/ICMP
(servidor Python, `ping`), no una exfiltracion Windows de texto plano por TCP. Se implementa
texto plano por `TcpClient` al sink local.

## 2. Que hace

1. Crea 20 lineas de texto de juguete en `payload.txt`.
2. Las envia **sin cifrar** por TCP crudo a `192.168.65.1:9091`.
3. Escribe `efecto_local.txt` (bytes, `sha256_plano`).

**Guardarrail**: todo bajo `C:\lab-attack\ATA077\`; destino `192.168.65.*`; <=64 MiB;
<=120 s. Sin internet.

## 3. Prueba de efecto

`sink.log`: `TCP from=<IP> len=<N> sha256=<hash>`; el hash debe coincidir con
`sha256_plano` de `efecto_local.txt`.

## 4. `esperado`

`ATA077_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA077*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA077\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink TCP 9091 se levanta en el HOST antes de `t0` y se para tras `t1`.
