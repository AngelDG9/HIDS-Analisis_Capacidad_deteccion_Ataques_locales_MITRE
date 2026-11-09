# ATA075 - T1048.001 Exfiltration Over Symmetric Encrypted Non-C2 Protocol (Windows)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual** (mismatch ART). El clon ART `388942ad` no trae una atomica Windows de
exfiltracion simetrica AES + `TcpClient` que encaje con el laboratorio: `T1048` cubre
SSH/DNS y las variantes .002/.003 usan `curl` a internet o ICMP. Se implementa el caso
con criptografia .NET y TCP crudo al sink local.

## 2. Que hace

1. Crea 20 ficheros de juguete y los concatena en `payload.txt`.
2. Cifra con **AES-256** (clave/IV efimeros, no persistidos).
3. Envia el criptograma por **TCP crudo** a `192.168.65.1:9091` (`TcpClient`).
4. Escribe `evidencias/efecto_local.txt` (bytes, `sha256_cifrado`, destino).

**Guardarrail**: todo bajo `C:\lab-attack\ATA075\`; destino `192.168.65.*`; <=200 ficheros,
<=64 MiB, <=120 s. Sin internet.

## 3. Prueba de efecto

`sink.log` del HOST con una linea `TCP from=<IP> len=<N> sha256=<hash>`; el `sha256` debe
coincidir con `sha256_cifrado` de `efecto_local.txt`.

## 4. `esperado`

`ATA075_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA075*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA075\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink TCP 9091 se levanta en el HOST antes de `t0` y se para tras `t1`.
