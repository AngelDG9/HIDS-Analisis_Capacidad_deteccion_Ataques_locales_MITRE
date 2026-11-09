# ATA076 - T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol (Windows)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual** (mismatch ART). La atomica `T1048.002` (`1cdf2fb0`) exfiltra con
`curl -F` a `https://file.io/` (internet) y **no** usa cifrado asimetrico. No encaja con
el laboratorio (sin internet, sink local). Se implementa RSA-2048 + POST al sink.

## 2. Que hace

1. Construye un texto de juguete (`TFG-RSA-2026-B1.4 ...`).
2. Lo cifra con **RSA-2048 OAEP-SHA256** (clave efimera, no persistida).
3. Envia el criptograma en base64 por **POST** a `192.168.65.1:9090/upload/ATA076`.
4. Descifra localmente y comprueba que el texto recuperado coincide.

**Guardarrail**: todo bajo `C:\lab-attack\ATA076\`; destino `192.168.65.*`; <=120 s.
Sin internet.

## 3. Prueba de efecto

- `sink.log`: `POST /upload/ATA076 ... len=<N> sha256=<hash>`; el hash debe coincidir con
  `sha256_post` de `efecto_local.txt`.
- `descifrado_ok=True` en `efecto_local.txt` (roundtrip RSA).

## 4. `esperado`

`ATA076_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA076*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA076\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- El sink 9090 se levanta en el HOST antes de `t0` y se para tras `t1`.
