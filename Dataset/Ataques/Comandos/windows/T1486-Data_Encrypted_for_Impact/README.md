# ATA061 - T1486 Data Encrypted for Impact (Windows, `victima-windows`)

> **B1.1 (piloto mixto).** Canal **SSH**. **Manual** (el atomic T1486 exige GPG4Win o
> DiskCryptor, o solo cifra `.akira`; se implementa AES-256 con .NET).

## Que hace

1. Recorre los 5 ficheros pre-staged en `datos/`.
2. Cifra cada uno con **AES-256-CBC** (clave/IV fijos de laboratorio) -> `*.enc`.
3. Descifra `*.enc` -> `*.dec` y compara.
4. Escribe `efecto_local.txt`: `sha256(original)`, `sha256(.enc)`, `sha256(.dec)`,
   `cifrado=before!=enc`, `roundtrip=dec==before`.

**Guardarrail**: solo escribe bajo `C:\lab-attack\ATA061\datos`. Sin red.

## Prueba de efecto

`efecto.txt` de la iteracion: los 5 ficheros con `cifrado=True` y `roundtrip=True`
(`sha256` antes != despues del cifrado). La alerta **no** es prueba de efecto.

## Capa HIDS

El filtro congelado (H4-W) usa FIM (`syscheck_path`) como **ancla/artefacto**, no como
deteccion. La deteccion se declara por **proceso** (`powershell.exe`) + ancla de carpeta.
Las alertas `554` de los `.enc`/`.dec` se atribuyen a `artefacto_ataque` (nunca ruido).

## Esperado

`ATA061_esperado.csv` (pre-registrado).
