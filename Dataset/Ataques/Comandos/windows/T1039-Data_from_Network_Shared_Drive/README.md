# ATA103 - T1039 Data from Network Shared Drive (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**ART adaptado**. Test #2 "Copy a sensitive File over Administrative share with Powershell":

| Campo | Valor |
|---|---|
| `guid` | `7762e120-5879-44ff-97f8-008b401b9a98` |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1039/T1039.yaml` |
| Commit | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |

**Adaptacion**: el test copia un fichero por `\\remote\C$\...`; en el laboratorio se crea un
share **loopback** `\\127.0.0.1\labshare` con **20 ficheros de juguete** y se copian por UNC a
`copiados\`. Pareja Windows de **ATA039** (T1039, Linux). Limitacion: recurso loopback; sin
auditoria SMB (no 5140/5145).

## 2. Que hace

1. Crea `share\` con 20 ficheros y publica `labshare` (`New-SmbShare`).
2. `t0`: copia `\\127.0.0.1\labshare\*` a `copiados\`.
3. Verifica 20 ficheros y `sha256` identicos.
4. **Elimina el share** en `finally` (`Remove-SmbShare`).

**Guardarrail**: solo `C:\lab-attack\ATA103\`; share loopback; <=200 ficheros, <=64 MiB,
<=120 s; sin red externa.

## 3. Prueba de efecto

`efecto_local.txt` con `ficheros_copiados=20`, `sha256_coinciden=True`, `copia_ok=True`.

## 4. `esperado`

`ATA103_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA103*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA103\run.cmd"
```

## 6. Notas

- Si `New-SmbShare`/UNC falla, `efecto_parcial` declarado.
- El share se elimina siempre; no queda recurso compartido.
