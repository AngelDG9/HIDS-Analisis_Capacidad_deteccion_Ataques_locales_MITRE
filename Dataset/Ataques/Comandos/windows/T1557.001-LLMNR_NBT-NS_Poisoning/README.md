# ATA091 - T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay (Windows)

> **B2.1 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Tecnica | **T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1557.001/T1557.001.yaml` |
| Commit | `388942ad` |
| Prueba | **LLMNR Poisoning with Inveigh (PowerShell)** |
| `guid` | `deecd55f-afe0-4a62-9fba-4d1ba2deb321` |
| Fuente normalizada | `ART_adaptado` |

## 2. Que hace y que se adapta

El atomic descarga Inveigh de internet y lo ejecuta con `-NBNS Y -MDNS Y -HTTPS Y -PROXY Y`.
Aqui **Inveigh esta pre-staged** en el caso (copiado antes de `t0`); se ejecuta en un job con
`-NBNS Y -MDNS Y` (sin HTTPS/proxy, sin relay real) y se lanza una consulta LLMNR/NBT-NS
**solo desde el invitado** (`dir \\tfg-fake\share`). El hash NTLM capturado **no se guarda**:
solo se registra `capturado=True` y su longitud. Ambos roles (atacante y victima) estan en el
mismo invitado.

**Guardarrail**: todo bajo `C:\lab-attack\ATA091\`; sin relay; sin internet; hash no persistido.

## 3. Prueba de efecto

`efecto_local.txt` con `capturado=True`, `longitud=32`, `hash_guardado=False`.
Si no captura, `capturado=False` y se declarara `efecto_parcial`.

## 4. `esperado`

`ATA091_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA091*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA091\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- **El hash NTLM no se guarda** en ningun fichero del repo.
