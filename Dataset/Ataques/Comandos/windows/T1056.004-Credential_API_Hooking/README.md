# ATA106 - T1056.004 Credential API Hooking (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**ART adaptado**. Test "Hook PowerShell TLS Encrypt/Decrypt Messages":

| Campo | Valor |
|---|---|
| `guid` | `de1934ea-1fbf-425b-8795-65fb27dd7e33` |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1056.004/T1056.004.yaml` |
| Commit | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| DLL | `D:\TFG-VMs\material-windows\b2\T1056.004x64.dll` (`sha256=e728be21…`, 127488 B) |

**Adaptacion**: el test inyecta la DLL con `mavinject` y hace una peticion TLS a
`https://www.example.com`. En el laboratorio se usa un **TLS local** (`127.0.0.1:8443`,
certificado autofirmado) y un **PowerShell de juguete** (`ATA106_toy.ps1`); la DLL se inyecta
con `mavinject` y su salida se captura en `hook.log`. Pareja Windows de **ATA035** (Linux).

## 2. Que hace

1. Verifica la DLL pre-staged (`C:\lab-attack\ATA106\T1056.004x64.dll`, 127488 B).
2. Levanta un servidor TLS local (job) con certificado autofirmado.
3. Arranca el toy (`powershell.exe -File ATA106_toy.ps1`), que espera 5 s y hace la peticion TLS.
4. Inyecta la DLL con `mavinject` en el PID del toy.
5. Espera 14 s, para el toy/servidor y busca `***HOOKED CAPTURE LOG***`/`EncryptMessage`/`DecryptMessage`
   en `hook.log`/`hook_err.log`.

**Guardarrail**: solo `C:\lab-attack\ATA106\`; TLS loopback; <=64 MiB; <=120 s.
La DLL se inyecta **solo** en el PowerShell de juguete, nunca en procesos del sistema.

## 3. Prueba de efecto

`efecto_local.txt` con `inyectado=True`, `hook_log=True`, `efecto_parcial=False`.
Si `mavinject` falla o la DLL no escribe el log, se declara **`efecto_parcial=True`** (no se inventa).

## 4. `esperado`

`ATA106_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA106*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA106\run.cmd"
```

El runner debe pre-staged la DLL (`-PrestageDll`) antes de `t0`.

## 6. Notas

- La DLL es de **x64**; el toy usa el PowerShell de 64 bits.
- Si el hook no dispara, `efecto_parcial` (limitacion declarada en el plan).
