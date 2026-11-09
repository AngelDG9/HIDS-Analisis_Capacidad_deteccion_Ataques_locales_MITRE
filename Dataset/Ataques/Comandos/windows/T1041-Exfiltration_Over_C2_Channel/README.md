# ATA074 - T1041 Exfiltration Over C2 Channel (Windows, `victima-windows`)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente ART

| Campo | Valor |
|---|---|
| Tecnica | **T1041 - Exfiltration Over C2 Channel** |
| Fichero | `Soporte/Ataques/atomic-red-team/atomics/T1041/T1041.yaml` |
| Commit | `388942ad` |
| Prueba | **C2 Data Exfiltration** |
| `guid` | `d1253f6e-c29b-49dc-b466-2147a6191932` |
| Fuente normalizada | `ART_adaptado` |

## 2. Que hace y que se adapta

El atomic crea un fichero de texto y lo envia por `POST` a un C2. Aqui se conserva la accion
(POST de un fichero al C2 local) y se cambia el executor de `Invoke-WebRequest` a
**`curl.exe`** (cliente nativo de Windows 10) para que el proceso quede anclado por
`win_image`/`win_command_line` (H4-W). El destino es el sink local `192.168.65.1:9090`;
sin internet.

**Guardarrail de ruta**: todo se escribe bajo `C:\lab-attack\ATA074\`. El script aborta si
`$dir` no empieza por `C:\lab-attack\ATA074` o si el destino no es `192.168.65.*`.
Cotas: <=200 ficheros, <=64 MiB, <=120 s.

## 3. Prueba de efecto (no es deteccion)

`payload.txt` (20 ficheros de juguete concatenados) se envia por POST; el `sink.log` del
HOST registra `POST /upload/ATA074 ... len=<N> sha256=<hash>`. El `sha256` debe coincidir
con el de `payload.txt` anotado en `evidencias/efecto_local.txt`.

## 4. `esperado` (pre-registrado)

`ATA074_esperado.csv` (esquema v5, field-first):
- `win_image` `powershell.exe`, `curl.exe` y `cmd.exe` + ancla `win_command_line` `*lab-attack*ATA074*`.
- `syscheck_path` `C:\lab-attack\ATA074\*` como **`ambigua`** (D-5), no `deteccion`.
- Sin `rule_id`.

`sha256` del `esperado`: ver `ATA074_pre_registro.sha256`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA074\run.cmd"
```

## 6. Notas

- **No modificar** `ATA074_esperado.csv` despues del sello.
- El sink (9090/9091) se levanta en el HOST antes de `t0` y se para tras `t1`.
- Sysmon 3 (red) es **ciego** en el C0; la deteccion esperada es de proceso.
