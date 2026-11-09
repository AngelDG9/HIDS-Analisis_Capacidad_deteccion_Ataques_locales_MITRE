# ATA107 - T1074.002 Remote Data Staging (Windows)

> **B2.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. No hay test ART para T1074.002 en el clon. Pareja Windows de **ATA040** (Linux).

## 2. Que hace

1. Crea `staging_local\` con 20 ficheros de juguete.
2. `t0`: sube cada fichero al **WebDAV del HOST** `http://192.168.65.1:9092/staging/` con `PUT`.
3. El sink (`sink_webdav.py`) guarda cada cuerpo en `cloud_bucket\staging\` y registra
   `PUT <ruta> from=<IP> len=<N> sha256=<hash>` en `sink_webdav.log`.
4. Verifica 20 subidas y los `sha256`.

**Guardarrail**: solo `192.168.65.1:9092`; <=200 ficheros, <=64 MiB, <=120 s; sin otra red.
El host levanta el servicio con `arrancar_servicios_host.py start` (`-Servicios`).

## 3. Prueba de efecto

`efecto_local.txt` con `ficheros_subidos=20`, `staging_ok=True` y los `sha256`.
Evidencia primaria en el HOST: `Logs/ATA107_iterN/sink.log` (una linea PUT por fichero) y
`staging_host.csv` (listado de `cloud_bucket\staging`).

## 4. `esperado`

`ATA107_esperado.csv` (v5, field-first): `powershell.exe` y `cmd.exe` + ancla
`*lab-attack*ATA107*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA107\run.cmd"
```

## 6. Notas

- El staging remoto es el HOST (`192.168.65.1`), no una nube real.
- Si el WebDAV no esta levantado o el PUT falla, `efecto_parcial` declarado.
