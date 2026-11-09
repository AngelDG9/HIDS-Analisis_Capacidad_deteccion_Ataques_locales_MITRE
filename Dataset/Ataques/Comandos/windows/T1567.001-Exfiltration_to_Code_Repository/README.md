# ATA078 - T1567.001 Exfiltration to Code Repository (Windows)

> **B1.4 - preparacion.** Caso **pre-registrado** y sellado; **no ejecutado** todavia.
> Sin secretos.

## 1. Fuente

**Manual**. El clon ART `388942ad` **no** trae `T1567.001` (solo `T1567.002/.003/.004`).
Se implementa un `git push` a un repositorio **bare local** en `C:\lab-attack\ATA078\repo.git`.

## 2. Que hace

1. Crea un repo bare local (`repo.git`) si no existe.
2. Crea un repo de trabajo (`work\`) con 20 ficheros de juguete.
3. `git add` + `git commit` + `git remote add origin repo.git` + `git push`.
4. Lee `git log --oneline -1` del repo bare y lo escribe en `efecto_local.txt`.

**Guardarrail**: todo bajo `C:\lab-attack\ATA078\`. `PortableGit` debe estar pre-staged en
`C:\tfg-tools\PortableGit\bin\git.exe` (fuera del repo); si no existe, el script aborta.
Sin red.

## 3. Prueba de efecto

`efecto_local.txt` con `commit=<hash> <mensaje>` y `push=<salida>`; el `git log` del repo
bare debe mostrar el commit. No es deteccion.

## 4. `esperado`

`ATA078_esperado.csv` (v5, field-first): `powershell.exe`, `git.exe` y `cmd.exe` + ancla
`*lab-attack*ATA078*`; `syscheck_path` como `ambigua`; sin `rule_id`.

## 5. Ejecucion prevista

```powershell
ssh -i <clave> angel@192.168.65.130 "cmd /c C:\lab-attack\ATA078\run.cmd"
```

## 6. Notas

- **No modificar** el `esperado` tras el sello.
- `PortableGit` y el repo bare se preparan **fuera** de `[t0,t1]`.
