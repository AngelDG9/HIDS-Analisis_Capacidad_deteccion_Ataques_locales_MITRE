# ATA060 - T1496.001 Compute Hijacking (Windows, `victima-windows`)

> **B1.1 (piloto mixto).** Canal **SSH**. **Manual** (sin atomic Windows aprovechable
> para T1496.001 en el clon de ART).

## Que hace

1. Mide CPU total y memoria disponible antes (`Get-Counter`, `Win32_OperatingSystem`).
2. Lanza **4 trabajadores de computo** (runspaces del mismo proceso) durante **30 s**.
3. Mide CPU (3 muestras) y memoria durante; espera a los 4 trabajadores.
4. Escribe `efecto_local.txt` con CPU antes/durante, delta y `Available MBytes`.

**Guardarrail**: 30 s y 4 trabajadores (cota del plan <=120 s). Sin red.

## Prueba de efecto

`efecto.txt` de la iteracion: `cpu_before_pct` vs `cpu_during_avg_pct` (delta > 0) y
`mem_before_available_mb` / `mem_during_available_mb`. **No hay regla de recursos** (R9):
la alerta, si la hay, es por **proceso**, no por CPU.

## Esperado

`ATA060_esperado.csv`: `win_image` (`powershell.exe` / `cmd.exe`) + ancla
`win_command_line` con `C:\lab-attack\ATA060`.
