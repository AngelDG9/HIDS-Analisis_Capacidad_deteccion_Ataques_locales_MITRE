# ATA044 · T1025 — Data from Removable Media (medio extraíble simulado, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda A** (1.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-10-02**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA044** |
| Técnica | **T1025 — Data from Removable Media** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART solo trae prueba **Windows**, `Get-Volume`/PowerShell) |
| Ejecución | usuario `angel`, **con `sudo`** (solo `losetup`/`mount`/`umount`) |

## 2. Por qué es un ataque manual

`atomics/T1025` solo implementa la recolección desde unidades extraíbles **en Windows**
(PowerShell). No hay prueba Linux ni medio físico en el laboratorio. Se simula el **medio
extraíble** con una **imagen vfat** pequeña y fijada, adjuntada en **solo-lectura** (equivalente
local del USB). Fuente `propio`, motivo `art_no_prueba_plataforma` («solo la otra»).

## 3. Qué hace y dónde escribe

- **Pre-staging (fuera de `[t0,t1]`):** `ATA044_prestaging.sh` crea `removable.img` (4 MiB FAT)
  con documentos señuelo (`clientes_2026.csv`, `nominas.csv`, `notas.txt`). Registra su `sha256`.
- **Acción de la ventana:** `ATA044_ataque.sh` **adjunta** el medio (`losetup --read-only`),
  lo **monta en ro**, **lista** y **copia** los documentos a `collected/`, comprueba
  `sha256` origen==copia y **desmonta/detacha**.
- **Destino:** SOLO `/home/angel/lab-attack/ATA044/removable.img` (imagen de fichero).
- **Sin NAT**, sin red.

## 4. ⚠️ Alcance y qué **NO** se toca (regla dura)

- **Guardarraíl DURO:** el medio es una **imagen de fichero** bajo la carpeta del ataque; el guion
  **aborta** si la ruta contiene `/dev/` o no cuelga de `lab-attack/ATA044`. Montaje **siempre `-o ro`**.
- **JAMÁS** discos/particiones/USB reales. `trap` que desmonta y detacha loops residuales al salir.

## 5. Señales esperadas (convención H4)

`ATA044_esperado.csv` (todas `deteccion`):

- `T1025-S1..S6` `audit_exe ∈ {losetup, mount, find, cp, sha256sum, umount}` (`80792`).
- `T1025-S7` `audit_cwd=/home/angel/lab-attack/ATA044/*` — ancla H4.

> **Sin señales `ambigua`:** todo ocurre fuera de rutas vigiladas por el FIM. La creación del
> medio es **pre-staging** y queda fuera de la ventana.

## 6. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `dd`, `mkfs.vfat`, `losetup`, `mount`, `umount`, `find`, `cp`, `sha256sum` (de serie) |
| Dependencias | ninguna nueva (dosfstools 4.2, util-linux 2.39.3) |
| Elevación | **sí**: `sudo` **solo** para `losetup`/`mount`/`umount` (`sudo -S` por stdin) |
| C0 | `mount`/`losetup`/`cp` no caen en silenciador (`Soporte/Ataques/c0/ATA044_logtest.txt`) |

## 7. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA044/`.
2. **Pre-staging** (antes de `t0`, fuera de ventana):
   `SUDO_PW='<contrasena>' bash ATA044_prestaging.sh`.
3. `cd /home/angel/lab-attack/ATA044 && SUDO_PW='<contrasena>' bash ATA044_ataque.sh 2>&1 | tee ejecucion.out`.

## 8. Prueba de éxito (independiente de la alerta)

Cada documento copiado a `collected/` tiene el **mismo `sha256`** que el original del medio
montado, y **0 loops residuales** ⇒ la recolección del medio extraíble ocurrió de verdad.
Evidencia en `Logs/ATA044_iter*/ejecucion.out`.

## 9. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack`). El manager **no** se revierte.
- **Higiene:** **nunca** se tocan discos/particiones reales; el loop deriva de la imagen del ataque.
  Sin datos reales (documentos de juguete con nombres creíbles).

## 10. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «medio extraíble» es una
> **imagen de fichero** local (equivalente acotado de un USB); **el entorno no tiene usuarios/servicios
> reales** y **las rutas del ataque son conocidas por el analista**. Los datos son de juguete.
