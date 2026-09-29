# ATA030 · T1560.001 — Archive via Utility (tar + gzip, custom)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda A**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA030** |
| Técnica | **T1560.001 — Archive via Utility** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **archiva** el material recolectado con una **utilidad de línea de órdenes**
  (`tar -czf`, que invoca `gzip`). Es el **contraste científico** con **ATA013/T1560.002**
  (archivo por **librería** con `python3` → **NO detectado** por el punto ciego de fábrica
  `92600`): el **mismo objetivo** («archivar») hecho con **utilidad** sí deja `execve`.
- **Destino:** todo bajo `/home/angel/lab-attack/ATA030/` (`staging/` + `collected_ATA030.tar.gz`).
- **Capa del HIDS que ejercita:** **`execve` de la utilidad** (`tar`; y `gzip` invocado por `tar`).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | `tar` (`/usr/bin/tar`), `gzip` (`/usr/bin/gzip`), `mkdir`, `cat`, `sha256sum`, `grep` |
| Dependencias | ninguna nueva (`zip` **no** está instalado; se usa `tar`+`gzip`, presente) |
| Elevación | **no** |

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA030` y `scp -r` del directorio de la técnica ahí.
2. `cd /home/angel/lab-attack/ATA030 && bash ATA030_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA030_esperado.csv`:

- `T1560.001-S1` (**deteccion**) `audit_exe=/usr/bin/tar` — la utilidad de archivado (`80792`).
- `T1560.001-S2` (**deteccion**) `audit_exe=/usr/bin/gzip` — el compresor invocado por `tar -z`.
- `T1560.001-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA030/*` — ancla H4.

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de `tar` (y de `gzip`) — `80792`, nivel 3 — anclado al `cwd`.
- **Contraste:** esto demuestra que **la elección de la herramienta decide la detección** (la
  misma acción «archivar» es invisible si se hace con `python3`, por `92600`).

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: `collected_ATA030.tar.gz` existe, **no está vacío** y `tar -tzf` muestra los **3**
ficheros del material (`miembros_de_datos=3`). Evidencia en `Logs/ATA030_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** no hay `sudo`, ni secretos, ni datos reales (material de juguete).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (se archiva material
> simulado, nunca datos reales ni del sistema); **el entorno no tiene usuarios/servicios reales**
> y **las rutas del ataque son conocidas por el analista**.
