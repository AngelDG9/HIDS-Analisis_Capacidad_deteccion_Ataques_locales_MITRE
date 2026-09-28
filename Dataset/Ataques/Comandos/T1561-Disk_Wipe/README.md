# ATA005 · T1561 — Disk Wipe (`dd`/`shred` sobre un fichero de trabajo)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda A**. Redactado el **2026-09-28** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-28**. **No
> contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA005** |
| Técnica | **T1561 — Disk Wipe** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1561` aparece en `Hojas/cobertura_atomic.csv` como **`sin_pruebas`** (`prueba_art=no`): Atomic
Red Team **no trae ninguna prueba** para esta técnica. La técnica **sí aplica a Linux** → el ataque
**se escribe a mano**.

## 3. Qué hace y dónde escribe — **SIMULACIÓN SEGURA**

- **Qué hace:** **machaca** (sobrescribe con bytes aleatorios) un **fichero de trabajo** de 32 MiB
  con `dd if=/dev/urandom … conv=notrunc` (mismo tamaño, contenido destruido) y, además, borra
  *seguro* (`shred -n 1 -z -u`) un fichero pequeño. Es el vector destructivo de un *disk wipe*
  **sin tocar jamás un disco**.
- **Destino:** **`/home/angel/lab-attack/ATA005/`** (`backup_completo_2026-09.bin` —una copia de
  seguridad **simulada**— + `notas_operaciones.txt`). Son datos de juguete; la escena imita la
  destrucción de una copia de seguridad real.
- **Ruta NO vigilada** → no hay eventos watch/FIM; la detección es **por `execve`**.

## 4. ⚠️ Guardarraíles de seguridad (duros, en el guion)

1. El **destino DEBE** estar bajo `$HOME/lab-attack/ATA005/` (`case` que **aborta** si no).
2. El destino **NO puede ser un fichero de dispositivo** (`-b`/`-c` → **aborta**).
3. **Nunca** se referencia `/dev/sd*`, `/dev/nvme*` ni ninguna partición: solo `/dev/zero` (lectura)
   y `/dev/urandom` (lectura) como **fuentes**.
4. Todo ocurre en `$HOME`; el revert a `lab-listo` lo borra.

## 5. Herramienta, dependencias y elevación

| Elemento | Valor |
|---|---|
| Herramientas | **`dd`, `shred`, `sha256sum`, `stat`** (coreutils de serie) |
| Dependencias | ninguna nueva (se instala **nada**) |
| Elevación | **no** |

## 6. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA005/`.
2. `cd /home/angel/lab-attack/ATA005/ && bash ATA005_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 7. Señales esperadas (convención H4)

`ATA005_esperado.csv`:

- `T1561-S1` (**deteccion**) `audit_exe=dd` — sobrescritura in-situ (`80792`; `dd` ya está probado
  en ATA002).
- `T1561-S2` (**deteccion**) `audit_exe=shred` — borrado seguro.
- `T1561-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA005/*` — ancla H4 del proceso.

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md` v4).

## 8. Prueba de éxito del ataque (independiente de la alerta)

El guion compara el **`sha256` ANTES vs DESPUÉS** con el **tamaño estable** (`stat`): si el hash
cambia y el tamaño no, **el contenido se sobrescribió** (wipe) ⇒ prueba de que el ataque "funcionó".
Evidencia en `Logs/ATA005_iter*/ejecucion.out`.

## 9. C0 (pre-flight base-contra-base) — **EJECUTADO** (2026-09-28)

Captura `Soporte/Ataques/c0/ATA005_logtest.txt`
(`sha256=58ea13da1b2dacfb244ff0bfa496292ae0a117cac94202c5494be178a5bd225c`) → informe
`Soporte/Ataques/c0/ATA005_preflight.md`. **Resultado: PASA**.

- **Ganadoras de fábrica:** `80792` *Audit: Command: /usr/bin/dd* y `80792` *Audit: Command:
  /usr/bin/shred*, ambas **`level 3` ⇒ SÍ avisan**. **Sin** silenciador de fábrica. Plan original en
  `Soporte/Ataques/c0/ATA005_c0_plan.md`.
- **No** se espera evento de fichero: la ruta del ataque **no está vigilada**.

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El manager
  **no** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se destruye la máquina);
> **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas por el
> analista**. Los datos de juguete llevan **nombres creíbles** (escena de empresa) para que la
> ventana se parezca a un caso realista, pero **no son datos reales**.
