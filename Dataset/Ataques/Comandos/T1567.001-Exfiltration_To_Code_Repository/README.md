# ATA022 · T1567.001 — Exfiltration to Code Repository (`git push` a un repo **local**)

> Artefacto del bloque `fase-03-ampliacion`, **tanda B** (5.º de 5). Redactado el **2026-09-29**
> con los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales
> las **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA022** |
| Técnica | **T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

La técnica exfiltra a un **repositorio de código**. La biblioteca ART no trae una prueba Linux
ejecutable **sin NAT** (usaría un remoto real tipo GitHub/GitLab, con credenciales). Se escribe a
mano, pero el «repositorio de código» es un **`git` bare LOCAL** creado **dentro de `lab-attack`**
(`file://…`): **cero tráfico de red**, **cero credenciales**, **cero contacto con remotos reales**.

## 3. Qué hace y dónde escribe

- **Qué hace:** **exfiltra** un fichero de «código fuente» simulado mediante **`git push`** a un
  repositorio de código **local**. Crea el bare repo, un repo de trabajo, commitea el dato y empuja.
- **Origen/ejecución:** **`/home/angel/lab-attack/ATA022/`** (**NO** vigilado → detección del
  proceso por **`execve`** de `git`).
- **Destino (efecto):** `file:///home/angel/lab-attack/ATA022/repo.git` (repositorio **local**).
- **Prueba del efecto:** el bare repo **recibió** el commit y el blob del fichero tiene el **mismo
  `sha256`** que el original.

## 4. ⚠️⚠️ Guardarraíl DURO (R6) — prohibido un remoto real

- **`git push` SOLO a `file://…/lab-attack/ATA022/…`**. El guion **ABORTA antes de empujar** si el
  remoto no empieza por `file:///home/angel/lab-attack/ATA022/` o si contiene `http`/`git@`/`github`/
  `gitlab`. **JAMÁS** al repositorio del TFG ni a GitHub/GitLab. **Sin credenciales.**
- **Sin NAT**: no hay red. El repositorio es **infraestructura local**.

## 5. Señales esperadas (convención H4)

`ATA022_esperado.csv`:

- `T1567.001-S1` (**deteccion**) `audit_exe=git` — herramienta de la exfiltración (`80792`).
- `T1567.001-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA022/*` — ancla H4.

> **C0 (`ATA022_preflight.md`):** `git` → `80792` **nivel 3** (sin silenciador). La **red no es
> visible** para el HIDS; el efecto lo prueba el propio repositorio local.

## 6. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA022/`.
2. `cd /home/angel/lab-attack/ATA022/ && bash ATA022_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC). **No requiere receptor.**

## 7. Prueba de éxito del ataque (independiente de la alerta)

`git --git-dir=…/repo.git log` muestra el commit recibido y `git cat-file -p HEAD:<fichero>` tiene el
**mismo `sha256`** que el fichero local ⇒ el dato **llegó al repositorio de código**. Evidencia en
`Logs/ATA022_iter*/ejecucion.out`.

## 8. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramienta | **`git`** (`/usr/bin/git`) — presente (no se instala nada) |
| Dependencias | ninguna nueva |
| Elevación | **no** |
| C0 | `Soporte/Ataques/c0/ATA022_{c0_plan.md,logtest.txt,preflight.md}` |

## 9. Receptor y firewall

**No aplica**: la exfiltración es a un repositorio **local** (`file://`), no hay tráfico de red ni
receptor. No se levanta `sink_http.py` para ATA022 (el receptor de la tanda se usa en ATA019/020/021/023).

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/`). El
  **manager NO** se revierte.
- **Higiene:** sin credenciales, claves ni tokens; el repo es **desechable y local**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el «repositorio de código» es
> un **repo `git` local simulado** (sin NAT, sin nube, sin credenciales) y **no se toca ningún
> remoto real**; **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son
> conocidas por el analista**. Los datos de juguete llevan **nombres creíbles** pero **no son reales**.
