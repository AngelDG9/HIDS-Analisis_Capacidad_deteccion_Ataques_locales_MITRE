# ATA016 · T1213.006 — Databases (recolección de una BD local, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda A**. Redactado el **2026-09-29** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Validación humana:
> **APROBADO 2026-09-29**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA016** |
| Técnica | **T1213.006 — Data from Information Repositories: Databases** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (la prueba ART de T1213 depende de repositorios en red/SaaS → sin NAT) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **recolecta** información de una **base de datos local** (SQLite). La víctima tiene
  `clientes_clientes.db` (clientes **falsos**, escena de empresa) en la ruta **VIGILADA**
  `/home/angel/lab-legit`. El atacante **copia la BD** y **extrae los registros**.
- **Destino:**
  - **Lectura/copia** de `/home/angel/lab-legit/clientes_clientes.db`.
  - **Salida** en `/home/angel/lab-attack/ATA016/collected/` (`clientes.db`, `clientes_codigos.txt`).

## 3. ⚠️ Dependencia y punto ciego declarados

- **`sqlite3` NO está instalado** en la víctima (paso 0), ni `strings`. La BD **SQLite real** se
  crea con la **stdlib de `python3`** (módulo `sqlite3`).
- ⚠️ El `execve` de **`python3`** cae en el **punto ciego de fábrica `92600`** (nivel 0) → **no
  alerta** (reproduce el hallazgo de ATA013). La **COLECCIÓN** propiamente dicha (copiar la BD y
  extraer registros) se hace con **`cp`/`grep`**, que **sí alertan** (`80792`).

## 4. Herramienta, dependencias y elevación

| Elemento | Valor (paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`cp`, `grep`, `sort`, `wc`, `sha256sum`** (de serie) + **`python3`** (siembra de la BD) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`) |

## 5. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA016/`.
2. `cd /home/angel/lab-attack/ATA016/ && bash ATA016_ataque.sh 2>&1 | tee ejecucion.out`.

## 6. Señales esperadas (convención H4)

`ATA016_esperado.csv`:

- `T1213.006-S1` (**deteccion**) `audit_exe=cp` — copia de la BD local (`80792`).
- `T1213.006-S2` (**deteccion**) `audit_exe=grep` — extracción de registros de la BD.
- `T1213.006-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA016/*` — ancla H4.
- `T1213.006-A1/A2/A3` (**ambigua**) `rule_id ∈ {80790, 80781, 80782}` — escritura bajo **watch**
  en `lab-legit` (siembra de la BD; efecto) → `dudosa` → veredicto humano **`artefacto`**.

## 7. Hipótesis de detección

- **DETECTADO** por el `execve` de **`cp`/`grep`** (`80792`, nivel 3) anclado al `cwd` del ataque.
- La **siembra** de la BD (con `python3`, en `lab-legit`) **no alerta** por `92600`, pero **sí**
  deja su **huella `watch`** por la escritura del fichero (declarada `ambigua`).

## 8. Prueba de éxito (independiente de la alerta)

La copia es una **SQLite válida** (magic `SQLite format 3`) con el **mismo `sha256`** que el
original y **≥4 códigos de cliente** extraídos ⇒ la BD se recolectó **íntegra**. Evidencia en
`Logs/ATA016_iter*/ejecucion.out` + `sha256_artefacto.txt`.

## 9. Reversión e higiene

- **Reversión:** víctima a **`lab-listo`**; el manager **no** se revierte.
- **Higiene:** sin credenciales reales; clientes **de juguete**.

## 10. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**; **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**. Los datos
> son **de juguete** con **nombres creíbles** (escena de empresa), pero **no son datos reales**.
