# ATA034 · T1560.003 — Archive via Custom Method (método propio con builtins)

> Artefacto del bloque `fase-03-ampliacion-2`, **tanda B**. Redactado el **2026-09-29** con los
> datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-29**.
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA034** |
| Técnica | **T1560.003 — Archive via Custom Method** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS que ejercita | **ninguna señal de ejecución del archivado** (builtins); el **arnés sí ejecuta coreutils** → `execve` → `artefacto_ataque` |

## 2. Qué hace y dónde escribe

- **Qué hace:** **archiva** el material recolectado con un **método propio**: un contenedor casero
  (cabecera `MAGIC` + `FILE`/`END` + contenido con las líneas invertidas) construido **solo con
  builtins de bash** (`read`, `printf`, aritmética de cadenas y redirección). **El bucle de
  archivado no usa** `tar`/`zip`/`gzip` ni ningún binario externo; el **arnés** que lo rodea sí
  ejecuta coreutils (`date`, `mkdir`, `cat`, `sha256sum`…) en *setup*/evidencia (→ `execve`).
- **Destino:** todo bajo `/home/angel/lab-attack/ATA034/` (`staging/`, `collected_ATA034.arc`,
  `reconstructed/`).
- **Tercer vértice del trío de archivo:** contrasta con **ATA030/T1560.001** (utilidad `tar` →
  detectado por `execve`) y **ATA013/T1560.002** (librería `python3` → no detectado por el punto
  ciego de fábrica `92600`).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas del archivado | **builtins de bash** (`read`/`printf`/redirección); **cero binarios externos** en el bucle de archivado |
| Herramientas de semilla/evidencia | `mkdir`, `cat`, `sha256sum`, `awk`, `head` (setup/evidencia, no el archivado) → **sí generan `execve`** |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** |

> **Prueba de «cero binarios externos» (del bucle de archivado):** el bucle de archivado se ejecuta
> con `PATH=/nonexistent`; si necesitase cualquier binario externo, **fallaría**. (**Matiz:** el
> *arnés* de *setup*/evidencia sí invoca coreutils; su `execve` es telemetría real del ataque, pero
> **no** del archivado.)

## 4. Cómo se ejecuta

1. `mkdir -p /home/angel/lab-attack/ATA034` y `scp -r` del directorio de la técnica ahí.
2. `cd /home/angel/lab-attack/ATA034 && bash ATA034_ataque.sh 2>&1 | tee ejecucion.out`
   (como `angel`). Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas

`ATA034_esperado.csv`:

- **No se declara ninguna señal `deteccion`** (O2 = **0/0**): **la operación de archivar** (builtins)
  **no ejecuta ningún binario externo**, así que no existe un `audit_exe` del archivado que anclar.
  (**Matiz:** el **arnés** sí ejecuta coreutils → esos `execve` **sí** alertan (`80792`) pero son
  genéricos y quedan como `artefacto_ataque`, **no** como detección de la técnica.) Es un **punto
  ciego por AUSENCIA de telemetría de la operación de archivar** (distinto del silenciamiento `92600`
  de ATA013).
- `T1560.003-A1/A2` (**ambigua**) `rule_id ∈ {80790, 80781}` — **efecto** del ataque (creación/
  escritura del `.arc`), → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

## 6. Hipótesis de detección

- **NO DETECTADO** como técnica por la capa `execve`: **la operación de archivar** (builtins) no
  deja ejecución de herramienta. El `execve` del **arnés** (coreutils) **sí** aparece, pero es
  genérico → `artefacto_ataque`; la única huella del `.arc` (`watch` genérico de la **creación**)
  es un **efecto**, no la detección de la técnica.
- **Depende de la implementación:** con **binario propio compilado** → `execve` → **detectable**
  (ATA030); con **`python3`** → suprimido por **`92600`** (ATA013). El hallazgo no es «técnica
  indetectable», sino que **el HIDS no distingue el archivado casero dentro de un intérprete**.
- Sirve para **delimitar el alcance** del HIDS: ve *procesos* y *escrituras*, pero **no la
  semántica** de un archivado casero hecho dentro de un intérprete.

## 7. Prueba de éxito (independiente de la alerta)

Al finalizar: el `.arc` tiene formato propio (cabecera `ATA034-CUSTOM-ARCHIVE v1`) y la
**reconstrucción** reproduce los **3** ficheros con **`sha256` idéntico** al original
(`reconstruidos_sha256_ok=3/3`). Evidencia en `Logs/ATA034_iter*/ejecucion.out`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** no hay `sudo`, ni secretos, ni datos reales (material de juguete).

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (se archiva material
> simulado, nunca datos reales ni del sistema); **el entorno no tiene usuarios/servicios reales**
> y **las rutas del ataque son conocidas por el analista**.
