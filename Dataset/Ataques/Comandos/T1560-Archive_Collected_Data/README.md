# ATA013 · T1560 — Archive Collected Data (`gzip` en Python)

> Artefacto **R-13** del piloto (`fase-03-piloto`). Redactado el **2026-09-25** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada** (gate humano **validado el 2026-09-25**).
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA013** |
| Técnica | **T1560.002 — Archive Collected Data: Archive via Library** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Fuente de la atómica (Atomic Red Team)

| Campo | Valor |
|---|---|
| Prueba | *Compressing data using GZip in Python (FreeBSD/Linux)* |
| **GUID** | `391f5298-b12d-4636-8482-35d9c17d53a8` |
| Path en el clon | `atomics/T1560.002/T1560.002.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Repo | `https://github.com/redcanaryco/atomic-red-team.git` (MIT) |

Comando original (defaults `path_to_input_file=/etc/passwd`, `path_to_output_file=/tmp/passwd.gz`):

```bash
which_python=`which python || which python3`
$which_python -c "import gzip;input_file=open('#{path_to_input_file}', 'rb');content=input_file.read();input_file.close();output_file=gzip.GzipFile('#{path_to_output_file}','wb',compresslevel=6);output_file.write(content);output_file.close();"
```

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0) |
|---|---|
| Herramienta | **`python3` 3.12.3** con **stdlib `gzip`** (también `tarfile`) — `/usr/bin/python3` |
| Dependencias | ninguna nueva (stdlib) |
| Instalación | **no se instala nada** |
| Elevación | **no** |

## 4. Parametrización (y por qué)

- `python3` **fijo** en lugar de `which python || which python3`: en esta víctima `python` **no**
  existe (comprobado en el paso 0), así que la atómica acabaría en `python3` igualmente, pero
  evitando procesos `which` innecesarios en la ventana (menos ruido, misma técnica).
- `path_to_input_file` = **`/etc/passwd`** (default de la atómica, legible por todos).
- `path_to_output_file` = **`/home/angel/lab-attack/ATA013/passwd.gz`**.

## 5. Dónde escribe

- **`/home/angel/lab-attack/ATA013/passwd.gz`**.
- **`/home/angel/lab-attack` NO está vigilado** (ni por `auditd` ni por `syscheck`), así que la
  creación del `.gz` **no genera evento de fichero**: la técnica solo se ve por el **`execve` de
  `python3`** (regla `80792`). Es el comportamiento previsto en el plan (§12.4).

## 6. Cómo se ejecuta

1. (Fase B, tras revert) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA013/`
   (crea el directorio; el script lo exige como precondición).
2. `bash ATA013_ataque.sh` **como `angel`**; imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 7. Señales esperadas

`ATA013_esperado.csv`:

- `T1560-S1` (**deteccion**) `audit_exe=python3` — `execve` de Python (`80792`).

## 8. Reversión

Revertir la víctima a **`lab-listo`** (el `.gz` y el material copiado desaparecen).
El manager **no** se revierte.

## 9. Higiene

- Sin contraseñas, claves ni tokens. El ataque se ejecuta como `angel` sin `sudo`.
