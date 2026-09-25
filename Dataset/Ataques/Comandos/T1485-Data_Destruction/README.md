# ATA002 · T1485 — Data Destruction (`dd`)

> Artefacto **R-13** del piloto (`fase-03-piloto`). Redactado el **2026-09-25** con los datos
> del **paso 0** y con las señales esperadas **antes de ejecutar nada** (gate humano **validado el 2026-09-25**).
> **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA002** |
| Técnica | **T1485 — Data Destruction** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Fuente de la atómica (Atomic Red Team)

| Campo | Valor |
|---|---|
| Prueba | *FreeBSD/macOS/Linux — Overwrite file with DD* |
| **GUID** | `38deee99-fd65-4031-bec8-bfa4f9f26146` |
| Path en el clon | `atomics/T1485/T1485.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Repo | `https://github.com/redcanaryco/atomic-red-team.git` (MIT) |

Comando original de la atómica (`input_arguments` por defecto: `overwrite_source=/dev/zero`,
`file_to_overwrite=/var/log/syslog`):

```bash
dd of=#{file_to_overwrite} if=#{overwrite_source} \
   count=$(ls -l #{file_to_overwrite} | awk '{print $5}') iflag=count_bytes
```

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0) |
|---|---|
| Herramienta | **`dd` (coreutils 9.4)** — `/usr/bin/dd` |
| Dependencias | ninguna nueva (coreutils de serie) |
| Instalación | **no se instala nada** (regla del plan §2) |
| Elevación | **no** (requisito del plan §1) |

## 4. ⚠️ Desviación D1 — destino distinto de `/etc` (contradicción del plan, declarada)

El plan (§1/§12) exige ATA002 **sin elevación** y con destino
`/etc/tfg_lab_scratch_dd.txt`. El **paso 0** comprueba que **eso es imposible sin `sudo`**:

```text
$ id angel              -> uid=1000(angel) gid=1000(angel) ... groups=...,27(sudo),...
$ stat -c "%A %U:%G %n" /etc   -> drwxr-xr-x root:root /etc
$ [ -w /etc ]           -> NO          # angel NO puede escribir en /etc
```

`/etc` es `root:root 0755`: crear/sobrescribir allí requiere `sudo`. Usar `sudo` en el ataque
(a) contradice el plan §1 («elevación: no»), (b) metería **ruido de `sudo`/PAM** (RS1
`5402`/`5501`/`5502`) en la ventana —justo lo que el plan §1 quiso evitar— y (c) tocaría el
límite de «sin secretos» (habría que alimentar la contraseña).

**Decisión mínima (sin bloquear):** el destino pasa al **único directorio escribible por `angel`
que tiene `auditd` watch** —`/home/angel/lab-legit/` (regla `-w /home/angel/lab-legit -p wa`,
clave `audit-wazuh-w`; está en `lab-listo` desde `deploy_rs2_auditd.sh`):

```text
TARGET = /home/angel/lab-legit/ATA002_scratch_dd.txt
```

**Consecuencias (declaradas):**
1. Se **pierde la señal FIM** (`syscheck_path`) que el plan §5 esperaba: `/home/angel/lab-legit`
   **no** está en los `<directories>` de `syscheck` del agente (solo `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot`).
2. La detección se apoya en **`execve` de `dd`** (regla `80792`) y en los **eventos watch** de
   `auditd` sobre `lab-legit` (reglas `80780`/`80781`/`80790`), todos con `audit_exe=/usr/bin/dd`.
3. El fichero creado **desaparece** al revertir a `lab-listo` (no hay que limpiarlo).

> Si el humano prefiere **conservar la señal FIM**, la alternativa es un ataque **con `sudo`**
> sobre `/etc`: más fiel a §5 pero introduce el ruido de elevación y el manejo de la contraseña.
> **Decide el humano en el gate.**

## 5. Dónde escribe

- Crea y sobrescribe **`/home/angel/lab-legit/ATA002_scratch_dd.txt`** (1 MiB de ceros).
- Nada fuera de `$HOME`; no toca ficheros del sistema (no es un *wipe* real, es la prueba de
  la técnica: sobrescritura destructiva de un fichero).

## 6. Cómo se ejecuta

1. (Fase B, tras revert) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA002/` (ver `Soporte/Ataques/piloto_procedimiento.md` §3).
2. `bash ATA002_ataque.sh` **como `angel`**. El script imprime `T0=…` al inicio y `T1_LOCAL=…`
   al final (marcadores UTC; el `t1` oficial se sella tras el scan FIM forzado, §4 del runbook).

## 7. Señales esperadas

`ATA002_esperado.csv` (mismas columnas que el resto del corpus):

- `T1485-S1` (**deteccion**) `audit_exe=dd` — `execve` y eventos watch de `dd`.
- `T1485-A1` (**ambigua**) `rule_id=80790` — creación genérica bajo watch.
- `T1485-A2` (**ambigua**) `rule_group=audit_watch_write` — evento watch en `lab-legit`
  (sustituye la señal FIM que el plan §5 preveía; ver **D1**).

## 8. Reversión

Basta revertir la víctima a **`lab-listo`** (el fichero creado no existe en el snapshot).
El manager **no** se revierte.

## 9. Higiene

- Sin contraseñas, claves ni tokens. El ataque se ejecuta como `angel` sin `sudo`.
- El material de la atómica vive en `Soporte/Ataques/atomic-red-team/` (ignorado por git; se
  versiona el sidecar `Soporte/Ataques/atomic-red-team.version`).
