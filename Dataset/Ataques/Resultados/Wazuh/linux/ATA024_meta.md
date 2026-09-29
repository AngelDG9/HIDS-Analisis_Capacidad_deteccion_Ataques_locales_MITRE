---
fase: 3
bloque: fase-03-ampliacion
tanda: C
ata_id: ATA024
tecnica: T1531
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA024 · T1531 Account Access Removal (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda C**, 1.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Solo** se tocó un **usuario desechable** (`tfg-victim01`), creado con `useradd` y borrado con
> `userdel`; **jamás** `angel`, `root` ni cuentas reales.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA024** |
| Técnica | **T1531 — Account Access Removal** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **con `sudo`** (`sudo -S` por stdin) |
| Capa del HIDS | **`execve`** (`80792`) + **`watch` de `/etc`** (`80790/80781/80791`) + **FIM/syscheck** (`550`) + **syslog/auth** (`5901/5902/5903`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `useradd` / `passwd -l` / `userdel -r` |
| Efecto | el usuario desechable se crea, se bloquea y se elimina; ya **no existe** |
| Elevación | **sí** (`sudo`, solo esas 3 herramientas) |
| Guardarraíl | **solo** `tfg-victim01`; **trap** que elimina el usuario si sobrevive; sin editar `/etc/passwd` a mano |

Artefacto: `.../T1531-Account_Access_Removal/ATA024_ataque.sh`
(`sha256=705e4be1384dc6bbaa6561850fc9e2947e40188011aa76b3dd0f8cf65ac872ea`).
Señales: `.../ATA024_esperado.csv` (`sha256=505581e2ae6c8c704381e6b849be0e90e26e86d4a6e67a72c8e096f60512f962`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA024_logtest.txt` (`sha256=9e1b955ea6a03113607e4eb7f2c21e7c2ff7222dfc21462799c7d1f2a2675779`)
→ `ATA024_preflight.md` (`sha256=4002bad75adbdabef04395d587ca2f121611b8adbe053276b5e7d01fd0cccec4`) **PASA**
(3 eventos `useradd`/`userdel`/`passwd` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T03:27:07Z` | `2026-09-29T03:27:39Z` | 32 s | 1195 | `705e4be1…72ea` |
| 2 | `2026-09-29T03:31:26Z` | `2026-09-29T03:31:58Z` | 32 s | 1345 | `705e4be1…72ea` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA024
SUDO_PW='<contrasena>' bash ATA024_ataque.sh   # useradd -m + passwd -l + userdel -r
```

## 6. Evidencia

`Logs/ATA024_iter{1,2}/`: `times.log`, `ejecucion.out`, `usuario_creado.txt`,
`cuenta_estado_previo.txt`, `cuenta_bloqueada.txt`.

**Prueba de éxito — el acceso se eliminó de verdad:**

| Iter | `usuario_creado.txt` | `id tfg-victim01` tras borrado | home | `ACCOUNT_REMOVAL` |
|---|---|---|---|---|
| 1 | `tfg-victim01:x:1001:1001::/home/tfg-victim01:/bin/bash` | **no existe** | no existe | **OK** ✅ |
| 2 | idéntico | **no existe** | no existe | **OK** ✅ |

`cuenta_bloqueada.txt` = `tfg-victim01 L 2026-09-29 0 99999 7 -1` (L = bloqueada).

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1205 | 1196 | 1195 |
| 2 | 1354 | 1346 | 1345 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1195 | **40** | 608 | 359 | **0** | 188 | 42 | 1153 | 0 | 0 |
| 2 | 1345 | **40** | 622 | 496 | **0** | 187 | 47 | 1298 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 40 | 5 · `{550, 5901, 5902, 5903, 80792}` | 25 (`S1/S2/S3`) | **15 `novel`** |
| 2 | 40 | 5 · `{550, 5901, 5902, 5903, 80792}` | 25 | **15 `novel`** |

- `80792` × 25: `useradd` (8), `passwd` (9), `userdel` (8), **anclados** al `cwd` del ataque.
- **`550` × 12 (FIM/syscheck, no declarado):** *Integrity checksum changed* sobre `/etc/subuid`,
  `/etc/passwd`, `/etc/shadow`, `/etc/group`… → **capa FIM**.
- **`5901/5902/5903` (syslog/adduser, no declarados):** *New group added* / *New user added* /
  *Group (or user) deleted* → **capa syslog/auth**.
- **`dudosa` resueltas (163/iter):** todas **`80781/80790/80791`** del **watch de `/etc`**
  (efecto del ataque) → `artefacto`. **Ninguna** fila del ataque en `ruido`.

> ⚠️ **Anomalía declarada:** **30** filas (15/iter) 5402/5501/5502 (la **sesión `sudo`/PAM del
> ataque**; `dstuser=root`) cayeron en **`ruido_conocido/baseline`** de forma automática (el catálogo
> base contiene los equivalentes del operador). No es reclasificable sin editar el `esperado`
> firmado. **Declaradas (no son detección) en §10.1.**

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{550,5901,5902,5903,80792}` | `03:27:09.259Z` `audit_exe=/usr/sbin/useradd` | **3/3** (`S1,S2,S3`) | 40 / 188 / 359 | 40 / 5 `rule_id` |
| 2 | **sí** | `{550,5901,5902,5903,80792}` | `03:31:27.530Z` `audit_exe=/usr/sbin/useradd` | **3/3** | 40 / 187 / 496 | 40 / 5 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{550,5901,5902,5903,80792}=={550,5901,5902,5903,80792}`; `|40−40|=0 ≤ 2`; sin dudosas. Ver
`Bitacora/ATA024.json`.

## 10. Limitaciones y hallazgos

1. **⭐ La técnica ejercita 4 capas** (la más rica de la tanda): `execve` (`80792`) + **watch `/etc`**
   + **FIM `550`** + **syslog/auth `5901/5902/5903`**. **Corrección (cabos de documentación,
   2026-09-29):** lo **`novel`** real es **`550` + `5901-5903` = 15** (12 + 3); el **`watch` de
   `/etc`** (`80781/80790/80791`) **NO** es `novel`: ya estaba **declarado como `ambigua`** en el
   `esperado` (`T1531-A1/A2/A3`) y su categoría es **`artefacto`** (`artefacto_ataque`). El HIDS
   **sí ve** la manipulación de cuentas por varias vías; el `esperado` declaró **de menos** (solo
   `execve` + las `ambigua` de `/etc`).
2. **`550` (FIM) y `5901-5903` (syslog)** demuestran que el `esperado` declaró **de menos** (solo
   `execve`); se reporta como **hallazgo** (la checklist no es exhaustiva, por diseño).
3. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
4. **Huellas de la sesión del ataque declaradas** (no son detección): 5402/5501/5502 con
   `dstuser=root`. Ver **§10.1**.

### 10.1 Huellas de la **sesión del ataque** declaradas — **NO son detección**

> Añadido en `fase-03-ampliacion` (cabos de documentación, 2026-09-29). **No** se recalcula nada
> (métrica **congelada** y `esperado` **firmado**): se **declara** lo que el mecanismo no puede
> cazar. Complementa §8.1.

- **Qué filas:** **30** (15 por iteración) de `rule_id` **`5402`/`5501`/`5502`** con
  **`dstuser=root`** — la **sesión `sudo`/PAM del propio ataque** (el guion usa `sudo_cmd` en sus
  **5** llamadas: `useradd`, `passwd -S`, `passwd -l`, `passwd -S`, `userdel`; los **5 × `5402`**
  *Successful sudo to ROOT* de cada iteración casan exactamente con esas 5 llamadas). Por iteración:
  `5402`×5 + `5501`×5 + `5502`×5.
- **Dónde caen:** en **`ruido_conocido`/`baseline`** de forma **automática** (el catálogo base
  contiene los equivalentes del operador). *No reclasificable* sin editar el `esperado` firmado.
- **Por qué NO son detección:** son la **sesión de privilegio** que el ataque **necesitó** para
  ejecutar las herramientas; **no** identifican la manipulación de cuentas (son genéricas: cualquier
  `sudo` las produce). Nada del ataque **se pierde**: la técnica sigue **DETECTADA** por **`80792`**
  (`useradd`/`passwd`/`userdel`, anclados al `cwd`) + **`550`** (FIM) + **`5901-5903`** (syslog/auth).
- **Nota de alcance:** las `5501/5502` con `dstuser=angel` de la misma ventana son la **sesión del
  operador** (no del ataque) → `ruido` (criterio ratificado 2026-09-28). Solo las `dstuser=root` son
  la sesión del ataque.

### 10.2 Alcance del invariante «0 filas del ataque en `ruido`»

- El invariante **«0 filas del ataque en `ruido_conocido`/`auto_ruido`»** se cumple **bajo la
  pertenencia por carpeta** del mecanismo congelado: una fila cuyo **`audit_cwd`** o **ruta**
  (`audit_file`/`audit_dir`/`syscheck_path`) cae bajo **`lab-attack/ATA<NNN>`** → paso 3.5 →
  **`artefacto_ataque`**, **nunca** `ruido`.
- Quedan **fuera** de ese mecanismo las filas de la **sesión** del ataque (PAM/`sudo`, **sin `cwd`**
  ni ruta de la carpeta): el filtro no puede **demostrar** que son del ataque → se **declaran** aquí
  (§10.1) y **no** cuentan como detección. Es una **limitación declarada** del mecanismo, no un
  hallazgo nuevo.
