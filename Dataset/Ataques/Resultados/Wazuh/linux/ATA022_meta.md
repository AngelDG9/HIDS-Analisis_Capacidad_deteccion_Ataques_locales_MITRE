---
fase: 3
bloque: fase-03-ampliacion
tanda: B
ata_id: ATA022
tecnica: T1567.001
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA022 · T1567.001 Exfiltration to Code Repository (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda B**, 5.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Repositorio de código = `git` bare LOCAL** (`file://…/lab-attack/ATA022/repo.git`): **cero red**,
> **cero credenciales**, **cero contacto con remotos reales** (guardarraíl R6).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA022** |
| Técnica | **T1567.001 — Exfiltration Over Web Service: Exfiltration to Code Repository** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2) + `watch` de fábrica (`80791`/`80782`) en `.git` |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`git`** (`init`/`commit`/`push` a `file://`) |
| Efecto | el repo bare **local** recibe el commit; el blob del dato coincide con el original |
| Elevación | **no** |
| Guardarraíl **R6** | el remoto **DEBE** empezar por `file:///home/angel/lab-attack/ATA022/`; **aborta** si `http`/`git@`/`github`/`gitlab` |

Artefacto: `.../T1567.001-Exfiltration_To_Code_Repository/ATA022_ataque.sh`
(`sha256=ed1978bbc954332fe1e33cc83d6e52d189bc23a9b988af24554ad74001df8a96`).
Señales: `.../ATA022_esperado.csv` (`sha256=79c777dca4b8bb3844373c89c9ecefe844e7c51c40177c35ca54168b1991c748`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA022_logtest.txt` (`sha256=511c3b30e8beb94de1f1dff0ed7a3753091f986aeb4b277d91e52e373e039f7f`)
→ `ATA022_preflight.md` (`sha256=3f925afd29158d9d3a90da76610ca41f0c51427e162082363bf1fa7c70d80301`) **PASA**
(1 evento `git` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor** (la exfiltración es a un repo **local**).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T02:19:38Z` | `2026-09-29T02:20:10Z` | 32 s | 1194 | `ed1978bb…8a96` |
| 2 | `2026-09-29T02:23:39Z` | `2026-09-29T02:24:12Z` | 33 s | 1158 | `ed1978bb…8a96` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA022
bash ATA022_ataque.sh     # git init (bare local) + commit + push file:// al repo local
```

## 6. Evidencia

`Logs/ATA022_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`.

**Prueba de éxito — el dato LLEGÓ al repositorio de código (blob idéntico):**

| Iter | `sha256` local | `sha256` del blob en `repo.git` | commit | ¿coincide? |
|---|---|---|---|---|
| 1 | `efb4e38b8ddceddc091e9e228a5d5b71f19401a3f2030d7116e87c6bb096e943` | idéntico | `e13e640` | **SÍ** ✅ |
| 2 | `efb4e38b…e943` | idéntico | `f12a999` | **SÍ** ✅ |

`EXFIL_REPO=OK` en ambas; `remoto_verificado=file:///home/angel/lab-attack/ATA022/repo.git`.

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1202 | 1194 | 1194 |
| 2 | 1165 | 1158 | 1158 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1194 | **20** | 621 | 499 | **0** | 54 | 13 | 1181 | 0 | 0 |
| 2 | 1158 | **20** | 607 | 476 | **0** | 55 | 18 | 1140 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 20 | 1 · `{80792}` | 20 (`S1`) | 0 |
| 2 | 20 | 1 · `{80792}` | 20 | 0 |

- `git` (`/usr/bin/git` + `/usr/lib/git-core/git`) → `80792`, **anclados** al `cwd` del ataque.
- **`dudosa` resueltas (51/iter1, 55/iter2):** **42 `80791/80782`** (borrado/escritura en `.git`/`repo.git`,
  **efecto** del ataque) → `artefacto`; **9-13 PAM** del operador → `ruido`. **Ninguna** fila del ataque
  en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `02:19:40.253Z` `audit_exe=/usr/bin/git` | **1/1** (`S1`) | 20 / 54 / 499 | 20 / `{80792}` |
| 2 | **sí** | `{80792}` | `02:23:41.491Z` `audit_exe=/usr/bin/git` | **1/1** | 20 / 55 / 476 | 20 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|20−20|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA022.json`.

## 10. Limitaciones y hallazgos

1. **`git` no tiene silenciador** → el `execve` alerta (`80792`); el nº bruto es alto (git lanza muchos
   subprocesos `git-core`) pero **`rule_id` distinto = 1** (Anexo).
2. **Guardarraíl R6 respetado:** el `push` fue a un repo **local** (`file://`), sin credenciales; el
   guion **aborta** si el remoto no es el local.
3. **C0 sin punto ciego** (`git`→`80792`). **Realismo acotado** declarado (README §11).
