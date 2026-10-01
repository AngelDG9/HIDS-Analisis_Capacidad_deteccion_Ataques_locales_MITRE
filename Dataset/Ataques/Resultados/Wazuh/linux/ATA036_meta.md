---
fase: 3
bloque: fase-03-ampliacion-2
tanda: B
ata_id: ATA036
tecnica: T1565.003
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA036 · T1565.003 Runtime Data Manipulation (`ptrace`/memoria) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda B**, 3.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA036** |
| Técnica | **T1565.003 — Runtime Data Manipulation** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** de la herramienta; `ptrace`/memoria **invisible** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `memedit` (`ptrace`) sobre el proceso **de laboratorio** `target` |
| Efecto | el dato en memoria del proceso **en ejecución** cambia `SALDO=1000 → SALDO=9999` |
| Elevación | **no** |
| Payload | **precompilado** (la víctima **no tiene** `gcc`/`gdb`): `.b64` decodificado con `base64 -d` |

Artefacto: `.../T1565.003-Runtime_Data_Manipulation/ATA036_ataque.sh`
(`sha256=c7d1933231d62b5fb09d380f192e01bf37e88a4c7fbd345cf8e83b9bea68e5db`).
Señales: `.../ATA036_esperado.csv` (`sha256=f3e5315cf3ad1e1c47d5d04480aef283682ac9915a5874de37e7608775d94510`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA036_logtest.txt` (`sha256=dec1d6141491fe5beae6bdb12cb5d01efcc38b4861933b2661c8d7d0a179c19a`)
→ `ATA036_preflight.md` (`sha256=1b2f6a0032b10d2fd51e45dbfd01661942003f8cb1ad5c05844c68b4b0f0b24e`) **PASA**
(1 evento `memedit_c0` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
~95 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T10:35:01Z` | `2026-09-29T10:35:40Z` | 39 s | 937 | `c7d19332…e5db` |
| 2 | `2026-09-29T10:39:20Z` | `2026-09-29T10:39:59Z` | 39 s | 955 | `c7d19332…e5db` |

> **Incidente registrado (primer intento de iter1, descartado).** Con el binario `target` inicial,
> `memedit` falló con **`PTRACE_ATTACH: Operation not permitted`** por **`kernel.yama.ptrace_scope=1`**
> (Ubuntu): un proceso **no padre** no puede adjuntarse. La ventana **se descartó** (efecto **no**
> logrado); se añadió `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` al **proceso de laboratorio**
> (`target`, **declarado trazable**) y se **repitieron las 2 iteraciones**. **Sin `sudo`** y **sin
> cambiar el `sysctl`** del sistema.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA036
bash ATA036_ataque.sh   # base64 -d + target (en background) + memedit <pid> SALDO=1000 SALDO=9999
```

## 6. Evidencia

`Logs/ATA036_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el dato EN EJECUCIÓN cambió en memoria:**

| Iter | `target_pid` | ANTES | DESPUÉS | `RUNTIME_DATA_MANIPULATION` |
|---|---|---|---|---|
| 1 | 2990 | `SALDO=1000` | `SALDO=9999` | **OK** ✅ |
| 2 | 3018 | `SALDO=1000` | `SALDO=9999` | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 943 | 937 | 937 |
| 2 | 961 | 955 | 955 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 937 | **1** | 621 | 294 | **0** | 21 | 10 | 927 | 0 | 0 |
| 2 | 955 | **1** | 641 | 292 | **0** | 21 | 11 | 944 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 | 0 |
| 2 | 1 | 1 · `{80792}` | 1 | 0 |

- **`80792` × 1/iter:** `execve` de `memedit` anclado al `cwd` (señal `S1` ∧ ancla `S2`).
- **`artefacto_ataque` (auto):** los `execve` no declarados (`base64`, `target`, `kill`, `sleep`…) y
  sus escrituras. **Ninguna** fila del ataque en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `10:35:05.238Z` `Audit: Command: …ATA036/memedit` | **1/1** (`S1`) | 1 / 21 / 294 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `10:39:24.518Z` `Audit: Command: …ATA036/memedit` | **1/1** (`S1`) | 1 / 21 / 292 | 1 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|1−1|=0 ≤ 2`. **C3′:** ✅ sin dudosas.
  Ver `Bitacora/ATA036.json`.

## 10. Limitaciones y hallazgos

1. **⭐ Hallazgo (capa poco cubierta).** El HIDS ve la **herramienta** (`memedit`, `80792`) pero
   **no la manipulación** en sí: ni `ptrace` ni la escritura en `/proc/<pid>/mem` generan evento con
   este ruleset (audit audita `execve` y escrituras de fichero).
2. **`yama ptrace_scope=1`** (declarado): el proceso de laboratorio se **declara trazable**
   (`PR_SET_PTRACER_ANY`); en un caso real, si el objetivo **no** es trazable haría falta
   `CAP_SYS_PTRACE` (`sudo`) — **limitación declarada**.
3. **Fallback R1** (payload precompilado). **Sin `sudo`**; **0** filas del ataque en `ruido`.
   Realismo acotado declarado (README §9).

## 11. Filas `ruido` (para ratificación)

- **iter1: 294**; **iter2: 292** — **baseline** (PAM del login del operador, `sshd`, `591`…), ajenas
  al ataque. **0** filas del ataque en `ruido`.

---

## § Repetición auditada (rev)

> Bloque `fase-03-repeticiones` (**tanda R3**), **2026-10-01**. `esperado_rev` firmado **APROBADO 2026-10-01 (validación humana)** ANTES del primer `t0`. Añadido por `tfg-executor`. **Sin secretos.**

### Motivo

- **`motivo_repeticion` = `prestaging`.** Auditoría metodológica (`_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` §2; `Soporte/Ataques/criterio_ataques.md` §C): el ataque **materializaba su payload (`memedit`/`target`) y lanzaba el proceso `target` dentro de `[t0,t1]`**, ensuciando la ventana con una preparación que **no es la técnica**.

### Qué cambió respecto al original (el original NO se toca)

- **Método original:** propio — `base64 -d` del payload + lanzamiento de `target` **dentro** de la ventana, y luego `memedit <pid>`.
- **Método de la repetición (pre-staging):** `memedit` y `target` se materializan y el `target` se **lanza ANTES de `t0`** (modo `prestage`); la ventana ejecuta **solo** la acción de la técnica (el `ptrace` de `memedit`). Desaparecen las señales `ambigua` de creación del payload/estado.
- **Material antes de `t0`:** `memedit` (`sha256=8205ab6af66e92fb70576f80fb1f85abe52c157a4e549887c45c13105952de0c`), `target` (`sha256=53ee76e60a16ba921e3774b6a62455f18b696cd7c4ae8d5c383605cb91e1587e`); `target` lanzado antes de `t0` (pid 3500 en rev1 / 3585 en rev2; ver `Logs/ATA036_rev{1,2}/prestaging.out`).

### Iteraciones (rev)

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | auto_ruido | ruido_conocido | artefacto_ataque | dudosa |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-01T21:38:02Z` | `2026-10-01T21:38:37Z` | 912 | **1** | 700 | 198 | 13 | 0 |
| 2 | `2026-10-01T21:42:03Z` | `2026-10-01T21:42:38Z` | 965 | **1** | 755 | 196 | 13 | 0 |

### Resultado (métrica congelada O1+O2)

- **O1 (detectado):** sí — `rule_id` = `['80792']`.
- **O2 (acciones cubiertas):** iter1 = 1/1 · iter2 = 1/1 (`S1`; el ancla `S2` no es detector).
  - iter1 primera evidencia: `2026-10-01T21:38:03.965Z` `audit_exe=/home/angel/lab-attack/ATA036/memedit`.
  - iter2 primera evidencia: `2026-10-01T21:42:05.472Z` `audit_exe=/home/angel/lab-attack/ATA036/memedit`.
- **Doble iteración (v2):** `iguales` (mismo `rule_id` de detección; recuento estable; sin dudosas).
- **`dudosa` resueltas:** iter1: ruido=5 · iter2: ruido=5 (PAM del login del operador).
- **0 filas del ataque en `ruido`** (pertenencia por carpeta).

### Prueba de efecto (independiente de la alerta)

- iter1 y iter2: `RUNTIME_DATA_MANIPULATION=OK` — el dato en memoria del proceso **en ejecución** cambió (`SALDO=1000` → `SALDO=9999`); `memedit_rc=0`.

### Cómo se cumple el motivo (pre-staging)

- El payload y el proceso `target` se prepararon/lanzaron **ANTES de `t0`** (`prestaging.out`: `PRESTAGE=OK`, `target_pid=…`); **ninguna** señal `ambigua` de creación del payload/estado cae en `[t0,t1]`. La ventana mide **solo** el `execve` de `memedit`.

### Trazabilidad

- `esperado_rev`: `…/T1565.003-Runtime_Data_Manipulation/ATA036_esperado_rev.csv` (`sha256=e0e47bbe02d5440f64ddaf47ce292bd4f31cf6122b4b009b4165fd5f1c83cbed`).
- `ataque_rev`: `…/T1565.003-Runtime_Data_Manipulation/ATA036_ataque_rev.sh` (`sha256=197bee5b9ad117d292670f111ac9015bc03c1d24f6f6ed79cc4921387de41fb0`).
- C0: `Soporte/Ataques/c0/ATA036_rev_logtest.txt` + `ATA036_rev_preflight.md` (**PASA**, sin silenciadores).
- Detalle: `…/CSV/ATA036_rev{1,2}-Detalle.csv` · Auditado: `…/Auditado/ATA036_rev{1,2}-Audited.csv`.
