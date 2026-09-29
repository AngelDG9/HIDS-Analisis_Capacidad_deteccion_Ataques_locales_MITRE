---
fase: 3
bloque: fase-03-ampliacion
tanda: A
ata_id: ATA016
tecnica: T1213.006
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA016 · T1213.006 Databases (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda A**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica congelada.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA016** |
| Técnica | **T1213.006 — Data from Information Repositories: Databases** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2; **la detección**) + `watch` (efecto) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` |
| Herramientas | **`cp`, `grep`** + **`python3`** (siembra de la BD) |
| Objetivo | SQLite **real** `/home/angel/lab-legit/clientes_clientes.db` (**VIGILADO**) |
| Salida | `/home/angel/lab-attack/ATA016/collected/` |
| Elevación | **no** |

Artefacto: `.../T1213.006-Databases/ATA016_ataque.sh`
(`sha256=77a9543145f02edc478a036f39222d513c7e51d5041c2756c0f4e279a6a0143f`, idéntico repo↔víctima).
Señales: `.../ATA016_esperado.csv` (`sha256=304563b42fc772ed3ef2e25b4f16b65e2b9be5925d2613f23c2bff353b577e62`).
Validación humana: **APROBADO 2026-09-29**.
C0: `ATA016_logtest.txt` (`sha256=c20f71549e20be88a7cd1cfd6d17297124b20e8f692927f3f80a393a75323b9d`)
→ pre-flight **PASA** (2 eventos, `80792` level 3; sin silenciador).

## 3. Snapshot

Víctima a **`lab-listo`** por iteración (el manager **no** se revierte). **NAT off**; nada instalado.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas Detalle | sha256 `ATA016_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-29T00:39:16Z` | `2026-09-29T00:39:49Z` | 33 s | 1200 | `77a95431…a0143f` |
| 2 | `2026-09-29T00:42:45Z` | `2026-09-29T00:43:17Z` | 32 s | 1015 | `77a95431…a0143f` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA016
bash ATA016_ataque.sh     # siembra SQLite (python3), extrae registros (grep) y copia la BD (cp)
```

## 6. Evidencia

`Logs/ATA016_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `ps_antes.txt`, `sha256_artefacto.txt`.

**Prueba de éxito:** `COLECCION=OK` — la copia es una **SQLite válida** (magic `SQLite format 3`),
con el **mismo `sha256`** (`3726d9bc…2370`) que el original y **4 códigos de cliente** extraídos
(`cli1001…cli1004`).

## 7. Ventana extraída

Fichero diario `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-29.json` (H3); aislamiento a
`agent_name == victima-linux`.

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1200 | **3** | 534 | 647 | **0** | 16 | 1 | 1199 | 0 | 0 |
| 2 | 1015 | **3** | 545 | 451 | **0** | 16 | 1 | 1014 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | **3** | 1 · `{80792}` | 2 `grep` + 1 `cp` (`S2`,`S1`) | 0 |
| 2 | **3** | 1 · `{80792}` | 2 `grep` + 1 `cp` | 0 |

- Las 3 son **`execve`** de `grep` (extracción) y `cp` (copia de la BD), `80792`, **ancladas** por
  `T1213.006-S3`.
- **`dudosa` resueltas:** iter1 **19** (17 a `ruido`: `grep` de login `cwd=/`; 2 a `ruido`: `80782`
  *Watch write* en `/run/user/1000/systemd/` — **ajeno**); iter2 **11** (todas `grep` de login → `ruido`).
- **`artefacto_ataque=16`**: `execve` no declarados de la carpeta. **Ninguno** en `ruido`.

### 8.2 Métrica — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-29T00:39:25.769Z` `audit_exe=/usr/bin/grep` | **2/2** | **3 / 16 / 647** | 3 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-29T00:42:47.182Z` `audit_exe=/usr/bin/grep` | **2/2** | **3 / 16 / 451** | 3 / `{80792}` |

## 9. Doble iteración (**v2**) — **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ `rule_id` de `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|3−3\| = 0 ≤ 2` |
| C3′ sin `dudosa` | ✅ 0 y 0 |

## 10. Limitaciones y hallazgos

1. **⭐ Hallazgo (punto ciego reforzado `92600`):** la BD se siembra con **`python3`** (no hay
   `sqlite3`/`strings`). El `execve` de `python3` cae en **`92600` (level 0)** y **no alerta**; además,
   en las 2 ventanas **no aparece ningún evento `watch`** de la creación de la BD — consistente con
   que **la regla hermana `92600` también suprime el evento de auditoría atribuido a `python3`**
   (no solo su `execve`). La **colección** (`cp`/`grep`) **sí** se detecta.
2. **`grep` de login (`cwd=/`) → `dudosa`→`ruido`:** efecto H-A/H-B (churn de `update-motd.d`).
3. Datos de juguete; **realismo acotado** declarado.
4. **C0 sin punto ciego** (`cp`/`grep` → `80792` level 3).
