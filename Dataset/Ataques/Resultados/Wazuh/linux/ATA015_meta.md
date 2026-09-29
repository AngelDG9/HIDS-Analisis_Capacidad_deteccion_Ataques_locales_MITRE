---
fase: 3
bloque: fase-03-ampliacion
tanda: A
ata_id: ATA015
tecnica: T1114.003
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA015 · T1114.003 Email Forwarding Rule (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda A**, 3.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica congelada.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA015** |
| Técnica | **T1114.003 — Email Collection: Email Forwarding Rule** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`; **la detección**) + **`watch`/file-creation** (efecto) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (persistencia de reenvío) |
| Herramientas | **`cat`, `grep`, `cp`** |
| Destino | `/home/angel/lab-legit/.forward` + `.procmailrc` (**VIGILADO**); copia en `lab-attack/ATA015/collected/` |
| Elevación | **no** |

Artefacto: `.../T1114.003-Email_Forwarding_Rule/ATA015_ataque.sh`
(`sha256=c4d54c370cf19d7c552fa79ec9b3141bee9517e600ba36ac9bc45d2ff12b0be1`, idéntico repo↔víctima).
Señales: `.../ATA015_esperado.csv` (`sha256=3bee2db42cb9a21d5a1be1663e09172aaf0553e25f2935e8074b98699efea28f`).
Validación humana: **APROBADO 2026-09-29**.
C0: `ATA015_logtest.txt` (`sha256=7436b6b2487bf7da0f5c005ffbe7aac58e274bec741d204d8f877a6f6e383ae0`)
→ pre-flight **PASA** (3 eventos, `80792` level 3; sin silenciador).

## 3. Snapshot

Víctima a **`lab-listo`** por iteración (manager **no** revertido). **NAT off**; nada instalado.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas Detalle | sha256 `ATA015_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-29T00:46:13Z` | `2026-09-29T00:46:46Z` | 33 s | 1037 | `c4d54c37…2b0be1` |
| 2 | `2026-09-29T00:49:46Z` | `2026-09-29T00:50:18Z` | 32 s | 1158 | `c4d54c37…2b0be1` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA015
bash ATA015_ataque.sh     # crea .forward/.procmailrc (watch), los lee (grep) y los copia (cp)
```

## 6. Evidencia

`Logs/ATA015_iter{1,2}/` (ver ficha ATA014 §6 para la lista). **Prueba de éxito:** `REENVIO=OK` — la
regla de reenvío existe, contiene el destino del atacante (`dropbox@exfil-lab.example`, **simbólico**)
y la copia es **idéntica** (`sha256 7afb588c…`).

## 7. Ventana extraída

Fichero diario `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-29.json` (H3); sólo `victima-linux`.

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1037 | **6** | 541 | 475 | **0** | 15 | 1 | 1036 | 0 | 0 |
| 2 | 1158 | **6** | 536 | 601 | **0** | 15 | 1 | 1157 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id`** | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | **6** | 1 · `{80792}` | 2 `cat` (`S1`) + 2 `grep` (`S3`) + 2 `cp` (`S2`) | 0 |
| 2 | **6** | 1 · `{80792}` | 2 `cat` + 2 `grep` + 2 `cp` | 0 |

- Todo `80792`, **anclado** por `T1114.003-S4` a `cwd=/home/angel/lab-attack/ATA015`.
- **`dudosa` resueltas:** iter1 **44** (2 a **`artefacto`**: creación de `.forward`/`.procmailrc` bajo
  `watch`; 42 a **`ruido`**: `cat`/`grep` de `update-motd.d` con `cwd=/` por el **login del
  operador**); iter2 **58** (2 `artefacto` + 56 `ruido`). **Ninguna** fila del ataque en `ruido`.
- **`artefacto_ataque=15/15`:** `execve` no declarados + efectos `watch`.

### 8.2 Métrica — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-29T00:46:15.602Z` `audit_exe=/usr/bin/cat` | **3/3** | **6 / 15 / 475** | 6 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-29T00:49:48.727Z` `audit_exe=/usr/bin/cat` | **3/3** | **6 / 15 / 601** | 6 / `{80792}` |

## 9. Doble iteración (**v2**) — **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ `rule_id` de `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|6−6\| = 0 ≤ 2` |
| C3′ sin `dudosa` | ✅ 0 y 0 |

## 10. Limitaciones y hallazgos

1. **La técnica es una ESCRITURA** (regla de reenvío): el HIDS **sí** genera el `watch`
   (`80790/80781`, declarado **`ambigua`**), pero por la **regla única** del corpus ese `watch` se
   cuenta como **`artefacto`** (efecto), **no** como detección: **la detección es el `execve`**.
2. **`cat`/`grep` de login (`cwd=/`) → `ruido`** (42/55 filas; churn de `update-motd.d` disparado por
   las sesiones SSH del operador). Volumen alto porque se declaran **2** utilidades muy usadas por el
   login; se **lista para ratificación**.
3. Datos de juguete; dominio de reenvío **simbólico**.

## 11. C0

`ATA015_logtest.txt` → **PASA** (cat/cp/grep → `80792` level 3; sin silenciador de fábrica).
