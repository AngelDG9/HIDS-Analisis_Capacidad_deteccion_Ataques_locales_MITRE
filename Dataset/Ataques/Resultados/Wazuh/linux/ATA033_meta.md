---
fase: 3
bloque: fase-03-ampliacion-2
tanda: A
ata_id: ATA033
tecnica: T1491.001
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA033 · T1491.001 Internal Defacement (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion-2` (**tanda A**, 5.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> Objeto: la **raíz web de un portal interno** simulado; **no** hay webroot real.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA033** |
| Técnica | **T1491.001 — Internal Defacement** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (las atómicas de ART son Windows) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`) + **`watch`** del webroot (`80790/80781`, efecto) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `cp` del `deface_internal.html` sobre `index.html` |
| Efecto | el `sha256` del `index.html` **antes ≠ después**; marcador `COMPROMETIDA` |
| Elevación | **no** |
| Guardarraíl | objetivo **solo** bajo `lab-legit/intranet_web`; jamás `/var/www` |

Artefacto: `.../T1491.001-Internal_Defacement/ATA033_ataque.sh`
(`sha256=b04034b8f20fcf7fc8741df697f3d397f952da2c5b9f7f851a7d3b8b1026bf1b`).
Señales: `.../ATA033_esperado.csv` (`sha256=b14e811fa9d05711cf59d882ca749c73255c4daebeb6778af9d1c249f6b849a0`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA033_logtest.txt` (`sha256=cef14d876a0a7461963ca05545221b2a4de7e985ea987f78d46ca6ba4e6f8d00`)
→ `ATA033_preflight.md` (`sha256=1b411396e3fb606fe6775c605245c688b59d186c6ed2bae33c40561a359affd3`) **PASA**
(1 evento `cp` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T09:34:26Z` | `2026-09-29T09:34:58Z` | 32 s | 999 | `b04034b8…bf1b` |
| 2 | `2026-09-29T09:38:20Z` | `2026-09-29T09:38:52Z` | 32 s | 999 | `b04034b8…bf1b` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA033
bash ATA033_ataque.sh   # cp deface_internal.html -> lab-legit/intranet_web/index.html
```

## 6. Evidencia

`Logs/ATA033_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el portal se reescribió de verdad:**

| Iter | sha256 antes | sha256 después | marcador | `DEFACEMENT` |
|---|---|---|---|---|
| 1 | `667f1dd9…b49f` | `3bab3a83…0def6` | `COMPROMETIDA` | **OK** ✅ |
| 2 | `667f1dd9…b49f` | `3bab3a83…0def6` | `COMPROMETIDA` | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1005 | 1000 | 999 |
| 2 | 1005 | 1000 | 999 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 999 | **1** | 621 | 358 | **0** | 19 | 13 | 986 | 0 | 0 |
| 2 | 999 | **1** | 619 | 358 | **0** | 21 | 13 | 986 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 (`S1` cp) | 0 |
| 2 | 1 | 1 · `{80792}` | 1 | 0 |

- `80792` × 1: el **`cp`** que reescribe el webroot, **anclado** al `cwd` del ataque (señal
  `T1491.001-S1` ∧ ancla `S2`). **0 sorpresas** (`novel`).
- **`dudosa` resueltas (3/iter):** `80790` (creación de `intranet_web` + `index.html`) y `80781`
  (escritura) bajo el **`watch`** → **`artefacto`** (efecto). **Ninguna** fila del ataque en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `09:34:28.153Z` `audit_exe=/usr/bin/cp` | **1/1** (`S1`) | 1 / 19 / 358 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `09:38:21.862Z` `audit_exe=/usr/bin/cp` | **1/1** (`S1`) | 1 / 21 / 358 | 1 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|1−1|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA033.json`.

## 10. Limitaciones y hallazgos

1. **Capa declarada vs. capa real (honestidad).** El plan preveía **FIM sobre el webroot**; el
   `syscheck` del agente **no** vigila `lab-legit` (solo `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot`),
   así que la capa real es el **`watch` de auditd** (`80790/80781`), declarado **`ambigua`** →
   `artefacto`. La detección efectiva es el **`execve` de `cp`**.
2. **Solapamiento declarado con ATA007/T1491** (defacement): aquí el **objeto** es el **webroot de la
   intranet** (portal interno), frente al `public_site` genérico de ATA007.
3. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
