---
fase: 3
bloque: fase-03-piloto-custom
ata_id: ATA007
tecnica: T1491
tactica: Impact
version: 2
status: cerrado
fecha: 2026-09-26
---

# Ficha — ATA007 · T1491 Defacement (Linux / `victima-linux`)

> Bloque `fase-03-piloto-custom` (camino **ataque escrito por nosotros**). Generada por
> `tfg-executor`. **Sin secretos.** Estado **`cerrado`**: criterio de doble iteración **v2** →
> **`iguales`** (detección idéntica entre iteraciones; sin `dudosa` sin resolver).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA007** |
| Técnica / subtécnica | **T1491** Defacement |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual** (custom; Atomic Red Team **no** tiene pruebas Linux para T1491) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG; **no** copia de ART) |
| Herramienta | `cp` (coreutils, `/usr/bin/cp`) |
| Objetivo | `/home/angel/lab-legit/public_site/index.html` (**dir VIGILADO** por `auditd`, mock web) |
| Elevación | **no** (usuario `angel`) |

Artefacto: `Dataset/Ataques/Comandos/T1491-Defacement/ATA007_ataque.sh`
(`sha256=6918a2a8e0553ad2ef618c99ca4007e96c31ab818828108b880415a9b871ff4b`, idéntico en repo y víctima).
Señales esperadas: `.../ATA007_esperado.csv`
(`sha256=c9ee94d5fc0ea3dc399f32ddb13fe12e3f336757ed9c92a9f3219e7db230f8b9`).
Validación humana del `esperado` (CA5): **2026-09-26** (frontmatter de `plan.md`, gate).
C0: `Soporte/Ataques/c0/ATA007_logtest.txt` (`sha256=6e08fbd4ed4100602fe6ce2d00250c37c2b8752ea5ed50827f11ccd0abe617d1`)
→ pre-flight **PASA** (C0 ejecutado, `n=1` evento, **sin silenciadores de fábrica**).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada en la víctima.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA007_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-26T12:05:06Z` | `2026-09-26T12:05:42Z` | 36 s | 737 | `6918a2a8…1ff4b` |
| 2 | `2026-09-26T12:16:20Z` | `2026-09-26T12:16:55Z` | 35 s | 748 | `6918a2a8…1ff4b` |

`t0 < t1` en ambas (ventana `[t0,t1]` inclusiva). Reloj víctima↔manager < 1 s. `t0` sellado **tras
≥ 60–90 s de asentamiento** (H2).

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA007
bash ATA007_ataque.sh          # cp del defacement sobre la página "pública" simulada
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA007_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`.

> **Nota (`fase-03-cabos`, 2026-09-28):** este bloque **no** generó `sha256_artefacto.txt` (el fichero
> no existe en ninguno de los 6 directorios de `Logs/`; solo lo generó el piloto). El `sha256` del
> script consta en §2 y en `Bitacora/ATA007.json` (`ataque_sha256`) — **idéntico repo↔víctima**; no se
> reconstruye evidencia post-hoc.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-26.json` (extracción con
  `extraer_alertas.py` **H3**, con `srcip/srcuser/dstuser`; desplegado en el manager el 2026-09-26, ver §10).
- **Aislamiento por agente:** `_raw` → filtro a `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 744 | 737 | 7 | **737** | 6 | **0** |
| 2 | 756 | 748 | 8 | **748** | 6 | **0** |

## 8. Resultado (conteos por categoría y capa, con veredicto ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 737 | **4** | 609 | 124 | **0** | 4 | 733 | 0 | 0 |
| 2 | 748 | **4** | 620 | 124 | **0** | 4 | 744 | 0 | 0 |

### 8.1 Detecciones — **dos cifras** y desglose esperadas/sorpresas

| Iter | **alertas** detección | **`rule_id` distintos** | **genuinas / ajenas** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|---|
| 1 | 4 | 3 · `{80781,80790,80792}` | **4 / 0** | 4 (`T1491-S1`) | 0 |
| 2 | 4 | 3 · `{80781,80790,80792}` | **4 / 0** | 4 (`T1491-S1`) | 0 |

- Las **4** detecciones son del **mismo evento del `cp`** del ataque, visto por varias reglas:
  `80792`×2 (execve de `cp`), `80790` (*Created* del `public_site/`), `80781` (*Watch-Write* de `lab-legit`).
- **`T1491-S1` (`audit_exe=cp`) es ancha:** las escrituras que el `esperado` declaró **`ambigua`**
  (`T1491-A1`=`80790`, `T1491-A2`=`80781`) fueron **promovidas a `deteccion`** porque el mismo
  evento del `cp` las arrastra (paso 2 `deteccion` > paso 3 `ambigua`). → recuento **redundante**;
  el número "limpio" es **3 `rule_id`**.
- **`dudosa` resuelta (1/iter):** `80790` *Created: public_site.* (el `mkdir -p` del **setup** del
  ataque) → **`ruido`**, nota *"setup del ataque (creacion de carpeta); no es la tecnica - criterio
  del orquestador"*.

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80781,80790,80792}` == `{80781,80790,80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|4−4\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 609 vs 620 → Δ=11 |
| Sanidad `ruido_conocido` (aviso) | ✅ 124 vs 124 → Δ=0 |

## 10. Limitaciones y hallazgos (para la memoria)

1. **Señal `audit_exe` ancha (hallazgo transversal):** promueve a `deteccion` las escrituras del
   propio proceso. **Recomendación para el escalado:** declarar la detección por el **`rule_id` del
   execve** (`80792`) o por el **`audit_cwd` de la carpeta del ataque** (patrón corregido, sin `/*`),
   no por `audit_exe` genérico (runbook §8).
2. **Baseline que "tapa" la escritura (§3.1 del plan):** la ruta `lab-legit` es la que trabaja la
   actividad legítima; por eso A1/A2 se declararon `ambigua` (revisión humana), nunca `deteccion`.
3. **Gap de despliegue (runbook §8.1):** el `extraer_alertas.py` del manager estaba obsoleto (sin
   `srcip`); se **desplegó** la versión del repo y se **re-extrajo** esta ventana.
4. `lab-listo` prístino: no se instaló nada; el `public_site/` creado desaparece al revertir.
