---
fase: 3
bloque: fase-03-piloto-custom
ata_id: ATA012
tecnica: T1119
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-26
---

# Ficha — ATA012 · T1119 Automated Collection (Linux / `victima-linux`)

> Bloque `fase-03-piloto-custom` (camino **ataque escrito por nosotros**). Generada por
> `tfg-executor`. **Sin secretos.** Estado **`cerrado`**: criterio de doble iteración **v2** →
> **`iguales`** (detección idéntica; sin `dudosa` sin resolver).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA012** |
| Técnica / subtécnica | **T1119** Automated Collection |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual** (custom; ART **no** tiene pruebas Linux para T1119) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG; **no** copia de ART) |
| Herramientas | `find`, `cp`, `tar` (`/usr/bin/{find,cp,tar}`) |
| Staging | `/home/angel/lab-attack/ATA012/collected/` + `collected.tar.gz` (**NO vigilado** → sin watch) |
| Elevación | **no** (usuario `angel`; lee rutas world-readable) |

Artefacto: `Dataset/Ataques/Comandos/T1119-Automated_Collection/ATA012_ataque.sh`
(`sha256=d5ecb91973cbb50f9afef58a2f72726ae58370950418d35e3c86d015a583016e`, idéntico repo↔víctima).
Señales esperadas: `.../ATA012_esperado.csv`
(`sha256=4486a26be6b21475c987b8e072409965d6d4e07864e943aecba589d71bf546f2`).
Validación humana (CA5): **2026-09-26**.
C0: `Soporte/Ataques/c0/ATA012_logtest.txt` (`sha256=029d45b59cf385f988d275afaa7c68ab5390f40d6a0f9849d6e754c2f8908f0b`)
→ pre-flight **PASA** (C0, `n=3` eventos `find`/`cp`/`tar`, **sin silenciadores de fábrica**).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA012_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-26T12:20:57Z` | `2026-09-26T12:21:33Z` | 36 s | 751 | `d5ecb919…3016e` |
| 2 | `2026-09-26T12:30:03Z` | `2026-09-26T12:30:38Z` | 35 s | 756 | `d5ecb919…3016e` |

`t0 < t1` en ambas. Reloj víctima↔manager < 1 s. `t0` sellado tras el asentamiento (H2).

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA012
bash ATA012_ataque.sh     # find /etc ... | cp -t staging ; tar czf collected.tar.gz
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA012_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`, `sha256_artefacto.txt`.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-26.json` (extractor **H3**, con `srcip`).
- **Aislamiento por agente:** `_raw` → filtro a `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 758 | 751 | 7 | **751** | 6 | **0** |
| 2 | 763 | 756 | 7 | **756** | 6 | **0** |

## 8. Resultado (conteos por categoría y capa, con veredicto ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | 751 | **11** | 619 | 121 | **0** | 3 | 748 | 0 | 0 |
| 2 | 756 | **11** | 620 | 125 | **0** | 3 | 753 | 0 | 0 |

### 8.1 Detecciones — **dos cifras**, genuinas/ajenas y desglose esperadas/sorpresas

| Iter | **alertas** detección | **`rule_id` distintos** | **genuinas / ajenas** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|---|
| 1 | 11 | 2 · `{80790,80792}` | **7 / 4** | 11 | 0 |
| 2 | 11 | 2 · `{80790,80792}` | **8 / 3** | 11 | 0 |

- **Motivos:** `T1119-S1` (`find`) ×8, `T1119-S2` (`cp`) ×1, `T1119-S3` (`tar`) ×2.
- **Genuinas del ataque** (ancladas a `cwd=/home/angel/lab-attack/ATA012`): iter1 **7**
  (`find`×4, `cp`×1, `tar`×2), iter2 **8** (`find`×5, `cp`×1, `tar`×2).
- **Ajenas (falso positivo por señal ancha):** `find` de `update-motd.d`
  (`landscape-sysinfo`/`update-notifier`, `cwd=/`) disparados por **el login SSH del operador** →
  contados por `T1119-S1`. iter1: **3** de ese tipo (+1 `find` con `cwd` vacío, ambiguo) = 4; iter2: **3**.
- **`dudosa` resueltas:** `5501`/`5502` (PAM del operador) → **`ruido`** (criterio fijado por el humano).
  El `5715` del operador se **auto-excluye** (`operador:5715`, `srcip=192.168.65.1`) con el extractor H3 (ver §10).

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80790,80792}` == `{80790,80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|11−11\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 619 vs 620 → Δ=1 |
| Sanidad `ruido_conocido` (aviso) | ✅ 121 vs 125 → Δ=4 |

## 10. Limitaciones y hallazgos

1. **Señal `audit_exe` ancha (hallazgo transversal):** el `find` del ataque y los `find` de
   `update-motd.d` (login del operador) son indistinguibles por `audit_exe` → 3 ajenas contadas como
   detección. **Recomendación:** anclar por `audit_cwd` de la carpeta del ataque (patrón corregido:
   `/home/angel/lab-attack/ATA<NNN>` **sin** `/*`) y/o por `rule_id` del execve (runbook §8).
2. **Ancla `audit_cwd` inerte en el `esperado`:** el patrón `/home/angel/lab-attack/ATA012/*` **no
   casa** el valor real del campo (`/home/angel/lab-attack/ATA012`, sin barra final) → `S4` no
   contribuyó; la detección vino de `S1/S2/S3` (`audit_exe`).
3. **Gap de despliegue (runbook §8.1):** el `extraer_alertas.py` del manager estaba obsoleto; tras
   desplegar el **H3** y re-extraer, `5715` → `ruido_conocido` / `operador:5715`.
4. `lab-listo` prístino: el staging se borra al revertir.
