---
fase: 3
bloque: fase-03-piloto-custom
ata_id: ATA012
tecnica: T1119
tactica: Collection
version: 5
status: cerrado
fecha: 2026-09-28
---

# Ficha — ATA012 · T1119 Automated Collection (Linux / `victima-linux`)

> Bloque `fase-03-piloto-custom` (camino **ataque escrito por nosotros**). Generada por
> `tfg-executor`. **Sin secretos.** Estado **`cerrado`**: criterio de doble iteración **v2** →
> **`iguales`** (detección idéntica; sin `dudosa` sin resolver).
>
> **Revisión (`fase-03-senales`, 2026-09-28):** recuento **re-generado** con el **ancla implícita
> + evento de ejecución** (`filtrar_ruido.py`); `deteccion` **11→6/7** (3/4 ajenas → `dudosa` →
> `ruido`); `Hojas/ATA_index.csv` **intacto** (sigue `cerrado`). Detalle en §8/§8.1/§9/§10.
>
> **Revisión (`fase-03-metrica`, 2026-09-28):** se añade la **métrica O1+O2** (§8.2) y la categoría
> **`artefacto_ataque`**: las **10** filas por iteración de la **huella del propio ataque**
> (`execve`/efectos con `cwd`/ruta bajo `/home/angel/lab-attack/ATA012`) **salen de `ruido_conocido`**
> (`126→116` y `129→119`). El `.tar.gz` creado por el ataque deja de ser `ruido`: el humano lo pliega
> con el nuevo veredicto **`artefacto`** (nunca `ruido`). **El veredicto no cambia** (`deteccion=6/7`)
> y **ninguna detección genuina se pierde**. `Hojas/ATA_index.csv` **intacto** (sigue `cerrado`).
>
> **Corrección (`fase-03-metrica`, ciclo 2, 2026-09-28):** coherentizada la fila `artefacto`
> (`80790` *Created: …/collected.tar.gz*): la **nota** ya dice **`artefacto`** ("es del ataque, pista
> floja → `artefacto`, nunca `ruido`") y la **cabecera** del `-Revision.csv` se regeneró con los
> conteos del pase actual (ya incluye `artefacto_ataque`). **Sin cambios de cifras** (`deteccion=6/7`,
> `artefacto_ataque=10/10`, `ruido_conocido=116/119`).

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
(`sha256=650d518283cbff3463b5024ddea539e05347fa20cc988f9cf6f69d937fa89424`).
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
`times.log`, `ejecucion.out`, `deps_ps_antes.txt`, `ps_despues.txt`.

> **Nota (`fase-03-cabos`, 2026-09-28):** este bloque **no** generó `sha256_artefacto.txt` (el fichero
> no existe en ninguno de los 6 directorios de `Logs/`; solo lo generó el piloto). El `sha256` del
> script consta en §2 y en `Bitacora/ATA012.json` (`ataque_sha256`) — **idéntico repo↔víctima**; no se
> reconstruye evidencia post-hoc.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-26.json` (extractor **H3**, con `srcip`).
- **Aislamiento por agente:** `_raw` → filtro a `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 758 | 751 | 7 | **751** | 6 | **0** |
| 2 | 763 | 756 | 7 | **756** | 6 | **0** |

## 8. Resultado (conteos por categoría y capa, con veredicto ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 751 | **6** | 619 | 116 | **0** | **10** | 3 | 748 | 0 | 0 |
| 2 | 756 | **7** | 620 | 119 | **0** | **10** | 3 | 753 | 0 | 0 |

### 8.1 Detecciones — **dos cifras**, genuinas/ajenas y desglose esperadas/sorpresas

| Iter | **alertas** detección | **`rule_id` distintos** | **genuinas / ajenas** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|---|
| 1 | 6 | 1 · `{80792}` | **6 / 0** | 6 (`T1119-S1/S2/S3`) | 0 |
| 2 | 7 | 1 · `{80792}` | **7 / 0** | 7 (`T1119-S1/S2/S3`) | 0 |

- **Motivos (iter1):** `T1119-S1` (`find`) ×4, `T1119-S2` (`cp`) ×1, `T1119-S3` (`tar` execve) ×1.
  **(iter2):** `S1` ×5, `S2` ×1, `S3` ×1. Todas `80792` (`audit_command`), **ancladas** a
  `cwd=/home/angel/lab-attack/ATA012` por `S4`.
- **`fase-03-senales` (2026-09-28) — recuento limpio con el ancla implícita:** las **ajenas** ya
  **no** cuentan como `deteccion`: los **3 `find` de `update-motd.d`** (`landscape-sysinfo`/
  `update-notifier`, `cwd=/`) del **login SSH del operador** y el `find` con `cwd` vacío caen a
  **`dudosa`/`sin_ancla:T1119-S1`**; la **escritura watch** del `tar` (`80790`) cae a
  **`dudosa`/`sin_ancla:T1119-S3`** (el evento watch no es `audit_command`). El humano las
  resolvió a **`ruido`**. *(Antes: 11 detección, 7/8 genuinas + 3/4 ajenas.)*
- **`dudosa` resueltas:** los `find` ajenos (`cwd=/`) y el `find` sin `cwd` → **`ruido`**
  (`sin_ancla:T1119-S1`); las `5501`/`5502` (PAM del operador) → **`ruido`**. La **escritura watch
  del `tar`** (`80790`, `sin_ancla:T1119-S3`) es **DEL ATAQUE** (`cwd=/home/angel/lab-attack/ATA012`)
  → **`artefacto`** (regla **D2/D5**, `fase-03-metrica`; nota actualizada en el ciclo 2: *"es del
  ataque, pista floja -> artefacto, nunca ruido"*). El `5715` del operador se **auto-excluye**
  (`operador:5715`, `srcip=192.168.65.1`) con el extractor H3 (ver §10).

### 8.2 Métrica de detección — **O1 + O2** (`fase-03-metrica`, decisión D1)

> **Definición:** **O1** = *detectado sí/no* + `rule_id` + primera evidencia; **O2** = *acciones
> cubiertas `k/m`* (señales `deteccion` ancladas ≥1 vez / total de señales `deteccion` no-ancla).
> El **nº bruto de alertas** y los `rule_id` distintos son **anexo**, nunca el resultado.

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo: alertas / `rule_id` distintos |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-26T12:20:58.850Z` `audit_exe=/usr/bin/find` | **3/3** (`S1`/`S2`/`S3`) | **6 / 10 / 116** | 6 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-26T12:30:04.598Z` `audit_exe=/usr/bin/find` | **3/3** (`S1`/`S2`/`S3`) | **7 / 10 / 119** | 7 / `{80792}` |

- **O2 = 3/3:** las **3 acciones** declaradas (`find`/`cp`/`tar`, señales `S1`/`S2`/`S3`) se anclan
  ≥1 vez en ambas iteraciones, todas al `cwd` del ataque (`S4`). Es la única técnica con `m=3`
  (las demás declaran 1 acción). Las **10** filas `artefacto_ataque`/iter son el staging del ataque
  (`execve` del árbol + el `.tar.gz` creado).

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|7−6\| = 1 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 619 vs 620 → Δ=1 |
| Sanidad `ruido_conocido` (aviso) | ✅ 116 vs 119 → Δ=3 |

> **Nota (`fase-03-senales`, 2026-09-28):** cifras recalculadas con el **ancla implícita + evento
> de ejecución**; `deteccion` pasa de **11/11** a **6/7** (3/4 ajenas → `dudosa` → `ruido`).
> Veredicto v2 sigue **`iguales`**.

## 10. Limitaciones y hallazgos

1. **Señal `audit_exe` ancha — ✅ RESUELTO (`fase-03-senales`, 2026-09-28):** los `find` de
   `update-motd.d` (login del operador) ya **no** se cuentan como `deteccion`: el ancla implícita
   (`exe ∧ cwd-ancla ∧ audit_command`) los manda a **`dudosa`/`sin_ancla:T1119-S1`** → `ruido`.
   Ver política §4 y runbook §8.2.
2. **Ancla `audit_cwd` (✅ `fase-03-senales`):** el ancla `S4` (`audit_cwd=/home/angel/lab-attack/ATA012/*`)
   ahora **sí casa** el valor real (`/home/angel/lab-attack/ATA012`, sin barra final) porque el match
   prueba `cwd` **y** `cwd + "/"`. Antes era **inerte** (patrón `/*` vs `cwd` sin barra).
3. **Gap de despliegue (runbook §8.1):** el `extraer_alertas.py` del manager estaba obsoleto; tras
   desplegar el **H3** y re-extraer, `5715` → `ruido_conocido` / `operador:5715`.
4. `lab-listo` prístino: el staging se borra al revertir.
