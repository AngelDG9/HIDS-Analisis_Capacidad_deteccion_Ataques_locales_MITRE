---
fase: 3
bloque: fase-03-piloto
ata_id: ATA013
tecnica: T1560.002
tactica: Collection
version: 2
status: review
fecha: 2026-09-28
---

# Ficha — ATA013 · T1560 Archive Collected Data (`gzip` en Python) (Linux / `victima-linux`)

> Piloto `fase-03-piloto`. Generada por `tfg-executor`. **Sin secretos.**
> Estado **`review`**: las dudosas quedaron **resueltas** por veredicto humano (2026-09-25), pero el
> **chequeo de sanidad** del criterio de doble iteración (§6 del plan) **falla** por el ruido de
> **arranque** entre iteraciones (mismo hallazgo que ATA002/ATA008). Los **3 criterios formales
> pasan**. Resultado de detección: **0 detecciones** en ambas iteraciones (ver §11: enmascaramiento
> por una regla de fábrica de Wazuh).
>
> **Revisión (`fase-03-metrica`, 2026-09-28):** se añade la **métrica de detección O1+O2** (§8.2) y
> la categoría **`artefacto_ataque`**: las **6** filas por iteración de la **huella del propio ataque**
> (`execve` `80792`: `bash`, `date`, `dirname`, `ls`, `cat`… con `cwd=/home/angel/lab-attack/ATA013`)
> **salen de `ruido_conocido`** (`220→214` y `146→140`). Aunque **`deteccion=0`** (enmascaramiento
> `92600`, §11.1), el **ataque deja 6 filas `artefacto_ataque` visibles** en su carpeta: es evidencia
> de que **corrió**. `Hojas/ATA_index.csv` **intacto** (sigue `review`).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA013** |
| Técnica / subtécnica | **T1560.002** Archive Collected Data: Archive via Library |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Prioridad | n/d (no definida en el corpus; ATA013 es de la primera tanda de 13) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Prueba ART | *Compressing data using GZip in Python (FreeBSD/Linux)* |
| GUID | `391f5298-b12d-4636-8482-35d9c17d53a8` |
| Path en el clon | `atomics/T1560.002/T1560.002.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Herramienta | `python3` — **Python 3.12.3** con **stdlib `gzip`** (`/usr/bin/python3` → `python3.12`) |
| Dependencias | ninguna nueva — `python3 -c "import gzip,tarfile"` OK (paso 0) |
| Elevación | **no** (usuario `angel`) |
| Parametrización | `path_to_input_file=/etc/passwd` (default de la atómica), `path_to_output_file=/home/angel/lab-attack/ATA013/passwd.gz`; `python3` fijo (evita procesos `which`). |

Artefacto: `Dataset/Ataques/Comandos/T1560-Archive_Collected_Data/ATA013_ataque.sh`
(`sha256=8efb703a62ddd9b3f0ca94f20aa695f20d9eeb43f2ba5c049660b59f788645bd`, idéntico en repo y víctima).
Señales esperadas: `.../ATA013_esperado.csv`
(`sha256=a5f23578d936b22ac91e5012b90679939fc2faa1cfb12325a23a0f798776218d`):
`T1560-S1` (**deteccion**) `audit_exe=python3` (Process Creation).
Validación humana (CA5): **2026-09-25**, registrada en `plan.md` (frontmatter `gate`) y en el
comentario de cabecera del propio `ATA013_esperado.csv` (reescrito de «PENDIENTE» a «validado»).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. Arranque observado:
  iter1 ≈ `21:42:02Z` (inicio de `audit.log`), iter2 ≈ `21:49:05Z` (`journalctl`, boot 0). El instante
  exacto del `vmrun revertToSnapshot` no se selló en ATA013 (el revert precede al arranque ~10-20 s);
  **no se inventa**.
- **Manager NO revertido**. **NAT desconectado** (no reconectado). No se instaló nada en la víctima.
- ATA013 **no usa receptor** (no hay `sink.log`).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | sha256 `ATA013_ataque.sh` |
|---|---|---|---|---|
| 1 | `2026-09-25T21:43:03Z` | `2026-09-25T21:43:43Z` | 40 s | `8efb703a…8645bd` |
| 2 | `2026-09-25T21:49:30Z` | `2026-09-25T21:50:11Z` | 41 s | `8efb703a…8645bd` |

`t0 < t1` en ambas (ventana `[t0,t1]` inclusiva). Reloj víctima↔manager < 1 s.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA013
bash ATA013_ataque.sh
```

Cuerpo (atómica parametrizada, sin elevación):
`python3 -c "import gzip; input_file=open('/etc/passwd','rb'); content=input_file.read(); input_file.close(); output_file=gzip.GzipFile('$HOME/lab-attack/ATA013/passwd.gz','wb',compresslevel=6); output_file.write(content); output_file.close();"`
`stdout`+`stderr` en `ejecucion.out` (rc=0 en ambas).

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA013_iter{1,2}/`:
`times.log`, `ejecucion.out`, `ps_antes.txt`, `ps_despues.txt`, `deps.txt`, `sha256_artefacto.txt`,
**`artefacto_salida.txt`**.

**Prueba de que el archivo se creó** (`artefacto_salida.txt`): `passwd.gz` de **691 B** en
`/home/angel/lab-attack/ATA013/`; `file` → *gzip compressed data, was "passwd"*; `gzip -l` →
**1822 B sin comprimir = tamaño exacto de `/etc/passwd`** (ratio 63,4 %).
sha256 `passwd.gz`: iter1 `6964d9bac4a2eb9d35bc61148bd1910862c9edb25f1e3bed98019cd00aea2888`,
iter2 `cc18e8bd7b3c28045d49dcfcbb2c61e2b2974e9ee1dc82d07c11c94ab2b39be1` (distintos solo porque gzip
embebe la `mtime`; contenido idéntico).

## 7. Ventana extraída

- Fichero diario (NO `alerts.json`): `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-25.json`.
- **Aislamiento por agente:** extracción `--detail` → `_raw` y filtro a `agent_name == victima-linux`.

| Iter | Filas en ventana (`_raw`) | victima-linux | wazuh-server (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 847 | 841 | 6 | **841** | 12 | **0** |
| 2 | 1038 | 1032 | 6 | **1032** | 12 | **0** |

Reparto por capa RS (Detalle): iter1 `RS2=833, RS1=8`; iter2 `RS2=1028, RS1=4`. RS3/RS4 vacías.
**0 filas de otro agente** (CA11 ✔).

## 8. Resultado (conteos por categoría, con veredicto humano ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque |
|---|---|---|---|---|---|---|
| 1 | 841 | **0** | 621 | 214 | **0** | **6** |
| 2 | 1032 | **0** | 886 | 140 | **0** | **6** |

**`deteccion` = 0** en ambas iteraciones: **Wazuh (de fábrica) NO detecta el ataque**. Ver §11 para la
causa raíz demostrada (enmascaramiento por la regla de fábrica `92600`, nivel 0).

**`artefacto_ataque` (6/iter, `fase-03-metrica`):** el **árbol de procesos del propio ataque**
(`execve` `80792` con `cwd=/home/angel/lab-attack/ATA013`) que **antes** caía en `ruido_conocido`;
ahora es `artefacto_ataque` (`motivo=del_ataque`). **Es evidencia de que el ataque corrió** aunque su
señal declarada (`python3`) quede enmascarada: el filtro emite **`AVISO`** *"posible señal de detección
no declarada"* por cada execve no declarado (ver §8.2 y `politica_filtrado_ruido.md` §3.ter).

### 8.2 Métrica de detección — **O1 + O2** (`fase-03-metrica`, decisión D1)

> **Definición:** **O1** = *detectado sí/no* + `rule_id` + primera evidencia; **O2** = *acciones
> cubiertas `k/m`* (señales `deteccion` ancladas ≥1 vez / total de señales `deteccion` no-ancla).
> El **nº bruto de alertas** y los `rule_id` distintos son **anexo**, nunca el resultado.

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo: alertas / `rule_id` distintos |
|---|---|---|---|---|---|---|
| 1 | **no** | `{}` | — | **0/1** (`T1560-S1`) | **0 / 6 / 214** | 0 / `{}` |
| 2 | **no** | `{}` | — | **0/1** (`T1560-S1`) | **0 / 6 / 140** | 0 / `{}` |

- **O2 = 0/1:** la única acción declarada (`execve` de `python3`, `T1560-S1`) **no** produce detección:
  la regla de fábrica `92600` (nivel 0) suprime la base `80792` (§11.1). **O1 = no** en ambas
  iteraciones. La huella del ataque (`6` filas `artefacto_ataque`/iter) **no** cuenta como detección.

**`dudosa` resueltas (11: 8 + 3):** ver §10. Todas `motivo=sin_campos` y todas `veredicto=ruido`
(11 PAM/sshd de las sesiones SSH del operador; el `19004` SCA ya **no** es `dudosa`: lo auto-excluye
el predicado `OPERADOR`).

## 9. Doble iteración (§6) — veredicto `review`

| Criterio | Resultado |
|---|---|
| 1) Mismo conjunto de `rule_id` con `deteccion` | ✅ `{}` == `{}` (ninguna detección en ambas) |
| 2) `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|0−0\| = 0 ≤ 2` |
| 3) Sin `dudosa` sin resolver | ✅ 0 y 0 (11 resueltas por el humano) |
| **Sanidad** `auto_ruido` (≤ 10 %) | ❌ **621 vs 886 → `Δ=265` (≫ 62,1)** |
| **Sanidad** `ruido_conocido` (≤ 10 %) | ❌ **214 vs 140 → `Δ=74` (≫ 21,4)** |

Los **3 criterios formales pasan**, pero **las dos sanidades fallan de forma clara** → por §6
**`review`** (no se cierra en silencio). Las **detecciones son idénticas** (0 y 0): la diferencia la
pone el **ruido de arranque**, no el ataque (ver §11). Mismo desenlace que ATA002 y ATA008.

## 10. Dudosas ATA013 — RESUELTAS ✔

Todas `motivo=sin_campos` (ninguna señal del `esperado` es evaluable: no hay campos `audit.*`).

| Iter | timestamp_utc | rule_id | descripción | veredicto | justificación |
|---|---|---|---|---|---|
| 1 | `2026-09-25T21:43:05.688Z` | 5715 | sshd: authentication success. | `ruido` | sesión SSH del operador |
| 1 | `2026-09-25T21:43:05.690Z` | 5501 | PAM: Login session opened. | `ruido` | sesión SSH del operador |
| 1 | `2026-09-25T21:43:05.704Z` | 5501 | PAM: Login session opened. | `ruido` | sesión SSH del operador |
| 1 | `2026-09-25T21:43:05.766Z` | 5502 | PAM: Login session closed. | `ruido` | cierre de sesión SSH |
| 1 | `2026-09-25T21:43:05.774Z` | 5715 | sshd: authentication success. | `ruido` | sesión SSH del operador |
| 1 | `2026-09-25T21:43:05.775Z` | 5501 | PAM: Login session opened. | `ruido` | sesión SSH del operador |
| 1 | `2026-09-25T21:43:05.787Z` | 5502 | PAM: Login session closed. | `ruido` | cierre de sesión SSH |
| 1 | `2026-09-25T21:43:15.389Z` | 5502 | PAM: Login session closed. | `ruido` | cierre de sesión SSH |
| 2 | `2026-09-25T21:49:30.363Z` | 5501 | PAM: Login session opened. | `ruido` | sesión SSH del operador |
| 2 | `2026-09-25T21:49:30.363Z` | 5715 | sshd: authentication success. | `ruido` | sesión SSH del operador |
| 2 | `2026-09-25T21:49:30.364Z` | 5502 | PAM: Login session closed. | `ruido` | cierre de sesión SSH |

- **11 PAM/sshd** → `ruido` con el **criterio fijado por el humano (2026-09-25)** para las sesiones
  del operador (nota en el `-Revision.csv`).
- **`19004` (grupo `sca`)** ya **no** es `dudosa`: lo **auto-excluye** el predicado `OPERADOR`
  (`motivo=operador:19004`, política §3.bis) → `ruido_conocido`. Es la **autoevaluación SCA periódica
  del propio agente Wazuh** (se dispara ~30 s tras arrancar el agente; hoy salió 3 veces: 20:30:38,
  21:42:25 —fuera de ventana— y 21:49:31 —dentro de iter2—), **ajena al ataque** y **no** cuenta como
  detección. Por eso el `-Revision.csv` de iter2 pasa de **4 a 3** filas (solo PAM/sshd), de forma
  **determinista** (paso 1.5), sin revisión humana. *Deuda (resuelta por el predicado):* añadir
  `19004`/grupo `sca` al catálogo de ruido.

## 11. Hallazgos y limitaciones (el valor del piloto) ⭐

### 11.1 ⭐ Enmascaramiento DENTRO del ruleset de fábrica de Wazuh (ATA013 no detectado)

- El `execve` de `python3` **sí lo capturó auditd**:
  `type=SYSCALL … comm="python3" exe="/usr/bin/python3.12" key="audit-wazuh-c"` (audit
  `1790372583.956:3296`, `2026-09-25T21:43:03Z`) — la regla de auditd `-S execve -k audit-wazuh-c`
  está activa y funciona.
- **Wazuh NO emitió ninguna alerta.** La regla de fábrica
  `/var/ossec/ruleset/rules/0850-audit_rules.xml` → **`92600` `level="0"`** casa `audit.exe` ~
  `python` (*"Executed python script."*) y, al usar **`<if_group>audit</if_group>`**, es **hermana**
  de `80792` (**mismo grupo `audit`**, NO hija) y **suprime** la alerta base `80792` (*Audit: Command*).
  Al ser **nivel 0**, no emite nada → **punto ciego silencioso**.
- Es el **mismo fenómeno «regla hermana que suprime la base»** que demostró el pre-flight (A2.2), pero
  **sin que intervenga ninguna regla nuestra**: aquí lo provoca el **propio ruleset de Wazuh**.
- Consecuencia: `dd` (ATA002) y `wget` (ATA008) sí alertan por `80792`; **`python3` no**.
- **Nota para el escalado:** el pre-flight **C1** comprueba *nuestras* reglas contra la base, **no
  base-contra-base** → considerar ampliarlo para detectar este tipo de punto ciego.

### 11.2 El ruido de arranque domina las ventanas cortas

Tras un `revert`+arranque, la 1ª parte de la ventana se llena de churn (`execve`/`watch` de
`systemd`, `dash`, `env`, `uname`, `find`…). Es lo que hace **fallar la sanidad** del §6 y deja los
**3 ataques del piloto en `review`**, pese a que las **detecciones son idénticas** entre iteraciones.
Mejora: esperar a que el arranque se asiente antes de `t0`, y/o comparar solo el régimen o excluir el
churn de arranque.

### 11.3 `sin_campos` del filtro → dudosas sistemáticas

Con una señal por `audit_exe`, toda alerta sin campos `audit.*` (PAM/sshd del operador, SCA) cae en
`dudosa`. Mejora: reconocer y excluir las **sesiones del propio operador** (y el SCA) para no acumular
filas a revisar.

### 11.4 Otras
- `/home/angel/lab-attack` **no está vigilado** (ni auditd ni FIM) → la creación del `.gz` no genera
  evento de fichero; la técnica solo se vería por el `execve`… que queda enmascarado (§11.1).
- El `.gz` de la atómica usa `gzip.GzipFile(...)`, que embebe la `mtime` → `sha256` distinto entre
  iteraciones (contenido idéntico, mismo tamaño descomprimido).
