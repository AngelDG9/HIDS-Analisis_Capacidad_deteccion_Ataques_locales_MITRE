---
fase: 3
tarea: A2.1 (T-11 · R-09/R-13) · A3.0 (H3/H4)
nombre: Política de filtrado de ruido y etiquetado auditado de alertas
version: 3
status: implementada
fecha: 2026-09-26
autor: tfg-executor
---

# Política de filtrado de ruido y etiquetado auditado

> Política **de la herramienta** `_artefactos/scripts/filtrar_ruido.py` (Fase 3 · A2.1).
> Este documento y el código deben coincidir **literalmente**: si se cambia uno, se cambia el
> otro. Referencia de decisión: `plan.md` (bloque `fase-03-filtro`) §2–§5 y `Dataset/Legitimo/
> baseline_meta.md` §9.

## 1. Entradas y salidas

- **Entrada de alertas:** CSV de **detalle por alerta** (una fila por alerta), producido por
  `extraer_alertas.py --detail`. Columnas: `timestamp_utc, agent_name, rule_id, rule_level,
  rule_description, rule_groups, rs_origen, audit_exe, audit_cwd, audit_key, audit_type,
  audit_file, audit_dir, syscheck_path` (nombres de campo **confirmados con datos reales** en el
  paso 0, 2026-09-25) **más `srcip, srcuser, dstuser`** (añadidas en H3, 2026-09-26, para evaluar
  la condición de origen de `5715`; el filtro las lee por nombre, no las vuelca al audited).
- **Catálogo baseline:** `Dataset/Legitimo/ruleids_legitimos.csv` (12 `rule.id`, 13.574 alertas).
- **Señales esperadas del ataque:** `Dataset/Ataques/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv`.
- **Salida:** `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iter{N}-Audited.csv`
  (default de `--out`; convención por SO, cabo 1 del afinado).
- **Revisión:** `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iter{N}-Revision.csv`
  (default de `--rev-out`; solo si hay filas dudosas).

## 2. Categorías y **orden exacto** de decisión (§2)

Una alerta recibe **una** categoría; **gana el primero que casa**:

1. **`auto_ruido`** — el origen es el propio Wazuh, **por campos** (no por `rule.id`) §3.
2. **`deteccion`** — casa una señal esperada de tipo `deteccion`.
3. **`ruido_conocido`** — **paso 1.5 (H3)**: casa el **predicado `OPERADOR`** §3.bis
   (motivo `operador:<rule_id>`). Va **después** de las señales de detección y **antes** de
   `dudosa`/`sin_campos`: si una señal `deteccion` casa la alerta, **gana la detección**.
4. **`dudosa`** — casa una señal esperada de tipo `ambigua`, **o** la alerta no permite evaluar
   **ninguna** señal (falta el campo; motivo `sin_campos`).
5. **`deteccion`** — `rule.id` **no** está en el catálogo (motivo `novel`).
6. **`ruido_conocido`** — `rule.id` **sí** está en el catálogo (motivo `baseline`).

`categoria ∈ {deteccion, ruido_conocido, auto_ruido, dudosa}`.

**Motivos:** `auto_ruido:<proceso>`, `senal:<senal_id>`, `operador:<rule_id>`,
`ambigua:<senal_id>`, `sin_campos`, `novel`, `baseline`.

## 3. `auto_ruido` — categoría propia (§3)

Se detecta **por campos**, en este orden, y **nunca** cuenta como detección:

1. `basename(audit_exe)` ∈ `{wazuh-agentd, wazuh-syscheckd, wazuh-logcollector, wazuh-modulesd,
   wazuh-execd, wazuh-db, wazuh-analysisd}` (se compara el **nombre base**: en `alerts.json` el
   campo trae la ruta completa, p. ej. `/var/ossec/bin/wazuh-agentd`).
2. `audit_cwd == /var/ossec`.
3. Alguna ruta (`audit_file`, `audit_dir` o `syscheck_path`, resuelta contra `audit_cwd` si es
   relativa) casa el glob `/var/ossec/var/run/*`.

`motivo = auto_ruido:<proceso>` (nombre base de `audit_exe`, o `cwd=/var/ossec` / `ruta` si no
hay `exe`). La `evidencia` es el campo que decidió (`audit_exe=…`, `audit_cwd=…`, `audit_file=…`).

`auto_ruido` **no se mezcla** con `ruido_conocido` (así el ~54 % queda visible) y se reporta
aparte en los conteos. Si una señal `deteccion` apuntara a un proceso de Wazuh, se emite
**`CONFLICTO`** por `stderr` y **prevalece `auto_ruido`** (no se resuelve en silencio).

## 3.bis Predicado `OPERADOR` — paso 1.5 (H3, 2026-09-26)

> **Principio rector: solo se auto-excluye lo DEMOSTRABLE como propio. Lo que no se puede
> demostrar, se revisa (`dudosa`).** Es el lado seguro contra falsos negativos silenciosos.

Se aplica **después** de `auto_ruido` (1) y de las señales de **detección** (2), y **antes** de
`dudosa`/`sin_campos` (3). Predicado explícito, con condición **estrecha** y por `rule_id` concreto
(no por usuario ni por grupo genérico):

| `rule_id` | Grupo requerido | Condición de exclusión | Motivo | Fundamento |
|---|---|---|---|---|
| **`5715`** (`sshd: authentication success`) | `sshd`/`syslog`/`authentication_success` | **`srcip ∈ OPERADOR_SRCIPS`** | `operador:5715` | Es **nuestra** sesión (host del operador). **Demostrable** por la IP. SSH del atacante desde otra IP → **NO** se excluye. |
| **`19004`** (SCA summary) | `sca` | **sin** condición de origen: basta regla + grupo | `operador:19004` | Autoevaluación del HIDS, **inequívoca**; no es un login. |
| **`5501`** (`PAM: Login session opened`) | — | **NINGUNA → NO se auto-excluye** | `ruido_conocido` **o** `dudosa` (según el `esperado`; ver abajo) | El `full_log` **no trae IP ni id. de sesión**: la atribución al operador **no es demostrable**. **Cae a `dudosa`/`sin_campos` solo si** el `esperado` **no** declara ninguna señal de campo siempre evaluable; **si** declara `rule_id`/`rule_group`, `sin_campos` **no** dispara → cae al paso 6 → **`ruido_conocido`/`baseline`**. |
| **`5502`** (`PAM: Login session closed`) | — | **NINGUNA → NO se auto-excluye** | `ruido_conocido` **o** `dudosa` (ídem) | Ídem. |

- `OPERADOR_SRCIPS = {192.168.65.1}` (IP del **host/sobremesa en VMnet1**, confirmada con
  `ipconfig` en el paso 0 el 2026-09-26 y con `data.srcip` real de los `5715` del piloto).
- **Si falta el campo de origen (`srcip`)** → la condición **no** se satisface → `dudosa`.
- Al excluir: `categoria=ruido_conocido`, `motivo=operador:<rule_id>`, `revision=""`, y
  `evidencia` = el campo que lo demuestra (`srcip=…` / `rule_group=sca`).
- **Nunca** se excluye una alerta de estas reglas si **no** cumple su condición.

### Garantía anti-frágil (señal declarada sobre el predicado)

Si el `esperado` del ataque **declara una señal** cuyo `campo=rule_id` (o `rule_group`) **casara
una regla del predicado H3** (`5715`/`19004` y sus grupos), la herramienta emite **`CONFLICTO` por
`stderr`** y **prevalece la detección** — la señal de detección va en el paso 2, **antes** del 1.5.
Así una señal declarada **nunca** se excluye en silencio y queda aviso trazable.

### Limitación declarada (residual)

**`5501`/`5502` permanecen en revisión humana por diseño**: sin IP ni id. de sesión no se puede
demostrar la atribución (un atacante con credenciales válidas, T1078, usaría el mismo usuario). Su
resultado **no** depende del predicado `OPERADOR` (que no las exime), sino de si el `esperado` del
ataque declara **alguna** señal de campo siempre evaluable:

- **(a) `esperado` SIN ninguna señal de campo siempre evaluable** (p. ej. solo `audit_exe`/`audit_cwd`):
  ninguna señal casa y `sin_campos` dispara → `5501`/`5502` caen a **`dudosa`** (`revision=pendiente`)
  y las **resuelve el humano**. **Caso real: ATA012** (T1119; su `esperado` solo declara
  `audit_exe`/`audit_cwd`) → `5501`/`5502` **`dudosa` → `ruido`**.
- **(b) `esperado` CON `rule_id`/`rule_group`** (campo evaluable): `sin_campos` **no** dispara → la
  alerta sigue al paso 6 y sale **`ruido_conocido`/`baseline`**. **Casos reales: ATA002, ATA004**
  (declara `rule_id=5402`) **y ATA007** (declara `rule_id=80790`/`80781`).

> **El `baseline` de (b) NO lo produce el predicado `OPERADOR`** (que exime **solo** `5715` y `19004`):
> es un **efecto del orden de decisión** (el paso 1.5 no exime las PAM) combinado con que **otra**
> señal del `esperado` sí es evaluable. `5501`/`5502` **siguen sin auto-excluirse** (lado seguro):
> mientras el predicado no cambie, nunca se resuelven solas por el paso 1.5.

**No es un defecto, es el lado seguro.** En el piloto fueron **13 filas** `dudosa` (ATA008 iter1=2,
iter2=3, ATA013 iter1=6, iter2=2) → ≈2–6 por ventana, volumen asumible; en el piloto-custom: ATA012
iter1=2, iter2=2.

> **Nota de trazabilidad (plegado de revisión):** las filas `5715` que el humano resolvió a mano en
> el piloto ahora se auto-excluyen por el predicado y su `evidencia` cambia (`srcip=…`); su clave de
> plegado ya no coincide y el filtro emite `AVISO: revisión con clave no encontrada`. Es **inocuo**:
> el resultado final (`ruido_conocido`) es el mismo que el veredicto humano previo.

## 4. Señales esperadas — atribución (§2)

Fichero `ATA<NNN>_esperado.csv`, columnas:

```text
senal_id,tipo,campo,patron,dato_componente,tecnica,nota
```

- `tipo ∈ {deteccion, ambigua}`.
- `campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key, syscheck_path}`.
- `patron`: literal o glob `*` / `?` (fnmatch).
- `audit_exe`: se compara el valor completo **y** el nombre base (p. ej. `openssl` casa
  `/usr/bin/openssl`).
- `rule_group`: casa si **cualquier** grupo de la alerta (separados por `|`) casa el patrón.
- `dato_componente` y `tecnica` se copian a `atribucion` como `tecnica|dato_componente`.

`evidencia` = `campo=valor` de la señal que casó. **Sin fichero de señales la herramienta falla
ruidosamente** (`exit ≠ 0`, código 3); solo `--modo baseline` permite pasar una ventana sin
ataque.

> **Convención de señales (H4, 2026-09-26):** en una técnica que **escribe en la carpeta del
> ataque** (`/home/angel/lab-attack/ATA<NNN>/`), toda señal `audit_exe` se **acompaña** de una
> señal de contexto `audit_cwd=/home/angel/lab-attack/ATA<NNN>/*`. El `audit_cwd` **ancla** el
> proceso al ataque y discrimina el churn (`/`, `var/ossec`…). Ver
> `Soporte/Ataques/plantilla_esperado.md`. El **esquema** del esperado **no** cambia (cambia
> el contenido: una señal más).

## 5. Dudosas y revisión humana (§4)

- `dudosa` = señal **ambigua** que casa, **o** `sin_campos`: la alerta no tiene **ningún** campo
  evaluable para las señales declaradas.
- La herramienta marca `revision=pendiente` y emite `ATA<NNN>_iter{N}-Revision.csv` con las filas
  dudosas **+ columnas `veredicto, nota, revisor, fecha`**.
- El humano escribe `veredicto ∈ {deteccion, ruido}` (+ `nota`, `revisor`, `fecha`).
- Al re-ejecutar con `--revision <fichero>` los veredictos se **pliegan**:
  `revision=resuelta`, `veredicto_humano` ∈ {`deteccion`,`ruido`}, y la categoría pasa a
  `deteccion` (si `deteccion`) o `ruido_conocido` (si `ruido`). `revisor`, `fecha` y `nota` se
  anexan a `evidencia` (`;revisor=…;fecha=…;nota=…`) para no alterar las columnas fijas de §6.
- La clave de plegado es `(timestamp_utc, rule_id, agent_name, evidencia)`; una revisión cuya
  clave no aparezca en la ventana se avisa y se ignora.

## 6. Salida audited — columnas exactas (§5)

```text
ata_id, iter, timestamp_utc, agent_name, rule_id, rule_level, rule_groups, rs_origen,
rule_description, categoria, motivo, atribucion, revision, veredicto_humano, evidencia
```

- `rs_origen` se **copia sin alterar** del extractor (RS1..RS4/UNKNOWN): la herramienta **no**
  tiene lógica de RS (compatibilidad con RS3/RS4 cuando se pueblen).
- Cabecera `#` con rutas y `sha256` de las entradas + conteos, **sin reloj**. Orden estable por
  `(timestamp_utc, rule_id, evidencia)`. Misma entrada → salida **byte a byte** idéntica (R-13).

## 7. Modo `--modo baseline` (§2)

Ventana **sin ataque**: no exige señales. Clasifica `auto_ruido` y, para todo lo demás,
`ruido_conocido` (motivo `baseline`) — una novedad no puede contar como detección en una ventana
declarada sin ataque (plan §8-a). **No** sustituye al modo ataque.

## 8. Referencias

- Código: `_artefactos/scripts/filtrar_ruido.py` (constantes `WAZUH_PROCESOS`, `SIGNAL_CAMPOS`,
  `OUT_HEADER`, `OPERADOR_SRCIPS`, `OPERADOR_REGLAS`).
- Extractores: `_artefactos/scripts/extraer_alertas.py` (`--detail`, `--muestra`).
- Diseño de RuleSets: `Soporte/Wazuh/Configuracion/rulesets_diseno.md` §4.
- Baseline: `Dataset/Legitimo/baseline_meta.md` §9 y §14.5.
- Convención de señales (H4): `Soporte/Ataques/plantilla_esperado.md`.
- Criterio de doble iteración (H2): `Soporte/Ataques/criterio_doble_iteracion.md`.
