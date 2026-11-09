---
fase: 3
tarea: A2.1 (T-11 · R-09/R-13) · A3.0 (H3/H4) · A3.0 (ancla implícita + evento de ejecución) · A3.0 (métrica + pertenencia al ataque) · A3.0 (rule_id 11 stats)
nombre: Política de filtrado de ruido y etiquetado auditado de alertas
version: 8
status: implementada
fecha: 2026-11-08
autor: tfg-executor
---

# Política de filtrado de ruido y etiquetado auditado

> Política **de la herramienta** `_artefactos/scripts/filtrar_ruido.py` (Fase 3 · A2.1).
> Este documento y el código deben coincidir **literalmente**: si se cambia uno, se cambia el
> otro. Referencia de decisión: `plan.md` (bloques `fase-03-filtro` §2–§5, `fase-03-senales` §2.2
> y `fase-03-metrica` §2–§3) y `Dataset/Legitimo/baseline_meta.md` §9.
>
> **v5 (`fase-03-metrica`, 2026-09-28):** se añade la categoría **`artefacto_ataque`** (la huella
> del propio ataque **nunca** cae en `ruido_conocido`), la **pertenencia al ataque por carpeta**
> (`ATTACK_ROOT = /home/angel/lab-attack/`, derivada del `--ata`), el **ancla por ruta** (mejora C),
> el **tercer veredicto humano `artefacto`** y el **guardarraíl de plegado**.
>
> **v6 (`fase-03-metrica` ciclo 2, 2026-09-28):** se **declara la limitación** de la pertenencia —
> es **mecánica** y cubre **solo** `ATTACK_ROOT/<ATA_id>`; una fila del ataque **fuera** de esa
> carpeta (el `mkdir` de ATA007 en `lab-legit`) se atribuye por el **veredicto humano** (`artefacto`)
> y **nunca** puede quedarse en `ruido` (§3.ter).
>
> **v7 (`fase-03-auditoria-metodologica`, 2026-10-01):** se añade a `auto_ruido` la **firma interna
> del manager** **`rule_id=11` ∧ grupo `stats`** (§3.d). Se coloca **al final** de
> `detectar_auto_ruido` para **no** alterar el `motivo`/`evidencia` de ninguna fila que ya casara los
> pasos anteriores (p. ej. ATA011_iter1 conserva `auto_ruido:ps`, `audit_cwd=/var/ossec`). Arregla el falso
> positivo de `ATA035_iter2` (detección `449 → 448`).

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

1. **`auto_ruido`** — el origen es el propio Wazuh, **por campos** (procesos, `cwd=/var/ossec`,
   rutas `/var/ossec/var/run/*`) **o** por la **firma interna del manager** `rule_id=11` ∧ grupo
   `stats` (§3; va al final, §3.d).
2. **`deteccion`** — casa una señal esperada de tipo `deteccion` **anclada** §2/§4: una señal
   `audit_exe` solo casa si `exe ∧ cwd-ancla/ruta ∧` **evento de ejecución** (`audit_command`).
3. **`ruido_conocido`** — **paso 1.5 (H3)**: casa el **predicado `OPERADOR`** §3.bis
   (motivo `operador:<rule_id>`). Va **después** de las señales de detección y **antes** de
   `dudosa`/`sin_campos`: si una señal `deteccion` casa la alerta, **gana la detección**.
4. **`dudosa`** — casa una señal esperada de tipo `ambigua` **o** casa un `audit_exe` de
   detección pero **falla el ancla / el evento de ejecución** (motivo `sin_ancla:<senal_id>`) **o**
   la alerta no permite evaluar **ninguna** señal (falta el campo; motivo `sin_campos`).
5. **`artefacto_ataque`** — **paso 3.5 (A3.0, §3)**: la fila es **DEL ATAQUE**
   (`audit_cwd` o ruta —`audit_file`/`audit_dir`/`syscheck_path` resuelta contra el `cwd`— bajo
   `ATTACK_ROOT/<ATA_id>`) y **no** casó una detección declarada (motivo `del_ataque`).
   **Nunca** cae en `ruido_conocido`.
6. **`deteccion`** — `rule.id` **no** está en el catálogo (motivo `novel`).
7. **`ruido_conocido`** — `rule.id` **sí** está en el catálogo (motivo `baseline`). Tras el
   arreglo, **solo** contiene filas que **no** son del ataque.

`categoria ∈ {deteccion, ruido_conocido, auto_ruido, dudosa, artefacto_ataque}`.

**Motivos:** `auto_ruido:<proceso>`, `senal:<senal_id>`, `operador:<rule_id>`,
`ambigua:<senal_id>`, `sin_ancla:<senal_id>`, `sin_campos`, `del_ataque`, `novel`, `baseline`.

> **Lo que no ancla NO se descarta** (§2.3 del plan): una fila que casa un `audit_exe` de
> detección pero falla el ancla o el evento de ejecución queda **`dudosa`** (`sin_ancla:*`,
> `revision=pendiente`) — **nunca** `deteccion` **ni** `ruido_conocido`. La resuelve el humano.

> **Aclaración (§3.4, v5):** el `sin_ancla` es `dudosa` **en la clasificación automática**. Si el
> humano pliega a `ruido`, la fila pasa a `ruido_conocido` **conservando el motivo** — y eso
> **solo** es legítimo si la fila **no** es del ataque. Sobre una fila del ataque, `ruido` está
> **prohibido** (§5); el humano elige `deteccion` o `artefacto`.

## 3. `auto_ruido` — categoría propia (§3)

Se detecta **por campos**, en este orden, y **nunca** cuenta como detección:

1. `basename(audit_exe)` ∈ `{wazuh-agentd, wazuh-syscheckd, wazuh-logcollector, wazuh-modulesd,
   wazuh-execd, wazuh-db, wazuh-analysisd}` (se compara el **nombre base**: en `alerts.json` el
   campo trae la ruta completa, p. ej. `/var/ossec/bin/wazuh-agentd`).
2. `audit_cwd == /var/ossec`.
3. Alguna ruta (`audit_file`, `audit_dir` o `syscheck_path`, resuelta contra `audit_cwd` si es
   relativa) casa el glob `/var/ossec/var/run/*`.
4. **Firma interna del manager (§3.d, v7):** `rule_id == 11` **∧** grupo `stats` → `auto_ruido`
   (`motivo=auto_ruido:stats`, `evidencia=rule_id=11`). Es el recuento periódico **interno** del
   propio Wazuh (grupo `stats`), **no** un proceso de la víctima. Se reconoce por la **firma de la
   regla** (`rule_id` + grupo), **nunca** por `agent_name` (todas las filas traen el mismo agente).
   Va **al final**: no cambia el `motivo`/`evidencia` de una fila que ya casara los pasos 1–3.

`motivo = auto_ruido:<proceso>` (nombre base de `audit_exe`, o `cwd=/var/ossec` / `ruta` si no
hay `exe`; `stats` en el paso 4). La `evidencia` es el campo que decidió (`audit_exe=…`,
`audit_cwd=…`, `audit_file=…`, `rule_id=11`).

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

## 3.ter Pertenencia al ataque y `artefacto_ataque` (A3.0 · v5)

> **Condición dura (rectora):** *nada que pueda ser del ataque se descarta; si no se demuestra
> ajeno, va a revisión.* Y, además: **la huella del propio ataque nunca se llama "ruido"**.

- **"Fila del ataque"** = fila cuyo `audit_cwd` **o** cuya ruta (`audit_file`, `audit_dir`,
  `syscheck_path`, resuelta contra el `cwd` si es relativa) cae **bajo**
  `ATTACK_ROOT/<ATA_id>` (constante `ATTACK_ROOT = "/home/angel/lab-attack/"`; el `<ATA_id>` se
  deriva del `--ata`, así **también** cubre a los 3 del piloto sin editar su `esperado`).
  Es una prueba **demostrable**: esa carpeta la crea y usa solo el ataque.
- **Paso 3.5:** una fila del ataque que **no** casó una señal `deteccion` declarada →
  **`artefacto_ataque`** (`motivo=del_ataque`). Es **determinista** → **no** requiere revisión
  humana. `evidencia` = el campo que demostró la pertenencia (`audit_cwd=…` / `audit_file=…`),
  para que un revisor lo compruebe desde el propio `-Audited.csv`.
- **`AVISO` por execve no declarado:** una fila `artefacto_ataque` con grupo `audit_command`
  (execve de un binario **no declarado** por el `esperado`) emite **`AVISO`** por `stderr`
  (*"posible señal de detección no declarada"*). Transparencia: no se oculta una detección.
- **No es un cepo:** las filas **ajenas** (fuera de la carpeta) **siguen** su curso normal
  (`ruido_conocido` por baseline, o `dudosa`→`ruido` por veredicto humano).
- **Limitación declarada — la pertenencia es mecánica (ciclo 2, v6):** la regla de pertenencia cubre
  **solo** `ATTACK_ROOT/<ATA_id>`. Una fila del ataque **fuera** de esa carpeta —**caso real: el
  `mkdir -p` del *setup* de ATA007 en `lab-legit`** (`80790` *Created: public_site.*)— **no** la
  cubre la regla automática: se atribuye **por el veredicto humano** (`artefacto`) y **nunca** puede
  quedarse en `ruido`.

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

### Ancla implícita + evento de ejecución (`fase-03-senales`, §2.2, 2026-09-28)

**Ancla de un `esperado`** = el conjunto de señales `tipo=deteccion, campo=audit_cwd` que declara.
Una señal `audit_cwd` de tipo `deteccion` es un **ancla**: es una **condición AND**, **no** un
detector por sí sola.

Si el `esperado` declara **≥1 ancla**, una señal `deteccion` con `campo=audit_exe` casa una fila
**solo si** se cumplen **las tres**:

1. el `audit_exe` casa el patrón (`full` **o** `basename`), **y**
2. el `audit_cwd` de la fila **o** una de sus rutas casa el ancla (el match prueba el `cwd` **y**
   `cwd + "/"`, de modo que el patrón `…/ATA<NNN>/*` casa el `cwd` real `…/ATA<NNN>`; **mejora C
   (v5):** prueba además `audit_file`/`audit_dir`/`syscheck_path` resueltos contra el `cwd`), **y**
3. la fila es un **evento de ejecución** (`rule_groups` contiene **`audit_command`**); en un
   evento `watch` (`audit_watch_*`) el `audit_exe` es el **causante de la escritura**, no "el
   proceso del ataque".

- Una fila que casa el `audit_exe` pero **falla** (2) o (3) → **`dudosa`** (motivo
  **`sin_ancla:<senal_id>`**, `revision=pendiente`). `evidencia` = el campo que falló
  (`audit_cwd=<cwd>` si falla (2); `audit_exe=<exe>` si falla (3)). **Nunca** `deteccion` **ni**
  `ruido_conocido`. Si la fila **además** casa una señal `ambigua` declarada, gana el motivo
  **`ambigua:<senal_id>`** (sigue siendo `dudosa`).
- **Sin ancla declarada** se mantiene el comportamiento **legado** (el `audit_exe` casa solo) y
  la herramienta emite un **`AVISO` por `stderr`** (no bloqueante) invitando a añadir el ancla.
- Las demás señales `deteccion` (`rule_id`, `rule_group`, `audit_key`, `syscheck_path`) **no**
  quedan condicionadas por el ancla.

## 5. Dudosas y revisión humana (§4)

- `dudosa` = señal **ambigua** que casa, **o** fila que casa un `audit_exe` de detección pero
  falla el ancla / el evento de ejecución (`sin_ancla:<senal_id>`), **o** `sin_campos`: la alerta
  no tiene **ningún** campo evaluable para las señales declaradas.
- La herramienta marca `revision=pendiente` y emite `ATA<NNN>_iter{N}-Revision.csv` con las filas
  dudosas **+ columnas `veredicto, nota, revisor, fecha`**.
- El humano escribe `veredicto ∈ {deteccion, ruido, artefacto}` (+ `nota`, `revisor`, `fecha`):
  - **`deteccion`** → `categoria=deteccion`, `revision=resuelta`, `veredicto_humano=deteccion`.
  - **`ruido`** → `categoria=ruido_conocido`, `revision=resuelta`, `veredicto_humano=ruido`.
    **Prohibido** sobre una fila **del ataque** (§3.ter): el guardarraíl hace **fallar** la
    herramienta (`exit != 0`, código 4) indicando la fila.
  - **`artefacto`** (tercer veredicto, v5) → `categoria=artefacto_ataque`,
    `revision=resuelta`, `veredicto_humano=artefacto`, `motivo=del_ataque`, `evidencia` = la
    ruta/campo que demuestra la pertenencia. Para "es el ataque, pero **no** cuenta como
    detección de la técnica" (p. ej. la escritura `watch` del `.tar.gz` que creó el ataque).
- Al re-ejecutar con `--revision <fichero>` los veredictos se **pliegan**. `revisor`, `fecha` y
  `nota` se anexan a `evidencia` (`;revisor=…;fecha=…;nota=…`) para no alterar las columnas fijas
  de §6.
- La clave de plegado es `(timestamp_utc, rule_id, agent_name, evidencia)`; una revisión cuya
  clave no aparezca en la ventana se avisa y se ignora.
- **El `--rev-out` no se reescribe** si no quedan `dudosa` sin resolver (así no se borran los
  veredictos ya escritos por el humano).

## 6. Salida audited — columnas exactas (§5)

```text
ata_id, iter, timestamp_utc, agent_name, rule_id, rule_level, rule_groups, rs_origen,
rule_description, categoria, motivo, atribucion, revision, veredicto_humano, evidencia
```

- `rs_origen` se **copia sin alterar** del extractor (RS1..RS4/UNKNOWN): la herramienta **no**
  tiene lógica de RS (compatibilidad con RS3/RS4 cuando se pueblen).
- Cabecera `#` con rutas y `sha256` de las entradas + conteos (`filas`, `deteccion`, `auto_ruido`,
  `ruido_conocido`, `dudosa`, `artefacto_ataque`), **sin reloj**. Orden estable por
  `(timestamp_utc, rule_id, evidencia)`. Misma entrada → salida **byte a byte** idéntica (R-13).
- `OUT_HEADER` **no cambia** (15 columnas): la categoría nueva viaja en `categoria`.

## 7. Modo `--modo baseline` (§2)

Ventana **sin ataque**: no exige señales. Clasifica `auto_ruido` y, para todo lo demás,
`ruido_conocido` (motivo `baseline`) — una novedad no puede contar como detección en una ventana
declarada sin ataque (plan §8-a). **No** sustituye al modo ataque.

## 8. Referencias

- Código: `_artefactos/scripts/filtrar_ruido.py` (constantes `WAZUH_PROCESOS`, `SIGNAL_CAMPOS`,
  `OUT_HEADER`, `OPERADOR_SRCIPS`, `OPERADOR_REGLAS`, `AUDIT_CMD_GROUP`, `CATEGORIAS`,
  `ATTACK_ROOT`).
- Métrica y pertenencia: `plan.md` bloque `fase-03-metrica` §2–§3; `Soporte/Ataques/
  criterio_doble_iteracion.md`.
- Extractores: `_artefactos/scripts/extraer_alertas.py` (`--detail`, `--muestra`).
- Diseño de RuleSets: `Soporte/Wazuh/Configuracion/rulesets_diseno.md` §4.
- Baseline: `Dataset/Legitimo/baseline_meta.md` §9 y §14.5.
- Convención de señales (H4): `Soporte/Ataques/plantilla_esperado.md`.
- Criterio de doble iteración (H2): `Soporte/Ataques/criterio_doble_iteracion.md`.

---

## 9. Perfil Windows — `filtrar_ruido_windows.py` (v8, aditivo, B1.0)

> **Aplica a Windows; Linux no cambia.** Se mantienen **las mismas categorías y el mismo orden
> de decisión** de §2. Cambian los **datos** (campos, raíz y catálogo). El perfil Linux sigue
> usando `filtrar_ruido.py` sin modificaciones.

### 9.1 Diferencias de datos

| Elemento | Linux | Windows |
|---|---|---|
| Script | `filtrar_ruido.py` | `filtrar_ruido_windows.py` |
| `ATTACK_ROOT` | `/home/angel/lab-attack/` | `C:\lab-attack\` |
| Campos de señal | `audit_exe`, `audit_cwd`, `audit_key`, `syscheck_path`, `rule_id`, `rule_group` | `win_image`, `win_command_line`, `win_cwd`, `win_target`, `syscheck_path`, `rule_id`, `rule_group` |
| Evento de ejecución | grupo `audit_command` (execve) | `event_id ∈ {1, 4688}` (Sysmon 1 o Seguridad 4688) |
| Catálogo | `Dataset/Legitimo/ruleids_legitimos.csv` | `Dataset/Legitimo/windows/ruleids_legitimos.csv` (v1+v2) |
| `auto_ruido` | procesos `wazuh-*`, `cwd=/var/ossec`, `rule_id=11 ∧ stats` | **solo la imagen del servicio del canal** (`sshd.exe`) → `auto_ruido:canal-ssh`; nunca sus hijos (§9.6) |
| Predicado `OPERADOR` | `5715` por `srcip` + `19004/sca` | **`OPERADOR_WIN`** por `rule_id` + usuario/logon (§9.6); la IP del `4624` de SSH **no existe** en este laboratorio (declarado) |

### 9.2 Ancla H4-W

Una señal `tipo=deteccion, campo=win_image` cuenta como `deteccion` **solo si**:

1. casa la **imagen** (`win_image`, ruta completa o nombre base; glob case-insensitive); **y**
2. casa **al menos un ancla** — `win_cwd`, `win_command_line`, `win_target` o
   `syscheck_path` — con `C:\lab-attack\ATA<NNN>`; **y**
3. la fila es un **evento de ejecución** (`event_id` 1 o 4688; fallback por grupo
   `sysmon_eid1`/`sysmon_event1` o `rule_id=67027`).

Lo que casa la imagen y falla el ancla/evento → **`dudosa`** (`motivo=sin_ancla:<senal_id>`),
**nunca** `deteccion` ni `ruido_conocido`. Si el `esperado` no declara `win_image`, una señal
`win_command_line` puede detectar por sí sola (legado) y se emite **`AVISO`**.

### 9.3 Pertenencia al ataque (Windows)

La carpeta `C:\lab-attack\ATA<NNN>\` es la prueba demostrable. Se comprueba en `win_cwd`,
`win_command_line`, `win_target` y `syscheck_path` (normalizados a `\` y minúsculas). Una fila
del ataque que no case una detección declarada cae en **`artefacto_ataque`** (`motivo=del_ataque`),
**nunca** en `ruido_conocido` **ni** `auto_ruido`. El guardarraíl de plegado (`veredicto=ruido`
prohibido sobre una fila del ataque) se mantiene idéntico.

> **Candado (G-SSH.1, B1.0-SSH.1).** La pertenencia se evalúa **antes** que `auto_ruido` y que
> `OPERADOR_WIN`: una fila con evidencia de ataque **nunca** puede caer en `auto_ruido` ni en
> `ruido_conocido` (o casa una detección declarada, o es `artefacto_ataque`; lo dudoso sigue
> yendo a `dudosa`). Para las filas **sin** evidencia de ataque se mantiene el orden Linux.

### 9.4 Salida y determinismo

- **Mismas 15 columnas** que Linux (§6). `OUT_HEADER` no cambia.
- Cabecera `#` con rutas y `sha256` de las entradas + conteos, sin reloj.
- Orden estable `(timestamp_utc, rule_id, evidencia)`; LF; UTF-8 sin BOM.
- Defaults Windows: `Dataset/Ataques/Resultados/Wazuh/windows/Auditado` y
  `Dataset/Ataques/Comandos/windows`.

### 9.5 Replay de la baseline Windows (CA-B1-08)

`filtrar_ruido_windows.py --replay-baseline` ejecuta:

| Ventana | Fichero | Catálogo | Esperado |
|---|---|---|---|
| v1 | `Dataset/Legitimo/windows/baseline_detalle_v1.csv` (72) | `ruleids_legitimos_v1.csv` | **0 `deteccion`** |
| v2 | `Dataset/Legitimo/windows/baseline_detalle_v2.csv` (87) | `ruleids_legitimos.csv` (v1+v2) | **0 `deteccion`** |

Mezclar el catálogo de una ventana con la otra **no** es prueba válida.

### 9.6 Predicado `OPERADOR_WIN` y `auto_ruido` de canal (B1.0-SSH.1)

> **Evidencia:** `Soporte/Ataques/c0/windows/canal_ssh.csv` (45 filas del dry run SSH del
> 2026-11-08) y `Soporte/Laboratorio/windows/ataques/B1.0-SSH.md`. Se **ratifica con la
> evidencia**, no se supone: el `4624` de SSH **no trae `ipAddress`** (`Source Network
> Address: -`), así que la atribución es por **usuario + regla + `logon_type`**.

- **`auto_ruido` del canal**: solo `win_image` con **nombre base `sshd.exe`** →
  `auto_ruido:canal-ssh`. **Nunca** sus hijos (`cmd.exe`, `powershell.exe`…): el ataque corre
  dentro de esa sesión y se atribuye por `C:\lab-attack\ATA<NNN>`.
- **`OPERADOR_WIN`** (paso 1.5, después de `auto_ruido` y de la detección, antes de `dudosa`):

| `rule_id` | `event_id` | Condición | Motivo | Fundamento |
|---|---|---|---|---|
| `60106` | 4624 | `win_target_user = angel` **∧** `logon_type = 3` | `operador:60106` | logon de **red** de la sesión SSH |
| `60137` | 4634 | `win_target_user = angel` **∧** `logon_type = 3` | `operador:60137` | logoff de la sesión SSH |
| `67024` | 4624 | `win_user ~ ^sshd_\d+$` | `operador:67024` | logon de **servicio** (cuenta virtual de sshd) |
| `67023` | 4634 | `win_user ~ ^sshd_\d+$` | `operador:67023` | logoff de la cuenta virtual |
| `67028` | 4672 | `win_user = angel` **∨** `win_user ~ ^sshd_\d+$` | `operador:67028` | privilegios especiales |
| `67022` | 4624 | `srcip = 192.168.65.1` | `operador:67022` | regla del plan; **no demuestra nada** (en SSH y en `vmrun` el `srcip` está vacío) |
| `67023` | 4634 | `srcip = 192.168.65.1` | `operador:67023` | ídem |

- **Lado seguro:** si falta el campo que demuestra la condición (`logon_type`, usuario, IP)
  → **no se excluye** (cae a `deteccion`/`dudosa`).
- **`win_user` vs `win_target_user`:** en `4624/4634/4688` el `win_user` normalizado es la
  cuenta *subject* (equipo/SYSTEM); el usuario efectivo es `targetUserName`
  (columna aditiva `win_target_user`). El predicado usa el **efectivo**.
- **Anti-frágil:** una señal `deteccion` que declare una regla del predicado emite
  `CONFLICTO` y **prevalece la detección** (la detección va antes).
- **Sensibilidad obligatoria (`--sin-operador`):** desactiva **solo** `OPERADOR_WIN` (no
  `auto_ruido`). En el canal medido: **0 `deteccion` con predicado** vs **30 sin él**.
- **El catálogo v1 no cambia** (4 reglas); el canal es una capa aparte.

> **Fallback `vmrun`: NO está listo (limitación declarada).** El `4624/4634` real de
> `vmrun` es **tipo 4 y con `srcip` vacío** (`c0_detalle.csv`: **147 + 147** filas), así que
> `67022/67023` por `srcip=192.168.65.1` **no exime ninguna fila**; además **`vmtoolsd.exe`
> no está en `auto_ruido`**. Si hubiera que usar `vmrun`, habría que **implementar y medir**
> su predicado (por usuario/regla) **antes** de medir ataques. **No se presenta como fallback
> listo**; la vía canónica es SSH.

### 9.7 Puntos ciegos declarados (C0 Windows, B1.0)

- **Sysmon 3** (conexión de red): el evento se genera, pero la regla base es nivel 0 y no
  alerta para conexiones genéricas (solo reglas específicas). Se declara punto ciego.
- **Sysmon 23** (FileDelete archivado): **no se genera** con la config Sysmon actual.
- **7036** (cambio de estado de servicio): **0 eventos** locales tras stop/start de Spooler;
  no hay alerta.
- **4698/106** (tarea programada creada): **no se generan** con la política de auditoría
  actual; el caso T1029 se apoya en `4688`/Sysmon 1 (`schtasks.exe`).
- **FIM de registro**: no es realtime; requiere `agent_control -r -u 002` (barrido forzado).
- **Huella del canal**: la del `vmrun` (`67022/67023/67028`, tipo 4) **no** es la de SSH;
  la de SSH es `60106/60137/67024/67023/67028` (tipo 3/5) y está resuelta en §9.6.
  **El `4624` de SSH no trae IP** (declarado; el predicado no depende de ella).

### 9.7.1 Sensibilidad `--fim-como-deteccion` (B2.0, NO canónica)

- **Qué hace**: con `--fim-como-deteccion`, las filas FIM de fichero (`550` modificado,
  `553` borrado, `554` añadido) cuyo `syscheck_path`/`win_target` cae bajo
  `C:\lab-attack\ATA<NNN>` pasan a `categoria=deteccion` (`motivo=fim_como_deteccion`) y se
  escriben en `Auditado_fim/` (paralelo). **Sin el flag, la salida es byte a byte idéntica a
  B1** (verificado con `ATA056_iter1-Audited.csv`).
- **Por qué no es canónica**: contar la huella del propio ataque como detección infla el plano
  de alerta; la categoría `artefacto_ataque` existe para no hacerlo. La canónica sigue siendo
  **sin** FIM-como-detección.
- **Implementación**: `FIM_RULES={550,553,554}`; el check se evalúa antes de las señales en el
  bloque de pertenencia. Cabecera con `fim_como_deteccion=on` solo con el flag.
- **Tests**: `test_filtrar_ruido_windows.py::test_fim_como_deteccion` (sin flag -> `dudosa`/
  `ambigua`; con flag -> `deteccion`/`fim_como_deteccion`).
- **Predicción H-B2-1**: a `N=7`, los casos con borrado (`553`, nivel 7) suben; los de
  creación/modificación (`554`/`550`, nivel 5) no. Se mide en B2.5.

### 9.8 Referencias

- Código: `_artefactos/scripts/filtrar_ruido_windows.py`.
- Plantilla v5 (H4-W): `Soporte/Ataques/plantilla_esperado.md` §7.
- C0: `Soporte/Ataques/c0/windows/clases_evento.csv`.
- Extractores: `_artefactos/scripts/extraer_alertas_windows.py`.
