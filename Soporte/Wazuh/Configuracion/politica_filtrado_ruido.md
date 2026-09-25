---
fase: 3
tarea: A2.1 (T-11 · R-09/R-13)
nombre: Política de filtrado de ruido y etiquetado auditado de alertas
version: 1
status: implementada
fecha: 2026-09-25
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
  paso 0, 2026-09-25).
- **Catálogo baseline:** `Dataset/Legitimo/ruleids_legitimos.csv` (12 `rule.id`, 13.574 alertas).
- **Señales esperadas del ataque:** `Dataset/Ataques/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv`.
- **Salida:** `Dataset/Ataques/Resultados/Wazuh/Auditado/ATA<NNN>_iter{N}-Audited.csv`.
- **Revisión:** `Dataset/Ataques/Resultados/Wazuh/Auditado/ATA<NNN>_iter{N}-Revision.csv`
  (solo si hay filas dudosas).

## 2. Categorías y **orden exacto** de decisión (§2)

Una alerta recibe **una** categoría; **gana el primero que casa**:

1. **`auto_ruido`** — el origen es el propio Wazuh, **por campos** (no por `rule.id`) §3.
2. **`deteccion`** — casa una señal esperada de tipo `deteccion`.
3. **`dudosa`** — casa una señal esperada de tipo `ambigua`, **o** la alerta no permite evaluar
   **ninguna** señal (falta el campo; motivo `sin_campos`).
4. **`deteccion`** — `rule.id` **no** está en el catálogo (motivo `novel`).
5. **`ruido_conocido`** — `rule.id` **sí** está en el catálogo (motivo `baseline`).

`categoria ∈ {deteccion, ruido_conocido, auto_ruido, dudosa}`.

**Motivos:** `auto_ruido:<proceso>`, `senal:<senal_id>`, `ambigua:<senal_id>`, `sin_campos`,
`novel`, `baseline`.

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
  `OUT_HEADER`).
- Extractores: `_artefactos/scripts/extraer_alertas.py` (`--detail`, `--muestra`).
- Diseño de RuleSets: `Soporte/Wazuh/Configuracion/rulesets_diseno.md` §4.
- Baseline: `Dataset/Legitimo/baseline_meta.md` §9 y §14.5.
