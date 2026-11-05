# incidencias.md — ventana `legitimo-v3` (2026-11-02 → 2026-11-05)

> Registro corrido de lo observado **leyendo el host**. No se ha tocado la víctima dentro de `[t0,t1]`.

| Hora (UTC) | Señal | Observación | Veredicto |
|---|---|---|---|
| 2026-11-02T00:00:03Z | vigilancia | Primer chequeo: `OK`, `bloque=fuera`, `hb=2s`, `df=4.4G`, `dia=-1B` (sin muestra previa), `wu=Stopped/Disabled`. | Normal (primer chequeo) |
| 2026-11-02T08:00:02Z | vigilancia | `OK` con `notas=gracia_borde(0m del bloque)`. | **H1 funcionando**: sin falsa alarma en el borde |
| 2026-11-02T09:30:07Z | vigilancia | `OK`, `reps=si`: el `watch` **repausó Windows Update**. | **H-6 mitigado** en producción |
| 2026-11-03T00:00:04Z | vigilancia | **`AVISO`** `arch=-246027119B`, `df=n/a`, `notas=sin_df`. Es la **rotación de medianoche** (archivos diarios a las 00:04Z): el delta sale negativo y la señal de disco pierde la muestra. | **Transitorio esperado**; se recupera solo |
| 2026-11-03T00:30:16Z | vigilancia | **`AVISO`** `df=n/a`, `notas=sin_df` (aún sin muestra tras la rotación). | **Transitorio**; a las 01:00Z ya vuelve `OK` |
| 2026-11-03T08:00:13Z | vigilancia | `OK` con `gracia_borde`; día 2 arranca con actividad (`doing_age=7m` a las 08:30Z). | Normal |
| 2026-11-03T07:00:08Z / 08:00:13Z | vigilancia | `reps=si` (segunda y tercera repausa de WU por el `watch`). | Normal (H-6) |
| 2026-11-04T16:59Z | host | **`TFG-Legit-Stop` desactivada** (no borrada) por el orquestador, para eliminar la carrera de 3 min entre la cosecha (`t1+2`) y la parada automática (`t1+5`). **No toca la víctima ni la medida**: la ventana termina en `t1`. La parada se hizo **a mano** tras verificar la cosecha. **Nota (05/11):** al cerrar, las **4 tareas `TFG-Legit-*` se desregistraron** (estado final: 0 tareas). | **Decisión operativa declarada** |

## Notas
- **0 huecos** > 31 min entre chequeos (68 chequeos hasta 2026-11-03T09:30Z).
- **0 `ALARMA`** en la ventana.
- Agente `001`: latido 1–20 s (umbral de alarma: 10 min).
- Host **sin reinicio** desde 2026-10-29T20:25Z (antes de `t0`).
- Disco de la víctima estable en **4,4 GB**; host ~172 GB.
- El **AVISO de `sin_df` en la rotación de medianoche** se repetirá cada noche (00:00Z y quizá 00:30Z): **declarado**, no es un fallo del banco.

## Corrección del filtrado de alertas (post-cosecha, 2026-11-05)

> Corrección **posterior a `t1`**, sobre los productos ya extraídos. **No** se ha vuelto a
> tocar la víctima ni el manager: solo se ha recortado el CSV de alertas y se han
> recalculado sus derivados.

### Qué estaba mal

`extraer_alertas.py --detail` vuelca **todas** las alertas de los diarios, sin separar por
agente. El `alertas_detalle.csv` original tenía **297.477** filas, pero **3.224** eran del
**manager** (`agent_name=wazuh-server`, agente `000`): sesiones PAM/SSH y `sudo` del
operador al entrar al manager durante la ventana (reglas `5402`, `5501`, `5502`, `5715`).
**No pertenecen al endpoint medido** (`victima-linux`, agente `001`) y contaminaban el
catálogo de ruido legítimo con actividad del propio banco, no de la víctima.

### Filtro aplicado

- `agent_name == victima-linux`, **y**
- `timestamp_utc` en `[2026-11-02T00:00:00Z, 2026-11-05T00:00:00Z]` (**ambos inclusive**),
  comparado **en UTC** (sin conversión a hora local).

Herramienta: `_artefactos/scripts/filtrar_ventana_alertas.py` (nueva; filtro + recálculo del
catálogo por `rule_id`, con tests en `_artefactos/scripts/tests/test_filtrar_ventana_alertas.py`).

```bash
python _artefactos/scripts/filtrar_ventana_alertas.py \
  --in  D:/TFG-VMs/legitimo-2026-11-02/alertas_detalle_sin_filtrar.csv \
  --out Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/alertas_detalle.csv \
  --ruleids-out Soporte/Laboratorio/legitimo_72h/ventana_2026-11-02/ruleids_legitimos.csv \
  --agente victima-linux \
  --desde 2026-11-02T00:00:00Z --hasta 2026-11-05T00:00:00Z
```

| Concepto | Valor |
|---|---|
| Filas de entrada | **297.477** |
| Filas de salida (`victima-linux`) | **294.253** |
| Descartadas por agente (`wazuh-server`) | **3.224** |
| Descartadas por ventana | **0** |
| `rule_id` distintos (antes → después) | **15 → 11** |
| Primer `timestamp_utc` | `2026-11-02T00:00:04.676Z` |
| Último `timestamp_utc` | `2026-11-04T23:59:56.971Z` |

**Integridad:** las 294.253 filas conservadas son **byte a byte idénticas** a las filas
`victima-linux` del original, en el **mismo orden**, con la **misma cabecera**. Solo se ha
añadido una **segunda línea `#`** que declara el filtro y sus recuentos (la cabecera
original se conserva como procedencia de la extracción).

**Copia del original (fuera del repo):**
`D:/TFG-VMs/legitimo-2026-11-02/alertas_detalle_sin_filtrar.csv`
(`sha256 4285145f45c3b21c21f1f3b757b2310a716ce2278f7d809dd8f776f893696adf`, idéntico al
`alertas_detalle.csv` anterior al recorte).

`sha256` de los productos corregidos: `alertas_detalle.csv`
`cc6af47e8bb4442d792c5121c6c2db34ac78c3c2a69963a35a8fdd24e9a07ec5` ·
`ruleids_legitimos.csv` `399c4b06a8c799fc2e0de4f060ede51996381efb6d8f3c7d23f104cf8a2ceb65` ·
`campana_fp.csv` `f41ea4ee9bcf9acbdd8ad4bc2d5c8ffbc0d2828dec872a6efc01ff68fc579d20`.

### Sobre la hora: `00:59:56` era hora **local**, no UTC

El CSV **no** contiene ninguna fila con `timestamp_utc >= 2026-11-05T00:00:00Z` (**0 filas
fuera de ventana**). La última fila es `2026-11-04T23:59:56.971Z`, que en
**Europe/Madrid** (CET, `+01:00` en noviembre) se lee como **`2026-11-05T00:59:56`** —
exactamente la cifra que se había interpretado como UTC. No hay una hora de más en el CSV.

El corte `--hasta` **sí actuó**: la cabecera del extractor declara `leidas=299523
en_ventana=297477` (2.046 líneas descartadas por caer fuera de `[t0,t1]`). Esa hora
posterior a `t1` existe en el **volcado de entrada** (`/tmp/alertas_ventana.jsonl` y el
diario del manager, que sigue creciendo hasta apagar `logall_json` en `t1+60`), no en el
producto entregado. Comprobación: la copia local de `ossec-archive-05.json` usada por el
denominador (`D:/TFG-VMs/legitimo-2026-11-02/denominador/`) contiene 2.550 eventos entre
`2026-11-05T00:00:02.995Z` y `2026-11-05T00:09:36.908Z`, **todos** posteriores a `t1`.

### Efecto en `ruleids_legitimos.csv`

Recalculado **desde el CSV filtrado**, mismo esquema
(`rule_id,rule_level,rule_description,groups,count,first_seen,last_seen,rs_origen`).
**Desaparecen 4 `rule_id`**, los cuatro al **100 % del manager**: `5402`, `5501`, `5502`,
`5715`. Los 11 restantes conservan **recuento, `first_seen` y `last_seen`** idénticos; la
suma de `count` es **294.253** (= filas del CSV filtrado).

- **Diferencia declarada (cosmética):** `80792` cambia la `rule_description` de ejemplo de
  `/usr/bin/date.` a `/usr/bin/bash.` porque esa descripción es **por alerta** (incluye el
  comando) y ahora la "primera aparición" se toma en el **orden del CSV** (que ordena por
  `timestamp, rule_id, exe, …`), no en el orden del JSONL crudo. `count`, `first_seen`,
  `last_seen`, `level` y `groups` **no cambian**.
- **`rule 11` se conserva:** es una alerta interna de estadísticas, pero la emite el
  agente `victima-linux` (1 alerta), **no** el manager. Su tratamiento como auto-ruido
  corresponde al filtro de la métrica, no a este recorte por agente.

### Efecto en `campana_fp.csv`

Rehecha con el CSV filtrado y el mismo comando/insumos
(`extraer_campana.py --ventanas campana/campana_ventanas.tsv --archives
D:/TFG-VMs/legitimo-2026-11-02/denominador/ossec-archive-0{2,3,4}.json.gz
…/ossec-archive-05.json --alertas <filtrado> --out campana_fp.csv`).
Resultado **byte a byte idéntico** al anterior (`sha256
f41ea4ee9bcf9acbdd8ad4bc2d5c8ffbc0d2828dec872a6efc01ff68fc579d20`): **11/11 `SI`**,
mismos recuentos. Es esperable: `extraer_campana.py` ya filtraba por
`agent_name == victima-linux` y las marcas de la campaña caen dentro de `[t0,t1]`.

### Verificación

| Comprobación | Resultado |
|---|---|
| Total filtrado | **294.253** |
| `rule_id` distintos | **11** |
| Primer / último `timestamp_utc` | `2026-11-02T00:00:04.676Z` / `2026-11-04T23:59:56.971Z` |
| Filas de `wazuh-server` | **0** |
| Filas fuera de `[t0,t1]` | **0** |
| Filas conservadas idénticas al original | **294.253 / 294.253** |
| `pytest` | **341 passed** |

## Orden de extracción invertido (V6) — declarado el 2026-11-05

> Detectado al cerrar. **No invalida** la ventana: §9.2 del plan (“fallo de la herramienta de
> extracción con **fuente íntegra** ⇒ se re-extrae”). El veredicto literal está en
> `veredicto_validez.md` (§V6).

| Hora (UTC) | Hecho | Fuente |
|---|---|---|
| `2026-11-05T00:08:22Z` | `cosecha.done` (43 ficheros + `MANIFEST.tsv`) | `evidencia/cosecha.done` |
| `00:09:16Z` | Arranca el `cleanup`; `logall_json off` a las **00:12:15Z** (el `off` **borra** `archives.json`) | `legitimo_host_control.log` |
| `00:12:17Z` | `CONFIG_IDENTICA` (`ossec.conf == ossec.conf.tfg-bak`) | ídem |
| ~`00:15Z` | Copia del denominador cerrada en `D:\TFG-VMs\legitimo-2026-11-02\denominador\` | `MANIFEST.tsv` (`mtime`) |

- **Qué se perdió:** el fichero **vivo** (`archives.json`). Su contenido era **solo posterior a
  `t1`** (2.550 eventos entre `2026-11-05T00:00:02.995Z` y `00:09:36.908Z`) ⇒ **0 eventos en la
  ventana**.
- **Qué estaba intacto:** los **3 diarios** `.gz` (rotados a las 00:00Z), con el **100 %** de
  `[t0,t1]`.
- **Qué se hizo:** re-extraer `M` desde la copia con `--estricto` → **`exit 0`**, **342.966**
  endpoint, `sha256` de entrada idénticos al `MANIFEST`.
- **Lo que no se puede reconstruir:** la secuencia exacta de las dos copias (manager→`/tmp` y
  `scp`→`D:`); la sesión manual no quedó en `legitimo_host_control.log`. Se declara.
