---
fase: 3
bloque: fase-03-piloto
tarea: T-09 / T-10 / T-11 (F-03 · R-07/R-09/R-11/R-13) · incluye A2.4 (cronómetro t0/t1)
nombre: Piloto de ataques — primer ciclo completo por ataque (3 técnicas, Linux)
version: 2
status: approved_by_human
fecha: 2026-09-25
fecha_aprobacion: 2026-09-25
aprobado_por: humano
autor: tfg-planner
gate: humano — (a) plan **aprobado ✔** (2026-09-25); (b) **los 3 `ATA<NNN>_esperado.csv` validados por el humano ✔ el 2026-09-25** (registro en este `plan.md` y en el comentario de cabecera de cada CSV)
---

# Plan — Bloque `fase-03-piloto`: primer ciclo completo de ataque (T-09/T-10/T-11)

> **Objetivo del bloque:** ejecutar **ataques de verdad** con **2-3 técnicas** y demostrar, de
> punta a punta, que la maquinaria funciona junta (`lab-listo` → t0 → copia → ataque → t1 →
> espera → extracción del **fichero diario** → filtrado → etiquetado → fila + ficha + bitácora +
> **doble iteración**), **descubriendo los enganchones con poco riesgo**. **No** busca resultados
> definitivos ni cobertura: eso es el escalado. KISS: 8/10 hecho > 10/10 sin hacer.

## 0. Objetivo y alcance

- **Entra:** las **3 técnicas** elegidas (§1), su artefacto ejecutable + README (R-13), los
  `ATA<NNN>_esperado.csv`, el ciclo real (6 ventanas = 3 técnicas × 2 iteraciones), el cronómetro
  t0/t1 (A2.4), la ficha por ataque, la bitácora, las filas de `Hojas/ATA_index.csv` de esas 3
  técnicas y el **procedimiento** reutilizable para el escalado.
- **NO entra:** las otras **10 técnicas** del corpus (`Hojas/ATA_index.csv`: **no se tocan sus
  filas**), Windows, η/precio de la detección (Fase 4), escribir reglas **RS3/RS4** (§10: **no** en
  el piloto), `Hojas/Detecciones.xlsx` / `BBDD/wazuh.db` (T-12), instalar nada en la víctima.

## 1. Decisión 1 — Qué 3 técnicas y por qué

Criterio: (i) estar entre las **7 con prueba de Linux** (`Hojas/cobertura_atomic.csv`); (ii) tocar
**tácticas distintas** (Impact / Exfiltration / Collection); (iii) **sin dependencias nuevas** (ver
§2); (iv) reversibles con el revert a `lab-listo`; (v) alineadas con el foco R/E/S del profesor.

| ATA | Táctica | Técnica | Prueba ART usada (GUID) | Dependencia | Elevación | Dónde escribe |
|---|---|---|---|---|---|---|
| **ATA002** | Impact | **T1485** Data Destruction | `atomics/T1485` → *FreeBSD/macOS/Linux - Overwrite file with DD* (`38deee99…`) | `dd` (coreutils) | no | crea y sobrescribe `/etc/tfg_lab_scratch_dd.txt` |
| **ATA008** | Exfiltration | **T1048** Exfil. Over Alternative Protocol | `atomics/T1048.002` → *Exfiltrate data in a file over HTTPS using wget* (`7ccdfcfa…`) | `wget` (o `curl`/`python3`) | no | `POST` a un receptor HTTP en el **host/sobremesa** (VMnet1) |
| **ATA013** | Collection | **T1560** Archive Collected Data | `atomics/T1560.002` → *Compressing data using GZip in Python* (`391f5298…`) | `python3` (stdlib) | no | `/home/angel/lab-attack/ATA013/passwd.gz` |

**Por qué estas y no otras** (declarado, para la memoria):
- **Impact:** se prefiere `T1485` a `T1489` (*Service Stop*) porque este último exige `sudo`
  (`systemctl stop cron`), y **el propio `sudo`** añade ruido `RS1` conocido (5402/5501/5502) que
  confunde la atribución. `T1485` con `dd` no necesita elevación. *(Nota: la atómica trae como
  destino por defecto `/var/log/syslog`; **se parametriza** a un fichero de prueba.*)
- **Exfiltration:** `T1567` (rclone/webhooks) exige **internet**; `T1048` es la única familia
  factible **sin NAT**, exfiltrando al **host/sobremesa** (el otro extremo del laboratorio, **fuera de
  las dos VMs**) por HTTP en `VMnet1`. El receptor vive en el **host, NO en el manager**: el manager es
  el **detector** y no debe ejecutar nada durante el ataque (§3).
- **Collection:** `T1074.001` descarga de GitHub (**internet**); `T1560.002` archiva con la
  **stdlib de Python** (sin dependencias) y es la vía barata.

## 2. Decisión 2 — Dependencias de las pruebas ⚠️ (decisión crítica)

**Decisión: (a) elegir pruebas SIN dependencias nuevas y NO instalar nada en la víctima.**
`lab-listo` se mantiene **prístino**.

- **Justificación:** `lab-listo` es la imagen sobre la que se grabó el **baseline de Fase 2**
  (12 `rule.id`, 13.574 alertas). Instalar paquetes (`apt`) añade `execve` de `dpkg`/`apt`, nuevos
  ficheros y posiblemente **`rule.id` nuevos** → **contaminaría el catálogo de ruido** y obligaría a
  **repetir las 2×4 h** de baseline. Además rompería la regla "mantener `lab-listo` prístino"
  (`atomic_red_team.md` §2).
- **Impacto:** se renuncia, **en el piloto**, a las atómicas con `gpg`/`ccrypt`/`7z`/`openssl`
  (p. ej. `T1486`). No es una pérdida: el corpus se escala en el bloque siguiente, y ahí se
  decidirá con datos si merece la pena instalar (y re-baselinar) o usar alternativa.
- **Cómo se garantiza:** **paso 0** comprueba con `which`/`python3 -c` en la víctima que existen
  `dd`, `python3` (con `gzip`/`tarfile`) y `wget` (o `curl`). **No se instala nada.** Si faltara la
  herramienta de exfiltración, se usa el **equivalente `python3` (stdlib `urllib`)** para la **misma**
  técnica `T1048` (sustitución de herramienta, no de técnica); se documenta en el README.
- **Riesgo declarado:** con `apt` **NO se toca la víctima**. Si el humano quisiera una atómica con
  dependencia, sería otro bloque (instalar + **repetir baseline**), no este.
- **Contraseña de sudo:** la facilita el orquestador **en el momento de ejecutar** y se usa **solo en
  memoria** (`sudo -S` por stdin) para leer `/var/ossec` y para `agent_control` en el manager.
  **Jamás** se escribe en el repo, ni en scripts, ni en la documentación (ahí: "la contraseña del
  laboratorio"). Los 3 ataques corren como `angel` **sin sudo** → ningún artefacto contiene secretos.

## 3. Decisión 3 — El ciclo por ataque, concreto y ejecutable

Se repite **3 técnicas × 2 iteraciones = 6 ventanas**. Numeración `iter ∈ {1,2}`. Para **cada**
ventana, en el **sobremesa** (host), con las VMs encendidas:
**Receptor de exfiltración (solo ATA008) — en el HOST (sobremesa, Windows), NO en el manager:** el
manager es el **detector** y **no debe ejecutar nada** durante el ataque; el receptor vive **fuera de
las dos VMs**. Se arranca un HTTP efímero **en el sobremesa**, escuchando en la **IP del host en
`VMnet1`** (normalmente `192.168.65.1`, se fija en el paso 0 §12), con el script
`Soporte/Ataques/receiver/sink_http.py` (stdlib; registra método/ruta/sha256 del cuerpo y responde
`200`, para que el `POST` de la víctima tenga éxito). **Log = evidencia:** `sink.log` en
`…/Logs/ATA008_iterN/` (una línea por `POST`; prueba primaria de que el dato salió). Se arranca
**antes de `t0`** y se para **tras `t1`**. Fallback cero-dependencias (documentado en el README):
`python -m http.server 9090 --bind <IP_host_VMnet1>` (registra el `POST` aunque responda `501`).

```
 0. Precondiciones: manager activo (wazuh-manager/indexer/dashboard) y agente 001 Active;
    NAT desconectado; relojes víctima↔manager alineados (|Δ| < 1 s, `date -u`).
    (Solo ATA008) receptor en el **HOST** listo: **IP del host en `VMnet1`** fijada (`192.168.65.0/24`,
    normalmente `192.168.65.1`) y **puerto 9090/tcp alcanzable** desde la víctima (regla de entrada del
    firewall de Windows; ver §12 paso 0).
 1. `vmrun -T ws stop  <victima> soft` → `vmrun -T ws revertToSnapshot <victima> lab-listo`
    → `vmrun -T ws start <victima> nogui`.  (El manager NO se revierte.)
 2. Esperar arranque + agente 001 `Active`.
 3. Copiar por `scp` (clave `id_ed25519_tfg_lab`, VMnet1) el script del ataque y el dir de la
    técnica a `/home/angel/lab-attack/ATA<NNN>/`.  Verificar dependencias (`which`).
 4. **t0** = `date -u +%Y-%m-%dT%H:%M:%SZ` (víctima) → a `times.log` + consola.  [§4]
 5. **EJECUTAR** `bash ATA<NNN>_ataque.sh` (la atómica con parámetros fijos; `stdout/stderr` a
    `ejecucion.out`).
 6. **Scan FIM forzado** en el manager: `sudo /var/ossec/bin/agent_control -r -u 001` (necesario
    porque el FIM es **programado a 12 h**: `baseline_meta.md` §6) → esperar ~30 s.
 7. **t1** = `date -u +%Y-%m-%dT%H:%M:%SZ` (víctima).   [§4]
 8. **Esperar** 60 s; extraer; si no aparece nada nuevo, **segunda consulta a los 300 s** (Fase 2).
 9. **Extraer** la ventana `[t0,t1]` del **fichero diario** del manager (NO `alerts.json`) y
    **LIMITARLA A LA VÍCTIMA** (`agent.id=001` / `agent.name=victima-linux`): las alertas del
    **manager** que caigan en la ventana (p. ej. las suyas propias) NO deben colarse como ataque.
    - `extraer_alertas.py` **no** filtra por agente (opciones reales: `--alerts`, `--desde`, `--hasta`,
      `--out`, `--detail`, `--muestra`, `--max-por-regla`, `--ruleset-dir`, `--etc-rules-dir`,
      `--test`), pero su `--detail` **sí** emite la columna `agent_name`. Se extrae a un crudo y se
      filtra por esa columna (KISS, **sin tocar la herramienta**; la variante `--agent` queda para el
      escalado como cambio declarado):
      · `sudo python3 /home/angel/extraer_alertas.py --alerts <diario> --desde <t0> --hasta <t1> --detail /tmp/ATA<NNN>_iterN-Detalle_raw.csv`
      · filtro CSV de una línea con la stdlib (deja solo `agent_name == victima-linux`):
        `python3 -c "import csv;f=open('/tmp/ATA<NNN>_iterN-Detalle_raw.csv',newline='');o=open('<…>/linux/CSV/ATA<NNN>_iterN-Detalle.csv','w',newline='');r=csv.reader(f);w=csv.writer(o);h=next(r);w.writerow(h);j=h.index('agent_name');w.writerows(x for x in r if x[j]=='victima-linux')"`
      (snippet canónico en `Soporte/Ataques/piloto_procedimiento.md`).
    - El **detalle filtrado** es el que entra en el pipeline: las filas de otros agentes **nunca**
      llegan a `filtrar_ruido.py` ni a los conteos.
10. **Filtrar/etiquetar:** `python3 filtrar_ruido.py --alerta <detalle> --ata ATA<NNN> --iter N \
        --out <…>/linux/Auditado/ATA<NNN>_iterN-Audited.csv \
        --rev-out <…>/linux/Auditado/ATA<NNN>_iterN-Revision.csv`   (modo ataque; usa el `esperado`).
11. **Revisar** las `dudosa` (si las hay) → veredicto humano en `-Revision.csv` → re-ejecutar con
    `--revision` (pliega y queda trazable).
12. **Guardar**: evidencia (§9), **ficha** `ATA<NNN>_meta.md` (§7), **bitácora** (§8) y **estado**
    del ataque en `Hojas/ATA_index.csv` (solo su fila: `en-curso` durante, `cerrado`/`review` al final).
```

> Tras las **2 iteraciones** se aplica el criterio de §6 y se cierra el ataque. El **manager nunca se
> revierte** (conserva las alertas). El **revert de la víctima entre iteraciones es obligatorio**.

## 4. Decisión 4 — El «cronómetro» t0/t1 (A2.4) — convención, no herramienta

- **Formato:** siempre **UTC**, `YYYY-MM-DDTHH:MM:SSZ`, con
  `date -u +%Y-%m-%dT%H:%M:%SZ`.
- **Dónde se sella:** **en la víctima** (`victima-linux`), que está sincronizada y cuya hora coincide
  con la del manager (Wazuh sella en UTC). El script del ataque **imprime él mismo** `t0` y `t1`
  (dos llamadas a `date -u`) → no hay intervención manual ni duda; se guardan además en
  `Logs/ATA<NNN>_iterN/times.log` y se copian **literalmente** a la ficha.
- **t0** = justo **antes** de ejecutar el comando del ataque (tras copiar y verificar deps; entre t0 y
  el comando **no ocurre nada más**). **t1** = **después** del ataque **y** del scan FIM forzado.
- **Ventana de extracción = `[t0, t1]` (inclusivo).** Se comprueba `t0 < t1`; si el reloj
  víctima↔manager difiere ≥ 1 s, **abortar la ventana**.
- **Nota:** si una ventana cruzara medianoche UTC, la extracción cubre **dos** ficheros diarios
  (se avisa; improbable).

## 5. Decisión 5 — El fichero de SEÑALES ESPERADAS `ATA<NNN>_esperado.csv`

- **Ruta (obligatoria, la que descubre el filtro):**
  `Dataset/Ataques/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv`.
  Columnas: `senal_id,tipo,campo,patron,dato_componente,tecnica,nota`
  (`tipo ∈ {deteccion, ambigua}`; `campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key,
  syscheck_path}`).
- **Quién y cuándo:** **`tfg-executor` lo redacta** (propone) como **primer paso de cada ataque
  (T-09), ANTES de t0**; **el humano lo valida** (gate §17). Es el **punto donde se puede sesgar el
  resultado**: por eso se escribe **antes** de ver ninguna alerta, se deriva de los **Data Components**
  de la técnica (`Hojas/corpus_host.csv`) + el ruleset Wazuh, se versiona y se valida.
- **Qué pasa si no está:** `filtrar_ruido.py` **falla ruidosamente** (`exit 3`) → **no se ejecuta el
  ataque** sin un esperado validado. No hay "modo" que lo evite salvo `--modo baseline`, que aquí
  **no** se usa.
- **Borradores a validar (el ejecutor los fija tras el paso 0):**

| ATA | Borrador de señales |
|---|---|
| **ATA002** (T1485) | `T1485-S1,deteccion,audit_exe,dd,Process Creation,T1485,dd sobrescribe` · `T1485-S2,deteccion,syscheck_path,/etc/tfg_lab_scratch_dd.txt,File Modification,T1485,FIM (scan forzado)` · `T1485-A1,ambigua,rule_id,80790,File Creation,T1485,creacion generica (la genera tambien lo legitimo)` |
| **ATA008** (T1048) | `T1048-S1,deteccion,audit_exe,<herramienta>,Process Creation,T1048,tool de exfiltracion` **← se deja SOLO la que exista** (`wget` \| `curl` \| `python3`, lo decide el paso 0) |
| **ATA013** (T1560) | `T1560-S1,deteccion,audit_exe,python3,Process Creation,T1560,archivado con la stdlib` |

> Nota: los `campo` de señal **no** incluyen `audit_file`/`audit_dir`; por eso la ruta del ataque se
> atribuye por **`syscheck_path`** (FIM) o por **`audit_exe`** (proceso), no por `audit_file`.

## 6. Decisión 6 — Criterio de la DOBLE ITERACIÓN (R-11)

**La igualdad exacta NO vale** (el ruido del baseline variaba ±3,5 % por regla; −1,5 % el total).
Dos iteraciones se consideran **equivalentes** si y solo si:

1. **Mismo conjunto de `rule_id`** con `categoria=deteccion` en `iter1` y `iter2`; **y**
2. el recuento de `deteccion` cumple `|n2 − n1| ≤ max(2, 10 % · n1)`; **y**
3. **no queda ninguna fila `dudosa` sin resolver** (revisión pendiente).

Si **falla** cualquiera → **`review=true`** en la bitácora y en `ATA_index.csv`, y **se avisa al
humano** (nunca se cierra en silencio). El margen del **10 %** es deliberadamente mayor que el ruido
observado (±3,5 %) porque las ventanas de ataque son **cortas y de N pequeño**; el suelo `±2` evita
disparar `review` por diferencias triviales. Se comparan también, como sanidad, los totales de
`auto_ruido`/`ruido_conocido` (≤ 10 %).

## 7. Decisión 7 — La ficha por ataque (equivalente a `baseline_meta.md`)

**Ruta:** `Dataset/Ataques/Resultados/Wazuh/linux/ATA<NNN>_meta.md`
(`status: completada | review`, generada por el ejecutor, una por ataque). **Esquema mínimo:**

```markdown
---
fase: 3 · bloque: fase-03-piloto · ata_id · tecnica · tactica · version · status · fecha
---
1. Identificación: ATA<NNN>, técnica/subtécnica, táctica, prioridad.
2. Fuente del ataque: ART GUID + path + commit pin (o "custom"), herramienta y verificación de deps.
3. Snapshot: lab-listo (hora del revert), manager NO revertido, NAT OFF.
4. Iteración 1 y 2: t0, t1 (UTC), duración, hash del script `ATA<NNN>_ataque.sh`.
5. Comando ejecutado: literal (sin secretos).
6. Evidencia: rutas a `Logs/ATA<NNN>_iterN/` (times, ejecucion.out, ps_antes/despues, deps, sink).
7. Ventana extraída: fichero diario, filas, `rule_id` distintos, reparto por RS, 0 UNKNOWN.
8. Resultado: conteos `deteccion/auto_ruido/ruido_conocido/dudosa` por iteración + RS.
9. Doble iteración: comparación (§6) y veredicto `iguales|review`.
10. Limitaciones y cabos descubiertos.
```

## 8. Decisión 8 — La bitácora `Bitacora/ATA<NNN>.json`

**Append-only** (array `eventos`); un fichero por ataque del piloto. Esquema mínimo:

```json
{
  "ata_id": "ATA002", "tecnica": "T1485", "tactica": "Impact",
  "sistema": "linux", "estado": "pendiente|en-curso|review|cerrado",
  "artefacto": "Dataset/Ataques/Comandos/T1485-Data_Destruction/",
  "atomic": { "fuente": "atomic-red-team", "guid": "38deee99-…", "path": "atomics/T1485", "commit": "388942a…" },
  "esperado_sha256": "…",
  "iteraciones": [
    { "iter": 1, "t0": "…Z", "t1": "…Z", "snapshot": "lab-listo",
      "detalle": "…/linux/CSV/ATA002_iter1-Detalle.csv",
      "audited": "…/linux/Auditado/ATA002_iter1-Audited.csv",
      "conteos": { "deteccion": 0, "auto_ruido": 0, "ruido_conocido": 0, "dudosa": 0 } }
  ],
  "doble_iteracion": "iguales|review",
  "eventos": [ { "ts": "…Z", "tipo": "inicio|t0|t1|extraido|filtrado|revision|cierre", "detalle": "" } ]
}
```

## 9. Decisión 9/10 — Rutas de salida y evidencia mínima (R-13)

Convención por sistema (`state.md`): **hoy `linux/`**.

| Qué | Ruta |
|---|---|
| Artefacto + README (R-13) | `Dataset/Ataques/Comandos/T1485-Data_Destruction/`, `…/T1048-Exfiltration_Over_Alternative_Protocol/`, `…/T1560-Archive_Collected_Data/` |
| Señales esperadas | `…/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv` |
| Detalle por alerta (T-10) | `Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA<NNN>_iterN-Detalle.csv` |
| Auditado + revisión (T-11) | `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iterN-Audited.csv` (+ `-Revision.csv`) |
| Evidencia | `Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA<NNN>_iterN/` |
| Ficha | `Dataset/Ataques/Resultados/Wazuh/linux/ATA<NNN>_meta.md` |

**Evidencia mínima por iteración** (en `Logs/ATA<NNN>_iterN/`): `times.log` (t0/t1 UTC),
`ejecucion.out` (stdout+stderr del ataque), `ps_antes.txt`/`ps_despues.txt` (procesos en la víctima),
`deps.txt` (`which`/versiones), `sha256_artefacto.txt`, `sink.log` (solo ATA008). Las capturas de
pantalla son **opcionales** (el log es la prueba primaria).

> ⚠️ **Enganchón conocido (declarado):** `filtrar_ruido.py` tiene su salida por defecto en
> `…/Wazuh/Auditado/` (sin `linux/`). En el piloto se pasa **`--out`/`--rev-out` explícitos** con la
> ruta `linux/` y **no se toca la herramienta**; actualizar ese default es deuda del escalado.

## 10. Decisión 11 — ¿Se escriben reglas RS3 en el piloto? **NO**

- **Decisión: ninguna regla propia (RS3/RS4) en el piloto.** Un ataque **no detectado** se registra
  como **resultado** (`0 detecciones`): eso es precisamente el dato que mide el TFG (capacidad de
  Wazuh **de fábrica**).
- **Justificación:** (1) el piloto valida la **maquinaria de medición**, no mejora la detección;
  (2) escribir una regla exige pasar el **pre-flight** (`preflight_enmascaramiento.py`), y **C2
  obliga a desplegar temporalmente** las reglas en el manager; mezclar "medir" con "mejorar" en el
  mismo piloto contamina el resultado; (3) RS3 está vacía hoy → el recuento refleja el ruleset real.
- **Dónde se hará:** en el **escalado** (`fase-03-escalado`), con el pre-flight por regla.

## 11. Decisión 12 — Volumen y disco

- El manager tiene **~25 GB libres** (`baseline_meta.md` §8). Cada ventana de ataque es **corta**
  (objetivo: `t1 − t0 ≤ 15 min`; espera ≤ 5 min) → ~250–400 alertas/ventana (ritmo de régimen
  ~24–25/min) + el ataque. **6 ventanas ≈ 2.000 alertas**, despreciable frente al logging continuo.
- **Control:** antes de cada ventana, `df -h /` en el manager; **abortar si < 10 GB libres**. El
  `alerts.json` rota a diario por diseño; los CSV extraídos son diminutos. **No** se activa ningún
  logging adicional (nada de `auditd` extra) para no alterar la telemetría.

## 12. Paso 0 (lo que el ejecutor fija antes de tocar nada; requiere VMs encendidas, solo lectura)

1. Encender manager + víctima; verificar `wazuh-manager/indexer/dashboard = active` y agente 001
   `Active` (`/var/ossec/bin/agent_control -l`, root).
2. **Relojes:** `date -u` en víctima y manager (diferencia < 1 s).
3. **Dependencias (sin instalar):** en la víctima `which dd python3 wget curl` y
   `python3 -c "import gzip,tarfile"`. Fijar la **herramienta de exfiltración** real (→ cierra la
   señal `T1048-S1`).
4. **Confirmar cobertura de telemetría** (para saber qué esperar): `sudo auditctl -l` y
   `/etc/audit/rules.d/tfg.rules` (auditd vigila `/etc` y `lab-legit`) + rutas FIM del agente. Dejar
   constancia en la ficha de que **`/home/angel/lab-attack` NO está vigilado** (por eso ATA002
   escribe en `/etc`, y ATA008/ATA013 solo se ven por `execve`).
5. **Fichero diario de hoy:** `ls /var/ossec/logs/alerts/2026/Sep/` (root) → fijar la ruta exacta.
6. **No regresión de herramientas:** `extraer_alertas.py --test` y
   `python filtrar_ruido.py` sobre el ejemplo del repo (exit 0); confirmar que el `--detail` incluye
   la columna `agent_name` (base del filtro por agente de §3 paso 9).
7. **Espacio:** `df -h /` en el manager.
8. **(Solo ATA008) IP del host:** en el sobremesa, `ipconfig` → fijar la **IP del host en `VMnet1`**
   (`192.168.65.0/24`, normalmente `192.168.65.1`); es a la que la víctima hará el `POST`.
9. **(Solo ATA008) Firewall de Windows:** con el receptor ya levantado, probar desde la víctima
   `timeout 3 bash -c '</dev/tcp/<IP_host_VMnet1>/9090' && echo OK || echo BLOQUEADO`. Si
   **BLOQUEADO**, añadir regla de entrada acotada al laboratorio:
   `netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24`;
   **retirar** la regla al cerrar el piloto.

## 13. Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `Dataset/Ataques/Comandos/T1485-Data_Destruction/{README.md,ATA002_esperado.csv,ATA002_ataque.sh}` | **nuevos** (artefacto R-13) |
| `Dataset/Ataques/Comandos/T1048-Exfiltration_Over_Alternative_Protocol/{README.md,ATA008_esperado.csv,ATA008_ataque.sh}` | **nuevos** |
| `Dataset/Ataques/Comandos/T1560-Archive_Collected_Data/{README.md,ATA013_esperado.csv,ATA013_ataque.sh}` | **nuevos** |
| `Dataset/Ataques/Resultados/Wazuh/linux/**` | **nuevos** (CSV, Auditado, Logs, `ATA<NNN>_meta.md`) |
| `Bitacora/ATA002.json`, `ATA008.json`, `ATA013.json` | **nuevos** |
| `Hojas/ATA_index.csv` | **solo** las filas ATA002/008/013 (`artefacto`, `estado`); **las otras 10 intactas** |
| `Soporte/Ataques/piloto_procedimiento.md` | **nuevo** (el procedimiento §3 como runbook reutilizable) |
| `Soporte/Ataques/receiver/{README.md,sink_http.py}` | **nuevos** (receptor de ATA008 **en el host/sobremesa** sobre VMnet1; log = `sink.log`) |
| `state.md`, `roadmap.md` | al **cierre** (orquestador) |

**No se toca:** `filtrar_ruido.py`, `extraer_alertas.py`, `preflight_enmascaramiento.py` (salvo que
el paso 0 revele un bloqueo duro → cambio aparte, declarado), `Soporte/Wazuh/**`, `Hojas/Detecciones.xlsx`,
`BBDD/`, `_recursos/`.

## 14. Criterios de aceptación y casos de prueba

| # | Criterio (verificable) | Caso de prueba |
|---|---|---|
| **CA1** | 3 técnicas elegidas (ATA002/T1485, ATA008/T1048, ATA013/T1560), **una por táctica**, entre las 7 de Linux. | Leer §1 + `cobertura_atomic.csv`: las 3 filas son `cubierta`. |
| **CA2** | **Cero** instalaciones en la víctima; `lab-listo` prístino. | `apt`/`dpkg` sin actividad nueva en la ventana; config auditd/FIM y snapshots **sin cambios**. |
| **CA3** | **6 ventanas** reales (3×2), cada iteración desde revert fresco a `lab-listo`; t0<t1 en UTC; extracción del **fichero diario**. | `times.log` de las 6 + cabecera del detalle (ruta del diario). |
| **CA4** | Por iteración existen: detalle, audited, evidencia, ficha y bitácora; `ATA_index.csv` con la fila al día. | Listado de rutas + `ATA_index.csv`. |
| **CA5** | Cada ataque tiene `ATA<NNN>_esperado.csv` **redactado antes** y **validado por el humano**; el filtro corre en **modo ataque**. | `sha256` del esperado + cabecera del audited (`modo=ataque`). |
| **CA6** | Criterio de doble iteración (§6) aplicado y registrado (`iguales`/`review`). | Comparar `rule_id` de `deteccion` y `|n2−n1| ≤ max(2,10 %·n1)` en los 2 audited. |
| **CA7** | **Determinismo (R-13):** re-ejecutar el filtro sobre el mismo detalle → audited **byte a byte** idéntico. | `sha256` igual en dos pasadas. |
| **CA8** | **Sin secretos** en el repo (ni en scripts, ni docs, ni bitácora). | `grep` de la contraseña real (no debe aparecer) + revisión de `git diff`. |
| **CA9** | Solo las **3** filas del piloto cambian en `ATA_index.csv`. | `git diff Hojas/ATA_index.csv` = 3 líneas. |
| **CA10** | `tfg-tester` verifica **sin lanzar ataques**; suite de tests en verde. | `pytest` + revisión de artefactos (§15). |
| **CA11** | **Aislamiento por agente:** la ventana se limita a la víctima; **0 filas** de otro agente. | En cada `-Detalle.csv`, contar filas con `agent_name ≠ victima-linux` = **0** (se filtró desde el `_raw`). |

## 15. Cómo se verifica (`tfg-tester`) — **sin lanzar ataques**

El tester **no ataca ni enciende VMs**. Verifica **procedimiento + artefactos + resultados**:
1. **Suite:** `pytest _artefactos/scripts/tests/` en verde (no regresión).
2. **Artefactos (R-13):** los 3 `README.md` + los 3 `ATA<NNN>_ataque.sh` existen, son coherentes con
   la atómica citada (GUID/path/commit), y **no contienen secretos**.
3. **Esperados:** los 3 CSV tienen el esquema exacto y se redactaron **antes** de la ejecución
   (fecha/commit anterior a los resultados; validación humana registrada).
4. **Resultados:** los 6 audited tienen las **15 columnas** exactas; cabecera con `modo=ataque` y
   `sha256` de entradas; conteos de la cabecera = conteos reales; **0 `dudosa` sin resolver**.
5. **Determinismo (CA7):** regenerar el audited desde el detalle → mismo `sha256` (CA7).
6. **t0/t1:** presentes, UTC, `t0<t1` en las 6; coherentes con la ventana del detalle.
7. **Doble iteración (CA6):** comprobar el criterio y el veredicto registrado.
8. **Trazabilidad:** ficha + bitácora coinciden con los CSV; `ATA_index.csv` solo toca 3 filas;
   `_recursos/` intacto. **Veredicto PASA/FALLA con evidencia.**
9. **Aislamiento por agente (CA11):** los 6 `-Detalle.csv` tienen **0 filas** con
   `agent_name ≠ victima-linux`; si el ejecutor conserva el `_raw`, comprobar que el filtrado es
   correcto.

## 16. Qué NO entra (fuera de alcance)

- Las **otras 10 técnicas** del corpus (**no se tocan sus filas** de `ATA_index.csv`).
- **Windows** (el piloto es 100 % Linux).
- **η / precio de la detección** (Fase 4) y las **gráficas**.
- **Escribir reglas RS3/RS4** (§10) y su pre-flight.
- `Hojas/Detecciones.xlsx`, `BBDD/wazuh.db`, `Estudio-Wazuh/` (T-12).
- **Instalar dependencias / re-baselinar** (§2).
- Automatizar el ciclo para el escalado: se deja como runbook (§3) y se decide al escalar.

## 17. Qué tiene que aprobar el humano (gate)

1. Las **3 técnicas** y el criterio de §1 (una por táctica, sin dependencias).
2. La **decisión de dependencias (§2): no instalar nada**; asumir que `T1486`/`gpg`… esperan al escalado.
3. El **cronómetro t0/t1** (§4) como convención (A2.4).
4. El **flujo del `ATA<NNN>_esperado.csv`** (§5) y los **borradores** de la tabla: validar los 3
   **antes** del primer t0.
5. El **criterio de doble iteración** (§6: mismo conjunto de `rule_id` + margen ≤ 10 % / ±2).
6. Los **esquemas** de ficha (§7) y bitácora (§8) y las **rutas `linux/`** (§9).
7. Que el piloto **NO escribe reglas RS3** (§10).
8. Que la **exfiltración (ATA008) usa un receptor HTTP en el HOST/sobremesa** (fuera de las dos VMs)
   escuchando en la **IP del host en `VMnet1`** (`192.168.65.0/24`, normalmente `192.168.65.1`), con
   `sink.log` como evidencia; el **manager NO ejecuta nada** durante el ataque (es el detector).
   Incluye la **regla de entrada del firewall de Windows** (§12 paso 0) para que entre el `POST`.
9. Que la **ventana se limita a la víctima** (`agent.id=001` / `agent.name=victima-linux`): **0 filas**
   de otro agente en el detalle (§3 paso 9, §14 CA11).
10. Que solo se tocarán **3 filas** de `Hojas/ATA_index.csv`.

---

> **Resumen para el ejecutor — lo que necesito:** las **VMs encendidas** para el **paso 0** (§12) y,
> con el plan aprobado, la **contraseña del laboratorio** (solo en memoria) para leer `/var/ossec` y
> `agent_control`. Sin el paso 0 no se fijan la herramienta de exfiltración ni la ruta del fichero
> diario; **no se inventan**.
