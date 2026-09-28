# Runbook — ciclo de una ventana del piloto (por ataque e iteración)

> **Procedimiento reutilizable** del bloque `fase-03-piloto` (plan §3, «Decisión 3»).
> Se repite **por técnica × iteración** (`ATA<NNN>_iterN`). Aquí se generaliza para el
> **escalado**. **Sin secretos**: cuando haga falta `sudo` se lee **la contraseña del
> laboratorio** por `stdin` (nunca se escribe).
>
> **Convención por sistema:** hoy **`linux/`** (`Dataset/Ataques/Resultados/Wazuh/linux/…`).

---

## ⚠️ Nota — limitación del repo: huellas y finales de línea

> Las huellas (`sha256`) que enlazan `esperado` ↔ `audited` ↔ bitácora ↔ ficha se calculan
> sobre los **bytes del fichero en disco**. El repo tiene finales de línea **mezclados** y
> **no lleva normalización**: **evitar `git checkout` / `stash` / `reset` / clonar** sobre este
> repositorio sin **recalcular** después las huellas afectadas. Los **binarios** (p. ej. `.png`)
> **no** deben pasar por reglas de texto.
>
> - **El riesgo no es solo al clonar:** también salta con **`git add`/commit** y por tener
>   **`core.autocrlf=true`** (hoy **activo** en este repo; reescribe LF→CRLF en Windows) —
>   **cualquier** operación de git que toque los finales de línea cambia los **bytes** y por tanto
>   el `sha256`.
> - **Cadena de huellas:** `ATA<NNN>_esperado.csv` ↔ `ATA<NNN>_ataque.sh` ↔ `-Audited.csv` /
>   `-Revision.csv` ↔ `Bitacora/ATA<NNN>.json` ↔ `ATA<NNN>_meta.md`. Los scripts calculan el
>   `sha256` **de los bytes en disco** → hay que **re-pasarlos** (regenerar y actualizar las citas)
>   tras **cualquier** operación de git que toque los finales de línea.

---

## 0. Resumen del ciclo

```text
preflight (manager+agente+relojes+espacio+NAT)
  → (ATA008; tanda B: ATA009/ATA010) receptor en el HOST + puerto 9090 alcanzable
    → stop/revert/start víctima (lab-listo)      [el manager NO se revierte]
      → esperar agente 001 Active
        → scp del script (+ dir de la técnica) a /home/angel/lab-attack/ATA<NNN>/
          → verificar dependencias
            → t0 (UTC, en la víctima)
              → ejecutar el ataque
                → scan FIM forzado (manager) + esperar ~30 s
                  → t1 (UTC, en la víctima)      [t0 < t1]
                    → esperar 60 s (o 300 s si nada)
                      → extraer [t0,t1] del FICHERO DIARIO  → filtrar por agente
                        → filtrar_ruido.py (modo ataque)  → revisar dudosas
                          → guardar ficha + bitácora + ATA_index.csv
```

**Marca de tiempos (vestuario del cronómetro A2.4):** siempre **UTC**
`YYYY-MM-DDTHH:MM:SSZ`, con `date -u +%Y-%m-%dT%H:%M:%SZ` **en la víctima**.
`t0` = justo antes del comando; `t1` = tras el ataque **y** el scan FIM forzado; ventana
`[t0,t1]` **inclusiva**; si el reloj víctima↔manager difiere ≥ 1 s, **abortar**.

---

## 1. Preflight (antes de cada ventana)

**Manager (`wazuh-server`, 192.168.65.128):**

```bash
for s in wazuh-manager wazuh-indexer wazuh-dashboard; do printf '%s: ' "$s"; systemctl is-active "$s"; done
echo '<contraseña del laboratorio>' | sudo -S /var/ossec/bin/agent_control -l   # agente 001 Active
df -h /                                                                          # ABORTAR si < 10 GB libres
```

**Extractor (sincronía repo ↔ manager — regla del §8.1):** antes de medir, comprobar que la copia
**desplegada** en el manager coincide con la del **repo**; si no, **desplegarla**:

```bash
sha256sum /home/angel/extraer_alertas.py                 # en el manager
# sha256 _artefactos/scripts/extraer_alertas.py          # en el repo -> deben coincidir
```

**Víctima (`victima-linux`, 192.168.65.129):**

```bash
systemctl is-active wazuh-agent
which dd python3 wget curl
python3 -c "import gzip,tarfile; print('gzip,tarfile OK')"
```

**Relojes (en paralelo):** `date -u +%s.%N` en ambas; `|Δ| < 1 s`.

**NAT:** desconectado (regla de oro). No reconectar.

**(ATA008 y tanda B: ATA009/ATA010) receptor + firewall:** en el **HOST**:

```powershell
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA008_iter1\sink.log"
```

Desde la víctima: `timeout 3 bash -c '</dev/tcp/192.168.65.1/9090' && echo OK || echo BLOQUEADO`.
Si **BLOQUEADO**, añadir (una sola vez) la regla de entrada acotada:

```text
netsh advfirewall firewall add rule name="TFG-sink-9090" dir=in action=allow protocol=TCP localport=9090 remoteip=192.168.65.0/24
```

> ⚠️ **Retirar al cerrar el piloto:** `netsh advfirewall firewall delete rule name="TFG-sink-9090"`.
>
> **Tanda B (`fase-03-escalado`):** el **mismo receptor** sirve para **ATA009 (T1567)** y
> **ATA010 (T1041)**; cambia solo el `--log` (`…/Logs/ATA010_iterN/sink.log`) y el endpoint que usa
> el cliente (`/api/upload/…` en ATA009, `/c2/beacon` en ATA010). Pasos concretos y retirada:
> `Dataset/Ataques/Comandos/T1567-Exfiltration_Over_Web_Service/README.md` §9.

---

## 2. Los 12 pasos

> Variables de trabajo (rellenar): `<NNN>` = número de ATA (002/008/013/…), `<N>` = iteración (1/2),
> `<TEC>`–`<DESC>` = carpeta de la técnica, `<DIARIO>` = fichero diario (§ paso 9),
> `<IPHOST>` = IP del host en VMnet1 (`192.168.65.1`).

### Paso 1 — Revert de la víctima a `lab-listo` (el manager NO se revierte)

```powershell
$vmrun   = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$victima = "D:\TFG-VMs\victima-linux\victima-linux.vmx"
& $vmrun -T ws stop   $victima soft
& $vmrun -T ws revertToSnapshot $victima lab-listo
& $vmrun -T ws start  $victima nogui
```

### Paso 2 — Esperar arranque + agente `001` `Active`

```bash
# en el manager
echo '<contraseña del laboratorio>' | sudo -S /var/ossec/bin/agent_control -l
```

### Paso 3 — `scp` del ataque y verificación de dependencias

Desde el **sobremesa** (clave `C:\Users\angel\.ssh\id_ed25519_tfg_lab`):

```powershell
$ssh = "C:\Program Files\Git\usr\bin\ssh.exe"; $scp = "C:\Program Files\Git\usr\bin\scp.exe"
$key = "C:\Users\angel\.ssh\id_ed25519_tfg_lab"
# script del ataque
& $scp -i $key "Dataset\Ataques\Comandos\<TEC>-<DESC>\ATA<NNN>_ataque.sh" `
  angel@192.168.65.129:/home/angel/lab-attack/ATA<NNN>/
# (solo ATA008) además el directorio de la técnica (trae src/artifact)
& $scp -i $key -r "Soporte\Ataques\atomic-red-team\atomics\T1048.002" `
  angel@192.168.65.129:/home/angel/lab-attack/ATA008/
```

Verificar en la víctima: `ls -l`, `which` de la herramienta y el `sha256` del script.

### Paso 4 — `t0`

> ⚠️ **H2 — sellar `t0` tras el asentamiento.** Esperar **≥ 60–90 s** desde que el agente `001`
> está `Active` **antes** de sellar `t0`. Así el **ruido de arranque queda FUERA de la ventana**
> (ocurre antes de `t0`) y el ataque empieza ya en régimen → `[t0,t1]` es comparable entre
> iteraciones **sin** recortar la ventana. Ver `Soporte/Ataques/criterio_doble_iteracion.md` §2.

`date -u +%Y-%m-%dT%H:%M:%SZ` **en la víctima** → a `Logs/ATA<NNN>_iterN/times.log` y consola.
El script del ataque **también** imprime `T0=…` al arrancar (doble registro).

### Paso 5 — Ejecutar el ataque

```bash
cd /home/angel/lab-attack/ATA<NNN>/
bash ATA<NNN>_ataque.sh 2>&1 | tee ejecucion.out
```

### Paso 6 — Scan FIM forzado (manager) + esperar ~30 s

```bash
echo '<contraseña del laboratorio>' | sudo -S /var/ossec/bin/agent_control -r -u 001
sleep 30
```

### Paso 7 — `t1`

`date -u +%Y-%m-%dT%H:%M:%SZ` **en la víctima**, tras el scan. Comprobar `t0 < t1`.

### Paso 8 — Esperar y, si nada nuevo, segunda consulta

Esperar **60 s**; extraer; si no aparece nada nuevo, **segunda consulta a los 300 s**.

### Paso 9 — Extraer la ventana del **fichero diario** y limitarla a la víctima

**Fichero diario (NO `alerts.json`):** `/var/ossec/logs/alerts/<YYYY>/<Mon>/ossec-alerts-<DD>.json`
(paso 0 del piloto: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-25.json`).

```bash
# en el MANAGER (root para leer /var/ossec)
echo '<contraseña del laboratorio>' | sudo -S python3 /home/angel/extraer_alertas.py \
  --alerts <DIARIO> --desde <t0> --hasta <t1> \
  --detail /tmp/ATA<NNN>_iterN-Detalle_raw.csv
```

**Snippet canónico — filtro por agente** (deja solo `agent_name == victima-linux`; se ejecuta
donde esté el `_raw`, p. ej. en el manager, y luego se copia al repo):

> ⚠️ `extraer_alertas.py --detail` **antepone una línea de comentario `#`** (metadatos de la
> extracción) y **debajo** va la cabecera real. El snippet **salta las líneas `#`** y toma como
> cabecera la **primera línea no comentada** (la real). Si en su lugar se copiara la primera
> línea tal cual, se escribiría el comentario como cabecera y se **descartaría la cabecera real**
> (el `Detalle.csv` quedaría sin columnas y `filtrar_ruido.py` leería mal).

```bash
python3 -c "import csv;f=open('/tmp/ATA<NNN>_iterN-Detalle_raw.csv',newline='');o=open('/tmp/ATA<NNN>_iterN-Detalle.csv','w',newline='');r=csv.reader(f);w=csv.writer(o);h=next(x for x in r if x and not x[0].lstrip().startswith('#'));w.writerow(h);j=h.index('agent_name');w.writerows(x for x in r if len(x)>j and x[j]=='victima-linux' and not x[0].lstrip().startswith('#'))"
```

**Traer al repo** (desde el sobremesa), conservando el `_raw` para la verificación (CA11):

```powershell
$dst = "Dataset\Ataques\Resultados\Wazuh\linux\CSV"
& $scp -i $key angel@192.168.65.128:/tmp/ATA<NNN>_iterN-Detalle.csv     "$dst\"
& $scp -i $key angel@192.168.65.128:/tmp/ATA<NNN>_iterN-Detalle_raw.csv "$dst\"
```

> **Aislamiento:** las filas de **otros agentes** (p. ej. el propio manager) **nunca** llegan a
> `filtrar_ruido.py` ni a los conteos. `extraer_alertas.py` no filtra por agente; su `--detail`
> **sí** emite la columna `agent_name` (confirmado en el paso 0).

### Paso 10 — Filtrar/etiquetar (en el sobremesa; `filtrar_ruido.py` vive en el repo)

```bash
python _artefactos/scripts/filtrar_ruido.py \
  --alerta "Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA<NNN>_iterN-Detalle.csv" \
  --ata ATA<NNN> --iter N \
  --out     "Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iterN-Audited.csv" \
  --rev-out "Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA<NNN>_iterN-Revision.csv"
```

- Localiza el esperado por
  `Dataset/Ataques/Comandos/*/ATA<NNN>_esperado.csv` (o pásalo con `--esperado`).
- Si falta el esperado → **`exit 3`** (no se ejecuta el ataque sin esperado validado).
- **Default arreglado (cabo 1, 2026-09-26):** el `--out`/`--rev-out` por defecto de
  `filtrar_ruido.py` **ya incluye `linux/`** → `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/`.
  Aquí se sigue pasando **explícito** para que la ruta quede **visible en la evidencia** (traza).

### Paso 11 — Revisión de `dudosa`

Abrir `ATA<NNN>_iterN-Revision.csv`, rellenar `veredicto` ∈ **{`deteccion`, `ruido`, `artefacto`}**
+ `nota`, `revisor`, `fecha`; re-ejecutar el paso 10 añadiendo `--revision <…>-Revision.csv`
(pliega los veredictos y queda trazable). **No puede quedar ninguna `dudosa` sin resolver.**

- **`deteccion`**: la fila **es** la detección de la técnica.
- **`ruido`**: ajena al ataque (p. ej. los `find` de `update-motd.d` del login del operador, las
  sesiones PAM `5501`/`5502`). ⛔ **Prohibido** sobre una fila **dentro** de
  `/home/angel/lab-attack/ATA<NNN>/`: la herramienta **falla** (`exit=4`) — elige `deteccion` o
  `artefacto`.
- **`artefacto`**: **es el ataque, pero no es la detección de la técnica** (p. ej. la escritura
  `watch` del `.tar.gz` que **creó** el ataque). Mapea a `artefacto_ataque`.

### Paso 12 — Guardar

- Evidencia en `Logs/ATA<NNN>_iterN/`: `times.log`, `ejecucion.out`, `ps_antes.txt`/`ps_despues.txt`,
  `deps.txt`, `sha256_artefacto.txt` y (solo ATA008) `sink.log`.
- Ficha `Dataset/Ataques/Resultados/Wazuh/linux/ATA<NNN>_meta.md` (esquema §7 del plan).

**Métrica de detección (bloque `fase-03-metrica`, decisión D1 = O1+O2):** la ficha reporta, por
iteración, la métrica **O1** (detección **Sí/No** + los `rule_id` que la originan + primera
evidencia) y **O2** (`acciones cubiertas k/m` = señales `deteccion` del `esperado` que se anclaron
≥1 vez / total de señales `deteccion`), **más** el desglose de categorías
`deteccion` / `artefacto_ataque` / `ruido_conocido`. El **nº bruto de alertas** y los
**`rule_id` distintos** quedan como **anexo** (transparencia), **nunca** como resultado.

```text
## Métrica de detección — O1 + O2 (por iteración)
- detectado (O1): <sí/no>   ·   rule_id: <set>   ·   primera evidencia: <evidencia>
- acciones cubiertas (O2): <k>/<m> = <señales deteccion ancladas ≥1 vez>/<señales deteccion del esperado>
- desglose: deteccion = <D>  ·  artefacto_ataque = <A>  ·  ruido_conocido = <R>
- anexo (transparencia, NO resultado): alertas de detección (bruto) = <N>  ·  rule_id distintos = <set>
```

> **Por qué O1+O2 (hallazgo 2026-09-28):** el **nº bruto** es **inválido** (redundancia: 1 acción
> → N reglas; procesos ajenos) y los **`rule_id` distintos** inflan (ATA007 = 3 `rule_id` para
> **1** acción). O1 es comparable entre las 13 técnicas e inmune a la redundancia; O2 da
> granularidad reutilizando el `esperado` ya validado por el humano. **Anexo:** el nº bruto y los
> `rule_id` distintos solo se citan como transparencia.
- Bitácora `Bitacora/ATA<NNN>.json` (append-only, esquema §8 del plan).
- Fila de `Hojas/ATA_index.csv` (`en-curso` durante; `cerrado`/`review` al final). **Solo su fila.**

Tras las **2 iteraciones** se aplica el **criterio de doble iteración v2** (la **detección**
decide: mismo conjunto de `rule_id` de `deteccion` + `|n2−n1| ≤ max(2, 10 %·n1)` + sin `dudosa`;
las **sanidades** de `auto_ruido`/`ruido_conocido` **pasan a aviso**, no bloquean) →
`iguales`/`review`. Regla completa: `Soporte/Ataques/criterio_doble_iteracion.md`.

---

## 3. Rutas de salida (convención `linux/`)

| Qué | Ruta |
|---|---|
| Artefacto + README | `Dataset/Ataques/Comandos/<TEC>-<DESC>/` |
| Señales esperadas | `…/Comandos/<TEC>-<DESC>/ATA<NNN>_esperado.csv` |
| Detalle por alerta | `Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA<NNN>_iterN-Detalle.csv` (+ `_raw`) |
| Auditado + revisión | `…/Wazuh/linux/Auditado/ATA<NNN>_iterN-Audited.csv` (+ `-Revision.csv`) |
| Evidencia | `…/Wazuh/linux/Logs/ATA<NNN>_iterN/` |
| Ficha | `…/Wazuh/linux/ATA<NNN>_meta.md` |

---

## 4. Cierre del piloto — **EJECUTADO** (2026-09-26)

1. **Receptor parado:** no quedaba ningún proceso `sink_http.py` levantado.
2. **Regla de firewall retirada:** `netsh advfirewall firewall delete rule name="TFG-sink-9090"` →
   «Se eliminaron 1 reglas»; verificado su ausencia con `netsh advfirewall firewall show rule
   name="TFG-sink-9090"` → «Ninguna regla coincide con los criterios especificados». El receptor
   `Soporte/Ataques/receiver/sink_http.py` y su regla quedan **retirados** al cerrar el piloto
   (se recrean por ventana si el escalado retoma ATA008).
3. **Víctima revertida a `lab-listo`** (el **manager NO** se revierte): arranca, el servicio
   `wazuh-agent` queda `active` con conexión establecida al manager (`192.168.65.128:1514`) — agente
   `001` `Active` — y `/home/angel/lab-attack/` **no existe** (estado limpio, sin rastro del ataque).
4. **VMs encendidas** (víctima recién revertida + manager) y **NAT desconectado** (sin default
   route). El **manager conserva las alertas** del piloto (no se ha revertido).

---

## 5. Desviaciones y notas declaradas (paso 0, 2026-09-25)

- **D1 (ATA002):** el plan pedía `/etc/tfg_lab_scratch_dd.txt` **sin elevación**; `/etc` **no** es
  escribible por `angel`. El destino pasa a `/home/angel/lab-legit/ATA002_scratch_dd.txt` (watch de
  `auditd`). Se **pierde la señal FIM**; ver `Dataset/Ataques/Comandos/T1485-Data_Destruction/README.md`.
- **t1 y scan FIM:** el plan §4 dice que el script sella `t1` «tras el ataque y el scan FIM»; el
  script no puede ejecutar el scan (vive en el manager). **Interpretación ejecutable (§2/§3 del
  plan):** el script imprime `T1_LOCAL` como marcador; el **`t1` oficial se sella en el paso 7**,
  después del scan. Los marcadores del script quedan en `ejecucion.out`.
- **Filtro por agente:** `extraer_alertas.py` **no** filtra por agente y **no se toca**; se extrae
  `--detail` (que incluye `agent_name`) y se filtra con la stdlib (paso 9).
- **Nota de mejora (escalado):** las señales esperadas se apoyan en el **nombre del proceso**
  (`dd`/`wget`/`python3`), que es **genérico**; en el escalado conviene hacerlas **más específicas**
  (p. ej. añadir la **carpeta del ataque** como señal).
- **Convención H4 (2026-09-26) — señales ancladas al `cwd`:** en toda técnica que **escriba en la
  carpeta del ataque** (`/home/angel/lab-attack/ATA<NNN>/`), cada señal `audit_exe` se **acompaña**
  de una señal de contexto `audit_cwd=/home/angel/lab-attack/ATA<NNN>/*`. El `audit_cwd` **ancla**
  el proceso al ataque y discrimina el churn (`/`, `var/ossec`…). Detalle y plantilla:
  `Soporte/Ataques/plantilla_esperado.md`. El **esquema** del esperado **no** cambia (una señal
  más). ⚠️ **No se tocan** los 3 `ATA<NNN>_esperado.csv` del piloto (rompería sus `sha256`).
  - **✅ RESUELTO (`fase-03-senales`, 2026-09-28):** el ancla es ya un **mecanismo real** (AND
    `exe ∧ cwd ∧ audit_command`); el filtro prueba el `cwd` **y** `cwd + "/"`, así que el patrón
    congelado `…/ATA<NNN>/*` casa el `cwd` real. Lo que casa el `exe` pero falla el ancla o el
    evento → **`dudosa`** (`sin_ancla:*`), nunca `deteccion`/`ruido`. Ver política §4.

---

## 6. Hallazgos del piloto (2026-09-25) — **anotados, NO arreglados**

> Registrados tras cerrar los 3 ataques del piloto (ATA002/T1485, ATA008/T1048, ATA013/T1560).
> **No** se cambia código de herramientas en el piloto; son **deuda del escalado**.

### H1 ⭐ Enmascaramiento **dentro del ruleset de fábrica** de Wazuh (punto ciego silencioso)

En **ATA013** (T1560, `python3` + `gzip`) el ataque **no se detecta** (0 detecciones), pero **no** por
falta de telemetría: el `execve` de `python3` **sí** está en `audit.log`
(`comm="python3" exe="/usr/bin/python3.12" key="audit-wazuh-c"`). La causa es una **regla de fábrica**:

- `/var/ossec/ruleset/rules/0850-audit_rules.xml` → **`92600` `level="0"`** casa `audit.exe` ~
  `python` (*"Executed python script."*) y, al usar **`<if_group>audit</if_group>`**, es **hermana**
  de `80792` (**mismo grupo `audit`**, NO hija) y **suprime la base** (*Audit: Command*). Al ser
  nivel 0, **no emite alerta**.
- Es el **mismo fenómeno «regla hermana que suprime la base»** demostrado en el pre-flight (A2.2),
  pero aquí lo provoca **el propio ruleset de Wazuh**, sin reglas nuestras. Consecuencia: `dd`/`wget`
  sí alertan (`80792`); **`python3` no**.
- **Mejora para el escalado:** el pre-flight **C1** comprueba *nuestras* reglas contra la base, **no
  base-contra-base** → considerar ampliarlo para descubrir estos puntos ciegos de fábrica.
  - ⚠️ **Puntero (cabo 5, 2026-09-26):** *esta referencia a **C1** es **histórica**.* El hallazgo
    H1 quedó **resuelto** en el bloque `fase-03-afinado` como chequeo **C0** (**base-contra-base**,
    `wazuh-logtest` con el ruleset base) — ver **§7**. La frase de arriba se conserva como
    **trazabilidad de cómo se descubrió**, no como deuda vigente.

### H2 El ruido de arranque domina las ventanas cortas (doble iteración en `review`)

Tras un `revert`+arranque, la ventana se llena de churn (`execve`/`watch` de `systemd`, `dash`, `env`,
`uname`, `find`…). Por eso el **criterio de doble iteración (§6) es demasiado estricto para ventanas
cortas justo tras un revert+arranque**: las **detecciones son idénticas** entre iteraciones, pero las
**sanidades de `auto_ruido`/`ruido_conocido` fallan** y los **3 ataques acaban en `review`**. Mejoras:
(a) esperar a que el arranque se asiente antes de `t0`; y/o (b) comparar solo el **régimen** o excluir
el churn de arranque del chequeo de sanidad.

### H3 `sin_campos` del filtro → **dudosas sistemáticas**

La regla `sin_campos` de `filtrar_ruido.py` convierte en **`dudosa`** toda alerta **sin campos
`audit.*`** — y las **sesiones SSH del operador** (PAM/sshd) **no los tienen** → **cada ataque genera
dudosas sistemáticas**. Mejora para el escalado: **reconocer y excluir las sesiones del operador**
(o reordenar el criterio), para no acumular cientos de filas a revisar. *(En ATA013 se sumó una dudosa
de otra naturaleza: la autoevaluación **SCA** `19004`, ajena al ataque.)*

### H4 Señales genéricas

Las señales `audit_exe` (`dd`/`wget`/`python3`) son **genéricas** (solo el nombre del proceso).
Ver la convención H4 anclada al `cwd` en §5 y `Soporte/Ataques/plantilla_esperado.md`.

---

## 7. Afinado del escalado (bloque `fase-03-afinado`, 2026-09-26)

Los hallazgos H2/H3/H4 de arriba quedan **resueltos** para el escalado (H1 es del bloque
siguiente; **no** forma parte de este):

- **H2 — criterio v2 vigente:** la detección decide; las sanidades pasan a aviso; ventana completa
  `[t0,t1]` sin recortes; `t0` se sella **tras el asentamiento** (≥ 60–90 s con el agente
  `Active`). Ver `Soporte/Ataques/criterio_doble_iteracion.md`.
- **H3 — predicado `OPERADOR` (paso 1.5):** `5715` con `srcip ∈ OPERADOR_SRCIPS` y `19004` con
  grupo `sca` se **auto-excluyen** (`motivo=operador:*`); **`5501`/`5502` NO** se auto-excluyen
  (limitación declarada): caen a **`dudosa`/`sin_campos` solo si** el `esperado` **no** declara
  ninguna señal de campo siempre evaluable; **si** declara `rule_id`/`rule_group`, `sin_campos`
  **no** dispara → paso 6 → **`ruido_conocido`/`baseline`**. El caso `dudosa` lo resuelve el humano.
  Principio: **solo se auto-excluye lo demostrable**.
  El `--detail` de `extraer_alertas.py` gana `srcip,srcuser,dstuser`. Ver
  `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §3.bis.
- **H4 — convención de señales:** `audit_exe` **+** `audit_cwd=/home/angel/lab-attack/ATA<NNN>/*`.
  Ver `Soporte/Ataques/plantilla_esperado.md`.

---

## 8. Hallazgos del bloque `fase-03-piloto-custom` (2026-09-26)

> Registrados al ejecutar ATA007 (T1491), ATA012 (T1119) y ATA004 (T1489) — el camino
> **"ataque escrito por nosotros"**. Ver fichas `Dataset/Ataques/Resultados/Wazuh/linux/ATA00{4,7,12}_meta.md`.

### 8.1 ⚠️ Repositorio y manager **desincronizados** (fallo de despliegue)

- **Qué pasó:** el `extraer_alertas.py` **desplegado en el manager** seguía siendo la versión
  **antigua** (sin `srcip/srcuser/dstuser`); el del **repo** ya traía las columnas nuevas de **H3**.
  Consecuencia: el **predicado `OPERADOR`** no podía leer `srcip` → las sesiones del operador
  (`5715`) **no se auto-excluían** y caían a `dudosa` (`sin_campos`).
- **Arreglo:** `scp` del `extraer_alertas.py` del repo al manager (backup del anterior) y **re-extracción**
  de las ventanas ya tomadas. Tras el arreglo: `5715` → `ruido_conocido` / `motivo=operador:5715` (`srcip=192.168.65.1`).
- **LECCIÓN (regla operativa):** *el **repositorio** y lo **desplegado** en el manager deben ir en
  **sincronía**: hay que **desplegar** los scripts modificados antes de medir; el pipeline usa la
  **copia del manager**, no la del repo.* Añadir al **paso 0** un chequeo de `sha256` manager↔repo
  de `extraer_alertas.py`.

### 8.2 ⚠️ Las señales por proceso/carpeta son **amplias** (recuento bruto ≠ eventos)

- **ATA007:** las escrituras del `cp` (`80790`, `80781`) —que el `esperado` declaró **`ambigua`**—
  fueron **promovidas a `deteccion`** por la señal `T1491-S1` (`audit_exe=cp`), porque el mismo
  evento del `cp` las arrastra. Recuento bruto **4 alertas / 3 `rule_id` distintos**.
- **ATA012:** **3 `find` AJENOS** al ataque (`update-motd.d`: `landscape-sysinfo`, `update-notifier`,
  `cwd=/`) disparados por el **login del operador** → contados como `deteccion` por `T1119-S1`
  (`audit_exe=find`). Genuinas: **7** (iter1) / **8** (iter2) de **11**.
- **ATA004:** **2 `systemctl --user`** del **cierre de sesión** del operador → contados como
  `deteccion` por `T1489-S1` (`audit_exe=systemctl`). Genuinas: **3** de **5**.
- **Observación de forma:** el patrón del ancla `audit_cwd=/home/angel/lab-attack/ATA<NNN>/*` **no
  casa** el valor real del campo (que es la **carpeta sin barra final**: `/home/angel/lab-attack/ATA<NNN>`)
  → el ancla queda **inerte**. Las detecciones funcionaron por las señales `audit_exe`, no por el ancla.
- **RECOMENDACIÓN para el escalado:** *para ataques cuyo proceso también corre por el sistema,
  **anclar la detección por el `audit_cwd` de la carpeta del ataque** (corrigiendo el patrón: sin `/*`
  final) **y/o por el `rule_id` del `execve`** (p. ej. `80792`), **no** por `audit_exe` genérico.*
- **Decisión:** **no se recalibran** los `esperado` ya validados (se escriben antes y no se ajustan
  después); el sesgo se **documenta** y se corrigen las señales en los **ataques nuevos** del escalado.
  En cada ficha se reportan las **dos cifras** y se **separan genuinas de ajenas**.
- **✅ RESUELTO (`fase-03-senales`, 2026-09-28) — hallazgos H-A (ancla inerte) y H-B (señal
  ancha):** el filtro implementa la **ancla implícita + evento de ejecución**: una señal
  `deteccion` con `campo=audit_exe` casa solo si `exe ∧ cwd-ancla ∧ audit_command`, y el `cwd` se
  prueba **y** `cwd + "/"` (el patrón `…/ATA<NNN>/*` casa el `cwd` real sin editar los `esperado`).
  Lo que casa el `exe` pero **falla** el ancla o el evento (los `find` `cwd=/`, los `systemctl
  --user` del cierre de sesión, las **escrituras** `watch`) pasa a **`dudosa`** (`sin_ancla:*` /
  `ambigua:*`), **nunca** `ruido_conocido`. Los 3 ataques del **piloto-custom** (ATA004/007/012)
  se **regeneraron**; los 3 del **piloto** (ATA002/008/013, sin ancla) quedaron **byte a byte
  idénticos**. Ver política §4 y fichas.

### 8.3 ⚠️ Punto ciego de journald — `40700` es `level="0"` (agrupador)

> Añadido en el bloque `fase-03-cabos` (2026-09-28). **No** requirió VMs ni root: el hallazgo sale de
> inspeccionar el ruleset de **fábrica** fijado por el laboratorio.

- **Qué pasó (ATA004 · T1489 Service Stop):** se esperaban alertas de **journald/systemd**
  (`40700`, grupo `systemd`) por la parada del servicio (`systemctl stop cron`) y salieron **0** en las
  2 ventanas. La captura **C0** solo cubrió la línea `execve` de `systemctl` → la expectativa quedaba
  **sin probar**.
- **Causa (inspección del ruleset de fábrica, Wazuh v4.14.7, `0285-systemd_rules.xml`):** la regla
  **`40700` es `level="0"`** — agrupador `<program_name>^systemd$|^systemctl$</program_name>`, **no
  emite alerta**. Sus **hijas** `40701`–`40705` (level 2/5) **solo** disparan con patrones de **fallo**
  (`Stale file handle`, `entered failed state`, `status=1/FAILURE`, `Time has been changed`…). Una
  **parada normal** de servicio (`systemctl stop cron`, mensajes `Stopping`/`Stopped`) **no casa
  ninguna hija** → gana `40700` (level 0) → **no hay alerta journald**.
- **Conclusión:** la expectativa era **estructuralmente imposible** — **no** era una detección
  "silenciada", era una detección **inexistente de fábrica**. La detección efectiva del ataque es el
  **`execve` `80792`** (audit). La hipótesis queda **resuelta** (no "sin probar").
- **CABO DEL ESCALADO:** si una técnica depende de **journald**, (1) confirmar empíricamente con un
  **C0** sobre una **línea journald real** capturada en la víctima y (2) **escribir la regla propia
  (RS3)** o declarar la detección por el **`rule_id` del `execve`**. Ver ficha `ATA004_meta.md`
  §8.1/§10.5.
- **Alcance:** se **documenta** (coste cero); **no** se extendió el C0 — exigiría VMs + root y una
  línea journald sintética de formato no trivial (riesgo de `garbage-in`) sin aportar hallazgo nuevo.

---

## 9. Hallazgo y arreglo del bloque `fase-03-metrica` (2026-09-28) — métrica + pertenencia al ataque

> **Offline** (sin VMs): se re-filtran los **mismos** `-Detalle.csv`. Ver `plan.md` del bloque
> `fase-03-metrica` y la política §2/§3.ter/§5.

### 9.1 El defecto (sistemático)

La huella del **propio ataque** (su árbol de procesos `execve`, y el fichero que crea) caía en
**`ruido_conocido`** porque el filtro decidía por catálogo **sin mirar la ubicación**: `80792` está
en el catálogo (es genérico) → cualquier `execve` no declarado salía "ruido". Medido: **84 filas**
en las 12 ventanas (**78** son huella **dentro** de la carpeta del ataque —las marca la regla
automática— + **6** que pliega el humano con el veredicto `artefacto`: **2** `sudo`, **2**
`Created: …/collected.tar.gz` y **2** `mkdir public_site` del *setup* de ATA007 en `lab-legit`).
Ninguna se queda en "ruido".

### 9.2 El arreglo (D2 = opción B completa)

- **Categoría nueva `artefacto_ataque`** (paso 3.5): fila **del ataque** (`audit_cwd` o ruta bajo
  `ATTACK_ROOT/<ATA_id>`) que no casó detección → `artefacto_ataque`, **nunca** `ruido_conocido`.
- **Ancla por ruta** (mejora C): el ancla prueba también `audit_file`/`audit_dir`/`syscheck_path`.
- **Guardarraíl de plegado**: `veredicto=ruido` sobre una fila del ataque → **`exit=4`**.
- **Tercer veredicto `artefacto`** (D5): "es el ataque, no cuenta como detección" → `artefacto_ataque`.
- **`AVISO`** por execve no declarado en la carpeta del ataque (posible detección no declarada).

### 9.3 Métrica de detección (D1 = O1+O2)

`detectado = sí/no` + `rule_id` + primera evidencia (**O1**); **acciones cubiertas `k/m`** (**O2**);
`deteccion`/`artefacto_ataque`/`ruido_conocido` como desglose. El **nº bruto** y los `rule_id`
distintos quedan como **anexo** (transparencia). Ver paso 12.

### 9.4 Resultado

**No cambia ningún veredicto** (5 detectados / ATA013 **no**) y **ninguna detección genuina se
pierde**: `deteccion` sigue en **39** filas en total; `ruido_conocido` **baja en 84** (1.836 →
1.752); aparece `artefacto_ataque` **= 84**. Cadena de huellas (`esperado`/`-Detalle` ↔
`-Audited`/`-Revision` ↔ bitácora ↔ ficha) recalculada; `-Detalle.csv`, los `esperado` (incl.
pilotos) y `Hojas/ATA_index.csv` **intactos**.

---

## 10. Escalado (bloque `fase-03-escalado`) — alcance y limitación declarada

> Añadido al abrir el escalado (**tanda A**, 2026-09-28). Aplica a **todas** las técnicas nuevas.

- **Realismo acotado (declarado).** *"La técnica y el comando son reales; el alcance es de
  laboratorio (no se destruye la máquina); el entorno no tiene usuarios/servicios reales y las rutas
  del ataque son conocidas por el analista."* Los datos de juguete llevan **nombres creíbles**
  (escena de empresa: web pública, datos de clientes falsos, copias de seguridad simuladas) para que
  la ventana se parezca a un caso realista, pero **no son datos reales**. La nota consta en el
  **README de cada técnica** y aquí.
- **Alcance de ATA006** (decisión humana 2026-09-28): la técnica es el **cambio de contenido**
  (`sed -i`); se **retiran** `touch`/`chmod` (falsear fecha/modo = **T1070.006 Timestomp**, otra
  técnica) para no ensuciar la atribución.


