---
fase: 3
bloque: fase-03-piloto-custom
tarea: T-09/T-10/T-11 (F-03 · R-09/R-11/R-13) · segundo piloto — camino "ataque escrito por nosotros"
nombre: Piloto 2 — 3 técnicas (2 ataques manuales + 1 de ART) + 2 arreglos previos
version: 1
status: approved_by_human
fecha: 2026-09-26
fecha_aprobacion: 2026-09-26
aprobado_por: humano
autor: tfg-planner
gate: humano — **(a) plan APROBADO ✔ (2026-09-26)** con las recomendaciones del orquestador (ATA007: escrituras `80781`/`80790` como **`ambigua`** → revisión humana; **ATA004 fijada**, alternativa ATA001 descartada). **(b) `esperado` VALIDADOS ✔ (2026-09-26)** — los 3 `ATA<NNN>_esperado.csv` aprobados por el humano antes del primer `t0`. **(c) Añadido aprobado por el humano:** cada **ficha** debe mostrar el desglose **"detecciones esperadas / sorpresas"** (`senal:` vs `novel`).
---

# Plan — Bloque `fase-03-piloto-custom`: validar el camino "ataque manual"

> **Objetivo del bloque:** probar el **camino que NO se ha recorrido todavía** — el **ataque
> ESCRITO POR NOSOTROS** — antes de escalar a las 6 técnicas que lo necesitan. Se hace con
> **3 técnicas** (2 manuales + 1 de ART como control), **2 iteraciones** cada una (**6 ventanas**),
> reutilizando el **ciclo ya validado** (runbook) con las **mejoras H1–H4** y el **criterio v2**.
> Incluye **2 arreglos previos** (cabos del afinado 1 y 5). KISS: 8/10 hecho > 10/10 sin hacer.
>
> **Fichero único de retorno: este `plan.md`.** Nada más se escribe hasta el gate.

---

## 0. Objetivo y alcance

- **Entra:** las **3 técnicas** y sus **2 ataques manuales** (§1–§2), las **señales H4** (§3), la
  **captura C0 por técnica** (§4), el **ciclo del runbook reutilizado** con criterio v2 (§5), los
  **2 arreglos previos** (§6), el aprendizaje esperado (§7), los artefactos + fichas + bitácoras +
  filas de `Hojas/ATA_index.csv` de esas 3 técnicas.
- **NO entra:** las **7 técnicas restantes** del corpus, **Windows**, η/Fase 4, **escribir reglas
  RS3/RS4**, la **memoria**, instalar dependencias/re-baselinar (§11). **No se tocan** los
  artefactos cerrados del piloto ni del afinado **salvo los 2 arreglos** (§6).

---

## 1. Decisión 1 — Las 3 técnicas: verificación de la propuesta del humano

Se **verifica** la propuesta contra `Hojas/cobertura_atomic.csv` y se **confirma** con matices.

| ATA | Técnica (táctica) | Vía | Cobertura ART (`cobertura_atomic.csv`) | Verificado |
|---|---|---|---|---|
| **ATA007** | **T1491** Defacement (*Impact*) | **manual** | `T1491` → **`solo_windows`** (0 pruebas Linux) | ✔ necesita script propio |
| **ATA012** | **T1119** Automated Collection (*Collection*) | **manual** | `T1119` → **`solo_windows`** (0 pruebas Linux) | ✔ necesita script propio |
| **ATA004** | **T1489** Service Stop (*Impact*) | **de ART** | `T1489` → **`cubierta`** (5 pruebas Linux) | ✔ control ART |

**Por qué estas (declarado, para la memoria):**

- **Son 2 manuales + 1 de ART** exactamente como se pidió: los 2 manuales validan el **camino
  nuevo**; el de ART es el **control** que confirma que la maquinaria sigue midiendo igual.
- **ATA007 (T1491) y ATA012 (T1119)** son **manuales obligados**: no existen pruebas de Linux en
  ART (verificado: `tests_linux=0`). Al ser manuales, **los diseña y escribe el TFG**.
- **ATA004 (T1489) como control de ART** es la única opción de ART **sin NAT y sin instalaciones**
  que además **añade una superficie de telemetría nueva** (ver §2.1): `systemctl` (execve) +
  **journald/systemd** + elevación/PAM — patrones todavía no vistos en el piloto (que solo vio
  `execve` + watch de `lab-legit`).
  - **Alternativa DESCARTADA (decisión del humano, 2026-09-26):** **ATA001 (T1486, `openssl`)** —
    misma familia *Impact*, **sin `sudo`** y sin NAT (prueba *Encrypt files using openssl*, GUID
    `142752dc-ca71-443b-9359-cf6f497315f1`). **Se descarta**: repetir el perfil "cifrado/`openssl`"
    (`execve` → `80792`, como `dd`) **aporta menos** que `Service Stop`, que añade **telemetría
    nueva** (journald/systemd). **No es una opción abierta en el gate.**
- **Lo que NO se elige y por qué:** `T1567` (ATA009) y `T1074.001` (ATA011) exigen **internet**
  (NAT desconectado); `T1486` con `gpg`/`7z`/`ccrypt` exige **paquetes nuevos** (rompe `lab-listo`
  prístino y obligaría a **re-baselinar**). Todo eso queda para el escalado.
- **Nota metodológica:** los 2 manuales **no salen de `cobertura_atomic.csv`** (son `custom`); el
  control **sí** cita GUID/path/commit de ART (§2). La distinción *"la técnica no aplica a Linux"*
  ≠ *"la biblioteca no la cubre en Linux"* se mantiene: **T1491 y T1119 SÍ aplican a Linux**.

---

## 2. Decisión 2 — Los 2 ataques manuales: qué hacen y dónde escriben

> ⚠️ **Hecho que condiciona el diseño (verificado en el repo):** la telemetría disponible es
> (a) **`execve` de todo binario** → regla `80792` (*Audit: Command*, key `audit-wazuh-c`);
> (b) **watch de escritura** solo sobre **`/etc`** y **`/home/angel/lab-legit`** (key
> `audit-wazuh-w` → `80780`/`80781`/`80790`); (c) **FIM (syscheck)** solo sobre
> `/etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot`; (d) **journald/systemd** (sí se ingiere:
> `location":"journald"`). **`/home/angel/lab-attack/` NO es una ruta watch** → escribir ahí **no**
> genera alerta de escritura (por eso ATA013 escribió ahí y no alertó; se detecta por `execve`).
> **`/etc` no es escribible por `angel`** sin `sudo`.

### 2.1 ATA007 · T1491 Defacement (manual) — **watch de escritura** en `lab-legit`

- **Qué hace:** **modifica el contenido de una página "pública" simulada** (mock web) mediante
  **`cp`** de un HTML de defacement (staged en la carpeta del ataque) sobre el fichero objetivo.
- **Dónde escribe:** **`/home/angel/lab-legit/public_site/index.html`** — la **única ruta
  escribible por `angel` que está watch de auditd** (por eso ATA002 usó `lab-legit`, cambio D1).
  El fichero es un **mock** (no hay servidor web); se declara en el README.
- **Cómo (esqueleto del `ATA007_ataque.sh`):**
  ```bash
  SRC="$HOME/lab-attack/ATA007/defacement.html"      # página de defacement (la trae el artefacto)
  DST="$HOME/lab-legit/public_site/index.html"        # fichero "público" simulado (dir VIGILADO)
  mkdir -p "$(dirname "$DST")"                         # execve mkdir
  [ -f "$DST" ] || cp "$SRC" "$DST"                    # 1) siembra de la página "legítima" si no existe
  cp "$SRC" "$DST"                                     # 2) DEFACEMENT: sobrescribe (execve cp + write)
  ```
  - Sin `sudo` (la ruta es de `angel`). Revert a `lab-listo` lo borra todo.
- **Telemetría que espero:** `execve` de **`cp`** (`80792`) **y** los eventos **watch de escritura**
  de `lab-legit` (`80781` *write* / `80790` *creat*). **Por qué sí:** `lab-legit` está en el `-w`
  de auditd (verificado en `auditd_tfg.rules`), y `cp` **no** lo silencia ninguna regla de fábrica
  (a diferencia de `python3`/`92600`) → **espero DETECCIÓN**.

### 2.2 ATA012 · T1119 Automated Collection (manual) — **`execve`** (collect + stage)

- **Qué hace:** **recolecta automáticamente** ficheros legibles del sistema y los **almacena
  (stage)** para exfiltración posterior.
- **Dónde escribe:** **`/home/angel/lab-attack/ATA012/`** (NO vigilado → **no** habrá watch; la
  detección es por `execve`, igual que ATA008/ATA013).
- **Cómo (esqueleto del `ATA012_ataque.sh`):**
  ```bash
  OUT="$HOME/lab-attack/ATA012/collected"
  mkdir -p "$OUT"                                       # execve mkdir
  # recolección automatizada de ficheros de configuración legibles
  find /etc -maxdepth 2 -type f -readable \
       \( -name '*.conf' -o -name 'hosts' -o -name 'passwd' -o -name 'os-release' \) \
       -exec cp -t "$OUT" {} + 2>/dev/null               # execve find + cp
  tar czf "$HOME/lab-attack/ATA012/collected.tar.gz" -C "$OUT" . 2>/dev/null   # execve tar (staging)
  ```
  - Sin `sudo` (lee rutas world-readable). Revert a `lab-listo` lo borra.
- **Telemetría que espero:** `execve` de **`find`**, **`cp`** y **`tar`** (`80792` cada uno).
  **Por qué sí:** ninguno está silenciado por una regla de fábrica (el silenciador conocido,
  `92600`, solo casa `python`); si el `find`/`cp`/`tar` se ejecutara con `python3`/`sh` se
  añadiría el `execve` del intérprete. **Espero DETECCIÓN** (≥3 eventos).

### 2.3 ATA004 · T1489 Service Stop (control de ART)

- **Prueba:** *Linux - Stop service using systemctl* — **GUID** `42e3a5bd-1e45-427f-aa08-2a65fa29a820`,
  path `atomics/T1489/T1489.yaml`, commit pin `388942adbd9641f4dfdcf079d7efe9a75ec0ac43`.
  Cuerpo: `systemctl stop <service>` (por defecto **`cron`**); `elevation_required: true`.
- **Qué hace:** **para un servicio** (`cron`, fijado en paso 0). **Dónde:** no escribe ficheros;
  cambia el estado del servicio.
- **Elevación (declarada):** el script **se lanza ya elevado** — el **ejecutor** hace
  `echo '<contraseña del laboratorio>' | sudo -S bash ATA004_ataque.sh` (la contraseña **solo en
  memoria**, por `stdin`; **nunca** en el artefacto). Dentro del script, `systemctl stop cron` corre
  como root, **sin `sudo` anidado** → una sola elevación. El script comprueba `id -u` y **aborta**
  si no es root (sin secretos).
- **Telemetría que espero:** `execve` de **`systemctl`** (`80792`) **+** la parada del *unit*
  registrada en **journald/systemd** (reglas de grupo `systemd`, `40700`) **+** eventos de
  **elevación/PAM** (`5402`, `5501`, `5502`). **Por qué sí:** `systemctl` no está silenciado y el
  agente ingiere `journald`; **la parada de `cron` debe verse**. La **elevación** se declara como
  **ambigua** (§3) para que **no infle** el recuento de detección.

---

## 3. Decisión 3 — Señales esperadas (convención H4) e hipótesis de detección

**Se redactan ANTES de atacar** (borradores abajo) y **las valida el humano** (gate, §13). Fichero
por ataque en `Dataset/Ataques/Comandos/T<id>-<desc>/ATA<NNN>_esperado.csv` (esquema invariante de
7 columnas). **Regla H4:** toda señal `audit_exe` se **acompaña** de `audit_cwd` (carpeta del
ataque) para **anclar** el proceso al ataque y discriminar el churn.

| ATA | Borrador de señales (`senal_id,tipo,campo,patron,dato_componente,tecnica,nota`) |
|---|---|
| **ATA007** (T1491) | `T1491-S1,deteccion,audit_exe,cp,Process Creation,T1491,cp sobrescribe la pagina publica simulada` · `T1491-S2,deteccion,audit_cwd,/home/angel/lab-attack/ATA007/*,Process Creation,T1491,ancla H4` · `T1491-A1,ambigua,rule_id,80790,File Creation,T1491,creacion generica bajo watch (tambien en churn)` · `T1491-A2,ambigua,rule_id,80781,File Modification,T1491,escritura en ruta vigilada (la tapa el baseline) -> va a dudosa/revision humana` |
| **ATA012** (T1119) | `T1119-S1,deteccion,audit_exe,find,Process Creation,T1119,deteccion de ficheros` · `T1119-S2,deteccion,audit_exe,cp,Process Creation,T1119,copia de lo recolectado` · `T1119-S3,deteccion,audit_exe,tar,Process Creation,T1119,empaquetado/staging` · `T1119-S4,deteccion,audit_cwd,/home/angel/lab-attack/ATA012/*,Process Creation,T1119,ancla H4` |
| **ATA004** (T1489) | `T1489-S1,deteccion,audit_exe,systemctl,Process Creation,T1489,parada del servicio` · `T1489-S2,deteccion,audit_cwd,/home/angel/lab-attack/ATA004/*,Process Creation,T1489,ancla H4` · `T1489-A1,ambigua,audit_exe,sudo,Process Creation,T1489,elevacion (parte del ataque, no de la tecnica)` · `T1489-A2,ambigua,rule_id,5402,Privilege Escalation,T1489,sudo a root (ruido de elevacion)` |

- Las **PAM `5501`/`5502`** de la elevación **no se declaran**: el **paso 1.5 (H3)** las deja
  `dudosa` y el humano las resuelve a `ruido` (≈2–6 por ventana; limitación declarada de H3).
- ⚠️ **Señales amplias:** no se usa `rule_group` genérico (evita el cabo 4 del afinado); las señales
  de `audit_exe` van siempre con el **`audit_cwd`** del ataque.

### 3.1 Nota de método — **el baseline puede "tapar" una detección** (limitación declarada)

> **El baseline acota, no etiqueta** (`Dataset/Legitimo/baseline_meta.md` §9). Si un ataque
> **escribe donde escribe la vida normal** del sistema, sus **reglas de escritura caen en el
> catálogo de ruido** y el filtro las manda a `ruido_conocido` — **el catálogo no distingue una
> escritura normal de una de ataque en la misma ruta**.

- **Caso concreto (ATA007):** el defacement escribe en **`/home/angel/lab-legit`**, la **misma
  carpeta** donde trabajaba el script de baseline. Las reglas de escritura de esa ruta (`80781`,
  `80790`) **están en el catálogo** → la **escritura** del `defacement` se descartaría como ruido.
- **Mitigación (decisión):** esas **escrituras se declaran `ambigua`** (`T1491-A1` = `80790`,
  `T1491-A2` = `80781`) → van a **`dudosa` y las decide un humano**, **no** se descartan. **NO** se
  declaran `deteccion`: sería un **falso positivo fácil** (esas reglas también saltan por
  escrituras de sistema en rutas vigiladas).
- **La detección "dura" de ATA007 sigue siendo el proceso** (`execve cp` → `80792`, `S1`/`S2`); la
  escritura aporta la **evidencia de que el defacement ocurrió** y se revisa a mano.
- **A declarar en la memoria** como **limitación del método**: *cuando el ataque comparte ruta con
  la actividad legítima, el filtro por catálogo **desclasifica** la escritura; por eso las señales
  de ruta se marcan ambiguas y se resuelven por revisión humana.*
- **ATA012 NO tiene este problema:** escribe en **`/home/angel/lab-attack/`** (**NO vigilado** →
  **no** hay reglas de watch en esa ruta) → no aplica la limitación; su detección es por `execve`
  (`find`/`cp`/`tar`), que **no está en el catálogo de ruido**.

**Hipótesis de detección (a confirmar por la medición; se escribe ANTES, no se ajusta después):**

| ATA | Espero | Razón |
|---|---|---|
| **ATA007** | **DETECTADO por el proceso** | `execve cp` (`80792`, no silenciado) = detección dura. La **escritura** en `lab-legit` (`80781`/`80790`) se declara **ambigua** → **`dudosa`/revisión humana**, no detección automática (§3.1). |
| **ATA012** | **DETECTADO** | `execve find/cp/tar` (`80792`); ninguno silenciado. |
| **ATA004** | **DETECTADO** (con matiz) | `execve systemctl` + `journald`; matiz: parte del recuento puede venir de la **elevación** → por eso se declara como **ambigua**. |

> **La captura C0 (§4) decide si alguna de estas detecciones queda silenciada por una regla de
> fábrica** (level 0). Si `C0` avisa → el "0 detecciones" (si ocurre) queda **explicado**.

---

## 4. Decisión 4 — La captura **C0 por técnica** (cabo 3 del afinado) ⭐

> **Por qué es obligatorio:** el chequeo **C0** del pre-flight **consume una captura de
> `wazuh-logtest` con el ruleset base** y **avisa** si una regla de fábrica (`level 0`) **silencia**
> la detección esperada. El silenciador `92600` (`python3`) es **de fábrica** y actuó en ATA013 con
> **RS3/RS4 vacías** → **aplica siempre**, también con 0 reglas propias.

**Procedimiento (quién / cuándo / dónde):**

1. **Quién:** el **ejecutor**, en el **paso 0** (necesita root para `wazuh-logtest`; **solo
   lectura**). La contraseña del laboratorio se usa **solo en memoria** (`sudo -S` por `stdin`).
2. **Cuándo:** **una vez por técnica**, **antes** del primer `t0` de esa técnica (las 3 se pueden
   capturar juntas en el paso 0).
3. **Cómo (por técnica):** partiendo de una **línea real de `audit.log`** (adaptada del golden
   `fixtures/c0_logtest_python3_ls.txt`), cambiar `comm`/`exe` por el del proceso clave y alimentar
   `wazuh-logtest`:
   ```bash
   # en el MANAGER, con el ruleset BASE (0 reglas propias)
   printf '%s\n' '<linea audit type=SYSCALL ... comm="cp" exe="/usr/bin/cp" ... key="audit-wazuh-c">' \
     | sudo -S /var/ossec/bin/wazuh-logtest -v  > c0_ATA007.txt 2>&1
   ```
   - **ATA007:** línea `execve` de **`cp`** (`exe="/usr/bin/cp"`, `key="audit-wazuh-c"`).
   - **ATA012:** líneas de **`find`**, **`cp`**, **`tar`** (mismo formato).
   - **ATA004:** línea de **`systemctl`** (`exe="/usr/bin/systemctl"`).
4. **Dónde se guarda (versionado):** `Soporte/Ataques/c0/ATA<NNN>_logtest.txt` (una por técnica).
   *(Formato idéntico al golden: bloques `Phase 1/2/3` + regla ganadora.)*
5. **Ejecutar C0 offline** y dejar el informe:
   ```bash
   python _artefactos/scripts/preflight_enmascaramiento.py \
     --logtest-base-c0 Soporte/Ataques/c0/ATA<NNN>_logtest.txt \
     --out Soporte/Ataques/c0/ATA<NNN>_preflight.md
   ```
   - `RESULTADO: PASA (AVISOS: C0=1)` significa que **hay** silenciador de fábrica (se documenta);
     sin captura → `INCOMPLETO` (**nunca** se mide sin C0).
6. **Evidencia:** las capturas + los informes `ATA<NNN>_preflight.md` se **versionan** y se citan en
   la ficha de cada ataque.

> **Ejemplo de cómo se hizo el golden:** `_artefactos/scripts/tests/fixtures/c0_logtest_python3_ls.txt`
> (captura real de `wazuh-logtest -v`, dos líneas: `python3`→`92600` level 0 = **AVISA**; `ls`→`80792`
> level 3 = **no avisa**). Las capturas del bloque **replican ese formato**, una por técnica.

---

## 5. Decisión 5 — El ciclo y el criterio (se reutiliza lo validado)

- **Ciclo:** se usa **tal cual** el runbook `Soporte/Ataques/piloto_procedimiento.md` (12 pasos):
  revert a `lab-listo` → (ataque) → scan FIM forzado → `t1` → espera → extracción del **fichero
  diario** `[t0,t1]` → **filtrado por agente** (`victima-linux`) → `filtrar_ruido.py` con las
  señales → revisión de `dudosa` → ficha + bitácora + fila de `ATA_index.csv`.
  - **`t0` tras el asentamiento (H2):** sellar `t0` **≥ 60–90 s** después de confirmar el agente
    `Active` (así el churn de arranque queda **fuera** de `[t0,t1]`).
  - **Filtro nuevo (paso 1.5, H3):** `5715` con `srcip` del operador y `19004` (SCA) se
    auto-excluyen; **`5501`/`5502` → `dudosa`** (revisión humana).
  - **3 técnicas × 2 iteraciones = 6 ventanas.** El manager **nunca** se revierte.
- **Criterio de doble iteración:** **v2** (`Soporte/Ataques/criterio_doble_iteracion.md`): decide la
  **detección** (mismo conjunto de `rule_id` de detección + `|n2−n1| ≤ max(2, 10 %·n1)` + sin
  `dudosa` sin resolver); las **sanidades** de `auto_ruido`/`ruido_conocido` **son aviso**, no
  bloquean. Verdicto `iguales`/`review`.
- **Rutas (convención `linux/`):** artefactos en `Dataset/Ataques/Comandos/…`; resultados en
  `Dataset/Ataques/Resultados/Wazuh/linux/{CSV,Auditado,Logs}`; ficha
  `…/linux/ATA<NNN>_meta.md`; bitácora `Bitacora/ATA<NNN>.json`.

> **El ATaque manual no cambia el ciclo**: solo cambia **de dónde sale el script** (lo escribimos
> nosotros en vez de copiar el cuerpo de una atómica). Esa es la hipótesis a validar.

---

## 6. Decisión 6 — Los 2 arreglos previos (cabos del afinado)

### 6.1 Cabo 1 — default de `--out`/`--rev-out` de `filtrar_ruido.py`

- **Problema:** `DEFAULT_AUDITED_DIR = "Dataset/Ataques/Resultados/Wazuh/Auditado"` (**sin `linux/`**)
  → una ejecución **sin `--out`** escribe **fuera** del árbol versionado por SO.
- **Arreglo (KISS):** `DEFAULT_AUDITED_DIR = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"`.
- **Verificación:** (a) los **75 tests** siguen en verde (las suites pasan `--out` **explícito** →
  no dependen del default; verificado por inspección); (b) **se añade un test** que asegura que el
  default **contiene `linux/Auditado`** (guard de regresión); (c) se actualizan las **rutas del
  default** en `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §1 y la **nota de enganchón**
  del runbook (paso 10), que deja de ser deuda.
- **Alcance:** cambio **mínimo**; **no** altera el formato ni el determinismo de la salida.

### 6.2 Cabo 5 — puntero en el runbook §6

- **Problema:** el runbook §6 (H1) contiene una frase **histórica** ("considerar ampliar **C1**…")
  que puede confundir al lector de la memoria.
- **Arreglo:** añadir en §6 (subsección H1) un **puntero explícito a §7**: *"H1 quedó resuelto en el
  afinado como chequeo **C0** (base-contra-base); la referencia a C1 es **histórica** — ver §7"*.
- **Alcance:** **una línea** de documentación; no cambia código.

---

## 7. Decisión 7 — Qué se espera aprender por técnica (y qué NO)

| Técnica | Qué aprende el TFG | ¿Se puede verificar **sin** lanzar el ataque? |
|---|---|---|
| **ATA007** (T1491) | Si un defacement **manual** se detecta por el **proceso** (`execve cp`) **aunque el baseline "tape" la escritura** en la ruta compartida (`lab-legit`), y cómo se resuelve esa escritura por **revisión humana** (§3.1). | **Sí:** el tester comprueba el artefacto, las señales H4 (incluidas las `ambigua`), la captura C0 y recomputa la doble iteración desde los CSV. |
| **ATA012** (T1119) | Si un proceso **`find`/`cp`/`tar`** escrito a mano es detectable por `execve` (y si el **listado de herramientas** del esperado cubre todas las detecciones). | **Sí:** ídem (artefacto + señales + C0 + recomputo). |
| **ATA004** (T1489, ART) | Si la **elevación** (`sudo`/PAM) contamina el recuento y si el **journald** añade detección; valida que el control ART sigue midiendo. | **Sí:** ídem; además C0 confirma si `systemctl` está silenciado. |

> **Lo que este bloque NO pretende:** cobertura, resultados definitivos, η, escribir reglas. Busca
> **descubrir los enganchones del ataque manual con poco riesgo** (el mismo espíritu del piloto 1).

---

## 8. Ficheros que se tocarán

| Fichero | Cambio |
|---|---|
| `Dataset/Ataques/Comandos/T1491-Defacement/{README.md,ATA007_esperado.csv,ATA007_ataque.sh,defacement.html}` | **nuevos** (artefacto R-13, manual) |
| `Dataset/Ataques/Comandos/T1119-Automated_Collection/{README.md,ATA012_esperado.csv,ATA012_ataque.sh}` | **nuevos** (artefacto R-13, manual) |
| `Dataset/Ataques/Comandos/T1489-Service_Stop/{README.md,ATA004_esperado.csv,ATA004_ataque.sh}` | **nuevos** (artefacto R-13, ART) |
| `Dataset/Ataques/Resultados/Wazuh/linux/**` | **nuevos** (CSV, Auditado, Logs, `ATA<NNN>_meta.md`) |
| `Soporte/Ataques/c0/{ATA007,ATA012,ATA004}_logtest.txt` + `…_preflight.md` | **nuevos** (cabo 3) |
| `Bitacora/ATA004.json`, `ATA007.json`, `ATA012.json` | **nuevos** |
| `Hojas/ATA_index.csv` | **solo** las filas ATA004/007/012 (`estado`); **las otras 10 intactas** |
| `_artefactos/scripts/filtrar_ruido.py` | **cabo 1**: default `--out`/`--rev-out` → `…/Wazuh/linux/Auditado` |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | **+1 test** (guard del default) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | **cabo 1**: rutas del default (§1) |
| `Soporte/Ataques/piloto_procedimiento.md` | **cabo 5** (puntero §6→§7) + nota del paso 10 (default arreglado) |
| `state.md`, `roadmap.md` | al **cierre** (orquestador) |

**No se toca:** los artefactos **cerrados** del piloto/afinado (sus `_esperado.csv`, `-Audited.csv`,
fichas, bitácoras, `-Detalle.csv`), `extraer_alertas.py`, `preflight_enmascaramiento.py`,
`Soporte/Wazuh/Reglas/**` (RS3/RS4), `Hojas/Detecciones.xlsx`, `BBDD/`, `_recursos/`.

---

## 9. Criterios de aceptación y casos de prueba

| # | Criterio (verificable) | Caso de prueba |
|---|---|---|
| **CA1** | 3 técnicas: **2 manuales** (ATA007/T1491, ATA012/T1119) + **1 de ART** (ATA004/T1489). | Leer §1 + `cobertura_atomic.csv` (T1491/T1119 = `solo_windows`; T1489 = `cubierta`). |
| **CA2** | **C0 por técnica**: captura versionada + informe del pre-flight. | Existen `Soporte/Ataques/c0/ATA00{4,7}…_logtest.txt` y `…_preflight.md`; sin captura → `INCOMPLETO`. |
| **CA3** | **6 ventanas** reales (3×2) desde revert fresco; `t0` **tras asentamiento**; `t0<t1` UTC; extracción del **fichero diario**. | `times.log` de las 6 + cabecera del detalle (ruta del diario). |
| **CA4** | Los 2 **ataques manuales** son **scripts propios** (no copias de ART) y **sin secretos**; el de ART cita GUID/path/commit. | `README.md` + `git diff` + `grep` de la contraseña (no aparece). |
| **CA5** | Señales **H4** (`audit_exe` **+** `audit_cwd`) **redactadas antes** y **validadas por el humano**. | `sha256` del esperado + comentario de cabecera con la fecha de validación + cabecera del audited (`modo=ataque`). |
| **CA6** | Criterio **v2** aplicado y registrado (`iguales`/`review`); sanidades **solo aviso**. | Comparar `rule_id` de detección y `|n2−n1| ≤ max(2,10 %·n1)` en los 2 audited de cada ataque. |
| **CA7** | **Cabo 1**: el default de `--out`/`--rev-out` cae en `…/Wazuh/linux/Auditado`; **75 tests verdes** + test del default. | `pytest` en verde; `filtrar_ruido.py` sin `--out` escribe bajo `…/linux/Auditado`. |
| **CA8** | **Cabo 5**: el runbook §6 apunta a §7 (frase histórica marcada). | Leer el runbook: puntero presente. |
| **CA9** | **Determinismo (R-13):** re-ejecutar el filtro → audited **byte a byte** idéntico. | `sha256` igual en dos pasadas. |
| **CA10** | **Aislamiento por agente:** 0 filas de otro agente en los 6 `-Detalle.csv`. | Contar `agent_name ≠ victima-linux` = 0. |
| **CA11** | Solo las **3** filas nuevas de `ATA_index.csv` cambian; piloto/afinado **intactos**. | `git diff Hojas/ATA_index.csv` + `git status` (sin cambios en artefactos cerrados salvo los 2 arreglos). |
| **CA12** | **Sin instalaciones** (`lab-listo` prístino) y sin reglas RS3/RS4. | `git status` + `apt/dpkg` sin actividad nueva + 0 reglas propias en el manager. |
| **CA13** | **ATA007**: las **escrituras** de ruta vigilada (`80781`, `80790`) se declaran **`ambigua`** (→ `dudosa`/revisión), **nunca `deteccion`**; la nota de limitación (§3.1) está documentada. | Leer `ATA007_esperado.csv` (A1=`80790`, A2=`80781` con `tipo=ambigua`) + §3.1 presente; en el audited, esas filas salen `dudosa` (no `ruido_conocido`). |

---

## 10. Cómo se verifica (`tfg-tester`) — **sin lanzar ataques**

El tester **no ataca ni enciende VMs**. Verifica **procedimiento + artefactos + resultados**:

1. **Suite:** `pytest _artefactos/scripts/tests/` en verde (incluido el **test nuevo del default**).
2. **Cabo 1:** comprobar por inspección/ejecución que el default apunta a `…/Wazuh/linux/Auditado`
   y que la doc coincide.
3. **Cabo 5:** el puntero §6→§7 existe en el runbook.
4. **Artefactos:** los 3 `README.md` + los 3 scripts existen; los 2 manuales **no** copian ART
   (son `custom`); el de ART cita GUID/path/commit; **sin secretos**.
5. **Esperados:** esquema exacto (7 columnas); **H4** (`audit_exe` + `audit_cwd`); redactados
   **antes** (fecha/commit anterior a los resultados); **validación humana** registrada. En
   **ATA007**, comprobar (CA13) que `80790`/`80781` son **`ambigua`** (no `deteccion`) y que §3.1
   está documentado.
6. **C0:** las 3 capturas versionadas existen y los informes `…_preflight.md` están presentes;
   `INCOMPLETO` si falta captura.
7. **Resultados:** los 6 audited con las **15 columnas** exactas; `modo=ataque`; conteos de cabecera
   = reales; **0 `dudosa` sin resolver**; `t0<t1` y coherentes con el detalle.
8. **Doble iteración (CA6)** recomputada desde los CSV → veredicto registrado en bitácora/índice.
9. **Determinismo (CA9)**, **aislamiento (CA10)**, **`ATA_index.csv` solo 3 filas (CA11)**,
   **sin secretos** y **`_recursos/` intacto**. **Veredicto PASA/FALLA con evidencia.**

---

## 11. Qué NO entra (fuera de alcance)

- Las **7 técnicas restantes** del corpus (**no se tocan sus filas** de `ATA_index.csv`):
  ATA001, ATA003, ATA005, ATA006, ATA009, ATA010, ATA011.
- **Windows** y el *split* del baseline por SO.
- **η / precio de la detección** (Fase 4) y las **gráficas**.
- **Escribir reglas RS3/RS4** y su pre-flight de despliegue.
- `Hojas/Detecciones.xlsx`, `BBDD/wazuh.db`, `Estudio-Wazuh/` (T-12).
- **Instalar dependencias / re-baselinar**; reconectar NAT.
- **Redactar la memoria** / tocar `_recursos/`.
- **Recalcular** los 3 ataques del piloto (cerrados; conservan su `review` histórico v1).
- **Expropiar** el camino ART ya validado: este bloque **solo** añade el camino manual.

---

## 12. Paso 0 (lo que el ejecutor fija antes de tocar nada; requiere VMs encendidas + root)

1. **Estado:** `wazuh-manager/indexer/dashboard = active`; agente `001` `Active`; **NAT
   desconectado**; **0 reglas propias**; `df -h /` ≥ 10 GB.
2. **Relojes:** `date -u` víctima↔manager, `|Δ| < 1 s`.
3. **Dependencias (sin instalar):** en la víctima `which cp find tar systemctl` y
   `systemctl is-active cron` (si `cron` no está activo, **fijar otro servicio benigno** y
   documentarlo; **nunca** parar `wazuh-agent`).
4. **Telemetría:** `sudo auditctl -l` y `/etc/audit/rules.d/tfg.rules` (confirmar watch de
   `/home/angel/lab-legit` y de `/etc`) + rutas FIM del agente. Constancia de que
   **`/home/angel/lab-attack` NO es ruta watch**.
5. **Fichero diario de hoy:** `ls /var/ossec/logs/alerts/2026/Sep/` → fijar la ruta exacta.
6. **Capturas C0 por técnica** (§4) + ejecutar el pre-flight C0 offline; guardar en
   `Soporte/Ataques/c0/`.
7. **No regresión:** `extraer_alertas.py --test` y `filtrar_ruido.py` sobre el ejemplo del repo
   (exit 0); tras el **cabo 1**, verificar que el default nuevo escribe bajo `…/linux/Auditado`.
8. **Confirmar** que `operador srcip` sigue siendo la IP del host en VMnet1 (H3).

> La **contraseña del laboratorio** se usa **solo en memoria** (`sudo -S` por `stdin`); **jamás** en
> el repo, scripts ni documentación (ahí: *"la contraseña del laboratorio"*).

---

## 13. Qué tiene que aprobar el humano (gate)

1. Las **3 técnicas** (§1): **2 manuales** (ATA007/T1491, ATA012/T1119) + **1 de ART**
   (ATA004/T1489, **fijada**). La alternativa **ATA001 (T1486/openssl) queda DESCARTADA** (por
   telemetría) y **ya no es una opción abierta**.
2. El **diseño de los 2 ataques manuales** (§2): ATA007 **escribe en `lab-legit`** (mock público);
   ATA012 **stagea en `lab-attack`**; ambos **sin `sudo`**.
3. La **elevación de ATA004** (el ejecutor lanza el script con `sudo -S`; contraseña **solo en
   memoria**; cero secretos en artefactos).
4. Las **señales esperadas** (§3, borradores) y la **convención H4**; se **validan antes** del
   primer `t0` (**segundo gate**, como en el piloto). En particular, en **ATA007** las escrituras
   de ruta vigilada (`80790`, `80781`) van como **`ambigua` → revisión humana**, y la
   **limitación "el baseline puede tapar la detección"** (§3.1) se **declara en la memoria**.
5. La **captura C0 por técnica** (§4) como **paso obligatorio** del paso 0 (con root).
6. El **criterio de doble iteración v2** (§5) y la **reutilización íntegra** del runbook.
7. Los **2 arreglos previos** (§6): cabo 1 (default `--out`) y cabo 5 (puntero del runbook).
8. Que **este bloque NO escribe reglas RS3/RS4**, **no escala** a las 7 restantes, **no toca** los
   artefactos cerrados (salvo los 2 arreglos) y **no mide η**.

---

> **Resumen para el ejecutor — lo que necesito:** las **VMs encendidas** y la **contraseña del
> laboratorio** (solo en memoria) para el **paso 0** (§12: deps, telemetría, **capturas C0**) y para
> ejecutar **ATA004** con elevación. Sin la captura **C0** de cada técnica, **no se mide** (C0 queda
> `INCOMPLETO`); sin los `esperado` validados por el humano, **no se ataca** (`exit 3`).
