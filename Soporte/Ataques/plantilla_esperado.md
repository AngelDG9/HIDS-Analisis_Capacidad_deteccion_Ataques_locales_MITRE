---
fase: 3
tarea: A3.0 (H4) · A3.0 (ancla implícita + evento de ejecución) · A3.0 (pertenencia al ataque)
nombre: Plantilla y convención de señales esperadas por ataque
version: 5
status: vigente
fecha: 2026-11-08
autor: tfg-executor
---

# Plantilla de señales esperadas (`ATA<NNN>_esperado.csv`)

> **Convención H4 (fase-03-afinado §5) · v4 (fase-03-metrica ciclo 2).** Fija **cómo se redactan** las
> señales esperadas de un ataque para que las **10 técnicas nuevas nazcan específicas**. El
> **esquema** del fichero **no** cambia (7 columnas); cambia el **contenido** (una señal de
> contexto más). En **v2** el ancla es un **mecanismo real** (AND `exe ∧ cwd ∧ audit_command`),
> no aspiracional: ver `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §4. En **v3** se
> añade la **pertenencia al ataque por carpeta** y el **veredicto humano `artefacto`**
> (política §3.ter/§5). En **v4** se declara que la pertenencia es **mecánica** y cubre **solo**
> `ATTACK_ROOT/<ATA_id>`: una fila del ataque **fuera** de esa carpeta se atribuye por el
> **veredicto humano** (`artefacto`), **nunca** `ruido`.
>
> **v5 (B1.0, 2026-11-08) — aditivo Windows.** Se añaden los campos `win_*` y el **ancla
> H4-W** (mecanismo `win_image ∧ ancla ∧ evento de ejecución`). **No** se toca el esquema de
> 7 columnas ni la convención H4 de Linux; un `esperado` Linux sigue siendo válido sin cambios.

---

## 1. Esquema (invariante, definido en A2.1)

```csv
senal_id,tipo,campo,patron,dato_componente,tecnica,nota
```

- `tipo ∈ {deteccion, ambigua}`.
- `campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key, syscheck_path}`.
- `patron`: literal o glob `*` / `?` (fnmatch).
- Redactado **antes** de atacar y **validado por el humano** (gate).

## 2. Convención H4 (v2) — anclar el proceso al `cwd` del ataque

Toda técnica que **escriba en la carpeta del ataque** (`/home/angel/lab-attack/ATA<NNN>/`)
**acompaña** cada señal `audit_exe` con una señal de **contexto de directorio**:

```csv
T<id>-S1,deteccion,audit_exe,<herramienta>,Process Creation,T<id>,ejecucion de la herramienta (ver nota H4)
T<id>-S2,deteccion,audit_cwd,/home/angel/lab-attack/ATA<NNN>,Process Creation,T<id>,ancla H4 (cwd sin /*; el patron con /* tambien casa)
```

- **Regla de redacción:** `audit_exe` (proceso) **más** `audit_cwd` (carpeta del ataque) cuando el
  artefacto copia a `/home/angel/lab-attack/ATA<NNN>/`. **Obligatorio** en v2: una señal `audit_exe`
  **sin** ancla deja el recuento ancho (el filtro emite un `AVISO`).
- **Por qué:** el `audit_cwd` **ancla** el proceso al ataque y **discrimina el churn** (`/`,
  `var/ossec`…). Una señal de `audit_exe` sola es **genérica** (cualquier `python3`/`dd` la activa).
- **Mecanismo (v2):** el ancla es una **condición AND**, no un detector: la señal `audit_exe` casa
  solo si `exe ∧ cwd-ancla ∧` evento de ejecución (`audit_command`). Lo que casa el `exe` pero falla
  el ancla o el evento → **`dudosa`** (`sin_ancla:<senal_id>`), nunca `deteccion` ni `ruido`.
- **Patrón:** el `audit_cwd` se compara como **glob** contra el valor del campo; se prueba el `cwd`
  **y** `cwd + "/"`, así que **tanto** `/home/angel/lab-attack/ATA<NNN>` (recomendado) **como**
  `/home/angel/lab-attack/ATA<NNN>/*` (los `esperado` congelados) casan el `cwd` real.

## 3. Retrocompatibilidad verificada con datos reales

La convención **no es teórica**: la señal `audit_cwd` **ya casaba** en los datos del piloto:

- **ATA002** (T1485): `audit_cwd=/home/angel/lab-attack/ATA002` en las **4 detecciones** (80781,
  80790, 80792).
- **ATA008** (T1048.002): `audit_cwd=/home/angel/lab-attack/ATA008` en las **2 detecciones** (80791,
  80792).

→ Añadir la señal de `audit_cwd` **no inventa** nada: confirma un campo que **ya estaba** en el
detalle por alerta (`extraer_alertas.py --detail`).

## 4. Ejemplo de formato

`Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/ATA001_esperado.csv` es un **EJEMPLO de
formato** (no un ataque ejecutado). Muestra la convención `audit_exe` + `audit_cwd`:

```csv
senal_id,tipo,campo,patron,dato_componente,tecnica,nota
T1486-S1,deteccion,audit_exe,openssl,Process Creation,T1486,herramienta de cifrado
T1486-S2,deteccion,audit_cwd,/home/angel/lab-attack/ATA001/*,Process Creation,T1486,la senal de exe queda anclada al cwd del ataque
T1486-S3,deteccion,rule_id,80782,File Creation,T1486,creacion bajo watch -> 80782 (verificado en el corpus); la senal gana al catalogo
T1486-S4,deteccion,audit_key,lab-attack*,File Modification,T1486,watch key del directorio del ataque
T1486-A1,ambigua,syscheck_path,/home/angel/lab-attack/*,File Modification,T1486,FIM del dir del ataque (puede ser legitimo)
```

> **⚠️ Corrección (2026-09-29, verificado en el corpus):** la **creación** de un fichero dentro de la
> carpeta del ataque **no** llega como `80790` (*Audit: Created*), sino como **`80782`**
> (*Audit: Watch - Write access*); según el caso pueden aparecer también **`80780`/`80781`/`80791`**.
> Declarar `80790` como señal de creación produce **señales muertas** (nunca casan): **los próximos
> `ATA<NNN>_esperado.csv` deben usar `80782`** para la creación vigilada del `.arc`/artefacto. Los
> `esperado` ya firmados **no se reescriben** (§5, regla 4).

## 5. Reglas de oro

1. **`audit_exe` siempre acompañado de `audit_cwd`** cuando el artefacto vive en la carpeta del
   ataque.
2. Las señales se redactan **antes** de atacar, con los datos del paso 0, y las **valida el humano**.
3. **Recuerda la garantía `CONFLICTO` (H3):** si declaras una señal `rule_id`/`rule_group` que casa
   el predicado `OPERADOR` (`5715`/`19004`), el filtro **avisa** y **gana la detección**.
4. ⚠️ **No se re-escriben** los `ATA<NNN>_esperado.csv` del **piloto** (cambiar un esperado invalida
   el `sha256` de sus `-Audited.csv`).
5. **Pertenencia al ataque (v3) — nada del ataque se llama "ruido".** La carpeta
   `/home/angel/lab-attack/ATA<NNN>/` es la **prueba demostrable** de pertenencia (la crea y usa
   solo el ataque). Toda fila del ataque que **no** case una señal `deteccion` declarada cae en
   **`artefacto_ataque`** (nunca `ruido_conocido`), y un `watch` sobre un fichero creado por el
   ataque **no** debe plegarse a `ruido`: usa el veredicto humano **`artefacto`** ("es el ataque,
   pero no cuenta como detección"). Un execve no declarado en la carpeta emite **`AVISO`**
   (posible detección no declarada) → valora declararlo.
   **(v4) La pertenencia es mecánica y cubre solo esa carpeta.** Una fila del ataque **fuera** de
   `/home/angel/lab-attack/ATA<NNN>/` (p. ej. el `mkdir` de *setup* de ATA007 en `lab-legit`) **no**
   la cubre la regla automática: se demuestra **a mano** (guion/ficha) y se pliega con el veredicto
   humano **`artefacto`** — **nunca** `ruido`.

## 6. Referencias

- Decisión: `plan.md` bloque `fase-03-afinado` §5 (H4).
- Esquema y consumo: `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §4.
- Procedimiento por ventana: `Soporte/Ataques/piloto_procedimiento.md`.

---

## 7. Perfil Windows — esquema v5 (aditivo, B1.0)

> **Aplica a Windows; Linux no cambia.** El fichero sigue teniendo **7 columnas**. Los campos
> `win_*` se usan **solo** en los `ATA<NNN>_esperado.csv` de `victima-windows`.

### 7.1 Campos admitidos en `campo`

| `campo` | Qué es | Uso |
|---|---|---|
| `win_image` | `Image` de Sysmon 1 / `NewProcessName` de 4688 | **detector** (proceso) |
| `win_command_line` | `CommandLine` de Sysmon 1 / 4688 | **ancla** si hay `win_image`; detector si no lo hay |
| `win_cwd` | `CurrentDirectory` (Sysmon 1; **puede faltar en 4688**) | **ancla** |
| `win_target` | `TargetFilename` de Sysmon 11 / destino de red de Sysmon 3 | **ancla** (si el extractor lo emite) |
| `syscheck_path` | ruta FIM | **ancla** y señal ambigua |
| `rule_id` | `rule.id` de Wazuh | detector |
| `rule_group` | grupo de la regla | detector |

- Los patrones son **glob** (`*`, `?`) y se comparan **sin distinguir mayúsculas** en Windows.
- El `win_image` se prueba **ruta completa y nombre base** (p. ej. `*\powershell.exe` casa
  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).

### 7.2 Regla H4-W (mecanismo, no aspiración)

Una señal `tipo=deteccion, campo=win_image` cuenta como **`deteccion`** solo si:

1. casa la **imagen**; **y**
2. casa **al menos una ancla** — `win_cwd`, `win_command_line`, `win_target` o
   `syscheck_path` — con `C:\lab-attack\ATA<NNN>`; **y**
3. la fila es un **evento de ejecución**: `event_id ∈ {1, 4688}` (Sysmon 1 o Seguridad 4688).

Lo que casa la imagen y **falla** el ancla o el evento → **`dudosa`**
(`motivo=sin_ancla:<senal_id>`), **nunca** `deteccion` ni `ruido`.

- Si el `esperado` **no** declara `win_image`, una señal `win_command_line` puede detectar por
  sí sola (comportamiento legado); se emite **`AVISO`** por `stderr` invitando a declarar
  `win_image` + ancla.
- Si el `esperado` declara `win_image` pero **no** declara ninguna ancla, se emite **`AVISO`**
  (recuento ancho) y se mantiene el comportamiento legado.
- La **pertenencia al ataque** es mecánica: `win_cwd`, `win_command_line`, `win_target` o
  `syscheck_path` bajo `C:\lab-attack\ATA<NNN>`. Una fila del ataque que no case una detección
  declarada cae en **`artefacto_ataque`**, nunca en `ruido_conocido`.

### 7.3 Ejemplo (T1041 / ATA074)

```csv
senal_id,tipo,campo,patron,dato_componente,tecnica,nota
T1041-S1,deteccion,win_image,*\powershell.exe,Process Creation,T1041,cliente de exfiltracion
T1041-S2,deteccion,win_command_line,*ATA074*,Command Execution,T1041,ancla H4-W
T1041-S3,deteccion,win_cwd,C:\lab-attack\ATA074*,Process Creation,T1041,ancla H4-W (solo Sysmon 1)
T1041-S4,deteccion,win_target,*ATA074*,Network Connection Creation,T1041,prediccion (Sysmon 3)
T1041-A1,ambigua,syscheck_path,C:\lab-attack\ATA074\*,File Creation,T1041,artefacto del ataque
```

> **Honestidad (B1.0).** `win_target` solo es evaluable si el extractor de Windows emite esa
> columna; si no está, la señal **no es evaluable** (no se inventa). En B1.0 el extractor
> (`extraer_alertas_windows.py`) emite `win_image`, `win_command_line`, `win_cwd`, `win_user` y
> `event_id`; `win_target` queda como **campo declarado pendiente** de ampliación aditiva en
> B1.1. Un `rule_id` solo se declara si está **probado**; si se predice, la columna `nota`
> lleva **`prediccion`**.

### 7.4 Reglas de oro (Windows)

1. `win_image` **siempre** acompañado de al menos un ancla (`win_command_line` o `win_cwd`).
2. El `esperado` se firma **antes** de `t0`; no se reescribe después.
3. **Nada del ataque se llama ruido**: la carpeta `C:\lab-attack\ATA<NNN>\` es la prueba.
4. Las `dudosa` se resuelven con `deteccion` / `artefacto` / `ruido` (este último **prohibido**
   sobre una fila del ataque).
5. Las reglas de Windows **no** están probadas en su mayoría: los `rule_id` predichos llevan
   `prediccion` en la nota (ver C0 `Soporte/Ataques/c0/windows/clases_evento.csv`).
