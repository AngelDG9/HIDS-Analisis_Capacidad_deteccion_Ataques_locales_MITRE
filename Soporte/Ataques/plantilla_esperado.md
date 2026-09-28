---
fase: 3
tarea: A3.0 (H4) · A3.0 (ancla implícita + evento de ejecución) · A3.0 (pertenencia al ataque)
nombre: Plantilla y convención de señales esperadas por ataque
version: 4
status: vigente
fecha: 2026-09-28
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
T1486-S3,deteccion,rule_id,80790,File Creation,T1486,regla conocida: la senal gana al catalogo
T1486-S4,deteccion,audit_key,lab-attack*,File Modification,T1486,watch key del directorio del ataque
T1486-A1,ambigua,syscheck_path,/home/angel/lab-attack/*,File Modification,T1486,FIM del dir del ataque (puede ser legitimo)
```

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
