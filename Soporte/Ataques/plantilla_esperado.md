---
fase: 3
tarea: A3.0 (H4)
nombre: Plantilla y convención de señales esperadas por ataque
version: 1
status: vigente
fecha: 2026-09-26
autor: tfg-executor
---

# Plantilla de señales esperadas (`ATA<NNN>_esperado.csv`)

> **Convención H4 (fase-03-afinado §5).** Fija **cómo se redactan** las señales esperadas de un
> ataque para que las **10 técnicas nuevas nazcan específicas**. El **esquema** del fichero **no
> cambia** (7 columnas); cambia el **contenido** (una señal de contexto más).

---

## 1. Esquema (invariante, definido en A2.1)

```csv
senal_id,tipo,campo,patron,dato_componente,tecnica,nota
```

- `tipo ∈ {deteccion, ambigua}`.
- `campo ∈ {rule_id, rule_group, audit_exe, audit_cwd, audit_key, syscheck_path}`.
- `patron`: literal o glob `*` / `?` (fnmatch).
- Redactado **antes** de atacar y **validado por el humano** (gate).

## 2. Convención H4 — anclar el proceso al `cwd` del ataque

Toda técnica que **escriba en la carpeta del ataque** (`/home/angel/lab-attack/ATA<NNN>/`)
**acompaña** cada señal `audit_exe` con una señal de **contexto de directorio**:

```csv
T<id>-S1,deteccion,audit_exe,<herramienta>,Process Creation,T<id>,ejecucion de la herramienta (ver nota H4)
T<id>-S2,deteccion,audit_cwd,/home/angel/lab-attack/ATA<NNN>/*,Process Creation,T<id>,la senal de exe queda anclada al cwd del ataque
```

- **Regla de redacción:** `audit_exe` (proceso) **más** `audit_cwd` (carpeta del ataque) cuando el
  artefacto copia a `/home/angel/lab-attack/ATA<NNN>/`.
- **Por qué:** el `audit_cwd` **ancla** el proceso al ataque y **discrimina el churn** (`/`,
  `var/ossec`…). Una señal de `audit_exe` sola es **genérica** (cualquier `python3`/`dd` la activa).
- El `audit_cwd` se compara como **glob** contra el valor del campo (`/home/angel/lab-attack/ATA002/*`).

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

## 6. Referencias

- Decisión: `plan.md` bloque `fase-03-afinado` §5 (H4).
- Esquema y consumo: `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` §4.
- Procedimiento por ventana: `Soporte/Ataques/piloto_procedimiento.md`.
