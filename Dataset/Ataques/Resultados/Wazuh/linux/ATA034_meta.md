---
fase: 3
bloque: fase-03-ampliacion-2
tanda: B
ata_id: ATA034
tecnica: T1560.003
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA034 · T1560.003 Archive via Custom Method (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion-2` (**tanda B**, 1.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Nota de criterio (2026-09-29):** el `estado` es **procesal** (cierre del ciclo y de la doble
> iteración), **no** un indicador de detección; **`review`** se usa cuando el criterio v2 **no** da
> `iguales` o hay **artefactos del mecanismo congelado**.
> **Tercer vértice del trío de archivo:** *utility* (ATA030, detectado) · *library* (ATA013, no
> detectado por `92600`) · **custom (ATA034, no detectado por AUSENCIA de telemetría de herramienta)**.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA034** |
| Técnica | **T1560.003 — Archive via Custom Method** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **ninguna señal de ejecución del archivado** (builtins); el **arnés sí ejecuta coreutils** (`mkdir`/`cat`/`sha256sum`…) → esos `execve` caen en **`artefacto_ataque`** (ver §8.1) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **builtins de bash** (`read`/`printf`/redirección); contenedor propio `ATA034-CUSTOM-ARCHIVE v1` |
| Efecto | `.arc` con formato propio + **reconstrucción 3/3** con `sha256` idéntico |
| Elevación | **no** |
| Guardarraíl | material/archivo/reconstrucción **solo** bajo `lab-attack/ATA034` |

Artefacto: `.../T1560.003-Archive_via_Custom_Method/ATA034_ataque.sh`
(`sha256=559f54ae22938e222c692b8718a6e4d8374ab4cb3156615e28d2520ca4d4259e`).
Señales: `.../ATA034_esperado.csv` (`sha256=a2f615624ba3631102e6454b0caef8559ad79fa7e7751dbbeb4e81d48eb7a763`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA034_logtest.txt` (`sha256=fb6992bc11d0b4ae0fb6157f0ce93fcf39ecedffb66a84528f8c1cb0671bf247`)
→ `ATA034_preflight.md` (`sha256=f903b4b8ac21e6cc25e9d44211464d4b995cdcbcbff2e6e52f71eae82f619255`) **PASA**
(1 evento `shell_c0` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
~95 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T10:09:13Z` | `2026-09-29T10:09:50Z` | 37 s | 769 | `559f54ae…259e` |
| 2 | `2026-09-29T10:14:11Z` | `2026-09-29T10:14:44Z` | 33 s | 921 | `559f54ae…259e` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA034
bash ATA034_ataque.sh   # archivado con BUILTINS (PATH=/nonexistent) + reconstruccion
```

## 6. Evidencia

`Logs/ATA034_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el archivo se creó con formato propio y se reconstruyó entero:**

| Iter | cabecera | `reconstruidos_sha256_ok` | `ARCHIVE_CUSTOM` |
|---|---|---|---|
| 1 | `ATA034-CUSTOM-ARCHIVE v1` | **3/3** | **OK** ✅ |
| 2 | `ATA034-CUSTOM-ARCHIVE v1` | **3/3** | **OK** ✅ |

- **Prueba de «cero binarios externos» (del bucle de archivado):** el bucle de archivado corrió con
  `PATH=/nonexistent` y **terminó bien** → **la operación de archivar** no invocó ninguna
  herramienta externa. (**Matiz:** el **arnés** sí ejecuta coreutils —`mkdir`, `cat`, `sha256sum`…—
  en *setup*/evidencia; esos `execve` **sí** generan telemetría y caen en `artefacto_ataque`, §8.1.
  Lo que **no deja rastro** es el **bucle de archivado**.)

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 775 | 769 | 769 |
| 2 | 927 | 921 | 921 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 769 | **0** | 617 | 125 | **0** | 27 | 1 | 768 | 0 | 0 |
| 2 | 921 | **0** | 605 | 287 | **0** | 29 | 10 | 911 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 0 | ∅ | — | 0 |
| 2 | 0 | ∅ | — | 0 |

- **`artefacto_ataque` (auto):** los `execve` **no declarados** de la mecánica (`date`, `mkdir`,
  `cat`, `head`, `sha256sum`, `rm`…) y un `watch` (`80782`) → todos con `audit_cwd` bajo la carpeta
  del ataque. **Ninguna** fila del ataque en `ruido` (verificado: `ruido_con_lab-attack=0`).
- **`dudosa`=0**: no hubo filas `80790`/`80781` (las escrituras del ataque caen en `lab-attack`, que
  **no** está bajo el `watch -w`; el `watch` genérico de `creat` emite `80782`, no declarado →
  `artefacto`).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **no** | ∅ | — (no hay detección) | **n/a (0/0)** | 0 / 27 / 125 | 0 / 0 `rule_id` |
| 2 | **no** | ∅ | — (no hay detección) | **n/a (0/0)** | 0 / 29 / 287 | 0 / 0 `rule_id` |

> **O2 = n/a (m=0):** el `esperado` **no declara señales `deteccion`** porque **la operación de
> archivar** (builtins) **no ejecuta ningún binario** que anclar. **Matiz:** el **arnés** sí ejecuta
> coreutils (`date`/`mkdir`/`cat`/`sha256sum`…) → esos `execve` **sí** son telemetría y caen en
> `artefacto_ataque` (§8.1); lo que **no deja rastro** es el **bucle de archivado** (funciones
> internas del shell). Es el **punto ciego por ausencia de telemetría de la operación de archivar**.

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`∅==∅` (mismo conjunto de `rule_id` de detección, vacío); `|0−0|=0 ≤ 2`; sin dudosas. Ver
`Bitacora/ATA034.json`.

## 10. Limitaciones y hallazgos

1. **⭐ Hallazgo (punto ciego por AUSENCIA de telemetría).** El **mismo objetivo** («archivar lo
   recolectado») queda:
   - **VISIBLE** con **utilidad** (`tar`/`gzip`, **ATA030**),
   - **INVISIBLE por silenciamiento** con **librería** `python3` (**ATA013**, regla hermana `92600`),
   - **INVISIBLE por ausencia de herramienta** con **método propio (builtins)** (**ATA034**).
2. **El intérprete (`bash`) sí alerta por `80792`**, pero es **genérico** (lo dispara cualquier
   script): **no** identifica la técnica y **no** se declara como detección (queda como
   `artefacto_ataque`, con su `AVISO`).
3. **Detección por `execve`** en el resto del corpus (R9); aquí **no hay detección por `execve`**
   (los `execve` del arnés caen en `artefacto_ataque`, §8.1): el HIDS ve *escrituras* y *procesos*,
   pero **no la semántica** de un archivado casero dentro de un intérprete.
4. **Matiz de redacción (2026-09-29) — «no detectado» NO significa «técnica indetectable».** Lo que
   es cierto: el **método propio (builtins)** **no genera telemetría de la operación de archivar**
   (por eso no hay `execve` de herramienta que anclar). La conclusión **depende de la
   implementación**: con un **binario propio compilado** habría `execve` → **detectable** (como
   ATA030, `utility`); con **`python3`** el `execve` existe pero queda **suprimido por `92600`**
   (ATA013, `library`). El hallazgo es **acotado**: el HIDS **no distingue el archivado casero
   dentro de un intérprete**; **no** es que la técnica sea indetectable en general.
5. **Sin `dudosa`** y **sin `sudo`**. Realismo acotado declarado (README §9).

## 11. Filas `ruido` (para ratificación)

- **iter1: 125**; **iter2: 287** — **baseline** (PAM del login del operador, `sshd`, `591`…), ajenas
  al ataque y sin `cwd`/ruta del ataque. **0** filas del ataque en `ruido`.
