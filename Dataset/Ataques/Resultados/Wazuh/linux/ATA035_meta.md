---
fase: 3
bloque: fase-03-ampliacion-2
tanda: B
ata_id: ATA035
tecnica: T1056.004
tactica: Collection / Credential Access
version: 2
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA035 · T1056.004 Credential API Hooking (`LD_PRELOAD`) — Linux / `victima-linux`

> Bloque `fase-03-ampliacion-2` (**tanda B**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`** (antes `review`; el falso positivo `rule_id 11` se arregló en el bloque
> `fase-03-auditoria-metodologica`, v2 de esta ficha; ver §9 y §10.2).
> Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA035** |
| Técnica | **T1056.004 — Credential API Hooking** |
| Táctica | Collection / Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (atómica solo Windows) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** del proceso de laboratorio; la **carga del módulo** es invisible |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `LD_PRELOAD=hook.so` sobre el binario **de laboratorio** `credfetch` (hook de `fgets`/`getenv`) |
| Efecto | `hook_capture.log` captura el **token de entorno** y la **contraseña del fichero** (simulados) |
| Elevación | **no** |
| Payload | **precompilado** (la víctima **no tiene compilador**; fallback R1): `.so` + binario transportados como `.b64` y decodificados con `base64 -d` |

Artefacto: `.../T1056.004-Credential_API_Hooking/ATA035_ataque.sh`
(`sha256=3da29a71ab74b61f65b9abc97ece122fa35cd39c781cf604dbee93eb3045ba09`).
Señales: `.../ATA035_esperado.csv` (`sha256=b7a85c704ab3f31a32bc6079588ef465cf790aaa378d3b0948923a436339bf09`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA035_logtest.txt` (`sha256=38e43bca8e1800cbb65274c607042dfcefab6d57bcb6cb7b9f457564d64cbc82`)
→ `ATA035_preflight.md` (`sha256=2c8b303078bb29c70f40f361fe6bf4de44eabead726acc0ca87dbceac3a8ddaa`) **PASA**
(2 eventos `base64`/`credfetch_c0` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
~95 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T10:19:26Z` | `2026-09-29T10:19:58Z` | 32 s | 978 | `3da29a71…ba09` |
| 2 | `2026-09-29T10:23:40Z` | `2026-09-29T10:24:12Z` | 32 s | 928 | `3da29a71…ba09` |

> **Nota de evidencia (iter1):** el `ejecucion.out`/`times.log` de iter1 se **recuperaron de la
> consola de ejecución** (la carpeta `lab-attack` se borra al revertir para iter2); su contenido es
> **literal** (el guion hace `tee`). iter2 sí conserva el fichero original.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA035
bash ATA035_ataque.sh   # base64 -d de hook.so/credfetch + LD_PRELOAD credfetch
```

## 6. Evidencia

`Logs/ATA035_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el hook interceptó las credenciales simuladas:**

| Iter | token env | contraseña fichero | `CRED_API_HOOKING` |
|---|---|---|---|
| 1 | **capturado** | **capturado** | **OK** ✅ |
| 2 | **capturado** | **capturado** | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 984 | 978 | 978 |
| 2 | 934 | 928 | 928 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 | UNKNOWN |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 978 | **1** | 600 | 362 | **0** | 15 | 13 | 965 | 0 | 0 | 0 |
| 2 | 928 | **1** | 620 | 292 | **0** | 15 | 11 | 916 | 0 | 0 | 1 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 | 0 |
| 2 | 1 | 1 · `{80792}` | 1 | 0 |

- **`80792` × 1/iter:** `execve` de `credfetch` anclado al `cwd` (señal `S1` ∧ ancla `S2`).
- **`rule_id 11` (iter2) — arreglado.** Era una alerta **interna del manager** (grupo `stats`,
  `full_log`: *«The average number of logs between 10:00 and 11:00 is 6588. We reached 16472.»*),
  **ajena al ataque**: trae campos `audit.*` (`audit_exe=/usr/lib/systemd/systemd-logind`,
  `audit_file=/run/systemd/sessions/6`) que **no** casaban los criterios previos de `auto_ruido`
  (que apuntan a `wazuh-agentd`/`/var/ossec`) → caía en **`novel`** → **`deteccion`** (falso
  positivo del criterio congelado). El bloque `fase-03-auditoria-metodologica` añadió al **final**
  de `detectar_auto_ruido` el predicado de la firma interna **`rule_id=11 ∧` grupo `stats`** →
  **`auto_ruido:stats`**. Ahora **`deteccion=1`** en las 2 iteraciones. **Ninguna** fila del ataque
  en `ruido` (`ruido_con_lab-attack=0`).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `10:19:28.027Z` `Audit: Command: …ATA035/credfetch` | **1/1** (`S1`) | 1 / 15 / 362 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `10:23:41.654Z` `Audit: Command: …ATA035/credfetch` | **1/1** (`S1`) | 1 / 15 / 292 | 1 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`** (cerrado)

- **C1′ (mismo conjunto de `rule_id` de detección):** ✅ — iter1 = `{80792}`; iter2 = `{80792}`
  (el falso positivo `rule_id 11` quedó **fuera** de `deteccion` al arreglarse, §10.2).
- **C2′ (recuento estable):** ✅ — `|1−1| = 0 ≤ max(2, 0.1·1) = 2`.
- **C3′ (sin `dudosa`):** ✅ — `dudosa=0`.
- **Veredicto:** **`iguales`** → **`cerrado`**. El `review` inicial (§9 de la v1) quedó **resuelto**
  al corregir el criterio congelado (bloque `fase-03-auditoria-metodologica`). Ver
  `Bitacora/ATA035.json`.

## 10. Limitaciones y hallazgos

1. **⭐ Hallazgo (punto ciego del HIDS).** El `execve` del **proceso de laboratorio** con el hook
   **sí** alerta (`80792`), pero el HIDS **no ve** la **carga del módulo** (`LD_PRELOAD`) ni la
   **intercepción de la API** (audit no audita el entorno ni las cargas de `.so`): **ve el proceso,
   no el hook**.
2. **⭐ Hallazgo (artefacto del mecanismo congelado) — RESUELTO.** La alerta **interna del
   manager `stats` (`rule_id 11`)** no estaba en el catálogo baseline → el filtro la marcaba
   **`novel` → `deteccion`** (falso positivo del **criterio congelado**). En ATA011 la misma regla 11
   cayó como `auto_ruido` **porque traía `audit_cwd=/var/ossec`**; aquí traía campos `audit.*`
   (`systemd-logind`/`/run/systemd/sessions`) que **no** casaban los criterios previos (que apuntan a
   `wazuh-agentd`/`/var/ossec`) → `novel`. Se arregló añadiendo **al final** de `detectar_auto_ruido`
   la firma **`rule_id=11 ∧` grupo `stats`** → `auto_ruido:stats` (bloque
   `fase-03-auditoria-metodologica`; las 86 ventanas solo cambian en esta fila). **No cambia** el
   veredicto de la técnica (era y sigue siendo `{80792}`, 1/1). Ya **no** provoca `review`.
3. **Fallback R1 declarado:** payload **precompilado** (la víctima no tiene `gcc`/`cc`/`make`).
4. **Sin `sudo`**; **0** filas del ataque en `ruido`. Realismo acotado declarado (README §9).

## 11. Filas `ruido` (para ratificación)

- **iter1: 362**; **iter2: 292** — **baseline** (PAM del login del operador, `sshd`, `591`…), ajenas
  al ataque. **0** filas del ataque en `ruido`.

---

## § Repetición auditada (rev)

> Bloque `fase-03-repeticiones` (**tanda R3**), **2026-10-01**. `esperado_rev` firmado **APROBADO 2026-10-01 (validación humana)** ANTES del primer `t0`. Añadido por `tfg-executor`. **Sin secretos.**

### Motivo

- **`motivo_repeticion` = `prestaging`.** Auditoría metodológica (`_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` §2; `Soporte/Ataques/criterio_ataques.md` §C): el ataque **preparaba su payload (`hook.so`/`credfetch`) dentro de `[t0,t1]`**, ensuciando la ventana con una preparación que **no es la técnica**.

### Qué cambió respecto al original (el original NO se toca)

- **Método original:** propio — decodificación del payload (`.b64`) + `LD_PRELOAD=hook.so credfetch` **dentro** de la ventana.
- **Método de la repetición (pre-staging):** el payload (`hook.so`, `credfetch`), la credencial simulada y el log se **materializan ANTES de `t0`** (modo `prestage`); la ventana ejecuta **solo** la acción de la técnica (`LD_PRELOAD`). Desaparecen las señales `ambigua` de creación del payload.
- **Material antes de `t0`:** `hook.so` (`sha256=dcee6f8cadc7179331dd7b00487f1eda50eebdfbc71f825eebf7db347e27f808`), `credfetch` (`sha256=ae68ff852fe2a2668762365340d2c871e383cbb1356b83d5c64efee911200479`), `credencial_simulada.txt`, `hook_capture.log` (ver `Logs/ATA035_rev{1,2}/prestaging.out`).

### Iteraciones (rev)

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | auto_ruido | ruido_conocido | artefacto_ataque | dudosa |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-01T21:30:20Z` | `2026-10-01T21:30:52Z` | 844 | **1** | 641 | 194 | 8 | 0 |
| 2 | `2026-10-01T21:34:21Z` | `2026-10-01T21:34:53Z` | 834 | **1** | 632 | 193 | 8 | 0 |

### Resultado (métrica congelada O1+O2)

- **O1 (detectado):** sí — `rule_id` = `['80792']`.
- **O2 (acciones cubiertas):** iter1 = 1/1 · iter2 = 1/1 (`S1`; el ancla `S2` no es detector).
  - iter1 primera evidencia: `2026-10-01T21:30:20.780Z` `audit_exe=/home/angel/lab-attack/ATA035/credfetch`.
  - iter2 primera evidencia: `2026-10-01T21:34:23.155Z` `audit_exe=/home/angel/lab-attack/ATA035/credfetch`.
- **Doble iteración (v2):** `iguales` (mismo `rule_id` de detección; recuento estable; sin dudosas).
- **`dudosa` resueltas:** iter1: ruido=5 · iter2: ruido=4 (PAM del login del operador).
- **0 filas del ataque en `ruido`** (pertenencia por carpeta).

### Prueba de efecto (independiente de la alerta)

- iter1 y iter2: `CRED_API_HOOKING=OK` — el hook capturó el token de entorno (`SERVICE_TOKEN toy-token-4242`) y la contraseña simulada (`clave-simulada-7777`); `credfetch_rc=0`.

### Cómo se cumple el motivo (pre-staging)

- El payload y la credencial se escribieron **ANTES de `t0`** (`prestaging.out`: `PRESTAGE=OK`); **ninguna** señal `ambigua` de la siembra (`80790`/`80781`/`80782`) cae en `[t0,t1]`. La ventana mide **solo** el `execve` del proceso con el hook.

### Trazabilidad

- `esperado_rev`: `…/T1056.004-Credential_API_Hooking/ATA035_esperado_rev.csv` (`sha256=22d26d8911147a2657f75c4e53c794f85c7fb82f1aba189e77332c4280f6a793`).
- `ataque_rev`: `…/T1056.004-Credential_API_Hooking/ATA035_ataque_rev.sh` (`sha256=e2ec504946b990612dc0687b817330ddac0548bf4f43290a9889a764a4fafe13`).
- C0: `Soporte/Ataques/c0/ATA035_rev_logtest.txt` + `ATA035_rev_preflight.md` (**PASA**, sin silenciadores).
- Detalle: `…/CSV/ATA035_rev{1,2}-Detalle.csv` · Auditado: `…/Auditado/ATA035_rev{1,2}-Audited.csv`.
