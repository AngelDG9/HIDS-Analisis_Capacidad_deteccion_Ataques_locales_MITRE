---
fase: 3
bloque: fase-03-ampliacion-2
tanda: B
ata_id: ATA035
tecnica: T1056.004
tactica: Collection / Credential Access
version: 1
status: review
fecha: 2026-09-29
---

# Ficha — ATA035 · T1056.004 Credential API Hooking (`LD_PRELOAD`) — Linux / `victima-linux`

> Bloque `fase-03-ampliacion-2` (**tanda B**, 2.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`review`**: criterio de doble iteración **v2** → **`review` JUSTIFICADO** (ver §9).
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
| 2 | 928 | **2** | 619 | 292 | **0** | 15 | 11 | 916 | 0 | 0 | 1 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 | 0 |
| 2 | 2 | 2 · `{80792, 11}` | 1 | **1** (`11`) |

- **`80792` × 1/iter:** `execve` de `credfetch` anclado al `cwd` (señal `S1` ∧ ancla `S2`).
- **Sorpresa de iter2:** **`rule_id 11`** — alerta **interna de Wazuh** (grupo `stats`,
  `full_log`: *«The average number of logs between 10:00 and 11:00 is 6588. We reached 16472.»*),
  **ajena al ataque**: **trae** campos `audit.*` (`audit_exe=/usr/lib/systemd/systemd-logind`,
  `audit_file=/run/systemd/sessions/6`), pero **ninguno casa los criterios de `auto_ruido`** (que
  apuntan a `wazuh-agentd`/`/var/ossec`, no a `/run/systemd`) → cae en **`novel`** (`rule_id` fuera
  del catálogo) → **`deteccion`**. Es un **falso positivo del criterio congelado** (no cambia el
  veredicto de la técnica). **Ninguna** fila del ataque en `ruido` (`ruido_con_lab-attack=0`).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `10:19:28.027Z` `Audit: Command: …ATA035/credfetch` | **1/1** (`S1`) | 1 / 15 / 362 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` (+`11`) | `10:23:41.654Z` `Audit: Command: …ATA035/credfetch` | **1/1** (`S1`) | 2 / 15 / 292 | 2 / 2 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`review` (justificado)**

- **C1′ (mismo conjunto de `rule_id` de detección):** ❌ — iter1 = `{80792}`; iter2 = `{80792, 11}`.
  La diferencia es **solo** la fila **`11`** (alerta **interna de Wazuh**, grupo `stats`, **no el
  ataque**); la detección de la técnica es **idéntica** (`{80792}`, 1/1, anclada).
- **C2′ (recuento estable):** ✅ — `|2−1| = 1 ≤ max(2, 0.1·1) = 2`.
- **C3′ (sin `dudosa`):** ✅ — `dudosa=0`.
- **Veredicto:** **`review`** por **C1′**, con la causa identificada y **ajena a la técnica**
  (artefacto del mecanismo congelado: una alerta `stats` del propio HIDS **no está en el catálogo
  baseline** → `novel` → `deteccion`). Ver `Bitacora/ATA035.json`.

## 10. Limitaciones y hallazgos

1. **⭐ Hallazgo (punto ciego del HIDS).** El `execve` del **proceso de laboratorio** con el hook
   **sí** alerta (`80792`), pero el HIDS **no ve** la **carga del módulo** (`LD_PRELOAD`) ni la
   **intercepción de la API** (audit no audita el entorno ni las cargas de `.so`): **ve el proceso,
   no el hook**.
2. **⭐ Hallazgo (artefacto del mecanismo congelado).** La alerta **interna `stats` de Wazuh
   (`rule_id 11`)** **no** está en el catálogo baseline → el filtro la marca **`novel` → `deteccion`**
   (falso positivo del **criterio congelado**). En ATA011 la misma regla 11 cayó como `auto_ruido`
   **porque traía `audit_cwd=/var/ossec`**; aquí **sí trae** campos `audit.*`
   (`systemd-logind`/`/run/systemd/sessions`) pero **ninguno casa los criterios de `auto_ruido`**
   (que apuntan a `wazuh-agentd`/`/var/ossec`) → `novel`. **No cambia** el veredicto de la técnica.
   Provoca el **`review`**.
3. **Fallback R1 declarado:** payload **precompilado** (la víctima no tiene `gcc`/`cc`/`make`).
4. **Sin `sudo`**; **0** filas del ataque en `ruido`. Realismo acotado declarado (README §9).

## 11. Filas `ruido` (para ratificación)

- **iter1: 362**; **iter2: 292** — **baseline** (PAM del login del operador, `sshd`, `591`…), ajenas
  al ataque. **0** filas del ataque en `ruido`.
