---
fase: 3
bloque: fase-03-ampliacion
tanda: A
ata_id: ATA018
tecnica: T1056.001
tactica: Collection/Credential-Access
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA018 · T1056.001 Keylogging (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda A**, 5.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica congelada.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA018** |
| Técnica | **T1056.001 — Input Capture: Keylogging** |
| Táctica | Collection / Credential Access |
| Sistema | Linux (`victima-linux`) |
| Vía | **manual / custom** (adaptación contenida de ART *«Logging bash history to syslog»*) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`; **la detección**); la captura escribe en **ruta NO vigilada** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` |
| Herramientas | **`tee`** (wrapper de captura), **`logger`** (persistencia en syslog) |
| Destino | `/home/angel/lab-attack/ATA018/keylog_capture.log` (**NO vigilado**) + syslog (journald) |
| Elevación | **no** |
| Contención | **NO** se toca `pam_tty_audit`/`auditd`/`/etc`; credencial **simbólica** `ClaveDemo-Fake123` |

Artefacto: `.../T1056.001-Keylogging/ATA018_ataque.sh`
(`sha256=d2d60990384af29c005994434b66243e61c2942488b36d5e16ffe0764d3ca60b`, idéntico repo↔víctima).
Señales: `.../ATA018_esperado.csv` (`sha256=b24c0ee53f0afe094c7aa75d1df520cc1b3cc9eb339bbeb3d241b6254d8d687a`).
Validación humana: **APROBADO 2026-09-29**.
C0: `ATA018_logtest.txt` (`sha256=84f2ddd66c6c959f0e37647728d528c5f5b234feec507c1bd22d02d001c2a957`)
→ pre-flight **PASA** (2 eventos, `80792` level 3; sin silenciador).

## 3. Snapshot

Víctima a **`lab-listo`** por iteración (manager **no** revertido). **NAT off**; nada instalado.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas Detalle | sha256 `ATA018_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-29T01:01:12Z` | `2026-09-29T01:01:44Z` | 32 s | 1180 | `d2d60990…d3ca60b` |
| 2 | `2026-09-29T01:04:41Z` | `2026-09-29T01:05:13Z` | 32 s | 1167 | `d2d60990…d3ca60b` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA018
bash ATA018_ataque.sh     # tee (captura la sesión) + logger (persiste el keylog en syslog)
```

## 6. Evidencia

`Logs/ATA018_iter{1,2}/`. **Prueba de éxito:** `KEYLOG=OK` — el fichero de captura contiene las
**6 líneas** de la sesión simulada, incluidos los comandos tecleados y la **credencial simulada**
(`ClaveDemo-Fake123`) ⇒ la entrada quedó registrada.

## 7. Ventana extraída

Fichero diario `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-29.json` (H3); sólo `victima-linux`.

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1180 | **3** | 555 | 605 | **0** | 17 | 3 | 1177 | 0 | 0 |
| 2 | 1167 | **3** | 553 | 594 | **0** | 17 | 3 | 1164 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id`** | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | **3** | 1 · `{80792}` | 2 `tee` (`S1`) + 1 `logger` (`S2`) | 0 |
| 2 | **3** | 1 · `{80792}` | 2 `tee` + 1 `logger` | 0 |

- Todo `80792`, **anclado** por `T1056.001-S3` a `cwd=/home/angel/lab-attack/ATA018`.
- **`dudosa` resueltas:** iter1 **15** (8×`5502`, 7×`5501` PAM `sin_campos`) → **`ruido`**; iter2 **17**
  (9×`5501`, 8×`5502`) → **`ruido`**. Son **sesiones del operador** (login/logout SSH), **ajenas** al
  ataque. **Ninguna** fila del ataque en `ruido`.
- **`artefacto_ataque=17`**: `id`, `whoami`, `hostname`, `bash`, `cat`… (`execve` no declarados).

### 8.2 Métrica — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-29T01:01:14.862Z` `audit_exe=/usr/bin/tee` | **2/2** | **3 / 17 / 605** | 3 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-29T01:04:43.567Z` `audit_exe=/usr/bin/tee` | **2/2** | **3 / 17 / 594** | 3 / `{80792}` |

## 9. Doble iteración (**v2**) — **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ `rule_id` de `deteccion` | ✅ `{80792}` ↔ `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|3−3\| = 0 ≤ 2` |
| C3′ sin `dudosa` | ✅ 0 y 0 |

## 10. Limitaciones y hallazgos

1. **El mecanismo «oculto» no se ve a nivel de host:** la escritura de la captura va a una **ruta no
   vigilada** (`lab-attack`) → **no** hay `watch`/FIM; y la persistencia vía `logger` cae en la regla
   de fábrica **`40700` (`level=0`)** → **no** alerta. La detección efectiva es el **`execve`** de
   `tee`/`logger`. Confirma el hallazgo §8.3 del runbook (journald `40700` es agrupador nivel 0).
2. **Contención declarada:** no se toca `pam_tty_audit` ni `auditd` reales; credencial **simbólica**.
3. **`dudosa` = PAM 5501/5502 → `ruido`:** sesiones del operador (ajenas); **se listan para
   ratificación** (no auto-demostrables, lado seguro).

## 11. C0

`ATA018_logtest.txt` → **PASA** (`tee`/`logger` → `80792` level 3; sin silenciador de fábrica).
