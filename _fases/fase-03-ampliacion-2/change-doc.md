# change-doc — Bloque `fase-03-ampliacion-2` (ronda 2): 15 técnicas Linux nuevas

> Cierre. Fecha: **2026-09-29** (con validación humana; revisión posterior). Estado: **CERRADO** —
> verificación `tfg-tester`: **PASA** en las **3 tandas**.
> Plan de referencia: `plan.md` (v1, `approved_by_human`). **Métrica congelada** (`fase-03-metrica`).

---

## 1. Objetivo

Segunda **ronda de 15 técnicas** (solo Linux), en **3 tandas de 5**, con la tubería probada y la
métrica congelada. Selección del planificador con criterios explícitos (táctica R/E/S → diversidad de
capas del HIDS → factibilidad sin NAT → dificultad).

---

## 2. 🎯 Resultado: **14 de 15 DETECTADAS** → corpus **41 de 43**

| Tanda | ATA · Técnica | ¿Det.? | `rule_id` | Evidencia del efecto |
|---|---|---|---|---|
| A | ATA029 · T1005 Data from Local System | **SÍ** | `80792` | copias con `sha256` idéntico |
| A | ATA030 · T1560.001 Archive via Utility | **SÍ** | `80792` | `tar -tzf` lista los 3 ficheros |
| A | ATA031 · T1667 Email Bombing | **SÍ** | `80792` | Maildir 0 → **25** mensajes |
| A | ATA032 · T1565.001 Stored Data Manip. | **SÍ** | `80792` | `sha256` del ledger antes ≠ después |
| A | ATA033 · T1491.001 Internal Defacement | **SÍ** | `80792` | `sha256` del `index.html` cambiado |
| B | **ATA034 · T1560.003 Archive via Custom Method** | **NO** | ∅ | `.arc` propio reconstruido 3/3 (`sha256` idéntico) |
| B | ATA035 · T1056.004 Credential API Hooking | **SÍ** *(review)* | `80792` (+`11`) | `hook_capture.log` con token y contraseña |
| B | ATA036 · T1565.003 Runtime Data Manip. | **SÍ** | `80792` | `SALDO 1000 → 9999` en proceso vivo (`ptrace`) |
| B | ATA037 · T1561.001 Disk Content Wipe | **SÍ** | `80792` | contenido cambiado; estructura intacta |
| B | ATA038 · T1529 System Shutdown/Reboot | **SÍ** | `80792`+`503`+`506` | `boot_id` distinto; agente `Active` al volver |
| C | ATA039 · T1039 Network Shared Drive | **SÍ** | `80792` | `sha256` local == el del share |
| C | ATA040 · T1074.002 Remote Data Staging | **SÍ** | `80792` | `sha256` en el manager == local |
| C | ATA041 · T1048.002 Asym. Encrypted Non-C2 | **SÍ** | `80792` | `sink.log` == blob cifrado; round-trip == original |
| C | ATA042 · T1048.003 Unencrypted Non-C2 | **SÍ** | `80792` | `sink.log` == fichero en claro |
| C | ATA043 · T1567.004 Exfiltration Over Webhook | **SÍ** | `80792` | `sink.log` == cuerpo JSON |

**C0: los 15 `PASA`** (ganadora `80792` nivel 3, **sin silenciadores**). **Doble iteración v2 `iguales`** en 14
(ATA035 en `review` por un artefacto del mecanismo, ver §4). **`dudosa=0`.** **0 filas del ataque en `ruido`.**

### Total acumulado del corpus (43 técnicas / 86 ventanas)

| Categoría | Filas |
|---|---:|
| **`deteccion`** | **449** |
| `auto_ruido` | 54.730 |
| `ruido_conocido` | 26.401 |
| `artefacto_ataque` | 2.045 |
| `dudosa` | **0** |
| **Total** | **83.625** |

**Detectadas: 41/43** — Impact **19/19** · Exfiltration **10/10** · Collection **12/14**.
**No detectadas: ATA013** (T1560, `92600`) y **ATA034** (T1560.003). *(39 `cerrado` + 4 `review`.)*

---

## 3. ⭐ Hallazgos de esta ronda (material de primera para la memoria)

1. **"¿Qué decide la detección?" — el trío del archivado** (¡es el hallazgo del TFG!):
   | Cómo se archiva | ¿Detectado? | Por qué |
   |---|---|---|
   | **Utilidad** (`tar`/`gzip`) — ATA030 | **SÍ** | `execve` de la herramienta |
   | **Librería** (`python3`) — ATA013 | **NO** | la regla **`92600`** de Wazuh lo suprime |
   | **Método propio** (builtins) — ATA034 | **NO** | **no hay `execve`** de la operación → sin telemetría |
   👉 **La técnica es la misma (archivar); lo que decide es la IMPLEMENTACIÓN.**
2. **`ATA034`: la conclusión depende de cómo se implemente.** Con un **binario propio** → `execve` → detectable
   (como ATA030); con `python3` → suprimido. **No es "la técnica es indetectable"**, sino *"el HIDS no distingue
   el archivado casero dentro de un intérprete"*. **Declarado en ficha/bitácora/README.**
3. **Capa nueva (ATA038):** el manager **sí ve** el cierre/arranque de la víctima por el **estado del agente**
   (`503` *stopped* / `506`); en cambio `40700` (journald) sigue siendo **level 0**.
4. **El HIDS ve el proceso, no el mecanismo:** ATA035 (`LD_PRELOAD`) y ATA036 (`ptrace`) solo se detectan por el
   `execve`; el *hook* y la manipulación en memoria **no** se ven.
5. **Confirmado otra vez:** **leer no deja rastro** (`auditd -p wa`) → ATA029 se detecta por el `execve` del lector.
6. **El `syscheck` no vigila `lab-legit`** (solo `/etc`, `/usr/bin`…) → en ATA032/033 la capa real fue el **`watch`**,
   no el FIM declarado. **Limitación declarada.**
7. **`audit_exe` = nombre REAL del binario** (`nc.openbsd`, `mke2fs`, `rsync`): la lección se aplicó y **casó**.

---

## 4. ⚠️ Limitaciones y desviaciones declaradas

1. **`rule_id 11` (alerta interna de Wazuh) contada como `novel` → `deteccion`** (ATA035 iter2): es un **falso
   positivo del criterio congelado** — `auto_ruido` caza *por campos* (`/var/ossec`, procesos de Wazuh) y esta
   alerta trae campos de `systemd-logind`/`/run/systemd/sessions`. Aparece en **2 de 86** ventanas (una como
   `auto_ruido`). **No cambia ningún veredicto** (ATA035 se detecta por `80792`); por eso **no se toca la métrica
   congelada**: se **declara** y queda **candidato a un arreglo futuro** (fuera de este bloque).
2. **Pivotes por falta de dependencias (sin NAT):** NFS/SMB/`sshfs` **no están** en la víctima → el "recurso de red"
   (ATA039/040) se implementó con un **daemon `rsync` local**; los payloads de ATA035/036 se **precompilaron** en el
   manager y se versionan como `.c` + `.b64`. **Declarado** en READMEs, fichas y `piloto_procedimiento.md` §13.
3. **Riesgo CRLF en los `.b64`:** sin `.gitattributes` y con `core.autocrlf=true`, un clon podría añadir CRLF y
   romper la decodificación de ATA035/036. **Es la limitación global ya declarada** (micro-bloque `fase-03-gitattributes`,
   OPCIÓN A). **Propuesta al humano:** un `.gitattributes` **mínimo** (`*.b64 -text`, `*.sh text eol=lf`) — **no aplicado**.
4. **`estado` = criterio PROCESAL**, no indicador de detección: ATA034 (no detectada) figura `cerrado` porque su
   doble iteración fue `iguales`; ATA013/ATA035 están `review` por artefactos del mecanismo/v2. **Escrito en las fichas.**
5. **Realismo acotado** (ya declarado) y **sin evasión** (bloque futuro).

---

## 5. Verificación (`tfg-tester`) — PASA en las 3 tandas

| Tanda | Resultado | Notas |
|---|---|---|
| **A** (ATA029–033) | **PASA** | 5/5; 85 filas PAM ajenas a `ruido` (justificadas); hallazgo "herramienta vs librería" |
| **B** (ATA034–038) | **PASA** | 4/5 (ATA034 no); aclaró que **ATA034 depende de la implementación**; detectó el FP `rule_id 11` (cuantificado: 2/86) |
| **C** (ATA039–043) | **PASA** | 5/5; validó el pivote `rsync` y las evidencias `sha256`; regresión y cadena OK |

**Reproducción:** **76/76** ventanas re-filtradas byte a byte (determinismo); **2.210** filas "del ataque" con
**0 violaciones** del invariante; `pytest` **93**; `auditar_cadena_huellas.py` → **1.411 citas, 0 desincronías**.

---

## 6. Entregables

- **15 carpetas** en `Dataset/Ataques/Comandos/` (guion + `esperado` firmado + README; ATA035/036 con `.c`/`.b64`).
- **15 C0** (`c0/ATA0{29..43}_*`), **30 ventanas** nuevas (`CSV/`, `Auditado/`, `Logs/`), **15 fichas** y **15 bitácoras**.
- `Hojas/ATA_index.csv`: **+15 filas** (43 en total). `Soporte/Ataques/piloto_procedimiento.md` **§13** (pivote rsync).
- `Soporte/Ataques/plantilla_esperado.md`: **corregido** el patrón de creación (**`80782`**, no `80790` → señales muertas).

---

## 7. Panorama y siguiente

- **Piscina P1-Linux casi agotada:** la ronda 2 la deja con **~29 técnicas**, de las que **muchas no son factibles
  sin NAT o repiten mecanismo**. → **Decisión pendiente del humano (R13):** abrir **P2** o dar **P1 por cerrada**.
- **Candidatos inmediatos:** (a) el **bloque de EVASIÓN** (versiones disfrazadas), (b) **Windows**, (c) la
  **memoria** (Fase 5) con el material ya reunido, (d) **Fase 4** (precio de la detección).
- **`push`:** los commits son locales; publicar es del humano.
