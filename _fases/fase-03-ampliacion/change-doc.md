# change-doc — Bloque `fase-03-ampliacion`: 15 técnicas nuevas en 3 tandas de 5

> Cierre. Fecha: **2026-09-29** (ejecución nocturna delegada). Estado: **CERRADO** —
> verificación `tfg-tester`: **PASA** en las **3 tandas** (con 2 ciclos de corrección por FALLA).
> Plan de referencia: `plan.md` (v1, `approved_by_human`; validación humana con revisión posterior).

---

## 1. Objetivo

Ampliar el corpus con **15 técnicas nuevas** (solo **Linux**), en **3 tandas de 5**, con la
**tubería ya probada** y la **métrica congelada** (`fase-03-metrica`). Selección hecha por el
planificador con criterios explícitos: táctica R/E/S → **diversidad de capas del HIDS** →
factibilidad sin NAT → dificultad/sorpresa.

---

## 2. 🎯 Resultado: **15 de 15 DETECTADAS** → corpus total **28 técnicas · 27 detectadas / 1 no**

### Tanda A — recolección local e integridad

| ATA | Técnica | ¿Det.? | `rule_id` | Evidencia del efecto |
|---|---|---|---|---|
| ATA014 | T1114 Email Collection | **SÍ** | `80792` | copia del buzón con `sha256` idéntico |
| ATA016 | T1213.006 Databases | **SÍ** | `80792` | copia **SQLite válida** (`SQLite format 3`), 4 códigos |
| ATA015 | T1114.003 Email Forwarding Rule | **SÍ** | `80792` | `.forward` → `dropbox@exfil-lab.example` |
| ATA017 | T1657 Financial Theft | **SÍ** | `80792` | transferencia **`TRF-9999`**; cartera sustraída |
| ATA018 | T1056.001 Keylogging | **SÍ** | `80792` | `keylog_capture.log` con credencial simulada |

### Tanda B — exfiltración (receptor compartido)

| ATA | Técnica | ¿Det.? | `rule_id` | Evidencia del efecto |
|---|---|---|---|---|
| ATA019 | T1048.001 Sym. Encrypted Non-C2 | **SÍ** | `80792` | `sink.log` `sha256` **== blob cifrado**; round-trip == original |
| ATA020 | T1020 Automated Exfiltration | **SÍ** | `80792` | 4 `POST` con `sha256` idénticos |
| ATA023 | T1496.002 Bandwidth Hijacking | **SÍ** | `80792` | 32 MiB recibidos (~1,2 s) |
| ATA021 | T1029 Scheduled Transfer | **SÍ** | `80792` | disparo **cron dentro de `[t0,t1]`**; `sha256` idéntico |
| ATA022 | T1567.001 Exfil. to Code Repository | **SÍ** | `80792` | `git push` a **repo local**; blob `sha256` idéntico |

### Tanda C — sabotaje/sistema (privilegios, recursos, destructivo acotado)

| ATA | Técnica | ¿Det.? | `rule_id` | Evidencia del efecto |
|---|---|---|---|---|
| ATA024 | T1531 Account Access Removal | **SÍ** | `{550,5901,5902,5903,80792}` | usuario desechable creado→bloqueado→borrado (`id` y home no existen) |
| ATA025 | T1496.001 Compute Hijacking | **SÍ** | `80792` | CPU **100 %**; `loadavg` sube; 0 procesos residuales |
| ATA028 | T1056.003 Web Portal Capture | **SÍ** | `80792` | `request.http` con el POST y credenciales de juguete |
| ATA026 | T1565.002 Transmitted Data Manip. | **SÍ** | `80792` | `sink.log` recibe el **contenido manipulado** (`sha256` ≠ original) |
| ATA027 | T1561.002 Disk Structure Wipe | **SÍ** | `80792` | imagen ext4 → `data`; `blkid` no la reconoce; **montaje falla** |

**C0 (examen previo, base-contra-base): los 15 `PASA`, ganadora `80792` nivel 3 → sin silenciadores.**
**Doble iteración v2: `iguales` en los 15.** **`dudosa=0`.** **Determinismo** en las 30 ventanas nuevas.

### Cifras globales (56 ventanas = 28 ataques × 2)

| | |
|---|---|
| Filas auditadas | **51.297** |
| **`deteccion`** | **301** |
| `artefacto_ataque` | 1.392 |
| `ruido_conocido` | 15.504 |
| `auto_ruido` | 34.100 |
| **Ataques** | **28 · 27 DETECTADOS / 1 NO** (ATA013) |

**Regresión: las 26 ventanas del bloque anterior, byte a byte.** **`pytest` 93.**

---

## 3. ⭐ Hallazgos de esta ronda (valen para la memoria)

1. **El HIDS ve más de lo que creíamos (ATA024/T1531):** un solo ataque ejercitó **4 capas** —
   `execve` (`80792`) + `watch /etc` + **FIM (`550`)** + **syslog (`5901-5903`)**. Las tres últimas
   **`novel`** (no están en el catálogo): Wazuh **sí** vigila la manipulación de cuentas.
2. **Audit registra el BINARIO REAL, no el nombre de la orden:** `nc` → `/usr/bin/nc.openbsd`,
   `mkfs.ext4` → `/usr/sbin/mke2fs`. **Regla práctica:** declarar `audit_exe` con el nombre **real**
   o con **glob** (si no, la señal no casa → la fila baja a `artefacto`).
3. **Wazuh no tiene reglas de red ni de recursos** (ATA023): el consumo de ancho de banda **no se ve**;
   solo el `execve` de la herramienta. *(Coherente con que el HIDS sea host-based.)*
4. **La capa syslog de `cron` sí alerta** (ATA021): regla `2832` *Crontab entry changed* + `watch` de
   fábrica sobre `/var/spool/cron` → **contradice** la hipótesis previa (el C0 solo había mirado `80792`).
5. **Punto ciego `python3` reforzado (ATA016):** la siembra con `python3` **no dejó ninguna alerta**
   (ni el `execve` **ni el `watch`** de la BD creada) → la regla `92600` suprime **también** eventos
   atribuidos a `python3`. *(La colección con `cp`/`grep` sí alerta.)*
6. **La lectura no es visible para el HIDS:** `auditd` vigila con `-p wa` (escritura/atributos) →
   leer un fichero **no** genera alerta; la técnica se detecta por el **`execve` del lector**.

---

## 4. ⚠️ Limitaciones declaradas (nuevas de esta ronda)

1. **Precisión del invariante "0 filas del ataque en `ruido`":** se cumple **bajo la pertenencia por
   carpeta** (`cwd`/ruta bajo `lab-attack/<ATA>`). Quedan **fuera** las filas de la **sesión** del
   ataque (**PAM/`sudo`, sin `cwd`**), que caen en `ruido_conocido/baseline`:
   **30** en ATA024 (la sesión `sudo`/PAM del ataque, `dstuser=root`), **4** en ATA027
   (ruta **URL-encoded** bajo `/dev/`), **1** en ATA026 (`nc.openbsd` sin `cwd`).
   **Ninguna es detección** (la técnica se detecta en otras filas) y **no son corregibles** sin tocar
   la métrica congelada o un `esperado` firmado → **declaradas** en fichas, bitácoras y runbook §12.
2. **Asimetría metodológica:** el **mismo evento real** (la sesión PAM del `sudo` del ataque) acaba en
   **`baseline`** (ATA024) o en **`artefacto`** (ATA027) según si el `esperado` declara algún campo
   **siempre evaluable**. Documentado (runbook §12.3).
3. **Realismo acotado** (ya declarado): ataques cortos, sin evasión, en un entorno "limpio".
   **El bloque de evasión (2ª versión "disfrazada") queda para cuando la cobertura P1 esté cerrada.**
4. **Dependencias/entorno:** sin NAT → los ataques con nube/AWS/descargas **se escriben a mano** o se
   declaran; `sqlite3`/`strings` no estaban en la víctima → se usó la **stdlib** de `python3`.

---

## 5. Verificación (`tfg-tester`) — PASA en las 3 tandas, con 2 FALLA corregidos

| Tanda | 1ª vuelta | Corrección | 2ª vuelta |
|---|---|---|---|
| **A** | **PASA** (con cabos) | — | — |
| **B** | **FALLA** | ATA021: 1 fila PAM mal plegada (`artefacto`→`ruido`) + conteos; **+ auditoría completa de la cadena de huellas** → 1 desincronía real (**ATA001**, por un retoque cosmético) corregida | **PASA** |
| **C** | **PASA** | Cabos de **documentación** (declarar las huellas en `baseline`; precisar `novel`; documentar la asimetría) | — |

**Aportación del ciclo:** se creó **`_artefactos/scripts/auditar_cadena_huellas.py`**
(**915 citas** verificadas; reproducible de forma independiente; 0 desincronías tras la corrección).

## 6. Incidencias de proceso (declaradas)

1. **El tester sobrescribió por error los `-Revision.csv`** de la tanda B (su re-ejecución del filtro
   sin `--rev-out`) y **los restauró byte a byte** validando contra el `revision_sha256` de cada
   bitácora (10/10). Sin daño.
2. **Primer intento de ATA019 iter1 abortado** (un `scp` con glob: Windows no expande) → ventana
   **descartada y repetida**; sin residuo.
3. **Primer `ATA024` iter1** con un criterio de éxito erróneo → **corregido y re-ejecutado**.
4. **El `state.md` fue escrito por el ejecutor** (tanda B): contenido correcto, pero es artefacto del
   **orquestador** → **asumido y reformulado** al cerrar.

---

## 7. Entregables

- **5 guiones + 5 `esperado` firmados + 5 README** por tanda (15 en total) + **15 C0**.
- **30 ventanas** nuevas: `-Detalle(_raw)`, `-Audited`, `Logs/`, fichas y bitácoras.
- `Hojas/ATA_index.csv`: **+15 filas** `cerrado`.
- `Soporte/Ataques/receiver/sink_http.py`: **`--tcp-port`** (retrocompatible) + README.
- `Soporte/Ataques/piloto_procedimiento.md`: §11 (receptor/tandas) + §12 (limitaciones de la tanda C).
- `_artefactos/scripts/auditar_cadena_huellas.py`: **nuevo** auditor de la cadena de huellas.
- Corrección de **1 huella desincronizada** (ATA001) con evento `correccion`.

---

## 8. Siguiente

1. **Seguir ampliando** hacia las **58 técnicas P1 con Linux** (`corpus_host.csv`): quedan **~43**.
2. **Después: el bloque de EVASIÓN** — repetir las técnicas en **versión disfrazada** (2ª pasada) para
   medir la **degradación** de la detección. *(Nota breve en `state.md` y `roadmap.md`.)*
3. **Windows**: más adelante (las técnicas de Windows + las híbridas otra vez).
4. **Fase 4** (el precio de la detección) y **Fase 5** (memoria).
5. **`push`:** los commits son locales; publicar es del humano.
