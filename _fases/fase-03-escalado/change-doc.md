# change-doc — Bloque `fase-03-escalado`: cerrar el corpus (7 técnicas restantes)

> Cierre. Fecha: **2026-09-29**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA** en las **2 tandas**).
> Plan de referencia: `plan.md` (v1, `approved_by_human`; D1–D6). **Métrica CONGELADA** (`fase-03-metrica`).

---

## 1. Objetivo

Escalar de **6 a 13** ataques: ejecutar las **7 técnicas restantes** del corpus Linux con el **mismo ciclo**
(snapshot → `t0` → ataque → `t1` → extraer → filtrar → ficha), **sin tocar la métrica ni el filtro**.

**Estructura aprobada:** **1 bloque, 2 tandas**; **tu validación, en 2 ratos** (no 7).

---

## 2. 🎯 Resultado: **CORPUS COMPLETO — 12 detectados / 1 no**

### Tanda A (Impact) — 4/4 DETECTADOS

| ATA | Técnica | ¿Detectado? | `rule_id` | O2 (`k/m`) | Evidencia del efecto |
|---|---|---|---|---|---|
| ATA001 | T1486 Cifrado | **SÍ** | `80792` (`openssl`) | 1/1 | cifrado/descifrado con `sha256` idéntico |
| ATA006 | T1565 Manipulación | **SÍ** | `80792` (`sed`) | 1/1 | contenido alterado + marcadores inyectados |
| ATA005 | T1561 Borrado | **SÍ** | `80792` (`dd`,`shred`) | 2/2 | `sha256` antes ≠ después; tamaño estable |
| ATA003 | T1490 Inhibir recuperación | **SÍ** | `80792` (`rm`) | 1/1 | las copias simuladas: existían → ya no |

### Tanda B (Collection + Exfiltración) — 3/3 DETECTADOS

| ATA | Técnica | ¿Detectado? | `rule_id` | O2 (`k/m`) | Evidencia del efecto |
|---|---|---|---|---|---|
| ATA011 | T1074 Staging | **SÍ** | `80792` (`mkdir`,`cp`) | 2/2 | `staging/` + manifiesto; `sha256sum -c` = 3 OK |
| ATA009 | T1567 Exfiltración web | **SÍ** | `80792` (`curl`) | 1/1 | **`sink.log` con `sha256` idéntico** al dato enviado |
| ATA010 | T1041 Canal C2 | **SÍ** | `80792` (`curl`) | 1/1 | **`sink.log` del beacon con `sha256` idéntico** |

### Tabla final del corpus (13 técnicas / 26 ventanas)

| | Detectados | No detectados |
|---|---|---|
| **13 técnicas** | **12** (todos por `execve` anclado, `80792`) | **1: ATA013/T1560.002** |

> **ATA013 sigue siendo el único NO** — y es un **punto ciego de fábrica**: la regla **`92600`** del propio
> Wazuh suprime el `execve` de `python3`. **Pero el ataque dejó 6 rastros** en su carpeta
> (`artefacto_ataque`): **el ataque se ve; Wazuh no tiene regla para esa técnica.**

**Cifras del repo (26 ventanas):** filas **18.862** · `deteccion` **65** · `artefacto_ataque` **325** ·
`ruido_conocido` **2.146** · `auto_ruido` **16.326** · **`dudosa` 0**.

**C0 (examen previo) de los 7 nuevos:** los 7 con ganadora `80792` nivel 3 → **ningún silenciador**.

---

## 3. Decisión de criterio (normalización) — 2026-09-29

Para que la regla sea **una sola** (*el `esperado` declara; lo `ambigua` **nunca** es detección → el efecto
es `artefacto_ataque`*):

- **ATA007:** las **4 escrituras** pasan de `deteccion` a **`artefacto`** (`deteccion` 4→**2**, el `execve`
  del `cp`). **El ataque sigue DETECTADO.**
- **ATA006:** las 18 filas del efecto **ratificadas** como `artefacto`.
- **ATA011** nació ya con ese criterio.

---

## 4. Verificación (`tfg-tester`) — **PASA** (las 2 tandas)

| # | Comprobación | Resultado |
|---|---|---|
| CA1 | `esperado` **firmado por el humano ANTES** de atacar | ✅ (`APROBADO 2026-09-28` tanda A / `2026-09-29` tanda B) |
| CA2 | C0 por técnica (base-contra-base), sin punto ciego | ✅ (7/7) |
| CA3 | 2 iteraciones, `lab-listo`, fichero diario, UTC, aislamiento por agente | ✅ |
| CA4 | Métrica **O1+O2** por ventana; **`dudosa=0`** | ✅ |
| CA5 | **0 filas del ataque en `ruido`/`auto_ruido`** (26 ventanas) | ✅ |
| CA6 | Doble iteración v2 (`iguales`) | ✅ (7/7) |
| CA7 | Regresión: las 20 ventanas previas **byte a byte**; `pytest` **93**; filtro/metrica sin tocar | ✅ |
| CA8 | Ficha ↔ bitácora ↔ CSV ↔ cabecera; **cadena de huellas** (26/26) | ✅ |
| CA9 | Sin secretos, sin commit/push, `_recursos/`·`BBDD/`·`xlsx`·`Reglas/` intactos | ✅ |
| CA10 | Laboratorio cerrado (receptor parado, firewall retirado, VMs apagadas, NAT off) | ✅ (declarado; no verificable offline) |

**Prueba estrella del efecto:** el **`sha256` del cuerpo en el `sink.log` == `sha256` del dato local**
(ATA009 y ATA010) → **el dato salió de verdad**, no es una suposición.

---

## 5. ⚠️ Limitaciones y cabos declarados (para la memoria)

1. **Realismo acotado** (ya declarado en los 7 README nuevos + runbook §10): *la **técnica y el comando son
   reales**; el **alcance es de laboratorio** (no se destruye la máquina); el **entorno no tiene usuarios ni
   servicios reales** y las **rutas del ataque son conocidas por el analista**.*
2. **La "pertenencia al ataque" es atribución post-hoc** (usa la carpeta del laboratorio), **no** una
   detección del HIDS.
3. **La "checklist" (`esperado`) decide qué cuenta como detección** y se redacta **antes** + la valida el
   humano (sigue siendo el punto débil metodológico; declarado).
4. **ATA009 y ATA010 comparten mecanismo** (`curl` al receptor) y **captura de C0** (documentado): son dos
   técnicas distintas (servicio web vs canal C2), pero **la detección es la misma herramienta**.
5. **ATA005** borra un fichero de laboratorio de 32 MB: los **tiempos de la ventana** son de laboratorio, no
   de un ataque real.
6. **Cabos de registro** (sin impacto en datos): (a) el **intento abortado de ATA011 iter1** quedó anotado en
   `state.md` (0 residuo, verificado); (b) el **C0 compartido** de ATA009/ATA010 consta en bitácora/ficha pero
   no en el `c0_plan.md`; (c) en `times.log`, el campo `t1_local` es la **marca de fin del guion** (`t1` real =
   `T1_OFFICIAL`) — **no se editan** los logs (romperían las huellas).

---

## 6. Anomalías de proceso (declaradas)

1. **2 llamadas al ejecutor fallaron con `HTTP 400` sin reportar, pero dejaron trabajo hecho** (la 1ª, en el
   bloque `fase-03-metrica`; la 2ª, en esta tanda B: **solo dejó las firmas**). Ambas se auditaron y se
   continuó desde el punto exacto. **Lección:** un fallo de reporte no implica que no se haya actuado →
   **verificar el árbol antes de reintentar**.
2. **Un primer intento de ATA011 iter1 se abortó a media ventana** (PowerShell trató el prompt de `sudo` en
   `stderr` como error terminante). Se **descartó** (revert) y se repitió limpia; el tester confirmó **0
   residuo** (una sola ráfaga dentro de `[t0,t1]`, sin solapes ni duplicados).

---

## 7. Entregables

| Fichero | Cambio |
|---|---|
| `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/` · `T1565-Data_Manipulation/` · `T1561-Disk_Wipe/` · `T1490-Inhibit_System_Recovery/` · `T1074-Data_Staged/` · `T1567-Exfiltration_Over_Web_Service/` · `T1041-Exfiltration_Over_C2_Channel/` | **guion + `esperado` firmado + README** (7 ataques nuevos) |
| `Soporte/Ataques/c0/ATA0{01,03,05,06,09,10,11}_*` | **C0** (logtest + preflight) |
| `Dataset/Ataques/Resultados/Wazuh/linux/` | **14 ventanas nuevas** (`-Detalle`, `Audited`, `Logs/`), **7 fichas** |
| `Bitacora/ATA0{01,03,05,06,09,10,11}.json` | nuevas |
| `Hojas/ATA_index.csv` | **7 filas** → `cerrado` |
| `Soporte/Ataques/piloto_procedimiento.md` | nota del receptor (tanda B) + **§10 realismo acotado** |
| `Dataset/Ataques/Resultados/Wazuh/linux/Auditado/ATA007_*` · `ATA006_*` | normalización a `artefacto` |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` | test P2/P7 **robusto** (sin números fijos; cubre **cada** ventana) |

**Intactos:** `filtrar_ruido.py`, la política, los `esperado` **ya firmados**, los pilotos, `_recursos/`,
`Reglas/**`, `BBDD/`, `Detecciones.xlsx`.

---

## 8. Siguiente

- **Cerrar la cola de la Fase 3** (los 3 cabos de registro del §5.6) y **actualizar el `roadmap.md`**.
- **Tutoría H1/H2:** sigue sin contestar; **no bloquea**.
- **Fase 4 — el "precio de la detección"**: ataques **representativos** + medida de **recursos**; decidir
  **cuántos y cuáles** al empezar la fase. *(El corpus de 13 está cerrado: **12/13 detectados**.)*
- **`push`:** los commits son locales; publicar es del humano.
