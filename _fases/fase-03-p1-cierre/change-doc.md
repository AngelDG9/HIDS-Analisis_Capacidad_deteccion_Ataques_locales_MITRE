# change-doc — Bloque `fase-03-p1-cierre`: cierre de P1 en Linux

> Cierre. Fecha: **2026-10-02**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA** (tras **1 FALLA** corregida).
> Plan de referencia: `plan.md` (v3, `approved_by_human`). **Métrica y filtro CONGELADOS.**

---

## 1. Objetivo

**Cerrar la prioridad alta (P1) en Linux**: inventariar **todas** las técnicas P1 que citan Linux,
**medir las factibles** y **declarar con motivo** las que no lo son. Criterio del humano:
**factible = se puede en el laboratorio sin internet** (con pre-staging si hace falta); **no factible =
necesita nube/API real/otra plataforma**. **Una técnica distinta = una fila distinta**, aunque el mecanismo se parezca.

---

## 2. 🎯 Resultado: **12 técnicas nuevas, 12/12 DETECTADAS**

### Tanda A — DoS acotado

| ATA | Técnica | ¿Det.? | `rule_id` | `k/m` | Evidencia |
|---|---|---|---|---|---|
| ATA044 | T1025 Removable Media | **SÍ** | `80792` | 6/6 | documentos con `sha256` idéntico al medio (montaje `-o ro`) |
| ATA045 | T1499.001 OS Exhaustion Flood | **SÍ** | `80792` | 4/4 | `MemAvailable` −505 MB y recuperada; 0 residuo |
| ATA046 | T1499.003 App Exhaustion Flood | **SÍ** | `80792` | 4/4 | 16 peticiones caras; CPU app +2,29 s; app viva |
| ATA047 | T1499.002 Service Exhaustion Flood | **SÍ** | `80792` | 4/4 | 400 peticiones en `service.log`; servicio vivo |
| ATA048 | T1498.001 Direct Network Flood | **SÍ** | `80792` | 3/3 | 8 conexiones × 8 MiB = 67.108.864 B (sha idéntico) |

### Tanda B — "nubes" locales + GUI

| ATA | Técnica | ¿Det.? | `rule_id` | `k/m` | Evidencia |
|---|---|---|---|---|---|
| ATA049 | T1567.002 Cloud Storage | **SÍ** | `80792` | 1/1 | WebDAV local: 3 PUT con `sha256` idéntico |
| ATA050 | T1567.003 Text Storage (paste) | **SÍ** | `80792` | 1/1 | POST `/paste` → HTTP 200; `sha256` idéntico |
| ATA051 | T1113 Screen Capture | **SÍ** | `80792` | 2/2 | `.xwd` de 4.099.179 B con cabecera XWD válida |
| ATA052 | T1115 Clipboard Data | **SÍ** | `80792` | 1/1 | round-trip: `sha256` capturado == sembrado |
| ATA053 | T1056.002 GUI Input Capture | **SÍ** | `80792` | 2/2 | 111 eventos `KeyPress` capturados |

### Tanda C — servicios de red (la más delicada)

| ATA | Técnica | ¿Det.? | `rule_id` | `k/m` | Evidencia |
|---|---|---|---|---|---|
| ATA054 | T1498.002 Reflection Amplification | **SÍ** | `80792` | 2/2 | 25 req (400 B) → **102.400 B** al objetivo (factor ≈256) |
| ATA055 | T1557.003 DHCP Spoofing | **SÍ** | `80792` | 2/2 | el cliente acepta **gateway/DNS del atacante** |

**C0 de las 12: PASA** (sin silenciadores) · **v2 `iguales`** · **`dudosa=0`** · **0 filas del ataque en `ruido`**.
**Ninguna resultó "no factible"**: incluso **ATA053** (la más dudosa) se pudo hacer con `Xvfb`.

---

## 3. 📊 El cierre: la tabla de P1 en Linux

**`Hojas/cobertura_p1_linux.csv`** — **72 filas** (coincide **exactamente** con la piscina
`P1 ∧ host_eligible=YES ∧ Linux`):

| Categoría | N |
|---|---:|
| **`medida`** | **48** |
| `cubierta_por_ata` (misma técnica, ya medida; con cita) | 6 |
| `cubierta_madre` (todas sus formas medidas) | 8 |
| **`cubierta_parcial`** (etiqueta nueva: medimos unas formas; otras no son factibles) | 2 |
| `no_factible` (con motivo: otra plataforma / exploit necesario) | 8 |
| **Total** | **72** ✔ |

### Dos comprobaciones automáticas (lo que pediste)

- **C1 — Cuadre:** las 72 filas y los subtotales por categoría → **coherentes**.
- **C2 — Test padre/hijo:** falla si una **madre** figura `cubierta` **teniendo una forma factible sin medir**;
 si una **hija** se cubre por **otra hija**; si una **madre** cubre a sus **hijas**; o si una cita **no resuelve**.
 → **Sin violaciones sobre las 72** *(este test es el que habría cazado el error de T1498/T1499)*.
 - **Aplicadas a las 72** (no solo a las nuevas). **No apareció ninguna inconsistencia más.**

**Verificado:** `pytest` **120** · cadena de huellas **1.990 citas / 0 desincronías** · las **124 ventanas previas** intactas.

---

## 4. 🔒 Incidente de seguridad (resuelto y contenido)

**4 ficheros** `Soporte/Ataques/c0/ATA0{50..53}_logtest.txt` contenían **la contraseña del laboratorio en claro**
(se canalizaba al `stdin` de `wazuh-logtest`).
- **Comprobado: NUNCA estuvieron en el historial de git** (untracked; `git log -S`, `git grep` sobre todas las
 revisiones y objetos → **0**).
- **Saneados** (línea eliminada) · huellas actualizadas **con evento `correccion`** · **la herramienta de captura
 se corrigió** (autenticación previa + `sudo -n`) · **0 apariciones** en el repo y en `%TEMP%`.
- **Recomendación al humano: rotar la contraseña del laboratorio** (por precaución).

---

## 5. Verificación (`tfg-tester`) — **PASA** (tras 1 FALLA)

| # | Comprobación | Resultado |
|---|---|---|
| Cifras | 24 ventanas nuevas: `80792` anclado, `dudosa=0`, v2 `iguales`, **0 en `ruido`** | ✅ |
| C0 | 12/12 PASA, sin silenciador | ✅ |
| **Cierre** | C1 y C2 reproducidos; **conjunto de las 72 idéntico** a la piscina (0 faltan/sobran/duplicadas) | ✅ |
| Muestreo | 5 filas al azar con su cita → resuelven y corresponden | ✅ |
| Seguridad | **0 apariciones** en repo e historial | ✅ |
| Regresión | 124 ventanas previas intactas; `pytest` **120**; determinismo | ✅ |
| Alcance | sin commit; nada prohibido tocado | ✅ |

**La FALLA (1ª vuelta):** 3 citas de `auditoria_origen.csv` (**ATA051/052/053**) apuntaban a un **§9 inexistente**
→ **corregidas a §8** (verificador: **55/55 filas · 124/124 citas**).

---

## 6. Anomalías y decisiones operativas (declaradas)

1. **Segmentos AISLADOS para la Tanda C**: el reflector (T1498.002) y el DHCP señuelo (T1557.003) se montaron
 en **segmentos locales aislados** dentro de la víctima (`veth`/`netns`) — **no** en `VMnet1` (competir con el
 DHCP de VMware habría **roto la red**). Mecanismo **fiel** con **riesgo 0**. Documentado.
2. **`xargs` infla el conteo bruto** (ATA046/047): el mecanismo GNU lanza ~3× procesos; **no afecta a O1/O2**.
3. **Backlog de `analysisd`**: tras el FIM del pre-staging las alertas podían llegar tarde → se añadió una
 **espera de drenaje (120 s) antes de `t0`**; una ventana se repitió por eso.
4. **ATA051 tiene los ficheros `iter1/iter2` invertidos** respecto al orden cronológico: **no se renombran**
 (rompería hashes); la ficha se **alineó** con §4/bitácora y lleva una **nota aclaratoria**.
5. **T1498 queda `cubierta_parcial`** por decisión del plan (D3), aunque sus 2 formas del alcance están medidas.

---

## 7. Entregables

- **12 carpetas** en `Dataset/Ataques/Comandos/` (guion + `esperado` firmado + README) · **12 C0** ·
 **24 ventanas** nuevas · **12 fichas** y **12 bitácoras**.
- **`Hojas/cobertura_p1_linux.csv`** (las 72) · **`Hojas/cobertura_atomic.csv`** regenerada (**55**) ·
 `Hojas/ATA_index.csv` y `Hojas/auditoria_origen.csv` (**55**).
- **`_artefactos/scripts/verificar_cobertura_p1.py`** + **23 tests** (pytest **120**).

---

## 8. 🏁 El corpus, al terminar

| | |
|---|---|
| **Técnicas medidas** | **55** (43 + 12) |
| **Detectadas** | **53 / 55** *(ATA013 y ATA034 no)* |
| **Ventanas** | 86 base + 18 repetición + 24 nuevas = **128** |
| **P1-Linux** | **Cerrado**: 72 filas (48 medidas · 16 cubiertas · 2 parciales · 8 no factibles) |
| **Por táctica (P1)** | Impact, Exfiltration y Collection con sus formas P1 evaluadas |

---

## 9. Siguiente

1. **Bloque futuro anotado:** normalización de finales de línea + recálculo de huellas (para que un clon verifique).
2. **Arreglo futuro del filtro:** `19010/19011` (SCA) — mismo patrón que el `rule_id 11` ya arreglado.
3. **Alternativas:** seguir con **P2** · **evasión** (versiones disfrazadas) · **Windows** · **Fase 4** · **memoria**.
4. **`push`:** los commits son locales; publicar es del humano.
