---
fase: 3
bloque: fase-03-escalado
tanda: A
ata_id: ATA006
tecnica: T1565
tactica: Impact
version: 2
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA006 · T1565 Data Manipulation (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda A**, 2.º de 4). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada.
> **Alcance (decisión humana 2026-09-28):** la técnica es el **cambio de contenido**; **sin**
> *timestomp* (`touch`/`chmod` retirados; falsear fecha/modo = T1070.006, otra técnica).
>
> **Ratificación humana (`fase-03-escalado`, 2026-09-29):** las **9 filas/iter** del **efecto bajo
> `watch`** (`80790`/`80781`/`80791`) se confirman como **`artefacto_ataque`** (efecto del ataque,
> **no** detección): la detección es el **`execve` del `sed`** (`80792`). Firma
> `revisor=humano (ratificacion 2026-09-29)`. **Los conteos no cambian** (`deteccion=2`,
> `artefacto_ataque=22`).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA006** |
| Técnica | **T1565 — Data Manipulation** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (ART no tiene pruebas para T1565) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2; **la detección**) **+ watch** (`80790/80781/80791`, RS2; **efecto → `artefacto_ataque`**, ratificado por el humano 2026-09-29) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`sed -i`** (`/usr/bin/sed`) |
| Objetivo | `/home/angel/lab-legit/datos_clientes_2026.csv` (**dir VIGILADO** por `auditd`, datos falsos) |
| Elevación | **no** |
| Retirado | `touch -t`/`chmod` (T1070.006 Timestomp; ver README §3.1) |

Artefacto: `Dataset/Ataques/Comandos/T1565-Data_Manipulation/ATA006_ataque.sh`
(`sha256=df1a242b8ca78d893fa27ce11da616df8041586d816d7d53221033da5c23d98c`, idéntico repo↔víctima).
Señales esperadas: `.../ATA006_esperado.csv`
(`sha256=981fc6dec6309e5a0f9815209b29742f775f1399a8659c55969f760fd3c80020`).
Validación humana (CA1): **APROBADO 2026-09-28**.
C0: `Soporte/Ataques/c0/ATA006_logtest.txt`
(`sha256=1bc1533d31a43eecbf41555c4d94ff5be1996ed0c88007dcca403b1f07ec883e`)
→ pre-flight **PASA** (1 evento, `80792` level 3; **sin** silenciador).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. `t0` tras ≥ 90 s de asentamiento (H2).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA006_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T21:26:19Z` | `2026-09-28T21:26:50Z` | 31 s | 678 | `df1a242b…3d98c` |
| 2 | `2026-09-28T21:30:38Z` | `2026-09-28T21:31:09Z` | 31 s | 692 | `df1a242b…3d98c` |

Reloj víctima↔manager < 1 s; `t0 < t1` en ambas.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA006
bash ATA006_ataque.sh      # sed -i (replace de un importe + append de un cliente falso)
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA006_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `ps_antes.txt`, `ps_despues.txt`, `sha256_artefacto.txt`.

**Prueba de éxito:** `sha256` antes `e0658f32…` ≠ después `d306ff9b…`, marcadores `999999` y
`Mallory Consulting SL` presentes ⇒ **`MANIPULACION=OK`** en ambas iteraciones.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros | Detalle final |
|---|---|---|---|---|
| 1 | 684 | 678 | 6 | **678** |
| 2 | 698 | 692 | 6 | **692** |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 678 | **2** | 605 | 49 | **0** | **22** | 2 | 676 | 0 | 0 |
| 2 | 692 | **2** | 621 | 47 | **0** | **22** | 1 | 691 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **2** | 1 · `{80792}` | 2 (`T1565-S1`) | 0 |
| 2 | **2** | 1 · `{80792}` | 2 (`T1565-S1`) | 0 |

- Las **2 alertas** son los **2 `execve` de `sed`** (replace + append), `80792` (`audit_command`),
  anclados a `cwd=/home/angel/lab-attack/ATA006` por `T1565-S2`.
- **`dudosa` resueltas (9/iter) → `artefacto`:** el **efecto del ataque bajo watch** en `lab-legit`:
  `80790` *Created* (3: el fichero objeto + 2 temporales de `sed -i`), `80781` *Write* (4),
  `80791` *Deleted* (2, los `rename` de `sed -i`). Son **del ataque** (carpeta/`cwd`), pero **no** la
  detección declarada (el `esperado` los marca **`ambigua`**) → **`artefacto_ataque`** (efecto),
  **nunca `ruido`**. ✅ **Ratificado por el humano (2026-09-29)** (ver §10.2).
- **`artefacto_ataque=22`/iter** = 13 automáticos (árbol de `execve` en la carpeta) + 9 humanos.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T21:26:20.645Z` `audit_exe=/usr/bin/sed` | **1/1** (`S1`) | **2 / 22 / 49** | 2 alertas / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T21:30:39.016Z` `audit_exe=/usr/bin/sed` | **1/1** (`S1`) | **2 / 22 / 47** | 2 alertas / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|2−2\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ⚠️ 605 vs 621 → Δ=16 (aviso) |
| Sanidad `ruido_conocido` (aviso) | ✅ 49 vs 47 → Δ=2 |

## 10. Limitaciones y hallazgos

1. **Alcance (decisión humana):** sin *timestomp*. La acción característica es el **cambio de
   contenido** (`sed -i`); se evita ensuciar la atribución con T1070.006.
2. ✅ **Ratificación resuelta (2026-09-29):** las **9 filas/iter** del **efecto bajo watch**
   (`80790/80781/80791`) quedan como **`artefacto_ataque`** (son el ataque; **no** son la detección
   declarada). Confirmado por el humano (`revisor=humano (ratificacion 2026-09-29)`): la detección
   del ataque es el `execve` del `sed` (`80792`). Conteos **sin cambio** (`deteccion=2`,
   `artefacto_ataque=22`).
3. **Ruido `auto_ruido` alto (Δ16 entre iteraciones):** churn de `wazuh-agentd`/`syscheckd` (H);
   no es del ataque y no bloquea (criterio v2).
4. **C0 sin punto ciego** (`sed` → `80792` level 3). **Realismo acotado** declarado (README §11).
