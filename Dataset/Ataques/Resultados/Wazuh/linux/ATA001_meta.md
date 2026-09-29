---
fase: 3
bloque: fase-03-escalado
tanda: A
ata_id: ATA001
tecnica: T1486
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-28
---

# Ficha — ATA001 · T1486 Data Encrypted for Impact (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda A**, 1.º de 4). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`** (misma detección; sin
> `dudosa` sin resolver). Ejecutado con la **métrica congelada** (`_fases/fase-03-metrica/change-doc.md`).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA001** |
| Técnica | **T1486 — Data Encrypted for Impact** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **Atomic Red Team** (control) — prueba *Encrypt files using openssl* (`142752dc-ca71-443b-9359-cf6f497315f1`) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`audit_command`, regla `80792`, RS2) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `ART` (1 de los 4 tests Linux de T1486; es el **único** de los 7 del escalado que usa ART tal cual) |
| Herramienta | **`openssl`** (`/usr/bin/openssl`, OpenSSL 3.x) |
| Objetivo | `/home/angel/lab-attack/ATA001/datos_clientes_2026.csv` → cifrado `.enc` (**NO vigilado**) |
| Elevación | **no** |
| Desviación | `openssl enc` **simétrico** (AES-256-CBC+PBKDF2) en vez de `genrsa`+`rsautl` (deprecado/limitado). Documentada en el README §4 |

Artefacto: `Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/ATA001_ataque.sh`
(`sha256=0a01be24763f5c9363ae8ac102b8ddaaee956a9a0d701196bb557374c66bacd8`; la **ejecución** usó
`a4137192…7139` —un **retoque cosmético** del comentario, posterior al ataque, cambió el fichero—; ver
`correccion` en `Bitacora/ATA001.json`).
Señales esperadas: `.../ATA001_esperado.csv`
(`sha256=359cac966880a2bb7701a05f19c9c5e67d92c4b3d043fb9acb7b571efe4008b9`).
Validación humana del `esperado` (CA1): **APROBADO 2026-09-28** (firma en su cabecera).
C0: `Soporte/Ataques/c0/ATA001_logtest.txt`
(`sha256=b73d6f291b0d4ee3a23ceb239528f44a6628f089ea338ab247c3190474151923`)
→ pre-flight `ATA001_preflight.md` **PASA** (1 evento, ganadora `80792` level 3; **sin** silenciador de fábrica).

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada.
- `t0` sellado **tras ≥ 90 s de asentamiento** con el agente `active` (H2).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA001_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T21:16:13Z` | `2026-09-28T21:16:53Z` | 40 s | 689 | `a4137192…47139` |
| 2 | `2026-09-28T21:22:17Z` | `2026-09-28T21:22:48Z` | 31 s | 667 | `a4137192…47139` |

`t0 < t1` en ambas (ventana `[t0,t1]` inclusiva). Reloj víctima↔manager `|Δ|=0,02 s` (< 1 s).

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA001
bash ATA001_ataque.sh      # openssl enc -aes-256-cbc -pbkdf2 -salt (cifrado) + descifrado de prueba
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA001_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `ps_antes.txt`, `ps_despues.txt`, `sha256_artefacto.txt`.

**Prueba de éxito (independiente de la alerta):** el guion **descifra** el ciphertext y compara
`sha256`: `plain = recovered = e0658f32…` ⇒ **`ROUNDTRIP=OK`** en ambas iteraciones (el ciphertext es
válido y reversible con la clave).

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor **H3**; extrae de la fuente diaria, **no** de `alerts.json`).
- **Aislamiento por agente:** `_raw` → filtro a `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final | `rule_id` distintos | UNKNOWN |
|---|---|---|---|---|---|---|
| 1 | 695 | 689 | 6 | **689** | 6 | 0 |
| 2 | 673 | 667 | 6 | **667** | 6 | 0 |

## 8. Resultado (conteos por categoría, veredicto ya plegado)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 689 | **2** | 626 | 48 | **0** | **13** | 1 | 688 | 0 | 0 |
| 2 | 667 | **2** | 604 | 48 | **0** | **13** | 1 | 666 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **2** | 1 · `{80792}` | 2 (`T1486-S1`) | 0 |
| 2 | **2** | 1 · `{80792}` | 2 (`T1486-S1`) | 0 |

- Las **2 alertas** son **2 `execve` de `openssl`** (el cifrado y el **descifrado de prueba**),
  ambas `80792` (`audit_command`), **ancladas** a `cwd=/home/angel/lab-attack/ATA001` por `T1486-S2`.
- **`dudosa` resueltas:** 1/iter — `5502` *PAM: Login session closed.* (cierre de la sesión SSH del
  operador) → **`ruido`** (`revisor=executor tanda A`); no es del ataque.
- **`artefacto_ataque=13`**: `execve` no declarados de la carpeta del ataque (el árbol del guion:
  `bash`, `sha256sum`, `stat`, `date`…). Ninguno en `ruido` (CA5).

### 8.2 Métrica de detección — **O1 + O2** (métrica congelada)

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo: alertas / `rule_id` distintos |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T21:16:13.354Z` `audit_exe=/usr/bin/openssl` | **1/1** (`T1486-S1`) | **2 / 13 / 48** | 2 / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T21:22:18.654Z` `audit_exe=/usr/bin/openssl` | **1/1** (`T1486-S1`) | **2 / 13 / 48** | 2 / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|2−2\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ⚠️ 626 vs 604 → Δ=22 (aviso, no bloquea) |
| Sanidad `ruido_conocido` (aviso) | ✅ 48 vs 48 → Δ=0 |

## 10. Limitaciones y hallazgos

1. **2 alertas de detección para 1 técnica:** son **2 `openssl`** (cifrado + descifrado de prueba).
   La **O2** cubre **1/1** acción declarada (`S1`); el **descifrado** es el *proof* del ataque, no una
   acción adicional de la técnica.
2. **Datos de juguete con nombres creíbles** (export de clientes falso); **realismo acotado**
   declarado (README §11 y `Soporte/Ataques/piloto_procedimiento.md` §10).
3. **C0 sin punto ciego** (`openssl` → `80792` level 3).
