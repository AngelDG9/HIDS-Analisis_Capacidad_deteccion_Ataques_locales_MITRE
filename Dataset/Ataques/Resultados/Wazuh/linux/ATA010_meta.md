---
fase: 3
bloque: fase-03-escalado
tanda: B
ata_id: ATA010
tecnica: T1041
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA010 · T1041 Exfiltration Over C2 Channel (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda B**, 3.º de 3; cierre de la tanda B y del bloque). Generada por
> `tfg-executor`. **Sin secretos.** Estado **`cerrado`**: criterio de doble iteración **v2** →
> **`iguales`**. Métrica congelada (O1+O2). **Simulación segura:** el canal C2 es el **receptor local
> del HOST** (`sink_http.py`, **D4 opción A**), **sin NAT** y sin infraestructura de mando real.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA010** |
| Técnica | **T1041 — Exfiltration Over C2 Channel** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (ART no trae pruebas Linux de T1041 → `solo_windows`) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`audit_command`, regla `80792`, RS2) — la **red** no es visible para el HIDS de host |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`curl`** (`/usr/bin/curl`, 8.5.0) |
| Efecto | `POST` a `http://192.168.65.1:9090/c2/beacon` (receptor del HOST como C2) |
| Decisión | **D4 opción A** (reutilizar el receptor HTTP como C2; alternativa `bash /dev/tcp` documentada, no usada) |
| Elevación | **no** |
| Guardarraíl | el endpoint **DEBE** ser `http://192.168.65.1:9090/…` (aborta si no) |

Artefacto: `Dataset/Ataques/Comandos/T1041-Exfiltration_Over_C2_Channel/ATA010_ataque.sh`
(`sha256=b0f29a25441e333045a5bb127e0a635a404ca4d4d3e1cb2d4d45ab8e7fd6f3c4`).
Señales esperadas: `.../ATA010_esperado.csv`
(`sha256=7dc1fe5666261b621e42dd6b6cfc35df7dda87a4a0f079eee3412b0798c6839a`).
Validación humana (CA1): **APROBADO 2026-09-29** (firma en su cabecera).
C0: `Soporte/Ataques/c0/ATA010_logtest.txt`
(`sha256=47242630787b62307108eb12ce8f17b014baeb5a457ed1ff448ca8ea1957937a`, **mismo `curl`** que ATA009)
→ pre-flight `ATA010_preflight.md` **PASA** (1 evento `curl` → `80792` level 3; **sin** silenciador).

## 3. Snapshot y red

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. `t0` tras **95 s de asentamiento** en **una sola sesión SSH**.
- **Receptor-C2** levantado en el HOST **antes de `t0`** y **parado tras `t1`**. El puerto `9090` ya era
  alcanzable ⇒ **no se creó** regla de firewall (verificado ausente → CA10).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA010_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T23:21:49Z` | `2026-09-28T23:22:30Z` | 41 s | 640 | `b0f29a25…d6f3c4` |
| 2 | `2026-09-28T23:25:32Z` | `2026-09-28T23:26:13Z` | 41 s | 630 | `b0f29a25…d6f3c4` |

`t0 < t1` en ambas; `T1_LOCAL` (`…:50Z`, `…:33Z`) **≠ T0**. Reloj víctima↔manager `|Δ| < 1 s`.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA010
bash ATA010_ataque.sh      # curl POST del beacon (check-in del implante) al canal C2
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA010_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, **`sink.log`**.

**Prueba de éxito (independiente de la alerta) — el beacon SALIÓ por el canal C2:**

| Iter | beacon (`sha256` local) | `sink.log` del HOST | ¿coincide? |
|---|---|---|---|
| 1 | `8d21e366840a3c4bee5f8e7402555a26fcd977a181e7ee8924aecf72535e0ad8` | `POST /c2/beacon from=192.168.65.129 len=86 sha256=8d21e366…0ad8` | **SÍ** ✅ |
| 2 | `8d21e366840a3c4bee5f8e7402555a26fcd977a181e7ee8924aecf72535e0ad8` | idem | **SÍ** ✅ |

`HTTP=200 enviado=86B` en ambas. El `sha256` del cuerpo recibido es **IDÉNTICO** al del beacon ⇒ el
canal C2 quedó establecido y el payload **salió** de la víctima.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final |
|---|---|---|---|---|
| 1 | 647 | 640 | 7 | **640** |
| 2 | 638 | 630 | 8 | **630** |

## 8. Resultado (conteos por categoría)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 640 | **1** | 631 | 1 | **0** | **7** | 0 | 640 | 0 | 0 |
| 2 | 630 | **1** | 620 | 1 | **0** | **8** | 0 | 630 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **1** | 1 · `{80792}` | 1 (`S1`) | 0 |
| 2 | **1** | 1 · `{80792}` | 1 (`S1`) | 0 |

- La **única** alerta de detección es el **`execve` de `curl`** (`80792`, `audit_command`), anclado a
  `cwd=/home/angel/lab-attack/ATA010` por `T1041-S2`.
- **`artefacto_ataque`** (7/8): `execve` no declarados del árbol del guion (`sha256sum`, `date`…).
  **Ninguna fila del ataque en `ruido`** (CA5). **`dudosa` = 0** → **sin `-Revision.csv`**.

### 8.2 Métrica de detección — **O1 + O2** (métrica congelada)

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T23:21:51.517Z` `audit_exe=/usr/bin/curl` | **1/1** (`S1`) | **1 / 7 / 1** | 1 alerta / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T23:25:33.331Z` `audit_exe=/usr/bin/curl` | **1/1** (`S1`) | **1 / 8 / 1** | 1 alerta / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|1−1\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ⚠️ 631 vs 620 → Δ=11 (aviso) |
| Sanidad `ruido_conocido` (aviso) | ✅ 1 vs 1 → Δ=0 |

## 10. Limitaciones y hallazgos

1. **El HIDS ve el proceso, no el canal:** sin reglas de salida, la detección es el **`execve` de
   `curl`**; la **prueba** del canal es el **`sink.log`** del HOST (sha256).
2. **D4-A** (reutilizar el receptor HTTP como C2): `curl` ya existía en la víctima, **no** se instaló
   nada y **no** se inventó infraestructura. **Sin NAT**.
3. **C0 sin punto ciego** (`curl` → `80792` level 3). **Realismo acotado** declarado (README §12).
4. **Instrumentación t0/t1 (tanda B):** una sola sesión SSH; `T1_LOCAL > T0`; `t1` oficial tras el scan
   FIM; **0 `dudosa`**. **Cierre de la tanda B** (receptor parado, sin regla de firewall, víctima a
   `lab-listo`, VMs apagadas).
