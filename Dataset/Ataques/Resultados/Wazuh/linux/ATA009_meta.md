---
fase: 3
bloque: fase-03-escalado
tanda: B
ata_id: ATA009
tecnica: T1567
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA009 · T1567 Exfiltration Over Web Service (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda B**, 2.º de 3). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Simulación segura:** el "servicio web" es el **receptor local del HOST** (`sink_http.py`), **sin
> NAT**, sin nube y sin credenciales. No se toca ninguna ruta vigilada.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA009** |
| Técnica | **T1567 — Exfiltration Over Web Service** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (las pruebas ART de T1567 usan rclone→nube o terraform+AWS → no ejecutables sin NAT) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`audit_command`, regla `80792`, RS2) — la **red** no es visible para el HIDS de host |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`curl`** (`/usr/bin/curl`, 8.5.0) |
| Efecto | `POST` a `http://192.168.65.1:9090/api/upload/informe_ventas_2026-Q3.csv` (receptor del HOST) |
| Elevación | **no** |
| Guardarraíl | el endpoint **DEBE** ser `http://192.168.65.1:9090/…` (aborta si no) |

Artefacto: `Dataset/Ataques/Comandos/T1567-Exfiltration_Over_Web_Service/ATA009_ataque.sh`
(`sha256=a3788fc77420ae529901063840769250694f3743fb21b392419c08d834fa2070`).
Señales esperadas: `.../ATA009_esperado.csv`
(`sha256=40900f47b1b62e65f16c85d276cdc80499eba1e038340ceb0cc9ca3147350385`).
Validación humana (CA1): **APROBADO 2026-09-29** (firma en su cabecera).
C0: `Soporte/Ataques/c0/ATA009_logtest.txt`
(`sha256=47242630787b62307108eb12ce8f17b014baeb5a457ed1ff448ca8ea1957937a`)
→ pre-flight `ATA009_preflight.md` **PASA** (1 evento `curl` → `80792` level 3; **sin** silenciador).

## 3. Snapshot y red

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. `t0` tras **95 s de asentamiento** en **una sola sesión SSH**.
- **Receptor** (`sink_http.py`) levantado en el HOST **antes de `t0`** y **parado tras `t1`**.
  El puerto `9090` **ya era alcanzable** desde la víctima ⇒ **no se necesitó** regla de firewall
  (`TFG-sink-9090` **nunca se creó**; verificado ausente → CA10).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA009_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T23:13:17Z` | `2026-09-28T23:13:58Z` | 41 s | 645 | `a3788fc7…fa2070` |
| 2 | `2026-09-28T23:17:15Z` | `2026-09-28T23:17:56Z` | 41 s | 645 | `a3788fc7…fa2070` |

`t0 < t1` en ambas; `T1_LOCAL` (`…:18Z`, `…:16Z`) **≠ T0**. Reloj víctima↔manager `|Δ| < 1 s`.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA009
bash ATA009_ataque.sh      # curl POST del "informe de ventas" al receptor del HOST
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA009_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `sha256_artefacto.txt`, **`sink.log`**.

**Prueba de éxito (independiente de la alerta) — el dato SALIÓ de la víctima:**

| Iter | fichero exfiltrado (`sha256` local) | `sink.log` del HOST | ¿coincide? |
|---|---|---|---|
| 1 | `8122d8091521358fddb88ce7371a6a68367cb73c248e244d037e08ca07a83e79` | `POST /api/upload/informe_ventas_2026-Q3.csv from=192.168.65.129 len=153 sha256=8122d809…e79` | **SÍ** ✅ |
| 2 | `8122d8091521358fddb88ce7371a6a68367cb73c248e244d037e08ca07a83e79` | idem | **SÍ** ✅ |

`HTTP=200 enviado=153B` en ambas. El `sha256` del cuerpo recibido es **IDÉNTICO** al del fichero
enviado ⇒ la exfiltración ocurrió **de verdad**.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros (descartadas) | Detalle final |
|---|---|---|---|---|
| 1 | 653 | 645 | 8 | **645** |
| 2 | 652 | 645 | 7 | **645** |

## 8. Resultado (conteos por categoría)

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 645 | **1** | 636 | 0 | **0** | **8** | 0 | 645 | 0 | 0 |
| 2 | 645 | **1** | 636 | 1 | **0** | **7** | 0 | 645 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **1** | 1 · `{80792}` | 1 (`S1`) | 0 |
| 2 | **1** | 1 · `{80792}` | 1 (`S1`) | 0 |

- La **única** alerta de detección es el **`execve` de `curl`** (`80792`, `audit_command`), anclado a
  `cwd=/home/angel/lab-attack/ATA009` por `T1567-S2`.
- **`artefacto_ataque`** (8/7): `execve` no declarados del árbol del guion (`sha256sum`, `date`…).
  **Ninguna fila del ataque en `ruido`** (CA5). **`dudosa` = 0** → **sin `-Revision.csv`**.

### 8.2 Métrica de detección — **O1 + O2** (métrica congelada)

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T23:13:19.202Z` `audit_exe=/usr/bin/curl` | **1/1** (`S1`) | **1 / 8 / 0** | 1 alerta / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T23:17:17.058Z` `audit_exe=/usr/bin/curl` | **1/1** (`S1`) | **1 / 7 / 1** | 1 alerta / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|1−1\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ✅ 636 vs 636 → Δ=0 |
| Sanidad `ruido_conocido` (aviso) | ✅ 0 vs 1 → Δ=1 |

## 10. Limitaciones y hallazgos

1. **El HIDS ve el proceso, no la red:** no hay reglas de salida en el ruleset base ⇒ la detección es
   el **`execve` de `curl`**; la **prueba** de la exfiltración es el **`sink.log`** del HOST (sha256).
2. **Sin NAT / sin nube / sin claves** (D3/D4 declarados). El "servicio web" es **infraestructura local**.
3. **C0 sin punto ciego** (`curl` → `80792` level 3). **Realismo acotado** declarado (README §11).
4. **Instrumentación t0/t1 (tanda B):** una sola sesión SSH; `T1_LOCAL > T0`; `t1` oficial tras el scan
   FIM; **0 `dudosa`** (sin PAM del operador dentro de la ventana).
