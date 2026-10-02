---
fase: 3
bloque: fase-03-p1-cierre
tanda: B
ata_id: ATA050
tecnica: T1567.003
tactica: Exfiltration
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA050 · T1567.003 Exfiltration to Text Storage Sites (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda B**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA050** |
| Técnica | **T1567.003 — Exfiltration to Text Storage Sites** |
| Táctica | Exfiltration |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **custom** |
| Capa del HIDS | **`execve` (`curl`, `80792`)** |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART solo trae la prueba Windows (pastebin.com con API key real); no hay prueba Linux. |
| Material externo | **no** (ninguno: curl de serie; endpoint /paste del receptor sink_http.py del repo) |
| Ataque | `T1567.003-Exfiltration_To_Text_Storage_Sites/ATA050_ataque.sh` (`sha256=a15b85e1c5b6ccb83dfc52656b189ac60168764293548e8f915bb4dfd1ba7928`) |
| Señales | `T1567.003-Exfiltration_To_Text_Storage_Sites/ATA050_esperado.csv` (`sha256=33336a11f8bd33137525aa5f02ffac11276081316a9b91c642c3a7a6069c0969`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA050_logtest.txt` (`d4bc0d433cf7e146890f07b574a0b82b5d077bb4b0fcbec65fc2f3b41a4edbbd`) → `ATA050_preflight.md` **PASA (sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | artefacto | ruido | auto_ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T01:51:06Z` | `2026-10-02T01:51:38Z` | 753 | 1 | 8 | 117 | 627 | `a15b85e1…` |
| 2 | `2026-10-02T01:55:30Z` | `2026-10-02T01:56:02Z` | 755 | 1 | 8 | 116 | 630 | `a15b85e1…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA050
bash ATA050_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** curl POST /paste -> HTTP 200; sink.log sha256=4c9dbfb3… identico al fichero (143 B, text/plain)
- **Iter 2:** idem iter1: POST /paste -> HTTP 200; sha256=4c9dbfb3… identico
- Evidencia en `Logs/ATA050_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `sink.log`).

## 7. Ventana extraída

| Iter | detalle | deteccion |
|---|---|---|
| 1 | 753 | 1 |
| 2 | 755 | 1 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque |
|---|---|---|---|---|---|---|
| 1 | 753 | **1** | 627 | 117 | **0** | 8 |
| 2 | 755 | **1** | 630 | 116 | **0** | 8 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 | 0 |
| 2 | 1 | 1 · `{80792}` | 1 | 0 |

- Iter 1: 1x audit_exe=/usr/bin/curl (execve 80792, cwd del ataque).
- Iter 2: 1x audit_exe=/usr/bin/curl (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T01:51:07.319Z` (execve anclado) | **1/1 (S1)** |
| 2 | **sí** | `{80792}` | `2026-10-02T01:55:32.041Z` (execve anclado) | **1/1 (S1)** |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; conjuntos de `rule_id` idénticos; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS no ve la red; la deteccion es el execve de curl anclado al cwd; la prueba es el sha256 del sink.
2. El endpoint /paste es el do_POST generico del receptor (sin codigo nuevo).
3. C0 sin silenciador. Sin API keys de terceros.
4. La tecnica se mide (POST de texto a un sitio de pegado); se sustituye pastebin real por un /paste local; cero API keys.
5. Sustituto declarado: pastebin.com (API key real) -> endpoint /paste local (192.168.65.1:9090).
6. Realismo acotado declarado (README).

