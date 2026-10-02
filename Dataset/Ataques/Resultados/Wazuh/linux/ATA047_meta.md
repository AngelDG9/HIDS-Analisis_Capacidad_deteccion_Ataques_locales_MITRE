---
fase: 3
bloque: fase-03-p1-cierre
tanda: A
ata_id: ATA047
tecnica: T1499.002
tactica: Impact
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA047 · T1499.002 Service Exhaustion Flood (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda A**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA047** |
| Técnica | **T1499.002 — Service Exhaustion Flood** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (propio; ART sin prueba de esta técnica/plataforma) |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART no trae prueba de T1499 (tecnica ausente del clon) -> propio. |
| Material externo | **no** (sin material externo: curl/xargs/seq/timeout de serie; el servicio es sink_http.py (Python stdlib) del repo) |
| Ataque | `T1499.002-Service_Exhaustion_Flood/ATA047_ataque.sh` (`sha256=340b22d6690c1f2d5095dd5a78e07de4791ccb8a8ae03deafbb78ebe1a677d60`) |
| Señales | `T1499.002-Service_Exhaustion_Flood/ATA047_esperado.csv` (`sha256=d76d8a186fce6c31b1ccd07a5db3bc51f417bcbd556d3bd429503e215ba467e9`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA047_logtest.txt` (`5199fc5b6b9fa90f1cd4454e713d31ed1c3ec99ae89a2e0de2f5f2735d1ef591`) → `ATA047_preflight.md` **PASA (4 eventos curl/xargs/seq/timeout -> 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T00:46:19Z` | `2026-10-02T00:46:53Z` | 34 s | 2340 | 1604 | 15 | 76 | `340b22d6…` |
| 2 | `2026-10-02T00:51:07Z` | `2026-10-02T00:51:41Z` | 34 s | 2316 | 1603 | 15 | 75 | `340b22d6…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA047
bash ATA047_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** peticiones_recibidas=400; svc_cpu_usada_s=0.19; svc_vivo_final=1
- **Iter 2:** peticiones_recibidas=400; svc_cpu_usada_s=0.19; svc_vivo_final=1
- Evidencia en `Logs/ATA047_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 2348 | 2340 | 2340 |
| 2 | 2323 | 2316 | 2316 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2340 | **1604** | 645 | 76 | **0** | 15 | 3 | 2337 | 0 | 0 |
| 2 | 2316 | **1603** | 623 | 75 | **0** | 15 | 3 | 2313 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1604 | 1 · `{80792}` | 1604 | 0 |
| 2 | 1603 | 1 · `{80792}` | 1603 | 0 |

- Iter 1: 1201x xargs + 398x curl + 4x timeout + 1x seq (execve 80792, cwd del ataque).
- Iter 2: 1198x xargs + 400x curl + 4x timeout + 1x seq (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T00:46:19Z` + segundos (execve anclado) | **4/4** (S1..S4 (curl/xargs/seq/timeout)) |
| 2 | **sí** | `{80792}` | `2026-10-02T00:51:07Z` + segundos (execve anclado) | **4/4** (S1..S4 (curl/xargs/seq/timeout)) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|1603−1604| = 1` dentro del margen; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. Wazuh no tiene reglas de servicio/recursos -> el volumen no se ve; solo el execve del cliente.
2. El servicio (python3, sink_http.py) arranca en el pre-staging (fuera de la ventana); nunca el manager.
3. ANOMALIA declarada: la rafaga genero ~1200 execve de xargs para 400 peticiones (~3x); el conteo bruto se infla, O1/O2 no se ven afectados.
4. C0 sin silenciador.
5. Realismo acotado declarado (README, realismo acotado).
