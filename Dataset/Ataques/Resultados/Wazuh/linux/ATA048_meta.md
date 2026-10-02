---
fase: 3
bloque: fase-03-p1-cierre
tanda: A
ata_id: ATA048
tecnica: T1498.001
tactica: Impact
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA048 · T1498.001 Direct Network Flood (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda A**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA048** |
| Técnica | **T1498.001 — Direct Network Flood** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (propio; ART sin prueba de esta técnica/plataforma) |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART no trae prueba de T1498 (tecnica ausente del clon) -> propio. |
| Material externo | **no** (sin material externo: nc.openbsd/head/timeout de serie; receptor sink_http.py del repo) |
| Ataque | `T1498.001-Direct_Network_Flood/ATA048_ataque.sh` (`sha256=fec875a482976c2bb9c60339e22e0f7aa3dd6faaa26b7adca90b971e4f0adb27`) |
| Señales | `T1498.001-Direct_Network_Flood/ATA048_esperado.csv` (`sha256=7c98658e66c6839765e6eb4bfd2c9fdaa5607f601df497fb256227a019040972`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA048_logtest.txt` (`dc2c1756dff9d6943b7673e64f8cba862fe791ad76ab999a960992d7f311e0a5`) → `ATA048_preflight.md` **PASA (3 eventos nc.openbsd/head/timeout -> 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T00:55:23Z` | `2026-10-02T00:55:56Z` | 33 s | 1008 | 43 | 26 | 329 | `fec875a4…` |
| 2 | `2026-10-02T00:59:51Z` | `2026-10-02T01:00:24Z` | 33 s | 1014 | 45 | 24 | 333 | `fec875a4…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA048
bash ATA048_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** sink TCP: 8 conexiones, cada una len=8388608, hash_cuerpo 2daeb1f3…; suma=67108864 B; nc residuales=0
- **Iter 2:** sink TCP: 8 conexiones, cada una len=8388608, hash_cuerpo 2daeb1f3…; suma=67108864 B; nc residuales=0
- Evidencia en `Logs/ATA048_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1016 | 1008 | 1008 |
| 2 | 1022 | 1014 | 1014 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1008 | **43** | 610 | 329 | **0** | 26 | 3 | 1005 | 0 | 0 |
| 2 | 1014 | **45** | 612 | 333 | **0** | 24 | 4 | 1010 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 43 | 1 · `{80792}` | 43 | 0 |
| 2 | 45 | 1 · `{80792}` | 45 | 0 |

- Iter 1: 28x timeout + 8x head + 7x nc.openbsd (execve 80792, cwd del ataque).
- Iter 2: 30x timeout + 8x nc.openbsd + 7x head (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T00:55:23Z` + segundos (execve anclado) | **3/3** (S1..S3 (nc.openbsd/head/timeout)) |
| 2 | **sí** | `{80792}` | `2026-10-02T00:59:51Z` + segundos (execve anclado) | **3/3** (S1..S3 (nc.openbsd/head/timeout)) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|45−43| = 2` dentro del margen; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS de host NO ve la red; la deteccion es el execve del cliente y la prueba es el sink.log (bytes recibidos).
2. Binario real de nc declarado (/usr/bin/nc.openbsd); si no, la fila baja a artefacto.
3. El flood va SIEMPRE al receptor del HOST (VMnet1); nunca el manager.
4. C0 sin silenciador.
5. Realismo acotado declarado (README, realismo acotado).
