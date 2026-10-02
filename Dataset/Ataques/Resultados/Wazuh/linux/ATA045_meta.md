---
fase: 3
bloque: fase-03-p1-cierre
tanda: A
ata_id: ATA045
tecnica: T1499.001
tactica: Impact
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA045 · T1499.001 OS Exhaustion Flood (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda A**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA045** |
| Técnica | **T1499.001 — OS Exhaustion Flood** |
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
| Material externo | **no** (sin material externo: dd/timeout/free/rm de serie) |
| Ataque | `T1499.001-OS_Exhaustion_Flood/ATA045_ataque.sh` (`sha256=7e82f500f41cad49531db9c79908fc9f9d0d857991f872eb873a69294d0f5148`) |
| Señales | `T1499.001-OS_Exhaustion_Flood/ATA045_esperado.csv` (`sha256=6c33c96c1d6cc11f3c1aae9c3aaf7cb29a283857760ae4442804341723f41c5e`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA045_logtest.txt` (`77fbe83bdf40fd560929c42560a77712e244c6de2a5b752b763fdf83451cc6cf`) → `ATA045_preflight.md` **PASA (4 eventos dd/timeout/free/rm -> 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T00:21:14Z` | `2026-10-02T00:21:53Z` | 39 s | 956 | 8 | 15 | 328 | `7e82f500…` |
| 2 | `2026-10-02T00:26:56Z` | `2026-10-02T00:27:35Z` | 39 s | 880 | 9 | 14 | 250 | `7e82f500…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA045
bash ATA045_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** mem_available antes=2483 MB, durante=1976 MB, despues=2494 MB; caida=507 MB; recuperado=518 MB; fichero_residual=no
- **Iter 2:** mem_available antes=2485 MB, durante=1980 MB, despues=2494 MB; caida=505 MB; recuperado=514 MB; fichero_residual=no
- Evidencia en `Logs/ATA045_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 964 | 956 | 956 |
| 2 | 888 | 880 | 880 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 956 | **8** | 605 | 328 | **0** | 15 | 1 | 955 | 0 | 0 |
| 2 | 880 | **9** | 607 | 250 | **0** | 14 | 6 | 874 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 8 | 1 · `{80792}` | 8 | 0 |
| 2 | 9 | 1 · `{80792}` | 9 | 0 |

- Iter 1: 4x timeout + 2x free + 1x dd + 1x rm (execve 80792, cwd del ataque).
- Iter 2: 4x timeout + 3x free + 1x dd + 1x rm (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T00:21:14Z` + segundos (execve anclado) | **4/4** (S1..S4 (dd/timeout/free/rm)) |
| 2 | **sí** | `{80792}` | `2026-10-02T00:26:56Z` + segundos (execve anclado) | **4/4** (S1..S4 (dd/timeout/free/rm)) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|9−8| = 1` dentro del margen; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. Wazuh NO tiene reglas de CPU/RAM -> el agotamiento no se ve; la unica capa es el execve.
2. Con builtins del shell no habria execve -> punto ciego total (R9).
3. C0 sin silenciador.
4. Realismo acotado declarado (README, realismo acotado).
