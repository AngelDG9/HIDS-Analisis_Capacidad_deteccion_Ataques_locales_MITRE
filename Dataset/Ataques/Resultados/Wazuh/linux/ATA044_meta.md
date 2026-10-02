---
fase: 3
bloque: fase-03-p1-cierre
tanda: A
ata_id: ATA044
tecnica: T1025
tactica: Collection
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA044 · T1025 Data from Removable Media (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda A**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA044** |
| Técnica | **T1025 — Data from Removable Media** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (propio; ART sin prueba de esta técnica/plataforma) |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART solo trae prueba Windows de T1025 (PowerShell/Get-Volume); no hay prueba Linux -> propio. |
| Material externo | **no** (sin material externo: todos los binarios son de serie; la imagen vfat se crea localmente en el pre-staging (sin URL)) |
| Ataque | `T1025-Data_from_Removable_Media/ATA044_ataque.sh` (`sha256=c18a644a131f9e17c37e07db3ecb9a9bdef5d66b064df203bb2e4339e14ba26d`) |
| Señales | `T1025-Data_from_Removable_Media/ATA044_esperado.csv` (`sha256=bcbc8ee26fd79b8b120c53984e62d1e48f5a56b8c6372b814e665c68598ac36e`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA044_logtest.txt` (`e1e7655a3edc71214b93b6aa53b9a73e3eb31a94cac635552e00c53411f480d7`) → `ATA044_preflight.md` **PASA (6 eventos mount/losetup/cp/find/sha256sum/umount -> 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T00:10:28Z` | `2026-10-02T00:11:05Z` | 37 s | 845 | 17 | 32 | 190 | `c18a644a…` |
| 2 | `2026-10-02T00:17:11Z` | `2026-10-02T00:17:44Z` | 33 s | 935 | 16 | 31 | 230 | `c18a644a…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA044
bash ATA044_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** documentos_recopilados=3; sha256 origen==copia; loop_residual=0; imagen hash_imagen 8142ddd5…
- **Iter 2:** documentos_recopilados=3; sha256 origen==copia; loop_residual=0; imagen hash_imagen 4d8c7063…
- Evidencia en `Logs/ATA044_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 853 | 845 | 845 |
| 2 | 942 | 935 | 935 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 845 | **17** | 606 | 190 | **0** | 32 | 16 | 829 | 0 | 0 |
| 2 | 935 | **16** | 658 | 230 | **0** | 31 | 18 | 917 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 17 | 1 · `{80792}` | 17 | 0 |
| 2 | 16 | 1 · `{80792}` | 16 | 0 |

- Iter 1: 7x sha256sum + 4x losetup + 3x cp + 1x mount + 1x find + 1x umount (execve 80792, cwd del ataque).
- Iter 2: 7x sha256sum + 3x losetup + 3x cp + 1x mount + 1x find + 1x umount (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T00:10:28Z` + segundos (execve anclado) | **6/6** (S1..S6 (losetup/mount/find/cp/sha256sum/umount)) |
| 2 | **sí** | `{80792}` | `2026-10-02T00:17:11Z` + segundos (execve anclado) | **6/6** (S1..S6 (losetup/mount/find/cp/sha256sum/umount)) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|16−17| = 1` dentro del margen; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS ve el execve de las herramientas de montaje/copia, no que el medio sea extraible ni el contenido.
2. El 'medio extraible' es una imagen de fichero en SOLO-LECTURA (equivalente local acotado de un USB).
3. C0 sin silenciador.
4. Realismo acotado declarado (README, realismo acotado).
