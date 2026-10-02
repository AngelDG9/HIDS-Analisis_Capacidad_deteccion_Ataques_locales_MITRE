---
fase: 3
bloque: fase-03-p1-cierre
tanda: A
ata_id: ATA046
tecnica: T1499.003
tactica: Impact
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA046 · T1499.003 Application Exhaustion Flood (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda A**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA046** |
| Técnica | **T1499.003 — Application Exhaustion Flood** |
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
| Material externo | **no** (sin material externo: curl/xargs/seq/timeout de serie; la app es Python stdlib del propio repo) |
| Ataque | `T1499.003-Application_Exhaustion_Flood/ATA046_ataque.sh` (`sha256=a748dffb250f721abed80b9598b9d04f3e3f1563a7715602f13829d826bf1a49`) |
| Señales | `T1499.003-Application_Exhaustion_Flood/ATA046_esperado.csv` (`sha256=b386cff01a23b319c0fdc76f07e0c1fa5fecca6e74e9427db51fb37a34280dd1`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA046_logtest.txt` (`8d47134b134dd8b6ae42a352dc663647cc5a61d5c84b01831d5a5c1ab0b3c0ca`) → `ATA046_preflight.md` **PASA (4 eventos curl/xargs/seq/timeout -> 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T00:37:00Z` | `2026-10-02T00:37:35Z` | 35 s | 791 | 70 | 20 | 75 | `a748dffb…` |
| 2 | `2026-10-02T00:41:41Z` | `2026-10-02T00:42:16Z` | 35 s | 780 | 70 | 20 | 75 | `a748dffb…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA046
bash ATA046_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** peticiones_servidas=16; app_cpu_usada_s=2.29; latencia_min_s=0.158020; latencia_max_s=0.590515; app_viva_final=1
- **Iter 2:** peticiones_servidas=16; app_cpu_usada_s=2.29; latencia_min_s=0.142941; latencia_max_s=0.576843; app_viva_final=1
- Evidencia en `Logs/ATA046_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 799 | 791 | 791 |
| 2 | 787 | 780 | 780 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 791 | **70** | 626 | 75 | **0** | 20 | 3 | 788 | 0 | 0 |
| 2 | 780 | **70** | 615 | 75 | **0** | 20 | 3 | 777 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 70 | 1 · `{80792}` | 70 | 0 |
| 2 | 70 | 1 · `{80792}` | 70 | 0 |

- Iter 1: 49x xargs + 16x curl + 4x timeout + 1x seq (execve 80792, cwd del ataque).
- Iter 2: 49x xargs + 16x curl + 4x timeout + 1x seq (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** sesiones PAM/`sudo` → `ruido`; `execve` sin ancla / del ataque → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T00:37:00Z` + segundos (execve anclado) | **4/4** (S1..S4 (curl/xargs/seq/timeout)) |
| 2 | **sí** | `{80792}` | `2026-10-02T00:41:41Z` + segundos (execve anclado) | **4/4** (S1..S4 (curl/xargs/seq/timeout)) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|70−70| = 0` dentro del margen; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. Wazuh no tiene reglas de recursos/aplicacion -> el grado de saturacion no se ve; solo el execve del cliente.
2. La app (python3) arranca en el pre-staging (fuera de la ventana): el posible punto ciego 92600 no afecta a la deteccion de la accion.
3. ANOMALIA declarada: la rafaga genero 49 execve de xargs (para 16 peticiones); el conteo bruto se infla, O1/O2 no se ven afectados.
4. C0 sin silenciador.
5. Realismo acotado declarado (README, realismo acotado).
