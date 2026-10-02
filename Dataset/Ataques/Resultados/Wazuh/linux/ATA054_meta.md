---
fase: 3
bloque: fase-03-p1-cierre
tanda: C
ata_id: ATA054
tecnica: T1498.002
tactica: Impact
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA054 · T1498.002 Reflection Amplification (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda C**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA054** |
| Técnica | **T1498.002 — Reflection Amplification** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (ART sin prueba de T1498) |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (propio; ART sin prueba de esta técnica) |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART no trae prueba de T1498 (técnica ausente del clon) → propio. |
| Material externo | **no** (perl/ip de serie; reflector/spoofer/target propios del repo) |
| Ataque | `T1498.002-Reflection_Amplification/ATA054_ataque.sh` (`sha256=3e6e24ee7784d4a47feda62f05add011f0f139021ad17ffb9bc0bdba07890710`) |
| Señales | `T1498.002-Reflection_Amplification/ATA054_esperado.csv` (`sha256=4dd9b164ab980027197c0775c98f32aab9f396a1f419a7bc9d24e9b21d90dabd`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA054_logtest.txt` (`4b070e0a32b5cc8143614fdd91254c516a36bd78670b3376d7b0402d138e92de`) → `ATA054_preflight.md` **PASA (2 eventos perl/ip → 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento. Segmento
local aislado (veth+netns) creado y retirado dentro de la ventana.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T03:14:11Z` | `2026-10-02T03:14:55Z` | 44 s | 1849 | 32 | 24 | 1183 | `3e6e24ee…` |
| 2 | `2026-10-02T03:19:29Z` | `2026-10-02T03:20:14Z` | 45 s | 1848 | 32 | 25 | 1179 | `3e6e24ee…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA054
echo '<pw>' | sudo -S bash ATA054_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** `spoofer requests=25 payload=400 B`; `reflector respuestas=25 bytes=102400`;
  `target paquetes=25 bytes=102400` → **factor ≈ 256**; netns/veth residuales=0.
- **Iter 2:** idéntico (`target paquetes=25 bytes=102400`).
- Evidencia en `Logs/ATA054_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `reflector.out`,
  `target.out`, `spoofer.out`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1858 | 1849 | 1849 |
| 2 | 1857 | 1848 | 1848 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1849 | **32** | 610 | 1183 | **0** | 24 | 8 | 1841 | 0 | 0 |
| 2 | 1848 | **32** | 612 | 1179 | **0** | 25 | 7 | 1841 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 32 | 1 · `{80792}` | 32 | 0 |
| 2 | 32 | 1 · `{80792}` | 32 | 0 |

- Iter 1: 30x `ip` + 2x `perl` (execve 80792, cwd del ataque).
- Iter 2: 29x `ip` + 3x `perl` (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** 13 (iter1) / 12 (iter2): sesiones PAM/`sudo` → `ruido`; `execve`/`watch`
  del ataque sin ancla → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T03:14:11.876Z` (execve `ip` anclado) | **2/2** (S1 `perl`, S2 `ip`) |
| 2 | **sí** | `{80792}` | `2026-10-02T03:19:30.320Z` (execve `ip` anclado) | **2/2** (S1 `perl`, S2 `ip`) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|32−32| = 0`; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS de host **no ve la red**; la detección es el `execve` del cliente/reflector y la prueba es
   el `target` (bytes amplificados recibidos).
2. El reflector se **monta en un segmento local aislado** (veth+netns) dentro de la víctima: sustituto
   declarado de un tercer reflector de red; **nunca** el manager ni el PC.
3. La señal `audit_exe=ip` es **ancha** (cualquier `ip`); el `cwd` la ancla. Los `ip`/`perl` con
   `cwd` vacío quedaron **`artefacto`** (no son la detección declarada).
4. Binario real declarado: `perl` → `/usr/bin/perl`; `ip` → `/usr/bin/ip` (symlink).
5. C0 sin silenciador.
6. Realismo acotado declarado (README §9).
