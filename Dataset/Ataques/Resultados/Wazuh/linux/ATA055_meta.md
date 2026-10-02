---
fase: 3
bloque: fase-03-p1-cierre
tanda: C
ata_id: ATA055
tecnica: T1557.003
tactica: Credential Access; Collection
version: 1
status: cerrado
fecha: 2026-10-02
---

# Ficha — ATA055 · T1557.003 DHCP Spoofing (Linux / `victima-linux`)

> Bloque `fase-03-p1-cierre` (**tanda C**). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA055** |
| Técnica | **T1557.003 — DHCP Spoofing** |
| Táctica | Credential Access; Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (ART sin prueba de T1557) |
| Capa del HIDS | **`execve`** (`80792`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (propio; ART sin prueba de esta técnica) |
| `fuente_norm` / `motivo_codigo` | `propio` / `art_no_prueba_plataforma` |
| Motivo | ART no trae prueba de T1557 (técnica ausente del clon) → propio. |
| Material externo | **no** (busybox/ip de serie; conf y lease_script propios del repo) |
| Ataque | `T1557.003-DHCP_Spoofing/ATA055_ataque.sh` (`sha256=7ae610bc5dd5430995e1c55b953b4344e3e502f0b33a676d893356fd6e2a35c6`) |
| Señales | `T1557.003-DHCP_Spoofing/ATA055_esperado.csv` (`sha256=014a0758c7af3b09ee52fb4c00551face05be8ea8b0caf675a4701ff5ce8f492`) |
| Validación humana | **APROBADO 2026-10-02** |
| C0 | `ATA055_logtest.txt` (`20c69abf79712cb8174a605c3f783c783c1a7f04347cd38fdd684f6830b28556`) → `ATA055_preflight.md` **PASA (2 eventos busybox/ip → 80792 level 3; sin silenciador)** |

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras el asentamiento. Segmento
local aislado (par veth) creado y retirado dentro de la ventana.

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | deteccion | artefacto | ruido | sha256 ataque |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-02T03:23:38Z` | `2026-10-02T03:24:20Z` | 42 s | 1849 | 10 | 29 | 1186 | `7ae610bc…` |
| 2 | `2026-10-02T03:27:44Z` | `2026-10-02T03:28:26Z` | 42 s | 1844 | 12 | 27 | 1184 | `7ae610bc…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA055
echo '<pw>' | sudo -S bash ATA055_ataque.sh
```

## 6. Evidencia y prueba de efecto (independiente de la alerta)

- **Iter 1:** `udhcpc: lease of 10.99.0.101 obtained from 10.99.0.1`; `lease.obtained`:
  `ip=10.99.0.101 mask=24 router=10.99.0.1 dns=10.99.0.1 serverid=10.99.0.1` →
  el cliente aceptó el **gateway/DNS del atacante**; udhcpd/veth residuales=0.
- **Iter 2:** idéntico.
- Evidencia en `Logs/ATA055_iter{1,2}/` (`times_iter*.log`, `ejecucion.out`, `srv.out`, `cli.out`,
  `lease.obtained`).

## 7. Ventana extraída

| Iter | raw | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1859 | 1849 | 1849 |
| 2 | 1854 | 1844 | 1844 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1849 | **10** | 624 | 1186 | **0** | 29 | 7 | 1842 | 0 | 0 |
| 2 | 1844 | **12** | 621 | 1184 | **0** | 27 | 7 | 1837 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 10 | 1 · `{80792}` | 10 | 0 |
| 2 | 12 | 1 · `{80792}` | 12 | 0 |

- Iter 1: 6x `ip` + 4x `busybox` (execve 80792, cwd del ataque).
- Iter 2: 8x `ip` + 4x `busybox` (execve 80792, cwd del ataque).
- **`dudosa` resueltas:** 9 (iter1) / 7 (iter2): sesiones PAM/`sudo` → `ruido`; `execve` del ataque
  sin ancla → `artefacto`. **0 filas del ataque en `ruido`**.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 |
|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-10-02T03:23:40.264Z` (execve `busybox` anclado) | **2/2** (S1 `busybox`, S2 `ip`) |
| 2 | **sí** | `{80792}` | `2026-10-02T03:27:46.421Z` (execve `busybox` anclado) | **2/2** (S1 `busybox`, S2 `ip`) |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792} == {80792}`; `|12−10| = 2 ≤ max(2, 10%·10)=2`; sin dudosas → **`iguales`**.

## 10. Limitaciones y hallazgos

1. El HIDS de host **no ve la red**; la detección es el `execve` (`busybox`/`ip`) y la prueba es el
   **lease** entregado por el señuelo.
2. El segmento se **simula con un par veth aislado** (sustituto declarado de `VMnet1`): el DHCP de
   VMware (`vmnetdhcp`) sirve el mismo rango `.128–.254` y competir con él podría **romper la red**;
   el segmento aislado hace el mecanismo **fiel con riesgo 0**.
3. La señal `audit_exe=busybox` es amplia (cualquier applet); el `cwd` la ancla.
4. Binario real declarado: `busybox` → `/usr/bin/busybox`; `ip` → `/usr/bin/ip` (symlink).
5. C0 sin silenciador.
6. Realismo acotado declarado (README §9).
