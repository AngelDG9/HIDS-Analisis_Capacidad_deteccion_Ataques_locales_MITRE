---
fase: 3
bloque: fase-03-ampliacion
tanda: C
ata_id: ATA028
tecnica: T1056.003
tactica: Collection
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA028 · T1056.003 Web Portal Capture (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion` (**tanda C**, 3.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> Portal **local y simulado** (loopback), credenciales **de juguete**; servido con **`nc`** (no
> `python3`) para **no** caer en el punto ciego de fábrica `92600`.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA028** |
| Técnica | **T1056.003 — Input Capture: Web Portal Capture** |
| Táctica | Collection / Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`) — el HIDS de host no ve la red |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `nc` (portal falso) + `curl` (cliente) |
| Efecto | el portal **registra** el POST con las credenciales **de juguete** |
| Elevación | **no** |
| Guardarraíl | **solo** `127.0.0.1`, puerto alto, `timeout` en el listener, credenciales de juguete |

Artefacto: `.../T1056.003-Web_Portal_Capture/ATA028_ataque.sh`
(`sha256=346a48cf30158128cdf09ce77762ce1a40f704071eef36647e86aafc67a2e476`).
Señales: `.../ATA028_esperado.csv` (`sha256=978ff1868628f33d933a185e530a5a7264ba0c2a16c36afb81b49e0af296afbb`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA028_logtest.txt` (`sha256=1202e1d6ce0ce9729f68094ce9d2cc360c5b586651de855fd296a6387221c914`)
→ `ATA028_preflight.md` (`sha256=9f713a3386ad88272591b13d113cd809efabe1e7392046c68ab9fc9e6b8c8db6`) **PASA**
(2 eventos `nc`/`curl` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración. **NAT off**. `t0` tras 90 s. **No usa el receptor
del HOST** (el portal vive en loopback de la propia víctima).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T03:43:06Z` | `2026-09-29T03:43:44Z` | 38 s | 1039 | `346a48cf…e476` |
| 2 | `2026-09-29T03:46:47Z` | `2026-09-29T03:47:25Z` | 38 s | 1148 | `346a48cf…e476` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA028
bash ATA028_ataque.sh     # portal nc -l 127.0.0.1:8081 + curl POST credenciales de juguete
```

## 6. Evidencia

`Logs/ATA028_iter{1,2}/`: `times.log`, `ejecucion.out`, **`request.http`** (captura del POST).

**Prueba de éxito — las credenciales quedaron capturadas:**

| Iter | `request.http` | `PORTAL_CAPTURE` |
|---|---|---|
| 1 | `POST /portal/login` … `usuario=demo&clave=demo-solo-juguete` | **OK** ✅ |
| 2 | idéntico | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1049 | 1040 | 1039 |
| 2 | 1158 | 1149 | 1148 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1039 | **1** | 606 | 413 | **0** | 19 | 10 | 1029 | 0 | 0 |
| 2 | 1148 | **1** | 621 | 510 | **0** | 16 | 1 | 1147 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 1 | 1 · `{80792}` | 1 (`S2`: `curl`) | 0 |
| 2 | 1 | 1 · `{80792}` | 1 (`S2`: `curl`) | 0 |

- `curl` (`/usr/bin/curl`) **anclado** al `cwd` del ataque.
- **`dudosa` resueltas:** iter1 → 7 `5501/5502` (PAM del operador) → `ruido`; iter2 → 1 `5502` →
  `ruido`.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `03:43:08.196Z` `audit_exe=/usr/bin/curl` | **1/2** (`S2`) | 1 / 19 / 413 | 1 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `03:46:49.678Z` `audit_exe=/usr/bin/curl` | **1/2** (`S2`) | 1 / 16 / 510 | 1 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|1−1|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA028.json`.

## 10. Limitaciones y hallazgos

1. **⭐ HALLAZGO (sistema):** el `esperado` declara `audit_exe=nc`, pero audit registra la **ruta
   resuelta del binario** `/usr/bin/nc.openbsd` (symlink/alternativa) → `nc` **no casa** y la señal
   `S1` **NO** se cumple (**O2 = 1/2**). La detección la sostiene **`curl`** (`S2`) → **O1 = sí**.
   **Consecuencia:** declarar `audit_exe` por el **nombre del comando** falla con symlinks
   (`nc→nc.openbsd`, `mkfs.ext4→mke2fs`, …); lo correcto es usar el **nombre real** o un glob
   (`nc*`). La misma causa afecta a **ATA026** (ver su ficha).
2. **Punto ciego evitado:** servido con **`nc`**, NO con `python3` → no se activa `92600`
   (a diferencia de ATA013).
3. **El HIDS de host no ve la red:** solo ve los **procesos**; la captura la prueba `request.http`.
4. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
