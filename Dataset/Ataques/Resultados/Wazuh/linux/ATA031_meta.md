---
fase: 3
bloque: fase-03-ampliacion-2
tanda: A
ata_id: ATA031
tecnica: T1667
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA031 · T1667 Email Bombing (Linux / `victima-linux`)

> Bloque `fase-03-ampliacion-2` (**tanda A**, 3.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **No destructivo**: buzón **simulado** y **volumen acotado** (`N = 25 ≤ 50`).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA031** |
| Técnica | **T1667 — Email Bombing** |
| Táctica | Impact (sabotaje) |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** de las entregas (`80792`) + **`watch`** (creación masiva, `80790`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `cp` en bucle (25 entregas acotadas) |
| Efecto | el Maildir gana **25** mensajes (`antes=0 → después=25`), `104K` |
| Elevación | **no** |
| Guardarraíl | Maildir **solo** bajo `lab-legit`; **cota dura `N ≤ 50`**; sin MTA real |

Artefacto: `.../T1667-Email_Bombing/ATA031_ataque.sh`
(`sha256=fb9670d743ac64dbdd5d6e6800db0a803b8c2b44c2dd0bfcec59da70fac887db`).
Señales: `.../ATA031_esperado.csv` (`sha256=53cce8b94362be74f18c616a5ffcc01f8b11df7c94840e112a119ab95fe35b89`).
Validación humana (CA1): **APROBADO 2026-09-29**.
C0: `.../c0/ATA031_logtest.txt` (`sha256=ec5d6feeaccb417ba60afad524c62971031f5b2678035081182fe9de92c5c0bd`)
→ `ATA031_preflight.md` (`sha256=2f417f0e5e38987d1b0d38dfbb712289b34900ff11e22f1c6cc6f75c053c560a`) **PASA**
(1 evento `cp` → `80792` level 3; sin silenciador).

## 3. Snapshot y red

Víctima revertida a **`lab-listo`** por iteración (manager **no** se revierte). **NAT off**. `t0` tras
90 s. **No usa receptor.**

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | sha256 ataque |
|---|---|---|---|---|---|
| 1 | `2026-09-29T09:17:13Z` | `2026-09-29T09:17:45Z` | 32 s | 1049 | `fb9670d7…7db` |
| 2 | `2026-09-29T09:21:09Z` | `2026-09-29T09:21:41Z` | 32 s | 1046 | `fb9670d7…7db` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA031
bash ATA031_ataque.sh   # 25 entregas cp en lab-legit/Maildir/new
```

## 6. Evidencia

`Logs/ATA031_iter{1,2}/`: `times.log`, `ejecucion.out`.

**Prueba de éxito — el buzón creció de verdad:**

| Iter | `mensajes_antes` | `mensajes_despues` | `delta_mensajes` | tamaño | `EMAIL_BOMBING` |
|---|---|---|---|---|---|
| 1 | 0 | 25 | 25 | 104K | **OK** ✅ |
| 2 | 0 | 25 | 25 | 104K | **OK** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 1055 | 1050 | 1049 |
| 2 | 1052 | 1047 | 1046 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 1049 | **25** | 623 | 357 | **0** | 44 | 14 | 1035 | 0 | 0 |
| 2 | 1046 | **25** | 619 | 358 | **0** | 44 | 14 | 1032 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 25 | 1 · `{80792}` | 25 (`S1` cp) | 0 |
| 2 | 25 | 1 · `{80792}` | 25 | 0 |

- `80792` × 25: las **25 entregas** (`cp`), **ancladas** al `cwd` del ataque (señal `T1667-S1` ∧ ancla
  `S2`). **0 sorpresas** (`novel`). El **volumen** queda reflejado en el número de detecciones.
- **`dudosa` resueltas (27/iter):** `80790` (creación del Maildir + 25 mensajes) bajo el **`watch`**
  → **`artefacto`** (efecto). **Ninguna** fila del ataque en `ruido`.
- **PAM** (`5501/5502`): aquí **no** caen a `dudosa` (el `esperado` declara `rule_id`) → van a
  **`ruido_conocido`/baseline** (comportamiento del mecanismo congelado, §12.3 del runbook).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `09:17:15.231Z` `audit_exe=/usr/bin/cp` | **1/1** (`S1`) | 25 / 44 / 357 | 25 / 1 `rule_id` |
| 2 | **sí** | `{80792}` | `09:21:10.388Z` `audit_exe=/usr/bin/cp` | **1/1** (`S1`) | 25 / 44 / 358 | 25 / 1 `rule_id` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

`{80792}=={80792}`; `|25−25|=0 ≤ 2`; sin dudosas. Ver `Bitacora/ATA031.json`.

## 10. Limitaciones y hallazgos

1. **El volumen se ve por la repetición del `execve`** (25 alertas) y por el `watch` (efecto). No hay
   regla específica de «bombardeo»: la detección es la misma familia `execve` que el resto (R9).
2. **Sin MTA local** → **no hay capa syslog** de correo (declarado en el README §5). El plan lo
   contemplaba como «posible»; aquí **no aplica**.
3. **PAM a `baseline`** (no a `dudosa`) por declarar el `esperado` un campo siempre evaluable
   (`rule_id`): asimetría conocida del mecanismo congelado (runbook §12.3), **no** se corrige.
4. **C0 sin punto ciego.** Realismo acotado declarado (README §9).
