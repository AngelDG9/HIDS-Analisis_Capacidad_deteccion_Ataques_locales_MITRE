---
fase: 3
bloque: fase-03-escalado
tanda: A
ata_id: ATA003
tecnica: T1490
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-28
---

# Ficha — ATA003 · T1490 Inhibit System Recovery (Linux / `victima-linux`)

> Bloque `fase-03-escalado` (**tanda A**, 4.º de 4; cierre de la tanda). Generada por `tfg-executor`.
> **Sin secretos.** Estado **`cerrado`**: criterio v2 → **`iguales`**. Métrica congelada.
> **Simulación segura:** solo se borran copias **mock**; **no** se toca ningún servicio/timer real.
> **Sin `systemctl`** (decisión humana): el vector es el **borrado de copias**; `systemctl` ya se cubrió
> en ATA004.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA003** |
| Técnica | **T1490 — Inhibit System Recovery** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** (ART solo trae pruebas Windows) |
| Ejecución | usuario `angel`, **sin `sudo`** |
| Capa del HIDS | **`execve`** (`80792`, RS2) **+ watch** (`80790/80791`, RS2; efecto → `artefacto`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | **`rm -rf`** (`/usr/bin/rm`) |
| Objetivo | `/home/angel/lab-legit/copias_seguridad/` (copias **mock**; dir **VIGILADO** por `auditd`) |
| Elevación | **no** |
| Guardarraíl | el objetivo **DEBE** ser exactamente `$HOME/lab-legit/copias_seguridad` (aborta si no) |

Artefacto: `Dataset/Ataques/Comandos/T1490-Inhibit_System_Recovery/ATA003_ataque.sh`
(`sha256=43eade0b3002a95565cc1d69855b236d698d0f04cc9337cf05dab31df9ac6a3b`).
Señales esperadas: `.../ATA003_esperado.csv`
(`sha256=c81d87e34faf54f4550a22543e7f0e23647dc0e847768fe05f78ff25fbc37311`).
Validación humana (CA1): **APROBADO 2026-09-28**.
C0: `Soporte/Ataques/c0/ATA003_logtest.txt`
(`sha256=ffabd7073909c04cf1cb00754993e123cefa5f8a5053a5169f68b1c18dfe01b8`)
→ pre-flight **PASA** (1 evento, `rm` → `80792` level 3; **sin** silenciador). **No se usa journald**.

## 3. Snapshot

- Víctima revertida a **`lab-listo`** antes de cada iteración. El **manager NO se revierte**.
- **NAT desconectado**; no se instaló nada. `t0` tras ≥ 90 s de asentamiento (H2).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Duración | filas Detalle | sha256 `ATA003_ataque.sh` |
|---|---|---|---|---|---|
| 1 | `2026-09-28T21:42:33Z` | `2026-09-28T21:43:04Z` | 31 s | 675 | `43eade0b…c6a3b` |
| 2 | `2026-09-28T21:46:53Z` | `2026-09-28T21:47:24Z` | 31 s | 687 | `43eade0b…c6a3b` |

Reloj víctima↔manager < 1 s; `t0 < t1` en ambas.

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA003
bash ATA003_ataque.sh      # mkdir del mock + rm -rf de copias_seguridad/
```

## 6. Evidencia

`Dataset/Ataques/Resultados/Wazuh/linux/Logs/ATA003_iter{1,2}/`:
`times.log`, `ejecucion.out`, `deps.txt`, `ps_antes.txt`, `ps_despues.txt`, `sha256_artefacto.txt`.

**Prueba de éxito:** `test -e` pasa de **EXISTE** (4 copias listadas) a **NO EXISTE** ⇒
**`BORRADO=OK`** en ambas iteraciones.

## 7. Ventana extraída

- Fichero diario: `/var/ossec/logs/alerts/2026/Sep/ossec-alerts-28.json` (extractor H3).
- **Aislamiento por agente:** `_raw` → `agent_name == victima-linux`.

| Iter | Filas `_raw` | victima-linux | otros | Detalle final |
|---|---|---|---|---|
| 1 | 681 | 675 | 6 | **675** |
| 2 | 693 | 687 | 6 | **687** |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 675 | **1** | 605 | 48 | **0** | **21** | 1 | 674 | 0 | 0 |
| 2 | 687 | **1** | 616 | 49 | **0** | **21** | 2 | 685 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | **alertas** detección | **`rule_id` distintos** | esperadas (`senal:…`) | sorpresas (`novel`) |
|---|---|---|---|---|
| 1 | **1** | 1 · `{80792}` | 1 (`T1490-S1`) | 0 |
| 2 | **1** | 1 · `{80792}` | 1 (`T1490-S1`) | 0 |

- La **única** alerta de detección es el **`execve` de `rm`** (`80792`, `audit_command`), anclado a
  `cwd=/home/angel/lab-attack/ATA003` por `T1490-S2`. (`rm` es **1** proceso; su árbol no genera más
  execve declarados.)
- **`dudosa` resueltas (51/iter):** **10 → `artefacto`** (el **efecto del ataque** bajo watch:
  `80790` *Created* ×5 del *setup* + `80791` *Deleted* ×5 del `rm -rf`, todos sobre
  `copias_seguridad`); **41 → `ruido`** (churn de **sesión systemd/PAM del operador**:
  borrados en `/run/systemd/...`, `/run/user/1000/...` al cerrar la sesión SSH; **ajenos** al ataque).
  ⚠️ Ver §10.1.
- **`artefacto_ataque=21`/iter** = 11 automáticos + 10 humanos.

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 detectado | `rule_id` | primera evidencia | O2 acciones | desglose `deteccion`/`artefacto_ataque`/`ruido_conocido` | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792}` | `2026-09-28T21:42:34.613Z` `audit_exe=/usr/bin/rm` | **1/1** (`S1`) | **1 / 21 / 48** | 1 alerta / `{80792}` |
| 2 | **sí** | `{80792}` | `2026-09-28T21:46:53.288Z` `audit_exe=/usr/bin/rm` | **1/1** (`S1`) | **1 / 21 / 49** | 1 alerta / `{80792}` |

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

| Criterio | Resultado |
|---|---|
| C1′ mismo conjunto de `rule_id` con `deteccion` | ✅ `{80792}` == `{80792}` |
| C2′ `\|n2−n1\| ≤ max(2, 10 %·n1)` | ✅ `\|1−1\| = 0 ≤ 2` |
| C3′ sin `dudosa` sin resolver | ✅ 0 y 0 |
| Sanidad `auto_ruido` (aviso) | ⚠️ 605 vs 616 → Δ=11 (aviso) |
| Sanidad `ruido_conocido` (aviso) | ✅ 48 vs 49 → Δ=1 |

## 10. Limitaciones y hallazgos

1. **La señal `ambigua` `T1490-A2` (`rule_group=audit_watch_write`) es ANCHA:** capturó **41
   eventos/iter** del **churn de sesión del operador** (`/run/systemd/...`, `/run/user/1000/...` al
   cerrar la SSH) → `dudosa` (resueltos a **`ruido`**). **Mejora sugerida:** acotar la señal a la ruta
   `…/lab-legit/copias_seguridad/*` (hoy el filtro no la acota porque la señal es por `rule_group`).
   **No se cambia el `esperado`** (congelado por firma); se documenta.
2. **El efecto del ataque (10/iter) → `artefacto`** (copias mock bajo watch; no la detección
   declarada). La detección de la técnica es el **`execve` de `rm`** (`80792`).
3. **Sin `systemctl`/journald** (decisión humana); `systemctl` ya cubierto por ATA004.
4. **C0 sin punto ciego** (`rm` → `80792`). **Realismo acotado** declarado (README §11).
