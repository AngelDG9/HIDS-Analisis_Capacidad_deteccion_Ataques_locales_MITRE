---
fase: 3
bloque: fase-03-ampliacion-2
tanda: B
ata_id: ATA038
tecnica: T1529
tactica: Impact
version: 1
status: cerrado
fecha: 2026-09-29
---

# Ficha — ATA038 · T1529 System Shutdown/Reboot (reinicio de la VM víctima) — Linux

> Bloque `fase-03-ampliacion-2` (**tanda B**, 5.º de 5). Generada por `tfg-executor`. **Sin secretos.**
> Estado **`cerrado`**: criterio de doble iteración **v2** → **`iguales`**. Métrica congelada (O1+O2).
> **Único caso disruptivo-acotado:** se reinicia **solo** la **VM víctima** (desechable, red de
> seguridad `lab-listo`). **Alternativa KISS (T1074.001) NO aplicada** (la medida resultó limpia).

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA038** |
| Técnica | **T1529 — System Shutdown/Reboot** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5 LTS) |
| Vía | **manual / custom** |
| Ejecución | usuario `angel`, **`sudo` solo** para `shutdown -r` |
| Capa del HIDS | **`execve`** del comando + **estado del agente** (`503`/`506`) |

## 2. Fuente del ataque

| Campo | Valor |
|---|---|
| Fuente | `custom` (escrito por el TFG) |
| Herramienta | `sudo shutdown -r +1` (enlace a `/usr/bin/systemctl`) |
| Efecto | la **VM víctima se reinicia** (`boot_id` distinto; agente `Active` de nuevo) |
| Elevación | **sí**, `sudo` (por `stdin`), **solo** `shutdown -r` |
| Guardarraíl DURO | se **exige** `hostname == victima-linux` **y** IP `192.168.65.129`; si aparece la IP del manager → **aborta** |

Artefacto: `.../T1529-System_Shutdown_Reboot/ATA038_ataque.sh`
(`sha256=554cd462fb831c1b2153dd0ea0e9ce3fc30a00550e4bdc068b2879df58190ec9`).
Señales: `.../ATA038_esperado.csv` (`sha256=197e72ad0987d6e6401dcfd02529da02659d83a3559600bf7a26595487c68423`).
Validación humana: **APROBADO 2026-09-29**.
C0: `.../c0/ATA038_logtest.txt` (`sha256=e7179c7315a09ddc9931c629306c1b80814760da771e4b354d42eb0df6a3591b`)
→ `ATA038_preflight.md` (`sha256=f0f315090474372a8d83a9b8c9ec0567e015bb677fdb9669d5a068a4de1f4bcf`) **PASA**
(1 evento `systemctl` → `80792` level 3; sin silenciador).

## 3. Snapshot, red y seguridad

Víctima revertida a **`lab-listo`** **antes** de cada iteración y **después** de la tanda (red de
seguridad). **NAT off**. `t0` tras ~100 s de asentamiento. Reinicio **programado a +1 min** para
sellar la evidencia. `t1` lo sella el **operador** tras la reconexión (la VM no puede sellarlo).

## 4. Iteraciones

| Iter | t0 (UTC) | t1 (UTC) | Dur | filas | boot_id antes → después |
|---|---|---|---|---|---|
| 1 | `2026-09-29T10:54:50Z` | `2026-09-29T10:58:15Z` | 205 s | 2103 | `bdd0155b…` → `db1dae2f…` |
| 2 | `2026-09-29T11:02:58Z` | `2026-09-29T11:06:16Z` | 198 s | 2120 | `34711a82…` → `cf8fe4df…` |

## 5. Comando ejecutado (literal)

```bash
cd /home/angel/lab-attack/ATA038
printf '%s\n' '<pw>' | bash ATA038_ataque.sh   # guardarraíl hostname/IP + sudo shutdown -r +1
```

## 6. Evidencia

`Logs/ATA038_iter{1,2}/`: `times.log`, `ejecucion.out`, `pre_reboot.txt`, `post_reboot.txt`.

**Prueba de éxito — la VM se reinició de verdad:**

| Iter | `boot_id` | `uptime_despues` | `wazuh_agent` tras arranque |
|---|---|---|---|
| 1 | **cambia** (`db1dae2f…`) | up 4 min | **active** ✅ |
| 2 | **cambia** (`cf8fe4df…`) | up 2 min | **active** ✅ |

## 7. Ventana extraída

| Iter | `_raw` | victima-linux | Detalle |
|---|---|---|---|
| 1 | 2135 | 2103 | 2103 |
| 2 | 2145 | 2120 | 2120 |

## 8. Resultado

| Iter | filas | deteccion | auto_ruido | ruido_conocido | dudosa | artefacto_ataque | RS1 | RS2 | RS3 | RS4 |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2103 | **3** | 1667 | 424 | **0** | 9 | 16 | 2087 | 0 | 0 |
| 2 | 2120 | **3** | 1635 | 471 | **0** | 11 | 16 | 2104 | 0 | 0 |

### 8.1 Detecciones — desglose

| Iter | alertas | `rule_id` distintos | esperadas | sorpresas |
|---|---|---|---|---|
| 1 | 3 | 3 · `{80792, 506, 503}` | 2 (`S1` `80792` + `S3` `503`) | **1** (`506`) |
| 2 | 3 | 3 · `{80792, 506, 503}` | 2 | **1** (`506`) |

- **`80792`** `Audit: Command: /usr/bin/systemctl` (señal `S1`, anclada al `cwd`) — el comando de
  reinicio.
- **`506`** *Wazuh agent stopped* (**`novel`**): el manager ve **parar** el agente (cierre de la VM)
  → **sorpresa** (no se declaró; el `esperado` declaró `504`, que **no** disparó).
- **`503`** *Wazuh agent started* (señal `S3`): el agente **vuelve** tras el arranque.
- **`dudosa` resueltas:** **7/iter1 y 8/iter2** — `80792` `systemctl` con `cwd=/home/angel`
  (**churn del login/motd del operador**, no anclable) y **1** `80781` (escritura en `/var/log/`
  durante el arranque) → **`ruido`** (criterio ratificado). **`auto_ruido`** domina (1667/1635:
  el propio HIDS), y **ninguna** fila del ataque en `ruido` (`ruido_con_lab-attack=0`).

### 8.2 Métrica de detección — **O1 + O2**

| Iter | O1 | `rule_id` | primera evidencia | O2 | desglose det/art/ruido | anexo |
|---|---|---|---|---|---|---|
| 1 | **sí** | `{80792, 506, 503}` | `10:54:52.743Z` `Audit: Command: /usr/bin/systemctl` | **2/3** (`S1`,`S3`) | 3 / 9 / 424 | 3 / 3 `rule_id` |
| 2 | **sí** | `{80792, 506, 503}` | `11:03:00.820Z` `Audit: Command: /usr/bin/systemctl` | **2/3** (`S1`,`S3`) | 3 / 11 / 471 | 3 / 3 `rule_id` |
| — | — | — | — | **Declaradas no disparadas:** `S4` (`504`) | — | — |

> **O2 = 2/3:** el `esperado` declaró `S3=503` y `S4=504`; disparó `503`, pero el manager usó
> **`506`** (*agent stopped*) en vez de `504` (*agent disconnected*) → **sorpresa**.
> **El `esperado` no se re-escribe** (firmado antes); la imprecisión se **declara**.

## 9. Doble iteración (criterio **v2**) — veredicto **`iguales`**

- **C1′:** ✅ `{80792, 506, 503} == {80792, 506, 503}`. **C2′:** ✅ `|3−3|=0 ≤ 2`. **C3′:** ✅ sin
  dudosas (7 + 8 resueltas por veredicto humano `ruido`). Ver `Bitacora/ATA038.json`.

## 10. Limitaciones y hallazgos

1. **⭐ Capa nueva: estado del agente.** El HIDS ve el **cierre y el arranque** de la VM por las
   reglas de **estado del agente del manager** (`506` *agent stopped*, `503` *agent started*),
   además del `execve` del comando (`80792`). **`journald`/`systemd`** (`40700` = `level 0`) **no**
   alerta (hallazgo ya documentado en ATA004).
2. **Imprecisión del `esperado` (declarada, no corregida):** se declaró `504` (*agent disconnected*);
   el manager emitió **`506`** (*agent stopped*) → **sorpresa** en ambas iteraciones. Se documenta.
3. **Reinicio ordenado** (`shutdown -r`), **solo VM víctima**, con snapshot `lab-listo` como red.
   **Cómo queda el agente:** `wazuh-agent` **`active`**, agente `001` **`Active`**, `auditd` recarga
   `tfg.rules`. **0** residuos (la víctima se revierte).
4. **Alternativa KISS (T1074.001) NO aplicada:** la medida quedó **limpia** (churn de arranque →
   `baseline`; solo las reglas de **estado del agente** son `novel`, y se declaran/reportan).

## 11. Filas `ruido` (para ratificación)

- **iter1: 424** (**7** añadidas por veredicto: `80792` `systemctl` `cwd=/home/angel` — login/motd);
  **iter2: 471** (**8**: 7 `systemctl` + 1 `80781` `/var/log` en el arranque) — **todas** ajenas al
  ataque, sin ruta del ataque. **0** filas del ataque en `ruido`.
