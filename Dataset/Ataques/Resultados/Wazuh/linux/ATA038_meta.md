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

---

## § Repetición auditada (rev)

> Bloque `fase-03-repeticiones` (**tanda R4**), **2026-10-01**. `esperado_rev` firmado **APROBADO 2026-10-01 (validación humana)** ANTES del primer `t0`. Añadido por `tfg-executor`. **Sin secretos.**

### Motivo

- **`motivo_repeticion` = `art+prestaging`.** (a) **ART:** había prueba de ART Linux offline del **mismo mecanismo** y el original era `custom` sin declarar por qué (`no_se_comprobo`); (b) **pre-staging:** el original escribía el **estado** dentro de `[t0,t1]`. Citas: `_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md` §3 H1/H2 y §2; `Soporte/Ataques/criterio_ataques.md` §A/§C.

### Qué cambió respecto al original (el original NO se toca)

- **Método original:** propio — `sudo shutdown -r +1` escrito por el TFG, con el estado escrito dentro de la ventana.
- **Método de la repetición:** atómica de ART **«Restart System via `shutdown`»** (`shutdown -r #{timeout}`, `timeout=+1`), declarada **`art_tal_cual`** (parametrizada) + el **estado (`pre_reboot.txt`) escrito ANTES de `t0`** (pre-staging); la ventana ejecuta **solo** la atómica (el reinicio programado).
- **Prueba ART citada:** `guid=6326dbc4-444b-4c04-88f4-27e94d0327cb` · `file=atomics/T1529/T1529.yaml` · `commit=388942adbd9641f4dfdcf079d7efe9a75ec0ac43`.
- **Material antes de `t0`:** `pre_reboot.txt` (boot_id/uptime/estado) escrito en el pre-staging; ver `Logs/ATA038_rev{1,2}/prestaging.out`.
- **Corrección de la imprecisión del original:** el `esperado_rev` declara **`506`** (*agent stopped*; el original declaró `504`, que no disparó).

### Iteraciones (rev)

| Iter | t0 (UTC) | t1 (UTC) | filas | deteccion | auto_ruido | ruido_conocido | artefacto_ataque | dudosa |
|---|---|---|---|---|---|---|---|---|
| 1 | `2026-10-01T22:04:42Z` | `2026-10-01T22:08:27Z` | 2793 | **12** | 2281 | 494 | 6 | 0 |
| 2 | `2026-10-01T22:12:23Z` | `2026-10-01T22:16:04Z` | 2883 | **12** | 2371 | 494 | 6 | 0 |

### Resultado (métrica congelada O1+O2)

- **O1 (detectado):** sí — `rule_id` = `['19010','19011','503','506','80792']` (ver nota de sorpresas).
- **O2 (acciones cubiertas):** iter1 = 3/3 · iter2 = 3/3 (`S1`=`80792`, `S3`=`503`, `S4`=`506`; el ancla `S2` no es detector).
  - iter1 primera evidencia: `2026-10-01T22:04:44.496Z` `audit_exe=/usr/bin/systemctl`.
  - iter2 primera evidencia: `2026-10-01T22:12:25.273Z` `audit_exe=/usr/bin/systemctl`.
- **Doble iteración (v2):** `iguales` (mismo conjunto de `rule_id` de detección; `|12−12|=0`; sin dudosas).
- **`dudosa` resueltas:** iter1: ruido=11 · iter2: ruido=11 (`80792` `systemctl` con `cwd=/home/angel` = churn de la sesión del operador).
- **0 filas del ataque en `ruido`** (pertenencia por carpeta); **6** filas `artefacto_ataque` = ejecutables del propio guion (`date`/`bash`/`hostname`/`sudo`) bajo `lab-attack/ATA038` (`AVISO`, nunca `ruido`).

### Sorpresas declaradas (no la técnica; criterio congelado)

- **`19010`/`19011` (grupo `sca`) × 9** en ambas iteraciones (*"CIS Ubuntu … sshd …: Status changed …"*): son el **re-escaneo SCA del agente** que dispara el arranque del agente tras el reinicio (diferencial contra el estado SCA acumulado en el **manager**, que **no** se revierte). El predicado OPERADOR del filtro **solo auto-excluye `19004`** (grupo `sca`) → estas caen a **`novel`** → `deteccion`. **Mismo patrón que el `rule_id 11`** (artefacto del criterio congelado). **Se documenta, no se corrige** (filtro congelado).
- **`506`** *agent stopped*: ahora **declarada** en el `esperado_rev` (deja de ser sorpresa). **Sin sorpresas en las señales declaradas.**

### Prueba de efecto (independiente de la alerta)

- iter1: `boot_id` `bf2aae3a-0950-49c6-a83e-b53ffbb92fd3` → `a911370e-a37d-4591-a71b-85a1f4ce5dc8`; `wazuh-agent` `active`; agente `001` `Active`.
- iter2: `boot_id` `f08d3336-c302-44aa-a393-ee7fe37bc180` → `17259ce2-e66f-4ec8-9022-e3281fc9c49f`; `wazuh-agent` `active`; agente `001` `Active`.

### Cómo se cumple el motivo

- **ART:** la atómica se ejecutó tal cual (parametrizada) y se cita `guid`+`file`+`commit`.
- **Pre-staging:** el estado (`pre_reboot.txt`) se escribió **ANTES de `t0`** (`prestaging.out`: `PRESTAGE=OK`); la ventana mide **solo** la atómica. **Guardarraíl duro respetado:** solo la VM víctima (`hostname`=`victima-linux`, IP `192.168.65.129`; aborta con la IP del manager), reinicio programado a +1 min; red de seguridad `lab-listo`.

### Trazabilidad

- `esperado_rev`: `…/T1529-System_Shutdown_Reboot/ATA038_esperado_rev.csv` (`sha256=e3761ae2496f2f85ddf5c0039748627019c2b929dce793137d8b3019897ceb65`).
- `ataque_rev`: `…/T1529-System_Shutdown_Reboot/ATA038_ataque_rev.sh` (`sha256=f40823aa555c2b4fd76f5378a3cb8fb35bb865327598c015a7940426e6b0e09e`).
- C0: `Soporte/Ataques/c0/ATA038_rev_logtest.txt` + `ATA038_rev_preflight.md` (**PASA**, sin silenciadores).
- Detalle: `…/CSV/ATA038_rev{1,2}-Detalle.csv` · Auditado: `…/Auditado/ATA038_rev{1,2}-Audited.csv`.
