# change-doc — Bloque `fase-02b-baseline`: línea base de Windows

> Cierre. Fecha: **2026-10-08**. Estado: **CERRADO** — verificación `tfg-tester`: **PASA**
> (con 3 matices de redacción, resueltos).
> Plan de referencia: `plan.md` (v2, `status: approved_by_human`, 2026-10-07).
> **Bloque de OBSERVACIÓN**: la víctima Windows se deja viva ejecutando **actividad legítima
> programada**; **no se ataca nada**. Es el **espejo** del baseline de Linux
> (`_fases/fase-02/change-doc.md` §3.2).

---

## 1. Objetivo

Grabar el **"ruido normal" de Windows** (el agente `victima-windows`, id `002`, **sin ataques** y con
actividad legítima variada) para usarlo como **referencia de falsos positivos** en `fase-03b`.
Entregable: un **catálogo por `rule.id`** (2 ventanas + unión) bajo `Dataset/Legitimo/windows/` con su
**medida de estabilidad**.

---

## 2. Resultado: **línea base de Windows COMPLETA** ✅

| # | Paso | Resultado |
|---|---|---|
| 1 | **2 ventanas × 4 h UTC** (mismas franjas que Linux, mismo día) | ✅ `00:45–04:45Z` y `12:00–16:00Z` del **2026-10-08** |
| 2 | **Actividad legítima** (script Windows + tarea programada) | ✅ **50 ciclos** por ventana, cubriendo `[t0,t1]` |
| 3 | **Extracción** del fichero diario, aislada al agente `002` | ✅ **72** alertas (v1) + **87** (v2) |
| 4 | **Catálogo por `rule.id`** (v1, v2, unión) | ✅ **4 / 7 / 7** reglas |
| 5 | **Estabilidad** v1↔v2 | ✅ **4 estables / 3 variables** (las 3 de FIM) |
| 6 | **FIM forzado** desde el manager | ✅ ejecutado en v2 (12:11Z) |
| 7 | **Verificación** `tfg-tester` | ✅ **PASA** (10/10 CA) |

**Números clave:** **159 alertas** en total (72+87) · **7 `rule.id`** en el catálogo unido ·
**0 `UNKNOWN`** · **RS1 100 %** · **0 contaminación** del operador en el detalle del agente `002`.

---

## 3. Ventanas y validez

| Ventana | `t0`–`t1` (UTC) | Alertas | `rule.id` | Cobertura | Válida |
|---|---|---|---|---|---|
| **v1 — noche** | `00:45–04:45Z` | 72 | 4 | horas 00–04, hueco máx. 40.8 min | ✅ |
| **v2 — tarde** | `12:00–16:00Z` | 87 | 7 | horas 12–15, hueco máx. 35.9 min | ✅ |

- **Anti-contaminación:** **0** eventos del operador (`192.168.65.1`) en el detalle del agente `002`
  en ambas ventanas. *(Los 8 `5715` del agente `000`/manager en v2 son el **acceso declarado al
  manager** para el FIM, excluidos del catálogo.)*
- **Agente:** **0** alertas `503`/`504` dentro de las ventanas (el único `503` cae a `11:45:32Z`,
  **fuera** de `t0`).
- **Actividad legítima:** `START ≤ t0` y `END ≥ t1` en **ambas** (`LastTaskResult=0`, `missed=0`).

---

## 4. Catálogo y estabilidad

**Catálogo unido** (`ruleids_legitimos.csv`, esquema **idéntico al de Linux**):
**7 reglas** = **4 en ambas** (`60642`, `60702`, `67027`, `92201`) + **0 solo v1** + **3 solo v2**
(`594`, `598`, `750`).

**Estabilidad** (`estabilidad_windows.csv`) — veredicto: **PARCIALMENTE ESTABLE**.
- **4 estables** (en ambas ventanas) / **3 variables** (`594`, `598`, `750`).
- Las 3 variables son **exactamente las del FIM forzado** (desviación declarada, §5.1).
- **Sin** el FIM forzado, **Δ total = −6.9 %** → **estable en régimen** (umbral ~10 %); el único
  `rule.id` con variación en régimen es `67027` (−5.88 %, actividad intermitente).

---

## 5. Desviaciones declaradas (ninguna bloqueante)

1. **🔴 FIM forzado solo en v2.** El plan (Q5) contempla `agent_control -r -u 002` **dentro de cada
   ventana**. **En la noche NO se ejecutó**; **sí en la tarde** (12:11:00Z) → **20 alertas FIM de
   registro** (`594`×6, `750`×10, `598`×4). **Sorpresa honesta:** el FIM de Windows **también vigila
   claves de registro** → **no fueron 0** como se esperaba. Es la **única diferencia de contenido**
   entre ventanas y **marca la estabilidad**.
2. **Arranque ≥ 15 min antes de `t0`** (ruido de arranque **fuera** de la ventana) — **diferencia
   con Linux**, declarada (mejora: la ventana Windows mide **régimen**, no arranque).
3. **Fuente diaria** (más estricta que el `alerts.json` de Linux Fase 2) · **aislamiento por agente
   `002`** (Linux no filtró) · **RS2 vacía** (no hay `auditd`) · **ubicación
   `Dataset/Legitimo/windows/`**.
4. **`-DurationMin 248`** ≠ los 260 del plan (para que el script escriba `END` antes del apagado del
   host y `END ≥ t1` se cumpla).
5. **Chequeo de suspensión (`SLEEPCHECK`) omitido** en los arranques (falta `TFG_GUEST_PW`); **no
   bloqueó** (ventanas completas).
6. **Esquema del detalle** 17 columnas (el fichero Linux era previo a H3, 14).

---

## 6. 🔴 Incidencia del 07/10 (ventana fallida y repetida)

- La **primera ventana de noche (07/10) FALLÓ**: el **Windows invitado se suspendía a los 30 min**
  (`STANDBYIDLE=1800s`) → el agente se desconectó (`504` a `01:16Z`) → **ventana INVÁLIDA**.
- **Arreglado:** `STANDBYIDLE`/`HIBERNATEIDLE`/`HYBRIDSLEEP` = **0** (verificado **dentro** del
  snapshot) + **snapshot `lab-listo-windows-baseline` re-creado**.
- **Las 2 ventanas se re-armaron para el 08/10** (mismo día; la tarde del 07/10 se canceló por
  decisión del humano). Las ventanas del 08/10 corrieron **completas** (v1 y v2) ✅.

---

## 7. Hallazgo para la memoria

**El ruido de Windows con esta actividad benigna y la telemetría curada es MUCHO más bajo que el de
Linux:** **7 `rule.id`** (Windows) frente a **12** (Linux).
- **Por qué:** las reglas "ruidosas" de Sysmon (rutas sospechosas, PowerShell rico) **solo saltan en
  el arranque** o cuando el binario corre desde una **ruta no estándar**. El `powershell.exe` del
  script corre desde la ruta **estándar** (`…\System32\WindowsPowerShell\v1.0\`) → **no dispara**
  detecciones de ruta sospechosa en régimen.
- **Consecuencia metodológica:** en Windows, el "ruido de régimen" es **pequeño y muy estable**; el
  grueso del ruido está en el **arranque** (por eso se deja **fuera** de la ventana).

---

## 8. Entregables

**Nuevos** (bajo `Dataset/Legitimo/windows/`): `ruleids_legitimos.csv` (unión) ·
`ruleids_legitimos_v1.csv`/`_v2.csv` · `resumen_por_origen.csv` (+`_v1`/`_v2`) ·
`baseline_detalle_v1.csv`/`_v2.csv` · `baseline_log_ventana1.txt`/`_ventana2.txt` ·
`baseline_meta.md` · `estabilidad_windows.csv`.

**Soporte:** `Soporte/Wazuh/Scripts/baseline_actividad_windows.ps1` (sha `EB60DF9D…`) ·
`Soporte/Laboratorio/windows/baseline_host_control.ps1` (tareas del host) ·
`Soporte/Laboratorio/windows/baseline_resultado.md` (evidencia operativa) ·
`_artefactos/scripts/unir_catalogo_ruido.py` (+ tests, 14/14).

**Sin tocar:** `extraer_alertas.py` (sha `4019fda8…` intacto, repo == manager) ·
`filtrar_ruido.py` · Linux · `_recursos/`. **Sin secretos.**

---

## 9. Verificación

`tfg-tester`: **PASA** — **10/10 CA** del plan cumplidos; las cifras se **re-derivaron desde el
diario real** del manager y **cuadran al dígito**. Únicas incidencias: **3 matices de redacción**
(acotar el "0 eventos `192.168.65.1`" al detalle del agente `002`; declarar el `SLEEPCHECK` omitido y
el `248` vs `260`), **ya resueltos**.

---

## 10. Siguiente

1. **`fase-03b` — ataques Windows**: piloto de **~5 técnicas** (2 con ART + 2 propias + 1-2 de
   comparación Linux↔Windows), reutilizando el criterio de ataque, la doble iteración y la métrica
   congelada. **Continúa la numeración desde `ATA055`.**
2. **Pendientes ya anotados** (no de este bloque): normalización de finales de línea + recálculo de
   huellas · arreglo futuro del filtro (`19010/19011`, SCA) · **Fase 4** (precio de la detección) ·
   memoria.
3. **`push`:** los commits son **locales**; publicar es del humano.
