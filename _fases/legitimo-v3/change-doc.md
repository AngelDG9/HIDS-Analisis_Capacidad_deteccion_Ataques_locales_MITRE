# change-doc — Bloque `legitimo-v3` (ventana legítima de 72 h + campaña dirigida)

> **Estado: CERRADO (2026-11-05).** Ventana ejecutada del **2026-11-02T00:00Z** al
> **2026-11-05T00:00Z** (72 h exactas). **Veredicto: VÁLIDA CON INCIDENCIA (V6)** — firmado con
> la evidencia delante (`ventana_2026-11-02/veredicto_validez.md`).
> Plan aprobado: `plan.md` (v5, `approved_by_human`, archivado en `_fases/legitimo-v3/`).

---

## 1. Qué se ha producido

| Producto | Valor |
|---|---|
| **Denominador `M`** (agente `001`) | **342.966** eventos (total con manager: 394.739) |
| **Alertas** en ventana | **294.253** (solo `victima-linux`; 98.064 / 98.254 / 97.935 por día) |
| **`rule_id` distintos** | **11** (`11, 554, 591, 80711, 80730, 80780, 80781, 80782, 80790, 80791, 80792`) |
| **Acciones GHOSTS** | **504** (163 / 178 / 163 por día) |
| **Campaña** | **11/11** casos con `esperado_cumplido=SI`; **0** alertas a `N≥7`; **0** mutaciones |
| **Cobertura de la receta** | **23/50** binarios del corpus; **25/50** con la campaña |
| **Concentración del ruido** | `80792` (cada `execve`) = **236.277** (80 %); `80791` (borrados) = **55.649** |
| **Nivel alto** | `N≥7`: **2** alertas en 72 h (`80711`, nivel 10) |

**Lectura:** a umbral bajo (`N=0/3`) ~**86 %** de los eventos generan aviso (es la configuración
de fábrica con `auditd`: cada comando y cada borrado son nivel 3). A `N≥7` el ruido **desaparece**.
El contraste umbral↔ruido es un **resultado**, no un defecto.

## 2. V1–V9 (resumen)

| # | Criterio | Veredicto |
|---|---|---|
| V1 | Cobertura (t0+4,7 s … t1−3,0 s; hueco máx. 62,6 s) | **PASA** |
| V2 | Actividad 163/178/163 (100 % de la receta; 0 fuera de bloque salvo B6) | **PASA** |
| V3 | Manager `active/2` y agente `Active` en 144/144; 3 diarios | **PASA** |
| V4 | 0 `srcip=192.168.65.1`; 0 sesiones del operador en el `001` | **PASA** |
| V5 | `ip route` sin `default` (aislada) | **PASA** |
| V6 | `M` obtenido, `--estricto` exit 0, MANIFEST con `sha256` | **VÁLIDA CON INCIDENCIA** (orden invertido; fuente íntegra) |
| V7 | `sha256sums` 169/169, `CONFIG_IDENTICA`, ruleset igual | **PASA** |
| V8 | `LastBootUpTime` 29/10 < t0; 0 `Kernel-Power` 42/107 | **PASA** |
| V9 | 0 recuperaciones · 2 rotaciones · 3 arranques | **PASA** |

## 3. Incidencias declaradas (ninguna invalida)

1. **V6 — orden invertido en el cierre:** se ejecutó `cleanup` (`logall_json off`, que **borra
   `archives.json`**) **antes** de la copia definitiva del denominador. **No se perdió nada**: los
   **3 `.gz` diarios** estaban rotados e intactos y el fichero vivo solo tenía eventos **posteriores
   a `t1`**. `M` se **re-extrajo** con `--estricto` (`exit 0`) desde el fichero diario íntegro.
   *Lección: copiar SIEMPRE antes de apagar `logall_json`.*
2. **3.224 alertas del manager excluidas:** el fichero de alertas contiene **todos** los agentes;
   se filtró a `victima-linux` (las 4 reglas de sesión `5402/5501/5502/5715` eran del servidor).
3. **4 `AVISO` de vigilancia** (03/11 y 04/11, 00:00 y 00:30): la **rotación de medianoche** deja
   la señal de disco sin muestra (`sin_df`). Se recupera sola.
4. **`rule 11`** (1 alerta, `stats`) queda `UNKNOWN` en `rs_origen` (regla interna).
5. **`n_acciones` vacío** en `campana_fp.csv`: no se generó el export **por acción** (solo el
   agregado). Se declara; `n_eventos`, `alertas`, `rule_id`, `level` y `esperado_cumplido` sí están.
6. **Windows Update se auto-repara** (3–10 min): mitigado con **re-pausa en el `watch`** (probada en
   producción: `reps=si` varias veces). El host **no** se reinició en la ventana.
7. **Defectos corregidos antes de la ventana** (trazados en `fix_receta_v3.md`): `sha256sum` sin
   redirección en Linux (`L-1`), comandos con `|` que GHOSTS no reportaba (`H-1`), `xcopy`/`del`/`if`
   en Windows, y la **gracia de borde** del `watch` (evitó las falsas alarmas de las 09:00 y 15:00).

## 4. Sellado y promoción

- **B10 v3** (`b10_sellado.md`): versiones, **`sha256` del binario del cliente** (`3e1a73a4…`),
  receta, instrumentación, 0 rec / 2 rot / 3 arranques, `M`, alertas, `rule_id`.
- **`boveda_congelacion.md` → `version: 2`** (+ sidecar `01be8d3e…`).
- **`metrica_hids.py` y `contar_denominador.py` → `VERSION_BOVEDA = 2`** (el flag sigue mandando).
- **Promoción a `Dataset/Legitimo/legitimo_72h/`** (8 ficheros, `PROMOCION.md` con `sha256`).
- **`pytest`: 342 passed.**

## 5. Cierre del laboratorio (CA-16)

**0 VMs · 0 tareas `TFG-Legit-*` · 0 reglas `TFG-*` · 0 procesos del laboratorio ·**
`TFG-Baseline-*` **Disabled** (no borradas; se desactivaron porque podían apagar el manager o
revertir la VM) · **Windows Update restaurado** (`Running/Manual`, políticas retiradas) ·
**`TFG_GUEST_PW` borrada** del entorno · `logall_json=no` + `CONFIG_IDENTICA` ·
`tfg_watch_estado.json` borrado.

## 6. Lecciones para los bloques siguientes

1. **Copiar antes de apagar** (el orden del plan no es un adorno).
2. **Filtrar por agente** en toda extracción de alertas (el manager también alerta).
3. **Export por acción** de `history_timeline` si se quiere `n_acciones`.
4. **Registrar en el log del host** las sesiones manuales de cierre (no reconstruibles después).
5. **Repausa de WU en el `watch`**: imprescindible; el servicio se auto-repara en minutos.

## 7. Siguiente

- **`L2` (`legitimo-analisis`)**: T3/T4/T5 con estos datos (FPR por evento, catálogo de ruido,
  reglas de doble uso) + **`M1b`** (re-corte de los 55 ataques con este legítimo).
- Después: **Windows** (B1 + su ventana legítima) y **Velociraptor**.
