# reviews.md — Ataque del plan (bloque `legitimo-72h-v2`)

> Revisión del **orquestador** sobre `plan.md` (v1, 765 líneas). Fecha: **2026-10-25**.
> **Veredicto: APROBABLE** — con **1 condición** (E0) y **1 decisión** (fecha).

---

## 1. Comprobaciones
- **Sin secretos** (0) ✅ · **`git status`**: solo `plan.md` + `_fases/legitimo-72h/` ✅.
- **Anclaje**: parte de `legitimo-fix` (cerrado, PASA), del diagnóstico del L1 y de la métrica congelada ✅.
- **No toca** Wazuh/métrica/corpus/`Hojas/`/`Dataset/`/`_recursos/` ✅.

## 2. Fortalezas
- **Ventana `26/10 00:00Z → 29/10 00:00Z`** (cortes a medianoche UTC ⇒ 3 `.gz` + 1 vivo; sin DST; `prep`/`arm`/timer/stop con horas exactas).
- **Qué hace el humano** claro (PC sin suspensión, sesión iniciada, **0 acceso** a la víctima, no limpiar `%TEMP%`).
- **Extracción con orden fijado** (cosecha a `t1+2`, parada `t1+5`, copia, puerta, `M`, `off`, alertas, acciones) — corrige el fallo de L1 (los logs de validez viven en el invitado).
- **Validez V1–V8 + V2bis** con umbrales objetivos (cobertura, 3 diarios, 0 `192.168.65.1`, NAT, `M`, huellas, `CONFIG_IDENTICA`, arranque).
- **20 CA + MC-1** y gate en lenguaje sencillo.
- **Lecciones del fallo** incorporadas (sin logs sin tope, vigilancia que mide "hacer", `df` del agente).

## 3. Condición y decisión
1. **⭐ E0 (obligatorio, ~45 min)**: el **`arm` nunca se ha ejecutado de punta a punta** (0 líneas `[arm]` en el log; el `prep` sí, 3× EXIT=0). **Sin E0 no se arranca.**
2. **📅 La fecha**: hoy es **25/10 ~20:00Z** y el `prep` sería a las **00:15 local** ⇒ **~2 h** para aprobar + E0 + prep. **Muy justo.**
   - **Opción A**: **26/10** (hoy/esta noche) → solo si el E0 sale **inmediato y perfecto**.
   - **Opción B (recomendada)**: **27/10 → 30/10** → 1 línea de `MAPA_DIAS` + regenerar + huellas (~20 min). **Sin prisa, sin repetir el error de las prisas.**

## 4. Notas
1. **Windows Update se ha auto-reparado** (`wuauserv` Manual/Running): hay que **re-pausar** antes de `prep` (G-10 aborta si no).
2. **`boveda_version: 2`** exige 3 cambios coherentes (bóveda + `.sha256` + `metrica_hids.VERSION_BOVEDA`) y **MC-1** (`exportar_acciones.sh` con `boveda_version=1` hardcodeado).
3. **El binario del cliente no está sellado en B10** y el `prep` lo redespliega → añadir su `sha256` a B10 y compararlo antes de `t0`.
4. Estado sano verificado: **53/53 huellas**, 0 VMs, **5 snapshots** (con `lab-listo-legit-v2`), `D:` 183 GB.

## 5. Recomendación
**Aprobar** el plan con la **fecha del 27/10 → 30/10** (opción B) y ejecutar **E0** antes de armar. Si el humano prefiere el 26, **E0 primero** y, si algo no sale perfecto, **mover al 27**.
