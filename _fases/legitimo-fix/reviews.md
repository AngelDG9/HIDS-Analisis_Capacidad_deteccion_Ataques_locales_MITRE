# reviews.md — Ataque del plan (bloque `legitimo-fix`, v3)

> Revisión del **orquestador** sobre `plan.md` (**v3**, 1407 líneas). Fecha: **2026-10-21**.
> **Veredicto: APROBABLE** — sin notas bloqueantes.

---

## 1. Comprobaciones
- **Sin secretos** (0) ✅ · **`git status`**: solo las rutas del bloque + `state.md` ✅.
- **Fuentes del navegador**: citadas con `fichero:línea` (`ghosts.client.linux.csproj:29-30`, `BaseBrowserHandler.cs:386,490`, `BrowserFirefox.cs:24-30,103,120`, `BrowserChrome.cs:22,26`, `RequestBuilder.cs:24-44`) ✅.
- **No toca** Wazuh/métrica/corpus/`Hojas/`/`Dataset/`/`_recursos/`/lab de ataques ✅.

---

## 2. La investigación del navegador (lo que importa)

**Existe** (`BrowserFirefox`/`BrowserChrome` vía Selenium), **pero**:
1. **No es determinista** de verdad: `random`/`randomalt` eligen URL con `_random.Next`; `stickiness`/`browse-probability`/`delay-jitter` meten azar; `{uuid}/{n}/{c}` cambian por petición.
2. **Bug serio**: si el driver falla, Firefox entra en un `while (!hasRunSuccessfully)` **sin espera** → **bucle caliente** y `_log.Debug` que **mantiene fresco `app.log`** → **engañaría al heartbeat**.
3. **Falta el driver** (no viene en el cliente; `selenium-manager` intentaría descargarlo y **sin NAT falla**).
4. **Coste**: víctima de **3 GB/9,8 GB** → **+300–600 MB de RAM** y **+300–400 MB de disco**.
5. **No hay DNS ni TLS** en el lab (HTTP + `/etc/hosts`) → **no ejercitaría** lo que se buscaba.
6. **⭐ Contra la métrica**: las reglas de `auditd` capturan **todo `execve` y toda escritura sin filtro de ruta** → el **churn de caché del navegador infla `M`** → **baja el FPR mecánicamente** → **degradaría la medida**, no la mejoraría.

⇒ **Decisión correcta: descartar el navegador** en esta ventana (falla **5 de 6** criterios del humano) y, **en su lugar**, una **sesión web "browser-like" con `curl`** (UA fija, cookies, `Referer`, `Accept-Encoding`, CSS/JS/SVG, PDF) **sin cambiar el recuento**. DT-B queda como **falsación**: si pasara completo, entraría **solo en B3** y se regeneraría la receta.

---

## 3. Fortalezas del v3
- **Regla pre-registrada** (DT-B, 6 criterios, tope 90 min) → **no se decide a posteriori** ✅.
- **Umbrales objetivos**: `M_nav/M_curl ≤ 1,4`/día, ≤1.500 eventos/sesión, RAM ≥512 MB, perfil ≤50 MB, 0 huérfanos ✅.
- **Chrome for Testing, nunca Firefox** (por el bug del bucle caliente) ✅.
- **La fecha sigue ABIERTA** (el humano dijo "el 26 ya veremos") ✅.

## 4. Notas
1. La **premisa del encargo** (TLS/DNS) **no se puede cumplir** en el lab actual; si se quisiera, sería **otro bloque** con infraestructura propia. Declarado.
2. **"Misma secuencia"**: se fija como **acciones** (no eventos) — correcto y necesario.
3. **La receta escribe fuera de `lab-legit`** (`~/Documentos`, `~/Descargas`): las escrituras seguirán generando `80780` por la regla global; **verificar en DT11** antes de usar `audit_dir`/`audit_file` como ancla. Declarado.
4. **`plan.md` sin git**: se guardará al aprobarse (Q7/CA-24).

## 5. Recomendación
**Aprobar** (Q1–Q9; el navegador **descartado**, la sesión *browser-like* adoptada) y **fijar la fecha** (26/10 propuesta, abierta). Después: arreglo + DT0–DT13 + DT-B (falsación) + snapshot v2 + ventana.
