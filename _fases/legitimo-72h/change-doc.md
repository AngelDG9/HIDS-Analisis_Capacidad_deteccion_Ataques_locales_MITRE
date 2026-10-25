# change-doc — Bloque `legitimo-72h` (L1): ventana de 72 h — **FALLIDO**

> Cierre. Fecha: **2026-10-20**. Estado: **FALLIDO** — la **ventana fue INVÁLIDA** (no se repitió: se diagnosticó y se arregló en `legitimo-fix`).
> Plan de referencia: `plan.md` (la **reconstrucción** del original; el original se perdió al no estar en git — lección aplicada).

---

## 1. Qué se intentó

La **captura de 72 h de actividad legítima** (Wazuh Linux, virgen) del **19/10 00:00Z al 22/10 00:00Z**, con GHOSTS + "internet local", arranque/parada automáticos y el denominador `M` instrumentado.

---

## 2. Qué pasó (causa raíz)

El **log de depuración de GHOSTS** (`ghasts.out`: NLog a *Trace* por stdout, sin tope) creció a **4,78 GB** → **disco de la víctima al 100 %** (19/10 14:03Z):
- 19/10 **21:59:56Z**: último keep-alive del agente `001` → **`Disconnected`**.
- 19/10 **22:00:11Z**: `CRITICAL … No space left` → **el agente murió**.
- El **motor de la timeline** de GHOSTS también murió (el proceso seguía vivo → el `watch` lo veía `Up`).

**Descartado**: reinicio, OOM, red, actualizaciones. **Fue el disco.**

---

## 3. La lección (aplicada en `legitimo-fix`)

1. **Ningún log sin tope** (el de GHOSTS ahora: `Warn` + 40 MB).
2. **La vigilancia debe medir "hacer"**, no "estar vivo" (edad de la última acción; `last keep alive` del agente, no `systemctl is-active`).
3. **El `df` ya lo mandaba el agente** (220 muestras; el 100 % se veía **8 h antes**) → la vigilancia ahora lo lee.
4. **Guardarraíles de disco** y **keepalive acotado**.
5. **El plan se guarda en git al aprobarse** (el original de L1 se perdió por no estar versionado).

---

## 4. Evidencia

- `Soporte/Laboratorio/legitimo_72h/diagnostico_fallo.md` (causa raíz con hora y log).
- `Soporte/Laboratorio/legitimo_72h/fallo_2026-10-19/` (MANIFEST 16/16, serie `df -P` de 220 muestras, `ghasts.out` truncado a 4,78 GB, dmesg, etc.).
- `Soporte/Laboratorio/legitimo_72h/plan_L1_2026-10-18_reconstruido.md` (reconstrucción del plan original).

---

## 5. Consecuencia

**La ventana no se "recicla"**: los datos tras el corte no sirven. La repetición se ejecuta en **`legitimo-72h-v2`**, con el arreglo de `legitimo-fix` (cerrado y verificado) y el snapshot **`lab-listo-legit-v2`**.
