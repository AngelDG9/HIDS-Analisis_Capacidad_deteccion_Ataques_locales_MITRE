# reviews.md — Ataque del plan (bloque `legitimo-infra`, L0)

> Revisión del **orquestador** sobre `plan.md` (v1, 506 líneas). Fecha: **2026-10-18**.
> **Veredicto: APROBABLE** — sin notas bloqueantes.

---

## 1. Comprobaciones
- **Sin secretos** (0) ✅ · **`git status`**: solo `plan.md` (untracked) ✅ · material protegido intacto ✅.
- **Anclaje**: cita R0 §7 (legítimo), R2 §2.2 (unidad/denominador) y la métrica congelada ✅.

## 2. Fortalezas
- **Go/no-go con 5 criterios objetivos** (G1 offline · G2 presupuesto RAM · G3 el cliente deja rastro visible por Wazuh · G4 control/timelines/contador · G5 ≤2 sesiones) + **plan B declarado** (acciones reales con navegador/apps, mismas unidades) → **el plan B no desperdicia L0** ✅.
- **⭐ Hallazgo importante**: en tu PC (**Windows 10 Home**) **Docker Desktop rompería VMware** (Hyper-V/WSL2) → el plan **prohíbe Docker** y va *host-native* (o una VM Linux pequeña) + **verifica** que las VMs siguen arrancando (G2) ✅.
- **Reaprovecha** lo ya montado (sink HTTP, nube WebDAV, paste) y **añade** solo un servidor web estático (stdlib, sin dependencias) ✅.
- **Higiene de medida**: montaje y pruebas **fuera** de ventana; snapshot nuevo **`lab-listo-legit`**; **`logall_json` OFF por defecto** (se prueba y se apaga); el **manager no se revierte** ✅.
- **Prueba de `logall_json`**: mide la **tasa real** y **estima las 72 h** → resuelve la incógnita que dejó R2, con **disparador numérico del fallback** (>~5 GB) ✅.
- **Puertos separados del manager** (nunca 443/1514/1515/55000) ✅.
- **12 CA verificables** + **gate en lenguaje sencillo** ✅.

## 3. Notas
1. **Decisión abierta real**: el *pin* de GHOSTS vs el runtime .NET (el host tiene **.NET 8**; GHOSTS v9 pide **.NET 10**) → el plan lo resuelve con *time-box* (release compatible o instalar SDK) ✅.
2. **Coordinación declarada**: el **sellado de la bóveda B10** lo hará **L1** (L0 no toca `Soporte/Metrica/`) ✅.
3. **Lo que L0 no puede garantizar** (y no finge): que GHOSTS deje rastro suficiente en el host → por eso **G3 es criterio de go/no-go**, no un supuesto ✅.

## 4. Recomendación
**Aprobar** y contestar el gate (§11, 6 preguntas). Después: el ejecutor monta y **prueba** (sin medir); verificación del *tester* (CA-L0-01…12) y cierre.
