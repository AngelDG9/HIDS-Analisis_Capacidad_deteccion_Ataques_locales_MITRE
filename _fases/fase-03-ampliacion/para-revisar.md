# Para revisar — decisiones tomadas por el orquestador (2026-09-29)

> **Qué se hizo:** la **ronda de 15 técnicas nuevas** acordada
> (`fase-03-ampliacion`), en **3 tandas de 5**, con **ejecutor + tester**.
> **Resultado: 15/15 DETECTADAS** → el corpus pasa a **28 técnicas · 27 detectadas / 1 no** (ATA013).
>
> Esto es la **lista de decisiones tomadas con validación humana registrada** (con revisión posterior
> de tu parte) y **los puntos que te recomiendo mirar**.

---

## 1. Decisiones tomadas (con validación humana registrada)

| # | Decisión | Por qué |
|---|---|---|
| **D1** | **Aprobar el plan** y **elegir las 15** (las propuso el planificador con criterios explícitos: táctica R/E/S → diversidad de capas del HIDS → factibilidad sin NAT → dificultad) | Era el encargo; el criterio quedó escrito en `plan.md` §2 |
| **D2** | **Firmar los 15 `esperado`** (= el diseño de cada ataque y sus señales) **antes** de atacar (CA1) | Sin firma no se puede atacar; se registró como **validación humana** |
| **D3** | **Diseño de cada ataque**: guion propio, **nada destructivo**, guardarraíles; **solo Linux**; **sin NAT**; **el ataque en su carpeta** y el efecto en `lab-legit` | Reglas ya fijadas (D3 de la ronda anterior) |
| **D4** | **ATA022** (`git`): el "repositorio de código" es un **repo LOCAL dentro de `lab-attack`** | Prohibido cualquier push a un remoto real; el repo del TFG **intacto** |
| **D5** | **ATA027** (abrasión de disco): **solo imagen de fichero (`loop`)** | **Nunca** discos reales; los guardarraíles no se dispararon |
| **D6** | Resolver a **`ruido`** las filas **demostrablemente ajenas** (churn de tu login / PAM) con el **criterio ya ratificado** | Está listado por ataque en fichas y bitácoras |
| **D7** | Corregir el **1 FALLA del tester** (ATA021: una fila PAM mal plegada → `artefacto` en vez de `ruido`) y **1 huella desincronizada** (ATA001, por un retoque cosmético anterior) | Integridad; quedan registrados con eventos `correccion` |
| **D8** | **Declarar la limitación nueva** (filas de la *sesión* del ataque —PAM/`sudo`, sin `cwd`— que caen en `baseline`): **30 en ATA024, 4 en ATA027, 1 en ATA026** | **No son corregibles** sin tocar la métrica congelada; **ninguna es detección** |
| **D9** | **La evasión, al futuro** (nota breve en `state.md` + `roadmap.md`) | Acordado contigo: primero la cobertura P1 sin evasión |

---

## 2. Lo que te recomiendo revisar (por orden)

1. **Los 3 hallazgos grandes** (`change-doc.md` §3):
   - **ATA024/T1531** ejercita **4 capas** del HIDS (`execve` + `watch /etc` + **FIM `550`** + **syslog `5901-5903`**).
   - **Audit registra el BINARIO REAL**, no el nombre de la orden (`nc`→`nc.openbsd`): hay que **declarar `audit_exe` con el nombre real o glob**.
   - **Wazuh no ve red ni recursos**; **cron sí** (syslog `2832` + `watch` del spool); **`python3` sigue ciego**.
2. **La limitación D8** (§4 del `change-doc`): ¿te vale declararla así, o quieres otra solución?
3. **La redacción del invariante**: *"0 filas del ataque en `ruido`"* pasa a leerse **"bajo la pertenencia por carpeta"**.
4. **Los `esperado` firmados** de las 15 (uno por técnica, en `Dataset/Ataques/Comandos/`): si algún diseño no te convence, se corrige antes de las próximas rondas.

---

## 3. Lo que **NO** se hizo (para tu tranquilidad)

- **Nada destructivo**: ningún guion tocó el sistema real, usuarios reales, discos o servicios; **los guardarraíles no se dispararon**.
- **La métrica y el filtro NO se tocaron** (siguen congelados).
- **No** hay **Windows**, **ni evasión**, **ni Fase 4**.
- **No** hay `git push` (los commits son **locales**) y **no** hay secretos en el repo.
- **El laboratorio quedó cerrado**: usuario desechable borrado, **0** loops/procesos, receptor parado, firewall ausente, VMs apagadas, NAT off.

---

## 4. Dónde está todo

| Qué | Dónde |
|---|---|
| Cierre completo del bloque | `_fases/fase-03-ampliacion/change-doc.md` |
| Plan y criterios de selección | `_fases/fase-03-ampliacion/plan.md` |
| Detalle por ataque | `Dataset/Ataques/Resultados/Wazuh/linux/ATA0*_meta.md` + `Bitacora/ATA0*.json` |
| Estado general | `state.md` (y `roadmap.md`) |
| Auditor de huellas (nuevo) | `_artefactos/scripts/auditar_cadena_huellas.py` |
