# reviews.md — revisión del plan `legitimo-v3` (estudio en frío + ventana mejorada)

> Revisión del **orquestador** sobre `plan.md` (817 líneas, v1, `status: draft`). Fecha: **2026-10-27**.
> **Veredicto: APROBABLE CON 3 CORRECCIONES** (ninguna afecta al diseño; dos son de precisión y una de
> verificación).

---

## 1. Lo que está bien (y sostiene la decisión)

1. **El estudio responde a lo que se pidió**: opciones A–E con veredicto, tabla de mejoras con coste,
   y descarte razonado de lo caro. No es una lista de deseos: cada mejora tiene requisito y riesgo.
2. **El hallazgo central es correcto y honesto**: `M` lo domina el fondo (≈33 k eventos/h frente a
   ~14 acciones/h) ⇒ **el realismo se compra con variedad, no con volumen**. Eso justifica no duplicar
   acciones y no gastar en navegador.
3. **Respeta la restricción dura**: **cero instalaciones y cero ampliación de disco**. Navegador,
   LibreOffice y GUI quedan fuera **con la prueba que ya existe** (DT-B0).
4. **La campaña es limpia**: los 12 casos son **no mutantes** (revisados uno a uno: lecturas de
   servicios/logs/cron, `tar`, `rm` de temporales propios, `curl`, `openssl` sobre copia propia,
   bucle de `cp`). No violan V7.
5. **Campaña dentro de la ventana, etiquetada y reportada con/sin** ⇒ evita la crítica de "fabricar FPs".
6. **Anti-aborto**: la cláusula es la lección correcta de v2.
7. **Contingencia escrita** (09/11 con núcleo recortado) y **condición de viabilidad con reloj**.

## 2. Correcciones obligatorias

### C-1 (bloqueante, de redacción): las horas de `prep`/`arm`/timer están en **UTC** pero etiquetadas "local"
El plan dice: `prep` **01/11 23:15 local** (`t0−45`), `arm` **23:40 local**, timer **23:55 local**.
Con `t0 = 02/11 00:00Z` (= **01:00 local**), esas horas **son UTC**: 23:15Z = **00:15 local**, etc.
Leídas como locales darían **1 h de desfase**.
**Corrección:** o se etiquetan **UTC**, o se escriben **00:15 / 00:40 / 00:55 local del 02/11**.
(El `stop` sí está bien: `05/11 01:05 local` = `00:05Z` = `t1+5`.)

### C-2 (verificación): `sudo -n` sin contraseña
- **FP-01** usa `sudo -n systemctl is-active` / `sudo -n df -h /`.
- **M5** usa `sudo -n -u soporte.ti`.
Si `angel` **no** tiene NOPASSWD, esos comandos **fallan** y el caso deja de ser "administración
legítima" (se convierte en un error, que es otra familia).
**Corrección:** comprobarlo en **E0-1** y decidir **antes** de `t0`: (a) regla `NOPASSWD` **dentro del
snapshot v3** (declarada), o (b) sustituir FP-01 por una consulta sin `sudo`, o (c) si falla M5, se cae
M5 (ya previsto).

### C-3 (congelación): **V2 se reescribe** si entra M6 (actividad nocturna)
Hoy V2 exige **0 acciones fuera de los bloques diurnos**; con `N1` (21:30-21:45Z) eso es falso.
**Corrección:** la **nueva V2** (con `N1` permitido) debe quedar **escrita y congelada antes de `t0`**,
publicada en el plan, y aplicarse **igual** a los tres días. No se puede reescribir después de ver datos.

## 3. Notas menores (no bloquean)

- `useradd -m` en `prep` debe ser **idempotente** (si el usuario existe, no fallar) y `G-13` comprobarlo.
- **`openssl enc` con contraseña desde fichero local**: ese fichero se genera **dentro de la invitada**
  y **nunca** se versiona; comprobar que no cae en `campana_fp/` versionado ni en el repo.
- **`find -delete`** y `rm -rf` deben apuntar **solo** a rutas bajo `~/Documentos/campana_fp/`.
- El **`watch`** con gracia de borde (H1) debe probarse en **dos** escenarios (inicio de bloque y
  reanudación tras pausa), como dice el plan.
- La **lista blanca** de binarios del generador debe ampliarse con las herramientas nuevas **y**
  justificarse (si no, `--check` fallará).
- **`boveda_version` → 2** y **MC-1** se aplican **una sola vez** al cerrar; conviene dejarlo como
  tarea explícita del cierre, no del ejecutor de la ventana.

## 4. Riesgo principal (declarado)

**El calendario.** 17–21 h de trabajo en 4 días (28–31/10) más 3 días de ventana. Si T1–T3 no están en
PASS el **31/10 12:00**, se pasa a **09/11** con el núcleo. **No se arranca a medias.** Es la decisión
correcta, pero conviene que el humano sepa que el plan **puede** deslizarse una semana.

## 5. Recomendación

**Aprobar** el plan con **C-1, C-2 y C-3** aplicadas **antes** de empezar T1, y con la cláusula
anti-aborto firmada. El estudio está bien hecho y la opción D acotada es la correcta: mejora lo que se
puede mejorar sin gastar una semana en instalar paquetes que además romperían el margen de disco.
