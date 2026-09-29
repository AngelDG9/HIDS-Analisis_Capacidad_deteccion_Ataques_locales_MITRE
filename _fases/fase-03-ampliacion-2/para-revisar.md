# Para revisar — Ronda 2 de ampliación (2026-09-29)

> **Qué se hizo:** la **2ª ronda de 15 técnicas** (`fase-03-ampliacion-2`), en **3 tandas de 5**, con
> **ejecutor + tester** por tanda y las 3 verificadas **PASA**.
> **Resultado: 14 de 15 detectadas** → **corpus: 43 técnicas · 41 detectadas / 2 no**.
>
> Lista de **decisiones tomadas** (con validación humana registrada; revisión posterior) y **lo que te toca mirar**.

---

## 1. ⭐ El hallazgo grande de esta ronda

**La misma técnica (archivar) se comporta de TRES formas distintas según CÓMO se implemente:**

| Cómo se archiva | ¿Detectado? | Por qué |
|---|---|---|
| Con una **utilidad** (`tar`, `gzip`) | **SÍ** ✅ | Se ejecuta un programa → el HIDS lo ve |
| Con una **librería** (`python3`) | **NO** ❌ | **Wazuh se auto-suprime** (su regla `92600`) |
| Con un **método propio** (funciones del shell) | **NO** ❌ | **No hay ejecución** → no hay nada que ver |

👉 **Lo que decide la detección es la IMPLEMENTACIÓN, no la técnica.** *(Esto es oro para la memoria.)*

**Y el matiz honesto que el tester me obligó a precisar:** el "no detectado" de ATA034 **depende de nuestra
elección** — con un **programa propio compilado** sí se detectaría. Queda escrito así en su ficha.

---

## 2. Decisiones tomadas

| # | Decisión |
|---|---|
| **1** | Aprobar el plan y las 15 (criterios del planificador por escrito) |
| **2** | Firmar los 15 `esperado` **antes** de atacar |
| **3** | **Seguridad extrema**: el borrado de disco y el reinicio → **solo imagen de fichero** y **solo la VM víctima** (guardarraíles **no** disparados) |
| **4** | **Pivotes por falta de dependencias**: sin NFS/SMB → el "recurso de red" se hizo con un **servicio `rsync` local**; sin compilador en la víctima → los programas de 2 ataques se **precompilaron** y se guardan como texto (`.b64`) |
| **5** | Mandar a `ruido` las filas **ajenas** (PAM del login) → **la única línea del ataque en `ruido` sigue siendo CERO** ✔ |
| **6** | **NO tocar la métrica** pese a un falso positivo detectado (ver §3) |
| **7** | Corregir la **plantilla de checklist**: el patrón de "creación de fichero" estaba mal (`80790` → es **`80782`**) → evita "señales muertas" en el futuro |

---

## 3. 👀 Lo que te toca mirar (3 cosas)

### 1️⃣ 🔴 **La decisión R13: ¿abrimos P2 o cerramos P1?**
La **piscina P1 de Linux está casi agotada**: quedan ~29, y **muchas no se pueden probar sin internet** o
**repiten el mismo mecanismo**. Opciones:
- **A.** **Cerrar P1** (41/43 detectadas, muestra sólida) y pasar a **evasión / Windows / Fase 4 / memoria**.
- **B.** **Abrir P2** (las técnicas "habilitadoras": 459 candidatas) y seguir midiendo.

👉 **Mi recomendación: A**, con una excepción: antes de cerrar, un bloque corto de **evasión** (que es el
complemento natural y ya está acordado).

### 2️⃣ 🟠 **El `.gitattributes` mínimo** (para poder clonar sin romper nada)
Hay 2 ataques cuyos programas se guardan como texto (`.b64`): **un clon con `autocrlf` podría romperlos**.
**Propuesta:** añadir **solo dos líneas** (`*.b64 -text`, `*.sh text eol=lf`). **No lo he hecho** (tú
revertiste un `.gitattributes` global; esto sería **mínimo y probado**). **¿Lo autorizas?**

### 3️⃣ 🟡 **El falso positivo `rule_id 11`** (declarado, no arreglado)
Una alerta **interna de Wazuh** se contó como "detección" en **2 de 86 ventanas**. **No cambia ningún
veredicto.** Arreglarlo exigiría **tocar la métrica congelada** → **no lo he hecho**: queda **declarado** y
**candidato a un arreglo futuro** (bloque propio).

---

## 4. Lo que NO se hizo

- **La métrica y el filtro, intactos** · **sin evasión** · **sin Windows** · **sin `push`** · **sin secretos**.
- **Nada destructivo**: los guardarraíles no se dispararon; **laboratorio cerrado** (servicios parados, share borrado, VMs apagadas, NAT off).

---

## 5. Dónde está todo

| Qué | Dónde |
|---|---|
| Cierre completo (con el hallazgo) | `_fases/fase-03-ampliacion-2/change-doc.md` |
| Plan y criterios de selección | `_fases/fase-03-ampliacion-2/plan.md` |
| Detalle por ataque | `Dataset/Ataques/Resultados/Wazuh/linux/ATA0{29..43}_meta.md` + `Bitacora/ATA0{29..43}.json` |
| Estado general | `state.md` (y `roadmap.md`) |
