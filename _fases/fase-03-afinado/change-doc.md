# change-doc — Bloque `fase-03-afinado`: las 4 mejoras del piloto (H1–H4)

> Cierre del bloque. Fecha: **2026-09-26**. Estado: **CERRADO** (verificación `tfg-tester`: **PASA**).
> Plan de referencia: `plan.md` (v1, `status: approved_by_human`, aprobado el 2026-09-26).

---

## 1. Qué se ha hecho

Quitar los **4 enganchones** que reveló el piloto (`_fases/fase-03-piloto/`) **antes de escalar**,
**sin tocar** los artefactos cerrados del piloto (verificado: **18/18 hashes intactos**) y **sin
romper** el determinismo (R-13).

| Mejora | Qué se ha cambiado |
|---|---|
| **H1** | El pre-flight gana un **tercer chequeo `C0` (base-contra-base)** que **avisa** cuando la detección esperada queda **silenciada por una regla de fábrica**. |
| **H2** | **Criterio de doble iteración v2**: **la detección decide**; las sanidades de ruido pasan a **aviso (no bloquean)**; **ventana completa `[t0,t1]` sin recortes**; el arranque se aparta **sellando `t0` tras el asentamiento**. |
| **H3** | El filtro **solo auto-excluye lo DEMOSTRABLE**: `5715` (login SSH) **solo si `srcip` = IP del operador**; **`5501`/`5502` → `dudosa`** (nunca auto-excluidas); `19004` (SCA) por regla+grupo. |
| **H4** | **Convención de señales**: `audit_exe` **+ `audit_cwd` = carpeta del ataque** (ancla el proceso al ataque). |

---

## 2. Entregables

| Fichero | Cambio |
|---|---|
| `_artefactos/scripts/preflight_enmascaramiento.py` | **+ chequeo C0** (C1/C2 intactos) · flag `--logtest-base-c0` |
| `_artefactos/scripts/tests/test_preflight_enmascaramiento.py` | **+6 tests** (golden python3/ls, INCOMPLETO, determinismo) |
| `_artefactos/scripts/tests/fixtures/c0_logtest_python3_ls.txt` | **nuevo** (captura real de `wazuh-logtest`, paso 0) |
| `_artefactos/scripts/filtrar_ruido.py` | **predicado `OPERADOR`** + `OPERADOR_SRCIPS` + **paso 1.5** + `motivo=operador:<id>` + **garantía `CONFLICTO`** |
| `_artefactos/scripts/extraer_alertas.py` | **+`srcip,srcuser,dstuser`** en `--detail` (agregado/`--test`/`--muestra` intactos) |
| `_artefactos/scripts/tests/test_filtrar_ruido.py` (+ fixtures) | **+11 tests** (golden del falso negativo) |
| `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md` | orden con el paso 1.5, principio **"solo lo demostrable"**, limitación y convención H4 |
| `Soporte/Wazuh/Configuracion/preflight_enmascaramiento.md` | **sección C0** (contrato de aviso, CLI) |
| `Soporte/Wazuh/Configuracion/preflight_informe.md` | ejemplo regenerado con sección C0 |
| **nuevo** `Soporte/Ataques/criterio_doble_iteracion.md` | regla **v2** + **nota de coherencia v1/v2** |
| **nuevo** `Soporte/Ataques/plantilla_esperado.md` | convención de señales (`audit_exe` + `audit_cwd`) |
| `Soporte/Ataques/piloto_procedimiento.md` | `t0` tras asentamiento, criterio v2, convención H4 |
| `Dataset/Ataques/Comandos/T1486-…/ATA001_esperado.csv` | ejemplo de formato actualizado (**no** es un ataque del piloto) |
| `.gitignore` | **+`_artefactos/tmp/`** |

---

## 3. Verificación (`tfg-tester`) — **PASA**

**Reprodujo de forma independiente** la prueba de seguridad desde el **diario real del manager**:

| Comprobación | Resultado |
|---|---|
| **`deteccion` intacta** | ATA002 **4/4** · ATA008 **2/2** · ATA013 **0/0** (mismos `rule_id`) |
| **Filas ajenas** | **0 cambios** (ATA002: 0 diferencias) |
| `5715` | **10** → `ruido_conocido` / `operador:5715` |
| `19004` | **1** → `ruido_conocido` / `operador:19004` |
| **`5501`/`5502`** | **13 → `dudosa`** — **la diferencia esperada** vs. el piloto, documentada |
| **⭐ Golden del falso negativo** | `5715` con **`srcip` ajeno → `dudosa`** · `5501/5502` **→ `dudosa`** · señal declarada → **`deteccion` + `CONFLICTO`** |
| **Piloto intacto** | **18/18 hashes**; `git diff` vacío en sus artefactos |
| **C0** | `python3` → **`92600` (level 0) → AVISA** · `ls` → **`80792` (level 3) → NO avisa** · sin captura → **`INCOMPLETO`** · determinista |
| **H2** | la regla escrita coincide con el plan; recálculo → los 3 dan **`iguales`**; **sin** menciones a recortes de 90 s |
| **Suite** | **75 tests en verde** |

---

## 4. Hallazgos y matices (declarados)

1. **C0 es obligatorio siempre** (también con 0 reglas propias): el silenciador `92600` **es de fábrica** y actuó en ATA013 con RS3/RS4 vacías → exigir la captura siempre es la lectura **más segura**. **Aceptado por el tester como coherente con el plan.**
2. **Recuento §4.3 vs re-extracción:** son **conjuntos distintos**, no una contradicción: **13** = PAM que quedan `dudosa`; **10** = `5715` auto-excluidas (5 más estaban en ATA002, donde el piloto ya las tenía como `baseline`).
3. **Las PAM de ATA002 caen en `baseline`** (no `dudosa`) porque su esperado tiene señales `rule_group` **siempre evaluables** → es **comportamiento preexistente**, no de H3.

---

## 5. Cabos para el escalado (anotados)

| # | Cabo | Acción |
|---|---|---|
| 1 | **Default de `--out`/`--rev-out` de `filtrar_ruido.py`** apunta a `…/Wazuh/Auditado/` **sin `linux/`** → una ejecución sin `--out` escribe **fuera** del árbol versionado | **Arreglar al inicio del escalado** |
| 2 | **`OPERADOR_SRCIPS = {192.168.65.1}` hardcodeado** | **Reconfirmar** en cada arranque del laboratorio (si cambia, `5715` → `dudosa`: lado seguro pero ruidoso) |
| 3 | Runbook §6 contiene una frase **histórica** del hallazgo (antigua) | Añadir puntero a §7 para no confundir al lector de la memoria |
| 4 | **⚠️ Amenaza preexistente:** con señales **`rule_group` amplias** (tipo ATA002), las PAM de un **hipotético atacante** caerían en `baseline` en vez de `dudosa` | **Tenerlo presente al escribir las señales del escalado** (preferir señales específicas, ya convención H4) |
| 5 | **C0 por técnica**: en el escalado habrá que **producir una captura C0 por técnica** antes de medir | Incluir en el procedimiento del escalado |

---

## 6. Siguiente

- **Escalar los ataques** a las **10 técnicas restantes** del corpus (bloque `fase-03-escalado`), con las
  mejoras ya aplicadas y la convención de señales.
- **Tutoría (H1/H2)**: sigue pendiente por parte del humano; **no bloquea** el escalado.
- Después: **Fase 4** (precio de la detección, con ataques representativos) y **Fase 5** (memoria).
- **`push`**: los commits son locales; publicar es tarea del humano.
