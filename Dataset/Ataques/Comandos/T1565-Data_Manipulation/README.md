# ATA006 · T1565 — Data Manipulation (`sed`/`touch`/`chmod` sobre un fichero *mock*)

> Artefacto **R-13** del bloque `fase-03-escalado`, **tanda A**. Redactado el **2026-09-28** con
> los datos del **paso 0** y con las señales esperadas **antes de ejecutar nada**. Las señales las
> **valida el humano** (gate por tanda, **antes** del primer `t0`) — **APROBADO 2026-09-28**. **No
> contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA006** |
| Técnica | **T1565 — Data Manipulation** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Por qué es un ataque manual

`T1565` aparece en `Hojas/cobertura_atomic.csv` como **`sin_pruebas`** (`prueba_art=no`): Atomic
Red Team **no trae ninguna prueba** (ni Linux ni Windows) para esta técnica. La técnica **sí aplica
a Linux** → el ataque **se escribe a mano**. Es el mismo camino "ataque escrito por nosotros" ya
validado en el piloto-custom (ATA007/ATA012).

## 3. Qué hace y dónde escribe

- **Qué hace:** **altera el contenido** de un fichero de datos *mock* (`sed -i`: infla la
  facturación de un cliente + inyecta un cliente falso). El dato **no se destruye** (T1485) ni se
  **publica** (T1491): se **modifica** (acción característica de T1565).
- **Origen/ejecución:** `/home/angel/lab-attack/ATA006/` (**NO** vigilado → la detección del
  proceso es por **`execve`**).
- **Efecto (D3):** **`/home/angel/lab-legit/datos_clientes_2026.csv`** — la carpeta **vigilada** por
  `auditd` (`-w /home/angel/lab-legit -p wa -k audit-wazuh-w`). El *efecto* genera eventos **watch**.
  El fichero contiene **clientes inventados** (datos de juguete; **sin** datos personales reales).
- **Semilla:** si el fichero no existe, el guion lo crea con un `printf` (builtin, sin `execve`) y
  contenido fijo ⇒ **determinista** e idempotente. Ese `write` de *setup* es un **artefacto** del
  ataque (fuera de su carpeta) que se atribuye por **veredicto humano `artefacto`** (plantilla v4
  §5), **nunca** `ruido`.

### 3.1 ⚠️ Alcance — sin *timestomp* (decisión humana 2026-09-28)

La **técnica es el cambio de contenido** (`sed -i`). **No** se falsean metadatos: el `touch -t`
(mtime) y el `chmod` (modo) se han **retirado** del guion y del `esperado` porque falsear fecha/modo
es **T1070.006 (Timestomp)**, **otra** técnica, y ensuciaría la atribución de T1565. Queda `sed` +
ancla + las dos señales `ambigua` de escritura bajo *watch*.

## 4. Herramienta, dependencias y elevación

| Elemento | Valor |
|---|---|
| Herramientas | **`sed`, `grep`** (coreutils/findutils de serie) |
| Dependencias | ninguna nueva (se instala **nada**) |
| Elevación | **no** |
| Desviación | ninguna; `sed` del paso 0 no está silenciado (C0 pendiente de confirmar). **Retirados** `touch`/`chmod` (T1070.006, ver §3.1) |

## 5. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a `/home/angel/lab-attack/ATA006/`.
2. `cd /home/angel/lab-attack/ATA006/ && bash ATA006_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. El guion hace `cd` a su carpeta (cwd = ancla H4) e imprime `T0=…`/`T1_LOCAL=…`.

## 6. Señales esperadas (convención H4)

`ATA006_esperado.csv`:

- `T1565-S1` (**deteccion**) `audit_exe=sed` — alteración del contenido (`80792`).
- `T1565-S2` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA006/*` — ancla H4 del proceso.
- `T1565-A1` (**ambigua**) `rule_id=80790` — creación/escritura genérica bajo watch.
- `T1565-A2` (**ambigua**) `rule_id=80781` — escritura en la ruta vigilada compartida con el baseline
  → va a **`dudosa`**/revisión humana.

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md` v4). **Sin** `touch`/`chmod` (retirados, §3.1).

## 7. Prueba de éxito del ataque (independiente de la alerta)

El guion **verifica** que los marcadores inyectados **están presentes** (`grep '999999'` y `grep
'Mallory Consulting SL'`) y que **el hash cambió** (`sha256sum` antes/después) ⇒ la manipulación
ocurrió. Evidencia en `Logs/ATA006_iter*/ejecucion.out`.

## 8. Solapamiento declarado (evitar crítica de "mismo ataque")

- **vs ATA002 (T1485 Data Destruction):** ATA002 **destruye** el dato (lo sobrescribe); ATA006 lo
  **modifica** sin destruirlo.
- **vs ATA007 (T1491 Defacement):** ATA007 **publica** un contenido (defacement de una página);
  ATA006 **altera** un dato interno sin publicarlo.
- **vs T1070.006 (Timestomp):** el *timestomp* queda **fuera** de este ataque (§3.1, decisión humana
  2026-09-28). La acción que **caracteriza** T1565 es la **alteración del contenido**.

## 9. C0 (pre-flight base-contra-base) — **EJECUTADO** (2026-09-28)

Captura `Soporte/Ataques/c0/ATA006_logtest.txt`
(`sha256=1bc1533d31a43eecbf41555c4d94ff5be1996ed0c88007dcca403b1f07ec883e`) → informe
`Soporte/Ataques/c0/ATA006_preflight.md`. **Resultado: PASA**.

- **Ganadora de fábrica:** `80792` *Audit: Command: /usr/bin/sed*, **`level 3` ⇒ SÍ avisa**.
  **Sin** silenciador de fábrica. Plan original en `Soporte/Ataques/c0/ATA006_c0_plan.md`.
- Las **escrituras** en `lab-legit` (`80790`/`80781`) se declaran **`ambigua`** → `dudosa`/revisión
  humana (protege frente al catálogo de ruido del baseline).

## 10. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `/home/angel/lab-attack/` y
  `/home/angel/lab-legit/datos_clientes_2026.csv`). El manager **no** se revierte.
- **Higiene:** sin contraseñas, claves ni tokens. Se ejecuta como `angel` **sin `sudo`**.

## 11. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se destruye la máquina);
> **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas por el
> analista**. Los datos de juguete llevan **nombres creíbles** (escena de empresa) para que la
> ventana se parezca a un caso realista, pero **no son datos reales**.
