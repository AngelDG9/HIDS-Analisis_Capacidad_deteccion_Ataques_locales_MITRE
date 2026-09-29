# ATA014 · T1114 — Email Collection (recolección de buzón local, custom)

> Artefacto del bloque `fase-03-ampliacion`, **tanda A** (`fase-03-escalado` → `fase-03-ampliacion`).
> Redactado el **2026-09-29** con los datos del **paso 0** y con las señales esperadas **antes de
> ejecutar nada**. Las señales las **valida el humano** (gate por tanda, **antes** del primer `t0`)
> — **APROBADO 2026-09-29**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA014** |
| Técnica | **T1114 — Email Collection** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (escrito por el TFG; ART no trae prueba Linux utilizable sin red) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** **recolecta** el correo local de la víctima. La víctima tiene un **buzón mbox
  simulado** (escena de empresa: presupuesto, nóminas, contrato) en la ruta **VIGILADA**
  `/home/angel/lab-legit`. El atacante localiza/parsea el buzón (`grep`) y **copia** los mensajes
  a la carpeta del ataque (`cp`).
- **Destino:**
  - **Lectura** de `/home/angel/lab-legit/mailbox_angel_2026.mbox` (vigilada con `-w … -p wa`).
  - **Copia** en `/home/angel/lab-attack/ATA014/collected/` (`asuntos.txt`, `mailbox_angel_2026.mbox`).
- **Capa del HIDS que ejercita:** `execve` + `watch` (la **siembra** del buzón escribe en la ruta
  vigilada → evento `watch`). **Ojo:** `-p wa` audita **escritura/atributos**, **no lecturas** →
  la **lectura** del buzón **no** genera evento `watch`; la detección es el **`execve`** del lector.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-09-29) |
|---|---|
| Herramientas | **`cat`, `grep`, `cp`, `mkdir`, `sha256sum`, `awk`** (de serie) |
| Dependencias | ninguna nueva (no se instala nada) |
| Elevación | **no** (usuario `angel`; escribe en su `$HOME`) |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica a
   `/home/angel/lab-attack/ATA014/`.
2. `cd /home/angel/lab-attack/ATA014/ && bash ATA014_ataque.sh 2>&1 | tee ejecucion.out`
   **como `angel`**. Imprime `T0=…`/`T1_LOCAL=…` (UTC).

## 5. Señales esperadas (convención H4)

`ATA014_esperado.csv`:

- `T1114-S1` (**deteccion**) `audit_exe=grep` — localización/extracción de mensajes (`80792`).
- `T1114-S2` (**deteccion**) `audit_exe=cp` — copia del buzón recolectado.
- `T1114-S3` (**deteccion**) `audit_cwd=/home/angel/lab-attack/ATA014/*` — ancla H4.
- `T1114-A1/A2/A3` (**ambigua**) `rule_id ∈ {80790, 80781, 80782}` — escritura bajo **watch** en
  `lab-legit` (efecto del ataque) → `dudosa` → veredicto humano **`artefacto`** (**nunca** `ruido`).

> **H4:** cada señal `audit_exe` va acompañada de `audit_cwd` de la carpeta del ataque
> (`Soporte/Ataques/plantilla_esperado.md` v4). Las `ambigua` se acotan **por `rule_id`** (nunca
> `rule_group` amplios, que capturan churn ajeno).

## 6. Hipótesis de detección

- **DETECTADO** por el `execve` de **`grep`/`cp`** (`80792`, nivel 3) anclado al `cwd` del ataque.
- La **siembra** del buzón (escritura en `lab-legit`) dispara **`watch`** (`80790/80781`), declarada
  **`ambigua`** (no cuenta como detección): es el **efecto**, no la técnica declarada.

## 7. Prueba de éxito (independiente de la alerta)

El buzón tiene **≥3 mensajes** y la copia en `lab-attack` conserva el **mismo `sha256`** que el
original ⇒ la recolección **ocurrió de verdad**. Evidencia en
`Logs/ATA014_iter*/ejecucion.out` + `sha256_artefacto.txt`.

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`** (borra `lab-attack` y `lab-legit`). El
  manager **no** se revierte.
- **Higiene:** sin contraseñas reales, claves ni tokens. Datos de correo **de juguete**.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio** (no se destruye la máquina);
> **el entorno no tiene usuarios/servicios reales** y **las rutas del ataque son conocidas por el
> analista**. Los datos de juguete llevan **nombres creíbles** (escena de empresa) pero **no son
> datos reales**.
