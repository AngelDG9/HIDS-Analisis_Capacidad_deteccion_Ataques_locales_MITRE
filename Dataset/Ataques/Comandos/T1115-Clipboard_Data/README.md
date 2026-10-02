# ATA052 · T1115 — Clipboard Data (`xclip` sobre display virtual Xvfb, ART adaptado)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda B** (4.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA052** |
| Técnica | **T1115 — Clipboard Data** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **ART adaptado** (atómica Linux `xclip`, guid `ee363e53…`; fuente del portapapeles simulada) |
| Ejecución | usuario `angel`, **sin `sudo`** en la ventana |

## 2. Qué hace y dónde escribe

- **Qué hace:** coloca contenido en el **portapapeles** del display virtual `:99` con
  **`xclip -selection clipboard`** y lo **lee** con **`xclip -selection clipboard -o`**,
  volcándolo a `portapapeles_capturado.txt` (mismo mecanismo que la atómica Linux de ART
  `history | xclip -sel clip; xclip -o > history.txt`).
- **Display:** **`Xvfb :99`** (servidor X **sintético** sin usuario real; pre-steado antes de `t0`).
- **Capa del HIDS que ejercita:** **`execve`** (`xclip`, `80792`). La **prueba de efecto** es el
  fichero capturado idéntico al contenido sembrado (`sha256`).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramienta | `xclip` (paquete **xclip**), `Xvfb` (paquete **xvfb**) |
| Dependencias | **pre-steadas offline** (paquetes `.deb` fijados URL+`sha256`, §5.1 del plan) |
| Elevación | **`sudo`** SOLO para `dpkg -i` de los paquetes **antes de `t0`** (fuera de la ventana) |
| Guardarraíl | display `:99` **sintético**; Xvfb **matado** por ventana; sin cambios persistentes |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica + el directorio de `.deb`.
2. **Pre-staging** (`ATA052_prestaging.sh`): `dpkg -i` offline + arranque de `Xvfb :99` + siembra
   de `historial_simulado.txt`.
3. `cd /home/angel/lab-attack/ATA052 && bash ATA052_ataque.sh 2>&1 | tee ejecucion.out`.
4. Tras `t1`: matar `Xvfb`. El revert a `lab-listo` lo elimina todo.

## 5. Señales esperadas (convención H4)

`ATA052_esperado.csv` (todas `deteccion`):

- `T1115-S1` `audit_exe=xclip` (`80792`) — acceso al portapapeles.
- `T1115-S2` `audit_cwd=/home/angel/lab-attack/ATA052/*` — ancla H4.

> ART usa `xclip` dos veces (poner y leer); ambas comparten `audit_exe=xclip`.

## 6. Prueba de éxito (independiente de la alerta)

`portapapeles_capturado.txt` **idéntico** a `historial_simulado.txt` (`diff -q` OK); su `sha256`
coincide. Evidencia en `Logs/ATA052_iter*/`.

## 7. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** `Xvfb` matado; paquetes y captura desaparecen con el revert; **sin NAT**.

## 8. Alcance y limitación declarada (realismo acotado)

> **La técnica y el binario (`xclip`) son reales; el portapapeles es de un display sintético sin
> usuario real.** La fuente del contenido en ART es el *history* del shell; aquí se sustituye por
> un **historial simulado** (el entorno headless no tiene sesión interactiva). El mecanismo
> (poner/leer el portapapeles con `xclip` + `execve` + fichero resultante) **sí** se ejercita.

> **Nota de arquitectura (servicio local).** El receptor `sink_http.py` se levanta en el **HOST**
> (`192.168.65.1`, VMnet1), **fuera de las dos VMs** — igual que en el piloto
> (`Soporte/Ataques/receiver/README.md` §1) — y de él **depende la prueba de efecto** (el `sha256`
> del `sink.log`). El endpoint `/paste` es el `do_POST` **genérico** del receptor (sin código nuevo).
> Los paquetes GUI de Tanda B (Xvfb/xclip/xdotool/xinput) se instalan **offline** (`dpkg -i`) en la
> víctima; esa copia se pierde en el revert. El estado pre-steado del HOST se limpia al cerrar la tanda.
