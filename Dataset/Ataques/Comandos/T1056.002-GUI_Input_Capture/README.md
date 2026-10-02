# ATA053 · T1056.002 — GUI Input Capture (captura de eventos X11 sobre Xvfb, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda B** (5.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**
>
> **Estado: SE INTENTA.** ART **no trae prueba Linux** para T1056.002 (solo macOS/Windows) → ataque
> **propio**. Si el mecanismo no fuera fiel, se declararía **no factible** con evidencia.

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA053** |
| Técnica | **T1056.002 — Input Capture: GUI Input Capture** |
| Tácticas | Collection; Credential Access |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **custom/propio** (ART sin prueba Linux; solo AppleScript/PowerShell) |
| Ejecución | usuario `angel`, **sin `sudo`** en la ventana |

## 2. Qué hace y dónde escribe

- **Qué hace:** **captura los eventos de entrada X11** (keylogging a nivel de GUI) del display
  virtual `:99` con **`xinput test-xi2 --root`**, mientras **`xdotool`** inyecta una secuencia
  sintética que simula a la víctima tecleando credenciales. El **keylog** queda en `keylog.txt`.
- **Display:** **`Xvfb :99`** (servidor X **sintético** sin usuario real; pre-steado antes de `t0`).
- **Capa del HIDS que ejercita:** **`execve`** (`xinput`, `xdotool`, `80792`). La **prueba de
  efecto** es `keylog.txt` con eventos `KeyPress` capturados.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramienta | `xinput` (paquete **xinput**), `xdotool` (paquete **xdotool**), `Xvfb` (**xvfb**) |
| Dependencias | **pre-steadas offline** (paquetes `.deb` fijados URL+`sha256`, §5.1 del plan) |
| Elevación | **`sudo`** SOLO para `dpkg -i` de los paquetes **antes de `t0`** (fuera de la ventana) |
| Guardarraíl | display `:99` **sintético**; entrada **sintética** (`xdotool`); sin cambios persistentes |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica + el directorio de `.deb`.
2. **Pre-staging** (`ATA053_prestaging.sh`): `dpkg -i` offline + arranque de `Xvfb :99`.
3. `cd /home/angel/lab-attack/ATA053 && bash ATA053_ataque.sh 2>&1 | tee ejecucion.out`.
4. Tras `t1`: matar `Xvfb`. El revert a `lab-listo` lo elimina todo.

## 5. Señales esperadas (convención H4)

`ATA053_esperado.csv` (todas `deteccion`):

- `T1056.002-S1` `audit_exe=xinput` (`80792`) — capturador de eventos X11.
- `T1056.002-S2` `audit_exe=xdotool` (`80792`) — inyector de entrada sintética.
- `T1056.002-S3` `audit_cwd=/home/angel/lab-attack/ATA053/*` — ancla H4.

## 6. Prueba de éxito (independiente de la alerta)

`keylog.txt` contiene eventos **`KeyPress`** (≥ 1); su `sha256` queda en `Logs/ATA053_iter*/`.
Evidencia de que la captura de entrada GUI ocurrió **de verdad**.

## 7. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** `Xvfb` matado; paquetes y keylog desaparecen con el revert; **sin NAT**.

## 8. Alcance y limitación declarada (realismo acotado)

> **La técnica (captura de entrada GUI a nivel X11) es real; la pantalla y la entrada son
> sintéticas.** No hay usuario real ni ventana de credenciales de un sistema real: la entrada la
> inyecta `xdotool` y el display es `Xvfb`. El mecanismo (cliente X que **captura** los eventos de
> teclado + `execve` + keylog resultante) **sí** se ejercita. ART **no incluye** esta prueba para
> Linux (solo AppleScript/PowerShell) → ataque **propio**; se declara el sustituto sintético.

> **Nota de arquitectura (servicio local).** El receptor `sink_http.py` se levanta en el **HOST**
> (`192.168.65.1`, VMnet1), **fuera de las dos VMs** — igual que en el piloto
> (`Soporte/Ataques/receiver/README.md` §1) — y de él **depende la prueba de efecto** (el `sha256`
> del `sink.log`). El endpoint `/paste` es el `do_POST` **genérico** del receptor (sin código nuevo).
> Los paquetes GUI de Tanda B (Xvfb/xclip/xdotool/xinput) se instalan **offline** (`dpkg -i`) en la
> víctima; esa copia se pierde en el revert. El estado pre-steado del HOST se limpia al cerrar la tanda.
