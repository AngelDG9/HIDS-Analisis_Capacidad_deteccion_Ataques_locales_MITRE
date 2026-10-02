# ATA051 · T1113 — Screen Capture (`xwd` sobre display virtual Xvfb, ART adaptado)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda B** (3.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA051** |
| Técnica | **T1113 — Screen Capture** |
| Táctica | Collection |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **ART adaptado** (atómica Linux `xwd`, guid `8206dd0c…`; se omite el visor interactivo con timeout) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** captura la **pantalla completa** del display virtual `:99` con **`xwd`**
  (`xwd -root -out captura_pantalla.xwd`), el mismo binario que usa la atómica Linux de ART;
  opcionalmente la **revisa** con `xwud` (bajo `timeout` defensivo).
- **Display:** **`Xvfb :99`** (servidor X **sintético** sin usuario real; pre-steado antes de `t0`).
- **Capa del HIDS que ejercita:** **`execve`** (`xwd`, `80792`). La **prueba de efecto** es el
  fichero `.xwd` válido (cabecera XWD, tamaño > 0) con su `sha256`.

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramienta | `xwd`, `xwud` (paquete **x11-apps**), `Xvfb` (paquete **xvfb**) |
| Dependencias | **pre-steadas offline** (paquetes `.deb` fijados URL+`sha256`, §5.1 del plan) |
| Elevación | **`sudo`** SOLO para `dpkg -i` de los paquetes **antes de `t0`** (fuera de la ventana) |
| Guardarraíl | display `:99` **sintético**; Xvfb **matado** por ventana; sin cambios persistentes |

## 4. Cómo se ejecuta

1. (Tras revert a `lab-listo`) `scp` del directorio de la técnica + el directorio de `.deb` a
   `/home/angel/lab-attack/ATA051/` y `/home/angel/lab-legit/tandaB_debs/`.
2. **Pre-staging** (`ATA051_prestaging.sh`): `dpkg -i` offline + arranque de `Xvfb :99`.
3. `cd /home/angel/lab-attack/ATA051 && bash ATA051_ataque.sh 2>&1 | tee ejecucion.out`.
4. Tras `t1`: matar `Xvfb`/`xeyes`. El revert a `lab-listo` lo elimina todo.

## 5. Señales esperadas (convención H4)

`ATA051_esperado.csv` (todas `deteccion`):

- `T1113-S1` `audit_exe=xwd` (`80792`) — captura de pantalla.
- `T1113-S2` `audit_exe=xwud` (`80792`) — revisión interactiva de la captura (ART).
- `T1113-S3` `audit_cwd=/home/angel/lab-attack/ATA051/*` — ancla H4.

## 6. Prueba de éxito (independiente de la alerta)

`captura_pantalla.xwd` existe, **tamaño > 0** y **cabecera XWD** válida (`00 00 00 6b 00 00 00 07`);
su `sha256` queda en `Logs/ATA051_iter*/`. Evidencia independiente de la alerta.

## 7. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** `Xvfb`/`xeyes` matados; paquetes y captura desaparecen con el revert; **sin NAT**.

## 8. Alcance y limitación declarada (realismo acotado)

> **La técnica y el binario (`xwd`) son reales; la pantalla es sintética (Xvfb).** El entorno no
> tiene usuario real ni escritorio; la captura es de un display **virtual** declarado. El
> mecanismo (herramienta real + `execve` + fichero de captura) **sí** se ejercita.

> **Nota de arquitectura (servicio local).** El receptor `sink_http.py` se levanta en el **HOST**
> (`192.168.65.1`, VMnet1), **fuera de las dos VMs** — igual que en el piloto
> (`Soporte/Ataques/receiver/README.md` §1) — y de él **depende la prueba de efecto** (el `sha256`
> del `sink.log`). El endpoint `/paste` es el `do_POST` **genérico** del receptor (sin código nuevo).
> Los paquetes GUI de Tanda B (Xvfb/xclip/xdotool/xinput) se instalan **offline** (`dpkg -i`) en la
> víctima; esa copia se pierde en el revert. El estado pre-steado del HOST se limpia al cerrar la tanda.
