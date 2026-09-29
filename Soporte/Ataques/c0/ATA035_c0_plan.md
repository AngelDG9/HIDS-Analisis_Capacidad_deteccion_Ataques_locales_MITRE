# C0 · pre-flight base-contra-base — ATA035 · T1056.004 (base64, credfetch)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA035).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`base64` (materializa el payload `.b64`) y el binario **de laboratorio** `credfetch` (el proceso
con el hook `LD_PRELOAD`). Control: se probó una copia de un binario **bajo `lab-attack`** para
confirmar que un `execve` de esa ruta alerta.

## Pasos (con las VMs encendidas)

**1. Capturar las líneas de audit REALES en la víctima** (root solo para leer el log): se
ejecutaron `base64 --version` y el stand-in `…/ATA035/credfetch_c0` (benignos) y se volcaron sus
eventos.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA035_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA035_logtest.txt`
→ `ATA035_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (*Audit: Command: /usr/bin/base64* y
  */home/angel/lab-attack/ATA035/credfetch_c0*), **`level 3` → SÍ avisan**.
- **Sin silenciador.** → PASA (`ATA035_preflight.md`).
- **Punto ciego declarado:** la **carga del módulo** (`LD_PRELOAD`) y la **intercepción** de la API
  **no** generan evento propio (audit no audita env ni cargas de `.so`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
