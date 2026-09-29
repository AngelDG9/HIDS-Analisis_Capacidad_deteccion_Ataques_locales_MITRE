# C0 · pre-flight base-contra-base — ATA030 · T1560.001 (tar, gzip)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA030).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`tar` y `gzip` (la **utilidad de archivado** y su compresor).

## Pasos (con las VMs encendidas)

**1. Capturar las líneas de audit REALES en la víctima** (root solo para leer el log):
se ejecutaron `tar --version` y `gzip --version` (benignos) y se volcó su línea de `audit(…)`.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA030_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA030_logtest.txt`
→ `ATA030_preflight.md`.

## Resultado (ejecutado)

- 2 eventos analizados; ganadora **`80792`** (*Audit: Command: /usr/bin/tar* y */usr/bin/gzip*),
  **`level 3` → SÍ avisan**.
- **Sin silenciador.**
- **RESULTADO: PASA** (`ATA030_preflight.md`).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
