# C0 · pre-flight base-contra-base — ATA038 · T1529 (systemctl: shutdown/reboot)

> **Estado: EJECUTADO** (antes del primer `t0` de ATA038).
> **No contiene secretos:** la contraseña de `sudo` se pasa por `stdin` en el momento de ejecutar.

## Objetivo

Descubrir **silenciadores de fábrica** del ruleset base: un comando clave cuyo `execve` **no**
alerta porque una regla **hermana** de nivel 0 lo suprime. **No** se escriben reglas propias (D5).

## Comandos clave

`shutdown -r` / `reboot` (**enlaces a `/usr/bin/systemctl`**; el `execve` registra el binario real).

## Pasos (con las VMs encendidas)

**1. Capturar la línea de audit REAL en la víctima** (root solo para leer el log): se ejecutó
`systemctl --version` (benigno) y se volcó su evento.

**2. Ejecutar `wazuh-logtest -v` en el manager** y **3.** guardar en
`Soporte/Ataques/c0/ATA038_logtest.txt`; **4.** generar el informe con
`preflight_enmascaramiento.py --logtest-base-c0 Soporte/Ataques/c0/ATA038_logtest.txt`
→ `ATA038_preflight.md`.

## Resultado (ejecutado)

- 1 evento analizado; ganadora **`80792`** (*Audit: Command: /usr/bin/systemctl*),
  **`level 3` → SÍ avisa**.
- **Sin silenciador.** → PASA (`ATA038_preflight.md`).
- **Capa adicional (no en el C0, sí en la ventana):** las reglas de **estado del agente**
  (`503`/`504`) son `novel` (fuera del catálogo) y **se declaran** en el `esperado`. El
  `juornald`/`systemd` (`40700`) es `level=0` → **no** alerta por un apagado normal (hallazgo ya
  documentado en ATA004).

## Si aparece un silenciador

Se **documenta** y la detección se declara por el `rule_id` del `execve`; **no** se escriben reglas
RS3 (D5).
