# Procedimiento por ventana — ataques Windows (B1.1+)

> **Runbook operativo** (B-2). Una **iteración = una ventana `[t0,t1]`** desde un snapshot
> limpio. **Sin secretos**: la contraseña y la clave privada viven fuera del repo. El canal
> es **SSH** (`lab-listo-windows-ataques-ssh`) salvo ATA071/072/073 (**S1**,
> `lab-listo-windows-ataques-gui`).

---

## 0. Antes de empezar (checklist de 10 puntos)

| # | Comprobación | Cómo |
|---|---|---|
| 1 | `victima-linux` **apagada** | `vmrun -T ws list` |
| 2 | Manager `wazuh-server` **encendido** | ídem |
| 3 | Agente `002` **Active** | `sudo /var/ossec/bin/agent_control -l` (manager) |
| 4 | Snapshot del canal **elegido** (`-ssh` o `-gui`) | `vmrun listSnapshots` |
| 5 | `C:\lab-attack` **vacío** | `dir C:\lab-attack` |
| 6 | **0** tareas `TFG-*` (salvo la del caso S1, creada antes de `t0`) | `schtasks /query` |
| 7 | NAT **off** (`default_route=0`) | `Get-NetRoute` |
| 8 | `Sysmon64`/`WazuhSvc` **Running**; Defender **Stopped** | `Get-Service` |
| 9 | Hora UTC invitado/host Δ ≤ 2 s | `Get-Date` vs host |
| 10 | Servicios del host (si el caso los usa) **arriba** | `arrancar_servicios_host.py status` |

## 1. Secuencia de una iteración

```text
revert <snapshot del canal>          # -ssh (normal) o -gui (S1)
start nogui
esperar agente 002 Active + 90 s     # t0 >= 90 s tras Active
[fuera de [t0,t1]] copiar C:\lab-attack\ATA<NNN>\ con scp
[fuera de [t0,t1]] pre-staging del caso (si aplica)
t0  ← marca UTC (invitado y host)
lanzar:
  SSH:  ssh -i <clave> -o BatchMode=yes angel@192.168.65.130 "cmd /c C:\lab-attack\ATA<NNN>\run.cmd"
  S1:   tarea TFG-Attack-<ATA> (InteractiveToken, disparo t0+30 s) — creada antes de t0
[t0,t1] ataque (<= 120 s)
t1  ← marca UTC
si el caso lo exige: agent_control -r -u 002 (FIM de registro)
cosechar: scp -r angel@192.168.65.130:C:/lab-attack/ATA<NNN>/evidencias ./Logs/ATA<NNN>_iterN/
stop soft / revert
```

## 2. Reglas duras

1. **Una ventana, un caso.** Nada de ataques en paralelo; `victima-linux` apagada.
2. **`t0 ≥ 90 s` tras `Active`** (deja fuera el ruido de arranque y el autologon de S1).
3. **El canal no es ataque**: una invocación SSH deja `60106/60137/67024/67023/67028` +
   `sshd.exe`; el filtro los resuelve como `operador`/`auto_ruido` (0 `deteccion`). Los
   **hijos** de `sshd.exe` (el `run.cmd`/`powershell` del ataque) **no** se excluyen: se
   atribuyen por `C:\lab-attack\ATA<NNN>`.
4. **Nada del ataque en `ruido`**: el guardarraíl del filtro lo impide; una fila del ataque
   que no case una señal va a `artefacto_ataque` o `dudosa`, nunca a `ruido_conocido`.
5. **FIM de registro** (ATA063): forzar `agent_control -r -u 002` **antes de `t1`** o esperar
   el ciclo; no es realtime.
6. **Sin secretos**: la clave privada y las contraseñas no se escriben en el repo ni en logs.
7. **Cierre**: revert al snapshot, `stop soft`, servicios del host parados, `TFG_GUEST_PW`
   borrada.

## 3. S1 — casos interactivos (ATA071/072/073)

- Snapshot **`lab-listo-windows-ataques-gui`**: `angel` entra por **autologon** (sesión 1).
- La tarea `TFG-Attack-<ATA>` se crea **antes de `t0`** con `InteractiveToken` y se dispara
  a `t0 + 30 s`; el único proceso del canal dentro de la ventana es el del ataque.
- El autologon genera un `4624` tipo 2 **al arrancar** (fuera de `[t0,t1]`). Se mide en el
  C0 y se declara; si el agente no lo reenvía (ocurrió el 2026-11-08), también se declara.

## 4. Cosecha y verificación

- `scp -r` de `C:\lab-attack\ATA<NNN>\evidencias` a `Logs/ATA<NNN>_iterN/`.
- Extraer alertas: `extraer_alertas_windows.py --alerts <diario> --desde t0 --hasta t1
  --agent-id 002 --detail ...-Audited.csv`.
- Filtrar: `filtrar_ruido_windows.py --alerta ... --ata ATA<NNN> --esperado ...`.
- Sensibilidad: repetir con `--sin-operador` y guardar `..._sens_sin_operador`.
- Comprobar: **0** filas del ataque en `ruido_conocido`; **0** `dudosa` sin revisar;
  **0** `deteccion` que sean solo canal.

## 5. Referencias

- Canal y evidencia: `B1.0-SSH.md`; bóveda: `boveda_v3.md`.
- Servicios del host: `servicios_host.md` + `_artefactos/scripts/arrancar_servicios_host.py`.
- Criterio de doble iteración: `Soporte/Ataques/criterio_doble_iteracion.md`.
- Plan: `plan.md` §6.5 y §9.
