# C0 Windows — clases de evento (B1.0)

> **Dry run, no ataque.** Ejecutado el **2026-11-08** en `victima-windows` (snapshot
> `lab-listo-windows-baseline`), con el agente `002` activo y el manager `wazuh-server`.
> Ventana de medida: **16:15:00Z–16:21:30Z** (incluye el barrido FIM forzado de registro).
> La tabla `clases_evento.csv` se deriva de las alertas del manager
> (`extraer_alertas_windows.py`) y del registro local del invitado.

## 1. Qué se provocó (una vez por clase)

| Clase | Acción | Resultado |
|---|---|---|
| Sysmon 1 | `cmd /c echo C0-Sysmon1` + PowerShell | **alerta** (92029/92033/92039/92004/92027/92052) |
| Sysmon 3 | `TcpClient` a `192.168.65.128:1514` | evento local **sí**, alerta **no** (185001 nivel 0) |
| Sysmon 11 | `Set-Content C:\lab-attack\c0_sysmon11.txt` | **alerta** (92213/92200) |
| Sysmon 23 | crear + borrar `c0_sysmon23.txt` | evento local **no** (config actual) |
| 4688 | proceso hijo de `cmd.exe` | **alerta** (67027) |
| 4104 | `Write-Output 'C0-4104'` | **alerta** (91818) |
| FIM fichero | crear/modificar/borrar en `C:\lab-attack` | **alerta** (554/553) |
| FIM registro | valor en `HKLM\...\Run` + `agent_control -r -u 002` | **alerta** (598/752/594/750 + 91844) |
| 7045 | `New-Service TFG-C0-Svc` | **alerta** (61138) |
| 7036 | stop/start de `Spooler` | evento local **no** (0 en System) |
| 4698/106 | `schtasks /create` + `/delete` | evento local **no** (política de auditoría) |
| 4720/4726 | `net user tfg_c0_tmp ... /add` + `/delete` | **alerta** (60109/60111) |
| 1074 | `shutdown /r /t 600 /f` + `shutdown /a` | **alerta** (67018) |

## 2. Puntos ciegos declarados

1. **Sysmon 3 genérico**: el evento se genera, pero no hay regla que alerte una conexión
   arbitraria (la base es nivel 0). Solo alertan patrones específicos (p. ej. 92104).
2. **Sysmon 23**: la config Sysmon actual no registra FileDelete archivado.
3. **7036**: no se observaron eventos 7036 en el log System tras stop/start de Spooler.
4. **4698/106**: la política de auditoría no genera la creación de tareas; el caso T1029
   (ATA079) se apoyará en `4688`/Sysmon 1 (`schtasks.exe`).
5. **FIM de registro**: no es realtime; solo aparece tras un barrido forzado
   (`agent_control -r -u 002`). En una ventana de ataque hay que forzarlo o esperar al ciclo.
6. **Huella del canal**: cada `vmrun runProgramInGuest` genera logon/logoff/privilegios
   (`4624/4634/4672`) que el manager alerta como `67022/67023/67028` (nivel 3). **No están
   en el catálogo baseline v1**. Con `auto_ruido` vacío contarían como `novel` en B1.1; es
   un riesgo abierto para el gate G-B1.0. **Resuelto en B1.0-SSH.1**: el canal pasa a **SSH**
   y su huella es `60106/60137/67024/67023/67028` (tipo 3/5); ver `canal_ssh.csv` y
   `../Laboratorio/windows/ataques/B1.0-SSH.md`.

## 3. Limpieza

Se borraron `TFG-C0-Svc`, `TFG-C0-Task`, `tfg_c0_tmp`, el valor `TFG-C0-Reg` y los ficheros
`C:\lab-attack\c0_*`. `C:\lab-attack` quedó vacío. La VM se revirtió después a
`lab-listo-windows-baseline` y el snapshot final `lab-listo-windows-ataques` se creó sin
estos artefactos.

## 4. Reproducción

```powershell
python _artefactos/scripts/extraer_alertas_windows.py --alerts <ossec-alerts-DD.json> `
  --desde 2026-11-08T16:15:00Z --hasta 2026-11-08T16:21:30Z `
  --agent-id 002 --detail c0_detalle.csv --out c0_agregado.csv
```

La tabla `clases_evento.csv` se construye a mano a partir de `c0_detalle.csv` y del registro
local (no se inventan `rule_id`; las clases sin alerta se marcan `NO`).

## 5. Archivo de los productos (B-2, 2026-11-08)

| Fichero | Filas | `sha256` |
|---|---|---|
| `c0_detalle.csv` | 759 alertas (agente `002`, ventana `16:15:00Z–16:21:30Z`) | `2241E44ECC702197D268AA84D0694268E233CE06BAB6AA2AA81621C8E46986C7` |
| `c0_agregado.csv` | 36 `rule_id` (`rs_origen=RS1`) | `2BFE4B78570A67EBDCEF0BA151490F70D46048574215CE220F216BFB214A3A68` |

> Regenerados con el extractor actual (27 columnas) **en el manager**, con el ruleset
> disponible (`unknown=0`). La ventana y el comando son los de §4.

## 6. Huella del canal SSH (B1.0-SSH.1)

| Fichero | Contenido | `sha256` |
|---|---|---|
| `canal_ssh.csv` | huella del canal: `rule_id,level,event_id,srcip,win_user,logon_type,win_parent_image` (45 filas) | `7A88A8AC2CCBA718F8CC221CF3173BC46E82F358995CABB392A3AA23EAFBD6DC` |
| `canal_ssh_detalle.csv` | detalle completo (todas las columnas) de esas 45 filas | `03C02EFF43787B00196E2335E4CF5C5D80E1CC2F253D2C6EB1C91A4DAE0AAC40` |

- Ventana: `2026-11-08T17:26:50Z–17:28:30Z` (dry run de **5 invocaciones** SSH;
  **45 = 5 × 9 alertas**).
- Reglas: `60106/60137` (4624/4634 tipo 3, `angel`), `67024/67023` (tipo 5,
  `sshd_<pid>`), `67028` (4672) y `67027` con imagen `sshd.exe`.
- **`srcip` vacío**: el `4624` de SSH trae `Source Network Address: -`; **no** hay
  `ipAddress`. El predicado `OPERADOR_WIN` es por **usuario + regla + `logon_type`**
  (`politica_filtrado_ruido.md` §9.6).
- Prueba: con predicado **0 `deteccion`**; con `--sin-operador` **30**.
  El `esperado` sintético usado está en `canal_esperado_sintetico.csv` (declara
  `rule_id=67027`, como cada caso; no es el `esperado` de ningún ataque).
