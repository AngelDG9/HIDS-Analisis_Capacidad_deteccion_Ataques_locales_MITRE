# Telemetría de Windows — capas y mapa capa→técnica (D4)

> **Entregable E3 del bloque `fase-02b-diseno`.** Diseño de la telemetría que sustituye a
> `auditd` en Windows. **No se ha configurado nada**: es el diseño que implementa
> `fase-02b-construccion`. Fuente: `plan.md` D4.

---

## 1. Capas (el "sustituto de `auditd`")

En Linux la capa que decide es **`audit`** (`execve`/`watch`) → reglas `807xx` (RS2) y
campos `data.audit.*`. En Windows **no hay `auditd`**: la telemetría es **registro de
eventos** + **FIM/Syscheck** + **registro**.

| Capa | Qué aporta | Canal / cómo se recoge | Reglas Wazuh (RS1) |
|---|---|---|---|
| **Sysmon** (config curada) | Process Create (1), Network (3), File Create (11)/Delete (23), Registry (12/13/14), ProcessAccess (10), ImageLoad (7) | Binario Sysmon + `sysmonconfig.xml`; el agente lee `Microsoft-Windows-Sysmon/Operational` | `0330-sysmon` (184665+), `0800`–`0870-sysmon_id_*` |
| **Registro de Seguridad** | `4688` creación de proceso (con línea de comandos), `4624/4625` logon, `7045` servicio, cuentas | Canal `Security` vía `<localfile><log_format>eventchannel</log_format>` | `0580-win-security` (60100–60232) |
| **PowerShell 4104** | Script Block Logging | GPO + canal `Microsoft-Windows-PowerShell/Operational` | `0915-win-powershell` (91801–91846) |
| **Syscheck / FIM** | Ficheros y **claves de registro** vigiladas | `<syscheck>` del agente (espejo del de Linux) | `550`–`559` (FIM base) |
| **Sysmon 12/13/14 + FIM de registro** | Modificación de claves (persistencia, T1490) | Sysmon / eventchannel | `0860-sysmon_id_13` |
| **Estado del agente** | Conexión/desconexión (equivale a `503`/`506`) | Reglas internas Wazuh | interno |

> **Sysmon sin filtro genera muchísimo evento** → exige **config curada + baseline**
> (riesgo `roadmap.md:160`). La config por defecto **no vale**.

---

## 2. Mapa capa → técnica (borrador del corpus)

> **Borrador de diseño**, a ratificar con el inventario final
> (`Hojas/inventario_p1_windows.csv`) y con la práctica. La columna *Data Component* sigue
> el criterio §B de `Soporte/Ataques/criterio_ataques.md`.

| Técnica (P1) | Táctica | Capa principal que la vería |
|---|---|---|
| T1486 / T1485 / T1561 | Impact | Sysmon 1/11/23 + Seguridad 4688 + FIM (ficheros) |
| T1490 | Impact | Sysmon 1 (proceso) + Seguridad 4688 + FIM/registro |
| T1489 | Impact | Seguridad 7045/4688 + Sysmon 1 |
| T1491 | Impact | FIM (ficheros) + Sysmon 11 |
| T1529 | Impact | Estado del agente + Sysmon 1 |
| T1531 | Impact | Seguridad (cuentas) + Sysmon 1 |
| T1041 / T1048 / T1567 | Exfiltration | Sysmon 3 (red) + Sysmon 1 (proceso) |
| T1005 / T1039 / T1074 / T1119 | Collection | Sysmon 1 + FIM + PowerShell 4104 |
| T1056 / T1056.001–.004 | Collection / Cred. Access | Sysmon 1/10 + PowerShell 4104 |
| T1113 / T1115 / T1123 / T1125 | Collection | Sysmon 1 + ProcessAccess (10) |
| T1560 / T1565 | Collection / Impact | Sysmon 1/11 + FIM |

> **Advertencia de honestidad:** es un **borrador**. La asignación definitiva se valida
> técnica a técnica al construir `ATTACK_ROOT` y el perfil de campos (D6), y se declara por
> técnica en su `esperado` (nunca se supone).

---

## 3. Campos de telemetría (esquema normalizado)

En Linux: `data.audit.{exe,cwd,key,file,…}` y `syscheck.path`. En Windows, el perfil
(D6.1) normaliza a `data.win.*`:

```text
win_image, win_parent_image, win_command_line, win_cwd, win_target, win_user
```

- `win_image` ≈ Sysmon 1 `Image` / Seg. 4688 `NewProcessName`.
- `win_command_line` ≈ Sysmon 1 / Seg. 4688 (requiere **4688 con línea de comandos**).
- `win_target` ≈ fichero / clave objetivo (FileCreate, Registry).
- La **convención H4** (ancla `exe` ∧ `cwd`) migra a `win_image` ∧ `win_cwd`.

---

## 4. Referencias

- Plan D4 / D6: `plan.md`.
- Reglas Windows activas: `Soporte/Wazuh/Configuracion/active_ruleset.txt`.
- Plantilla de señales: `Soporte/Ataques/plantilla_esperado.md`.
- Filtro: `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`.
