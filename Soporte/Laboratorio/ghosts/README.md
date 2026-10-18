# GHOSTS — servidor + cliente (bloque `legitimo-infra`, L0)

> **GHOSTS** (CMU-SEI) es el simulador de usuarios (NPCs) que genera la **actividad legítima**
> con la que `L1` medirá las **falsas alarmas**. En L0 **solo se monta y se prueba** (no se
> miden ni las 72 h ni el FPR).

## 1. Versión fijada (el *pin*) y por qué

| Elemento | Valor |
|---|---|
| Proyecto | `github.com/cmu-sei/GHOSTS` |
| **Tag** | **`v8.3.1`** (2025-05-29) |
| **Commit** | **`4d2e160860f508f699f935472b5515358f534844`** |
| Framework | **.NET 8** (`net8.0`) en API y clientes |

**Motivo del *pin*:** GHOSTS **v9** exige **.NET 10** (no instalado en el host, que solo tiene
**SDK 8.0.403**); **v8.3.1** es **`net8.0`** → se compila con el SDK ya presente, **sin descargas
extra** (§7.3 del plan: *priorizar un pin compatible con .NET 8*).

> **Nota de fijación:** GHOSTS se fija por **tag/commit** (**`v8.3.1`** / **`4d2e1608…`**), no por
> `sha256` — el **`sha256` solo aplica a PostgreSQL** (ZIP de binarios); el código de GHOSTS queda
> *pinneado* por el **commit** del clon.

## 2. Qué corre dónde

| Componente | Dónde | Puerto | Notas |
|---|---|---|---|
| **PostgreSQL 16.15** (portable) | **HOST** | `127.0.0.1:5432` | **solo localhost**; no visible a la víctima |
| **GHOSTS API** (.NET 8) | **HOST** | **`192.168.65.1:5000`** | genera IDs, entrega *timelines*, recoge resultados |
| **Cliente GHOSTS (Linux)** — proyecto `src/ghosts.client.linux` | **`victima-linux`** `.129` | — | *self-contained* (no requiere .NET en la víctima) |
| **Cliente GHOSTS (Windows)** | `victima-windows` `.130` | — | **preparado, NO desplegado** (es `B1`) |

## 3. Material y *pre-staging*

Ver `prestaging_material.md` (**URL + tamaño + `sha256`**). El material vive **fuera del repo**
en `D:\TFG-VMs\material-ghosts\` (repo de GHOSTS clonado + `pgsql\` + `pgdata\` + `api\` +
`client-linux\`). **Sin secretos.**

## 4. Arranque / parada (HOST, PowerShell)

```powershell
powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\start_ghosts.ps1
powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\stop_ghosts.ps1
```

`start_ghosts.ps1` arranca PostgreSQL (127.0.0.1:5432) y la API (`192.168.65.1:5000`) con la
**cultura invariante** activada (`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`, ver §7).

## 5. Despliegue y control del cliente (víctima)

```powershell
# desde el HOST (config + scp + alias /etc/hosts)
powershell -ExecutionPolicy Bypass -File Soporte\Laboratorio\ghosts\deploy_client.ps1
```

En la víctima:

```bash
bash /home/angel/ghosts-client/client_ctl.sh start|stop|status|id|log
```

## 6. Entrega de timeline y contador de acciones

```powershell
# espera a que la máquina se registre y devuelve su id
python Soporte\Laboratorio\ghosts\ghosts_api.py wait victima-linux
# lista máquinas
python Soporte\Laboratorio\ghosts\ghosts_api.py list
# entrega una timeline DESDE EL SERVIDOR (Type=Timeline)
python Soporte\Laboratorio\ghosts\ghosts_api.py send-timeline victima-linux --timeline Soporte\Laboratorio\ghosts\timeline_smoke.json
```

**Contador de acciones (unidad del legítimo, §5.2):** cada handler ejecutado se reporta al
servidor y se persiste en la tabla **`history_timeline`** de PostgreSQL. Es **exportable**:

```powershell
# consulta directa
D:\TFG-VMs\material-ghosts\pgsql\bin\psql.exe -h 127.0.0.1 -p 5432 -U ghosts -d ghosts `
  -c "select handler, count(*) from history_timeline group by handler;"
# o vía API (actividad por máquina)
python Soporte\Laboratorio\ghosts\ghosts_api.py count
```

## 7. Adaptaciones locales declaradas (build propio)

El binario se construye **desde el fuente**; se aplican **dos ajustes locales mínimos**,
necesarios para que el servidor (Windows, locale es-ES) entienda lo que envía el cliente (Linux):

1. **`QueueSyncService.cs` (línea ~174):** el separador de líneas se cambia de
   `Environment.NewLine` (`\r\n` en Windows) a `{ "\r\n", "\n" }` para aceptar los saltos de
   línea **`\n`** que emite el cliente Linux. *(Sin esto, ninguna acción se persiste.)*
2. **Cultura de la API:** se arranca con `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` porque
   `QueueSyncService` sella la fecha del cliente con `Convert.ToDateTime` (formato en-US) y con
   la cultura del host (es-ES) **fallaba**.

Ambas quedan **declaradas**; no alteran el ruleset ni la detección.

## 8. Incidencias conocidas (a vigilar en `L1`)

- **Duplicado de máquina en el primer arranque:** el cliente lanza en paralelo el alta por
  SignalR y el primer sondeo de *updates*; ambas sin `ghosts-id` pueden crear **dos máquinas**
  con el mismo nombre. Se conserva la del `instance/id.json` y se **borra la sobrante** (se hizo
  así en L0). En `L1`, tras el primer arranque, **reconciliar**.
- **`sudo` de la víctima pide contraseña** (no hay `NOPASSWD`): `/etc/hosts` se modifica con la
  contraseña **por STDIN**, nunca en fichero.
- El **manager de Wazuh** puede quedar **`failed`** tras encender la VM → `systemctl restart
  wazuh-manager` (higiene conocida, `state.md`).

## 9. Referencias

- Plan del bloque: `plan.md` §3, §5, §7.
- "Internet local": `Soporte/Laboratorio/internet_local/README.md`.
- Denominador `M`: `Soporte/Laboratorio/instrumentacion_denominador.md`.
- Decisión: `Soporte/Laboratorio/ghosts/decision_gonogo.md`.
