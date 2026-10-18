# Pre-staging del material — GHOSTS (bloque `legitimo-infra`, L0)

> **Sidecar de fijación del material** (los **binarios no entran al repo**; solo este
> sidecar con **URL + tamaño + `sha256`**). Material descargado por el humano/ejecutor **con
> NAT on en el host** y guardado **fuera del repo** en **`D:\TFG-VMs\material-ghosts\`**.
> **Sin secretos.**

---

## 1. Ficheros fijados

| Material | URL oficial | Tamaño (bytes) | `sha256` |
|---|---|---|---|
| **GHOSTS** (código fuente, tag **`v8.3.1`**, commit `4d2e160860f508f699f935472b5515358f534844`) | `https://github.com/cmu-sei/GHOSTS.git` | *(clon git)* | *(pin por commit, no por hash de fichero)* |
| **PostgreSQL 16.15** — binarios Windows x86-64 (EDB) | `https://get.enterprisedb.com/postgresql/postgresql-16.15-1-windows-x64-binaries.zip` | `332 441 502` | `25E6FCDFB8CAEC38691BF461125E7564508760666F7B8E5DC6A5F0818F58F81E` |

### Dependencias ya presentes en el host (no se descargan)

| Elemento | Versión | Comprobación |
|---|---|---|
| **.NET SDK** | `8.0.403` | `dotnet --list-sdks` |
| **Python** | `3.13.3` | `python --version` |
| **git** | `2.55.0.windows.5` | `git --version` |

> **Por qué no se descarga .NET:** el *pin* elegido (**v8.3.1**) es **`net8.0`**; el SDK 8 ya
> instalado basta. **No** se necesita .NET 10 (que exigiría GHOSTS v9).

---

## 2. Artefactos construidos en el host (a partir del *pin*)

| Artefacto | Comando | Destino |
|---|---|---|
| **Cliente Linux self-contained** | `dotnet publish src/ghosts.client.linux/ghosts.client.linux.csproj -c Release -r linux-x64 --self-contained true` | `D:\TFG-VMs\material-ghosts\client-linux\` → `victima-linux:/home/angel/ghosts-client/` |
| **API (framework-dependent, win-x64)** | `dotnet publish src/Ghosts.Api/ghosts.api.csproj -c Release -r win-x64 --self-contained false` | `D:\TFG-VMs\material-ghosts\api\` |
| **PostgreSQL (portable)** | `initdb -D pgdata -U ghosts -A trust -E UTF8` | `D:\TFG-VMs\material-ghosts\pgsql\` + `pgdata\` |

> El cliente se publica **self-contained**: la víctima **no** necesita .NET ni NAT.

---

## 3. Cómo se fijó

- `sha256` del ZIP de PostgreSQL: `Get-FileHash <fichero> -Algorithm SHA256` (host, 2026-10-18).
- El *pin* de GHOSTS es el **tag/commit** (`v8.3.1` / `4d2e1608…`), estable y auditable.
- **Adaptaciones locales declaradas** (build propio): ver `README.md` §7
  (`QueueSyncService` newline + cultura invariante).
