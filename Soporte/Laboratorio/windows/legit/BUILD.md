# BUILD.md — cliente Windows de GHOSTS (T1 de `plan_w3bis.md` v2)

> **ESTADO: COMPILADO ✅** — `Ghosts.Domain.dll` = `8.2.0.0` / **`8.2.7.90`** (discriminador,
> distinto del publicado `8.2.1.0`); `ghosts.exe` = `8.2.2.0` / `8.0.0.0`; arranca y responde
> `--help` y `--version` con código de salida 0.
>
> **Método:** SDK de .NET 8 ya instalado + *reference assemblies* **oficiales** de Microsoft
> desde NuGet. **No** se ha instalado Visual Studio, Build Tools ni nada con permisos de
> administrador.

| Campo | Valor |
|---|---|
| Fecha (UTC) | 2026-11-10 |
| Tanda | T1 (plan `_fases/windows-legit-prep/plan_w3bis.md` v2, `approved_by_human`) |
| Resultado | **Compilado** (CA-W3b-01) |
| Tiempo de la tanda | ~1 h 05 min (tope 2,5 h) |
| Máquina de compilación | host Windows del laboratorio (el que aloja VMware) |

---

## 1. Procedencia del código — verificada

Clon: `D:\TFG-VMs\material-ghosts\GHOSTS`

| Comprobación | Comando | Salida literal |
|---|---|---|
| Commit | `git rev-parse HEAD` | `4d2e160860f508f699f935472b5515358f534844` |
| Tag | `git describe --tags` | `v8.3.1` |
| Remoto | `git remote -v` | `origin https://github.com/cmu-sei/GHOSTS.git (fetch)` / `(push)` |
| Solución compilada | `src\ghosts.windows.sln` | `Ghosts.Domain` + `Ghosts.Client` |

El commit y el tag coinciden **exactamente** con los exigidos por el plan. La compilación se
hizo **desde ese árbol, sin modificar una sola línea de código**.

### 1.1 Estado del clon tras la compilación

```
$ git status --porcelain
 M src/Ghosts.Api/Infrastructure/Services/QueueSyncService.cs
```

- Es una modificación **preexistente** (mtime `2026-10-18 19:55:25`), anterior a esta tanda.
  **No se ha revertido** (decisión del orquestador: puede ser un cambio intencionado de otra fase).
- **No pertenece a la solución compilada**: `src\ghosts.windows.sln` contiene únicamente
  `Ghosts.Domain` y `Ghosts.Client`; `Ghosts.Api` no aparece en ella.
- **No entra en el binario**: no hay ninguna referencia a `Ghosts.Api` en `Ghosts.Client.csproj`
  ni en `Ghosts.Domain.csproj`, y el proyecto no se compila.
- `bin/`, `obj/` y `packages/` están cubiertos por `.gitignore`: no ensucian el estado.
  Con `--ignored` se ven como `!!` (artefactos de compilación, no fuente).

**Conclusión:** el clon no ha ganado ficheros versionables; el único cambio visible sigue siendo
el preexistente y ajeno al cliente Windows. Se declara aquí para CA-W3b-01 (criterio «clon solo
`bin/obj/packages`»).

---

## 2. Toolchain

| Pieza | Versión | Origen |
|---|---|---|
| .NET SDK | **8.0.403** | ya instalado en el host |
| MSBuild | **17.11.9.46202** (`dotnet msbuild -version`) | incluido en el SDK — cumple «MSBuild ≥ 17» |
| Roslyn / C# | el del SDK 8 (C# 12), `LangVersion=preview` del proyecto | — |
| *Reference assemblies* .NET Framework **4.6.2** | paquete **`Microsoft.NETFramework.ReferenceAssemblies.net462` 1.0.3** | NuGet oficial (ver §3) |
| Visual Studio / Build Tools | **no instalados** (no se han instalado) | — |
| `nuget.exe` | **no usado** | `dotnet restore` basta |

### 2.1 Corrección al paso B-1 del plan

El plan preveía «VS Build Tools 2022 + targeting pack 4.6.2 (+4.8) + `nuget.exe`» (45-90 min).
**No hace falta**: el MSBuild del SDK 8 compila el proyecto legacy en cuanto dispone de las
*reference assemblies* y de la resolución de `PackageReference`. Lo único que faltaba era lo
primero. `dotnet restore` sustituye a `nuget restore` (los 183 paquetes se resuelven por
`PackageReference`; el `packages.config` del proyecto es legado y **no** se usa).

---

## 3. Reference assemblies: paquete oficial (solo metadatos)

| Campo | Valor |
|---|---|
| Paquete | `Microsoft.NETFramework.ReferenceAssemblies.net462` |
| Versión | **1.0.3** |
| Origen | `https://api.nuget.org/v3-flatcontainer/…/microsoft.netframework.referenceassemblies.net462.1.0.3.nupkg` |
| `id` / `version` (nuspec) | `Microsoft.NETFramework.ReferenceAssemblies.net462` / `1.0.3` |
| `authors` / `owners` | **Microsoft** / **Microsoft** |
| `projectUrl` | `https://github.com/Microsoft/dotnet/tree/master/releases/reference-assemblies` |
| `copyright` | © Microsoft Corporation |
| Firma PKCS#7 (`.signature.p7s`) | **CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US** |
| Tamaño | 19.902.484 B |
| **`sha256`** | **`EE692A845743500910855D4C330CA6E9EF87C16E16F740E4474D187185D66E21`** |
| Desplegado en | `build-v8.3.1\refasm\` |

**Qué es y qué no es:** son **ensamblados de referencia** (solo metadatos: firmas, sin IL).
No se ejecutan, no se despliegan y **no alteran el IL generado**: el compilador los usa como
contrato de la API de .NET Framework 4.6.2, igual que haría el *targeting pack* de Visual
Studio. El binario resultante se ejecuta contra el .NET Framework del sistema, no contra estos
ficheros.

---

## 4. Comando exacto de compilación

```powershell
# 0) rutas (todo FUERA del repo)
$out = "D:\TFG-VMs\material-ghosts\client-windows\build-v8.3.1"
$sdk = "C:\Program Files\dotnet\sdk\8.0.403"

# 1) paquete oficial de reference assemblies (descargado y verificado en §3)
#    descomprimido en $out\refasm\

# 2) restore de los dos proyectos (idempotente; 183 paquetes)
cd D:\TFG-VMs\material-ghosts\GHOSTS
dotnet restore src\ghosts.windows.sln

# 3) compilación Release x64
$env:TfgRefAsmTargets   = "$out\refasm\build\Microsoft.NETFramework.ReferenceAssemblies.net462.targets"
$env:TfgConflictTargets = "$sdk\Sdks\Microsoft.NET.Sdk\targets\Microsoft.NET.ConflictResolution.targets"
$env:TfgPkgDepTargets   = "$sdk\Sdks\Microsoft.NET.Sdk\targets\Microsoft.PackageDependencyResolution.targets"

dotnet msbuild src\Ghosts.Client\Ghosts.Client.csproj `
  /p:Configuration=Release /p:Platform=x64 `
  /p:CustomAfterMicrosoftCommonTargets="$out\build-hooks.targets" `
  /p:MicrosoftNETBuildTasksAssembly="$sdk\Sdks\Microsoft.NET.Sdk\tools\net8.0\Microsoft.NET.Build.Tasks.dll" `
  /v:m
```

Salida: `src\Ghosts.Client\bin\x64\Release\` → `ghosts.exe`, `Ghosts.Domain.dll` y 279 ficheros más.

### 4.1 Por qué hay un `build-hooks.targets` (y por qué no toca el código)

`Ghosts.Client.csproj` es un proyecto **legacy** (`ToolsVersion=15.0`, `TargetFrameworkVersion=v4.6.2`),
no SDK-style. Consecuencia: no importa `Microsoft.PackageDependencyResolution.targets`, así que
los 183 paquetes restaurados **no llegaban al compilador** (fallaban `Logger`, `CimSession`,
`IWebDriver`, `Option`, los interop de Office…). Visual Studio lo resuelve con sus propios
targets; el SDK de .NET necesita que se le indiquen.

`build-hooks.targets` (3,0 KB, **fuera del repo**) se inyecta con el punto de extensión oficial
`/p:CustomAfterMicrosoftCommonTargets` y **solo actúa sobre `Ghosts.Client`**:

1. importa las *reference assemblies* oficiales de 4.6.2 (fijan `TargetFrameworkRootPath` a
   `refasm\build`, `NoStdLib` y `mscorlib`);
2. importa `Microsoft.NET.ConflictResolution.targets` y
   `Microsoft.PackageDependencyResolution.targets` del SDK;
3. declara **no-op** cinco targets exclusivos de netcoreapp que esos ficheros esperan
   (`ProcessFrameworkReferences`, `_DefaultMicrosoftNETPlatformLibrary`,
   `_ComputePackageReferencePublish`, `ResolveRuntimePackAssets`, `ResolveTargetingPackAssets`)
   y fija `TargetFramework=net462`, `DefaultImplicitPackages` y
   `_DotNetAppHostExecutableNameWithoutExtension`, que el proyecto legacy no declara.

**No se ha modificado ningún fichero del proyecto ni del repositorio.** El hook es
equivalente a lo que aporta Visual Studio; el código compilado es el del tag, byte a byte.

---

## 5. Resultado: versiones y `sha256`

Salida staged en `build-v8.3.1\client\` (**281 ficheros**), con `MANIFEST.sha256` de todos ellos.

| Binario | Bytes | AssemblyVersion | FileVersion | ProductVersion | **`sha256`** |
|---|---|---|---|---|---|
| **`ghosts.exe`** | 374.272 | `8.0.0.0` | **`8.2.2.0`** | **`8.0.0.0`** | `b0c5d33b9a20f8ee77a962f40f3dcd89c59f3dec33f6927249c9d18cefe44dec` |
| **`Ghosts.Domain.dll`** | 77.824 | **`8.2.0.0`** | **`8.2.7.90`** | `1.0.0+4d2e160860f508f699f935472b5515358f534844` | `e305cf2069e2ef9a16a2b9f10fab05a70ac6f0fef8042766cd52b15cf2eaa312` |
| `ghosts.exe.config` | 37.014 | — | — | — | `e42aad47891f75ebcdad269e4c74a27ac67502be780c7b7bc2666e7c6e4efbb4` |
| `ghosts.exe.manifest` | 172.041 | — | — | — | `907732e659083227313f4c274e26fa8a6956c52a5c874377af60348e19d67146` |

`MANIFEST.sha256` (281 líneas): `sha256 = 6F6EECD76E6AA76E374AEA0D692F81518B662364DC5098115BCB41778820DA6A`

### 5.1 El discriminador es el `FileVersion` del Domain

| | AssemblyVersion | **FileVersion** |
|---|---|---|
| **Compilado (este build)** | `8.2.0.0` | **`8.2.7.90`** ✅ |
| Publicado (ZIP 2024-10-15) | `8.2.0.0` | **`8.2.1.0`** |

Ambos comparten `AssemblyVersion 8.2.0.0`; **lo que distingue el build del tag es el
`FileVersion` `8.2.7.90`**. El `ProductVersion` del compilado lleva además el commit
(`1.0.0+4d2e1608…`), que es procedencia en el propio binario.

`ghosts.exe` **no cambia** respecto del publicado en `FileVersion`/`ProductVersion`
(`8.2.2.0` / `8.0.0.0`): es lo esperado (H-2 del plan), porque su `AssemblyInfo` ya declaraba
esos valores en el tag.

---

## 6. Arranque (`--help` / `--version`)

```
$ cmd /c "ghosts.exe --help"
EXITCODE=0
```

Salida literal (fichero `build-v8.3.1\help_stdout.txt`, `stderr` vacío):

```
             ('-. .-.               .-')    .-') _     .-')
            ( OO )  /              ( OO ). (  OO) )   ( OO ).
  ,----.    ,--. ,--. .-'),-----. (_)---\_)/     '._ (_)---\_)
 '  .-./-') |  | |  |( OO'  .-.  '/    _ | |'--...__)/    _ |
 |  |_( O- )|   .|  |/   |  | |  |\  :` `. '--.  .--'\  :` `.
 |  | .--, \|       |\_) |  |\|  | '..`''.)   |  |    '..`''.)
(|  | '. (_/|  .-.  |  \ |  | |  |.-._)   \   |  |   .-._)   \
 |  '--'  | |  | |  |   `'  '-'  '\       /   |  |   \       /
  `------'  `--' `--'     `-----'  `-----'    `--'    `-----'


Hello, and welcome to GHOSTS...
The GHOSTS client replicates highly-complex, realistic non-player characters (NPCs) on the desktop.
Valid options are:
GHOSTS NPC Orchestrator 8.0.0.0
Copyright ? 2017 - 2023

  -d, --debug          (Default: false) Launch in debug mode

  -h, --help           (Default: false) Display this help screen

  -v, --version        (Default: false) Client version

  -i, --information    (Default: false) Client id information

  --help               Display this help screen.

  --version            Display version information.
```

`--version` (confirma en ejecución las versiones del CA):

```
ghosts:8.0.0.0 [8.2.2.0]
mscorlib: 4.0.0.0
NLog: 5.0.0.0
ghosts.domain: 8.2.0.0
Quartz: 3.8.1.0
CommandLine: 2.9.1.0
...
WebDriver: 4.0.0.0
Microsoft.Management.Infrastructure: 1.0.0.0
...
```

El `.exe` **carga todas sus dependencias** (NLog, CommandLine, Selenium, MCI, interop de
Office, SignalR) y **termina con código 0**: no hay excepción ni fichero de log de error.

---

## 7. Avisos de la compilación (declarados, no bloqueantes)

0 errores; 23 líneas de advertencia:

| Aviso | Detalle | Efecto |
|---|---|---|
| `NU1903` ×2 | `SSH.NET 2024.0.0` con vulnerabilidades altas conocidas (GHSA-mggc-4xg6-vcxf, GHSA-q939-rpr3-3284) | vienen del tag; no se cambia la dependencia |
| `NU1605` ×4 | `HtmlAgilityPack` 1.11.67 → 1.11.61 y `NLog` 5.3.4 → 5.3.2 (el cliente fija versiones menores que `Ghosts.Domain`) | es del tag; el build toma la versión del cliente y `--version` carga bien |
| `MSB3277` | conflictos de versión resueltos por RAR a favor de la referencia principal | idem; sin impacto en el arranque |
| `MSB3884` | no encuentra `MinimumRecommendedRules.ruleset` (CodeAnalysis) | solo afecta a análisis estático, no al binario |
| `CS0168`, `CS1998` | variables sin usar / métodos async sin `await` | código del tag; inocuos |

---

## 8. Ficheros y logs (fuera del repo)

```
D:\TFG-VMs\material-ghosts\client-windows\build-v8.3.1\
├── client\                                  ← staging: 281 ficheros (ghosts.exe + Domain + deps)
├── MANIFEST.sha256                          ← sha256 de los 281 ficheros
├── build_v8.3.1.log                         ← LOG DE LA COMPILACIÓN CORRECTA (0 errores)
├── restore_v8.3.1.log                       ← restore (idempotente)
├── help_stdout.txt / help_stderr.txt        ← salida literal de --help
├── diagnostico_dotnet_build.log             ← primer intento (bloqueo MSB3644)
├── logs_intentos\                           ← intentos intermedios (MSB3644 → NETSDK1050)
├── build-hooks.targets                      ← hook MSBuild (fuera del repo)
├── refasm\                                  ← reference assemblies 1.0.3 descomprimidas
└── microsoft.netframework.referenceassemblies.net462.1.0.3.nupkg   ← paquete original (sha256 en §3)
```

`build_v8.3.1.log` → `sha256 = 4FE550AA8C96E67562F9C3BC6D6A87333C6FC7AA0FC89677909266559A1BB77C`

> **Aclaración de trazabilidad.** `diagnostico_dotnet_build.log`, `logs_intentos\` y
> `build-hooks.targets` corresponden a **intentos intermedios previos** al build correcto
> (`18:50:52`): el primero falló con `MSB3644` (sin reference assemblies) y el hook se creó a
> las `18:50:48`, **antes** de ese build. Solo `build_v8.3.1.log` documenta la compilación
> válida. Cualquier `preprocessed.xml` que aparezca en `logs_intentos\` es de esos intentos y
> **no** forma parte del artefacto.

**No se ha tocado** `extract\` ni el ZIP publicado
(`ghosts-client-x64-v8.0.0.zip`, `sha256 = 01A58C46…`, sigue intacto).

---

## 9. Qué se hará con este binario

**Nada en T1.** El cliente compilado se usará en **T2**: `deploy_windows.ps1 -ClienteDir
build-v8.3.1\client` sustituye el cliente del ZIP en `C:\Users\angel\ghosts-client` del
invitado (snapshot v2), y su `sha256` entra en el manifiesto del snapshot.
No se despliega ahora, no se arranca ninguna VM y no se toca la receta.

> Si el cliente compilado no reporta las 5/5 acciones en **WE0-2** (R2 del plan), se vuelve al
> publicado y se declara (CA-W3b-01b). Ese juicio es de T4, no de esta tanda.

---

## 10. Higiene

- **0 secretos** en este documento, en los logs y en las rutas.
- **Sin commits, sin `git push`.** El repo solo gana este `BUILD.md`.
- No se ha tocado `_recursos/`, `Hojas/`, `Dataset/`, `Soporte/Metrica/`, corpus, reglas,
  `plan.md` raíz, `_fases/windows-legit-prep/plan.md`, recetas ni campaña.
- **Defender no se ha desactivado** (no hacía falta).
- **Nada instalado con permisos de administrador**; no se ha instalado VS ni Build Tools.
