---
bloque: windows-legit-prep-w3bis
nombre: W3-bis v2 — chivato por red, keepalive de un solo proceso, doble FPR y cierre sellado
version: 2
status: approved_by_human
fecha: 2026-11-10
fecha_aprobacion: 2026-11-10
aprobado_por: humano
enmiendas: >-
  "2026-11-10 · Q1-Q5 aprobadas (9095; kill duro con alarma ≤12 min; v2 hermano;
  eventcreate elevado; 2 h antes del snapshot). §16: (a) excluir del FIM/Sysmon las rutas
  de logs del keepalive; (b) unidad de FP de Windows = línea de `archives`, igual que Linux."
autor: tfg-planner
sustituye_a: version 1 (2026-11-10)
cambios_v2: >-
  (1) El **latido por red es el método principal** del `watch` (no se mide primero el SSH: la
  medición es CA). (2) El keepalive pasa de **tarea cada 5 min** (864 procesos/72 h) a **1 proceso
  persistente** con bucle, mutex de instancia única y reinicio. (3) Se mide el **ruido total del
  operador** (watch + keepalive) con umbral 5 % y **doble FPR** (canónico + `sin_operador`).
  (4) **Comparabilidad con Linux explícita** (servicio persistente + watch SSH ≈ 0,2 %).
  Se mantiene todo lo demás del v1 (compilación 8.3.1 con tope 2,5 h, evidencia de 2 h sellada
  antes de revertir, `arm` idempotente, fase `crudo` + `cleanup` bloqueado, snapshot v2 hermano de
  v1 bajo `-ataques-gui`, manifiesto + lista negra, Defender en cada arranque, `eventcreate` opción A).
depende_de: >-
  `_fases/windows-legit-prep/plan.md` **v2 aprobado por el humano** (W0; **no se modifica**) ·
  W1/W2/W3 PASA (commit `6e73d39`) · `Soporte/Laboratorio/windows/legit/snapshot_windows_legit.md`
  · Linux `legitimo-v3` cerrada (GHOSTS **v8.3.1**, tag `v8.3.1` = commit `4d2e1608…`, 72 h,
  `M`=342.966, FPR=0,857963, 9 señales, `logall_json`) · `Soporte/Laboratorio/crudo/estado_crudo.md`
  + `state.md:8-18` (regla dura del crudo) · `Soporte/Metrica/metrica_hids.md` v1 (congelada)
no_toca: >-
  `_recursos/` · `Hojas/` · `Dataset/` · `Soporte/Metrica/` · corpus · ruleset · config de Sysmon ·
  `_fases/windows-legit-prep/plan.md` (v2) · plan de Linux · recetas `w1/w2/w3` ·
  `bloques_windows.env` · `casos_windows.md` · `campana_windows.csv` ·
  `construir_receta_legitima.py` · `campana.py` · `extraer_campana.py` · `extraer_alertas.py` ·
  `contar_denominador.py` · `exportar_acciones.sh` · `legitimo_host_control.ps1` ·
  `filtrar_ruido_windows.py` (canónico de B1/B2) · `Soporte/Ataques/receiver/sink_http.py` ·
  los **6** snapshots previos de `victima-windows` y `lab-listo-windows-legit` (v1)
ejecuta_ahora: >-
  NADA. Este documento es de diseño. No se compila, no se arranca ninguna VM, no se toca el manager
  y no se ejecuta ninguna acción de la receta ni de la campaña.
---

# plan_w3bis.md v2 — corrección de la ventana legítima Windows

> **Convención:** **[H]** hecho comprobado (fuente `fichero:línea` o comando leído) · **[D]** decisión
> de este plan (con coste y alternativa) · **[S]** suposición declarada que hay que medir.

---

## 0. Resumen y qué cambia respecto del v1

### 0.1 Los cuatro cambios que ordena el humano (y su efecto)

| # | v1 | **v2** | Efecto medido |
|---|---|---|---|
| **1** | `watch` por SSH consolidado (1 sesión/chequeo) y **se medía primero** para decidir | **Chivato por red como método principal**: el invitado **empuja** su estado al host; el `watch` **no toca el invitado**. La medición (1 chequeo ⇒ **0 alertas nuevas**) es **CA**, no fase de decisión | Ruido del `watch`: **0** procesos en el invitado |
| **2** | Keepalive = tarea cada 5 min ⇒ **864 `powershell.exe` en 72 h** ⇒ ~864 `67027` | **1 proceso de trabajo persistente** (`powershell.exe` + su `conhost.exe`, una vez) con bucle de 5 min, mutex global y reinicio | Ruido del keepalive: **1-3 alertas en 72 h** |
| **3** | Solo se medía el `watch` | **Ruido total del operador** (watch + keepalive), umbral **5 %**, **doble FPR** (canónico + `sin_operador`) | Operador estimado **< 0,2 %** (antes 16-36 %) |
| **4** | Comparación con Linux cualitativa | **Tabla de comparabilidad explícita**: Linux = servicio persistente + `watch` SSH (~0,2 % del denominador); Windows v2 = 1 proceso + push. Unidad **acción/hora** y **por técnica**; misma etiqueta | La comparación se mantiene y se justifica |

> **Por qué el v1 se quedaba corto:** con `67027` alertando por **cada proceso creado**
> (`Dataset/Legitimo/windows/ruleids_legitimos.csv:8`: 132 de 159 alertas), una tarea cada 5 min
> era, por sí sola, **~16 %** del numerador. El v1 lo daba por «instrumentación declarada»; el v2 lo
> **elimina en origen**: un solo proceso que late 72 h.

### 0.2 Lo que se mantiene del v1 (no se re-abre)

| Elemento | Estado |
|---|---|
| Compilar **GHOSTS 8.3.1** (tope **2,5 h**; CA = `Ghosts.Domain.dll 8.2.0.0/8.2.7.90` + commit + `sha256`; fallback = publicado declarado) | **igual** (§3) |
| Evidencia de las **2 h** copiada y sellada **antes** de borrar/revertir | **igual** (§6) |
| **`arm` idempotente** (2.º `arm` no borra `archives.json`) | **igual** (§7.2) |
| Fase **`crudo`** + `cleanup` bloqueado sin `crudo.done`; `off` solo tras copiar | **igual** (§7.2) |
| Snapshot **v2** derivado de `-ataques-gui`, **hermano** de v1; v1 y los 6 previos intactos; manifiesto + lista negra + verificación en cada arranque; abortar antes de `t0` | **igual** (§7) |
| **Defender** comprobado en **cada arranque** | **igual** (§7.3) |
| **`eventcreate`** opción **A** (tarea elevada pre-creada; nunca sustituir por lectura) | **igual** (§10, R12) |

### 0.3 Los dos hallazgos del v1 que siguen mandando

| # | Hallazgo **[H]** | Consecuencia |
|---|---|---|
| **H-1** | El ZIP «Windows x64» del release `v8.3.1` **no es el build del tag**: `ghosts.exe` compilado el **2024-10-15**, `Ghosts.Domain.dll` **8.2.1.0**; el tag es de **2025-05-29** y su fuente declara Domain **8.2.0.0 / 8.2.7.90** | Compilar es **necesario** |
| **H-2** | Compilar **no cambia** el `FileVersion` de `ghosts.exe` (el tag ya declara `8.0.0.0/8.2.2.0`) | El CA de la compilación es **`Ghosts.Domain.dll=8.2.0.0/8.2.7.90`**, no la cadena `8.3.1` |

---

## 1. Alcance y qué NO entra

### 1.1 Entra

1. **Chivato por red** (latido del invitado al host) como **método principal** del `watch` — §4.
2. **Keepalive de un solo proceso** (bucle persistente + mutex + reinicio) — §5.
3. **Ruido total del operador** y **doble FPR** — §8.
4. **Comparabilidad con Linux** explícita — §8.3.
5. Cliente **8.3.1**, evidencia de **2 h**, **`crudo`**, **snapshot v2** con manifiesto — §3, §6, §7.
6. **CA nuevos** y **declaraciones de memoria** — §11, §12.

### 1.2 NO entra

- **Ejecutar la ventana** de 72 h (eso es W4/WE0; la fecha la fija el humano).
- Cambiar **receta**, **campaña**, **métrica**, **ruleset**, **config de Sysmon**, **config del agente `002`** ni la bóveda.
- Tocar los **6 snapshots previos**, **v1**, el corpus, `Dataset/`, `Hojas/`, `_recursos/`, `Soporte/Metrica/`, el plan v2 del bloque.
- **Instalar software** en la víctima (sigue N-8/N-9 del plan v2).
- **Commits** (los hace el orquestador). **Sin secretos.**

---

## 2. Estudio A — base limpia vs derivado (sin cambios de fondo)

| Punto | Qué trae **[H]** | Qué le falta | Residuos |
|---|---|---|---|
| **`lab-listo-windows`** (uid 5) | Agente `002` + Sysmon 15.22 + Defender OFF + WU + NAT off (`construccion_resultado.md:19-29`) | **SSH server** y **autologon** (no existen) + todo el deploy | Ninguno |
| **`lab-listo-windows-ataques-gui`** (uid 12) | Todo lo anterior **+ SSH probado + autologon de `angel`** (`B1.0-SSH.md:217`) | Solo el deploy | **Ninguno comprobado**: `C:\lab-attack` vacío, **0** `TFG-*`, SSH OK |

| Opción | Coste | Riesgo | Veredicto |
|---|---|---|---|
| **A1. Base limpia** | **+3-5 h** | **Alto**: sin NAT, `Add-WindowsCapability` de OpenSSH puede fallar; repetir el canal costó una tanda | **No** |
| **A2. Derivado `-ataques-gui`** | **0 h** | Bajo, con control de integridad | **Recomendado** |

> **[D] A2**, con manifiesto + lista negra + **aborto antes de `t0`** si difiere (§7.3). El nombre
> «ataques» se declara: es el **canal** (creado **antes** de atacar), no residuos.

---

## 3. Estudio B — compilación de GHOSTS 8.3.1 (sin cambios de fondo)

| Paso | Qué | Pasa si | Coste |
|---|---|---|---|
| **B-1** | VS Build Tools 2022 + targeting pack 4.6.2 (+4.8) + `nuget.exe` | `vswhere` + `MSBuild` ≥ 17 | 45-90 min |
| **B-2** | `nuget restore` + `msbuild /t:Restore /p:RestorePackagesConfig=true` | 274 paquetes sin error | 10-20 min |
| **B-3** | `msbuild src\ghosts.windows.sln /p:Configuration=Release /p:Platform=x64` | `ghosts.exe` + `Ghosts.Domain.dll` en `bin\x64\Release` | 5-15 min |
| **B-4** | Verificar y sellar | `Ghosts.Domain.dll=8.2.0.0/8.2.7.90` (**discriminador**), `ghosts.exe=8.2.2.0/8.0.0.0`, `sha256`, `git status` del clon solo `bin/obj/packages` | 15 min |

**Aborto [D]:** **2 intentos** o **2 h 30 min**. Si falla ⇒ **publicado declarado** (no bloquea).
**Prueba de que el binario sirve:** **WE0-2 (5/5 acciones)** antes de las 2 h; si < 5/5 ⇒ volver al
publicado y declarar (R2).

---

## 4. Estudio C — el chivato por red (método principal del `watch`)

### 4.1 Principio

El `watch` **no entra** en el invitado. El invitado **empuja** su estado cada 5 min al host, y el
host lo lee **en local**. Es el espejo del `keepalive` de Linux (servicio persistente que late), pero
con el estado que Windows necesita (servicios, disco, sesión, Defender) y **sin abrir una sola
sesión SSH** dentro de `[t0,t1]`.

```
invitado (1 proceso)                      host
┌────────────────────────────┐   POST    ┌──────────────────────────────┐
│ tfg_keepalive (bucle 5 min)│ ────────► │ heartbeat_sink.py :9095      │
│  · disco, WU, servicios    │  JSON 1KB │  · heartbeat.jsonl + sha256  │
│  · cliente, dueño, IL      │           │  · recv_utc (reloj)          │
│  · sesión, Defender        │           └──────────────┬───────────────┘
└────────────────────────────┘                          │ lee local
                                              ┌─────────▼─────────────┐
                                              │ watch (30 min, host)  │
                                              │ + manager (solo lect.)│
                                              └───────────────────────┘
```

### 4.2 Mecanismo, puerto y formato

| Elemento | Valor **[D]** |
|---|---|
| **Emisor** | `tfg_keepalive_windows.ps1 -Loop` (1 proceso, §5). `Invoke-RestMethod` con **timeout 3 s** y `try/catch`; si falla, `hb=FAIL` y sigue |
| **Receptor** | `Soporte/Laboratorio/windows/host/heartbeat_sink.py` (**nuevo**, stdlib, ~80 líneas). Escucha en **`192.168.65.1:9095`** (VMnet1). **No** se toca `Soporte/Ataques/receiver/sink_http.py` (canónico de ataques) |
| **Puerto** | **9095** (dedicado). `prep` comprueba que está libre y que 9090/9091/9092 **no** están ocupados por sinks de ataque; si 9095 está ocupado ⇒ **`exit 48`** (no hay fallback silencioso) |
| **Endpoint** | `POST /heartbeat`, `Content-Type: application/json`, cuerpo ≤ 1 KB |
| **Formato** | 1 línea JSON por latido: `{"ts_utc","recv_utc","seq","ka_pid","ka_instancias","n_ghosts","cliente_pid","win_user","il","sesion","disco_mb","sysmon","wazuh","wu","defender","powercfg_ok","ruta_defecto","hosts_ok","armado","dia_k","client_out_mb","sha256_prev"}` |
| **Integridad** | `seq` monótono + `sha256_prev` (hash de la línea anterior) ⇒ cadena **a prueba de edición**; `MANIFEST.sha256` al cerrar. **Un corte de cadena se registra como `reinicio_bucle`** (el proceso nuevo no conoce el hash anterior) y **no** se trata como manipulación: se declara |
| **Lectura** | el `watch` lee **la última línea completa** de `heartbeat.jsonl` (tolerante a escritura parcial: si la última línea no parsea, usa la anterior y lo anota) |
| **Reloj** | el sink añade `recv_utc`; **Δ = recv − ts** se registra en cada línea (chequeo continuo de W-V9, no solo en `prep`) |
| **Secretos** | **ninguno**: no viaja contraseña, clave ni token |

### 4.3 Prueba de **0 huellas** (1 chequeo ⇒ 0 alertas nuevas)

| Paso | Comando / fichero | Criterio |
|---|---|---|
| 1 | `t_a` = hora UTC antes del chequeo | — |
| 2 | 1 ciclo completo del `watch` (host + manager, **sin SSH**) | `HB_EDAD_MIN ≤ 12` |
| 3 | `extraer_alertas_windows.py` sobre los diarios del manager, agente `002`, en `[t_a−60 s, t_a+120 s]` | **0 alertas nuevas** |
| 4 | `Select-String heartbeat.jsonl -Pattern '"recv_utc":"…"'` | 1 latido en la franja |
| 5 | Sysmon EID 3 del invitado en la franja (si está) | **1** conexión a `:9095` (`185001`, **nivel 0**, no alerta) |
| 6 | `Get-CimInstance Win32_Process` con `ParentProcessId = vmtoolsd` en el invitado | **0** |
| 7 | `sshd` en el invitado en la franja | **0** sesiones del host |

> **Lo único que toca el invitado es el POST del propio keepalive** (1 conexión TCP cada 5 min,
> Sysmon 3, que **no alerta** según C0: `185001(0)`). El `watch` **no** genera ni un proceso.
> **CA-W3b-12** lo exige con salida literal y `sha256`.

### 4.4 Caídas y contingencias (diseño, no improvisación)

| Caso | Qué pasa | Qué se hace |
|---|---|---|
| **Sink caído** | `POST` falla; el bucle registra `hb=FAIL` y **sigue**; `estado.json` local intacto | El `watch` da **ALARMA** por `HB_EDAD_MIN > 12`; el dato primario **no se pierde**; al volver el sink, los latidos se reanudan |
| **Red caída (VMnet1)** | `POST` falla **y** el agente `002` se desconecta del manager | Doble alarma (agente + latido); **invalida** si dura > 30 min (W-V3); no se toca nada a mano |
| **Puerto 9095 ocupado** | `prep` no arranca el sink | **`exit 48`** antes de `t0`; el humano decide (no se mata un proceso ajeno) |
| **Sink lento / cola** | El sink escribe en append; 288 líneas/día ≈ 3 MB/72 h | Sin límite práctico; `Rotar` a 5 MB por si acaso |
| **Latido duplicado** | `seq` repetido o `ka_instancias=2` | **ALARMA** (G-W13); se investiga antes de seguir |

---

## 5. Estudio C2 — keepalive de **un solo proceso**

### 5.1 El problema del v1, con el número exacto

| v1 (tarea cada 5 min) | v2 (1 proceso de trabajo persistente) |
|---|---|
| 288 `powershell.exe`/día × 3 días = **864 procesos** | **1 `powershell.exe`** (+1 `conhost.exe`) durante 72 h |
| 864 `67027` (L3) ⇒ **~16-25 %** del numerador | **1-3** `67027` (arranque + recuperaciones) ⇒ **< 0,1 %** |
| Cada ciclo re-importa el script y relee el estado | El estado vive en memoria; el bucle solo duerme |

### 5.2 Patrón

```
Tarea TFG-WinLegit-Keepalive (SYSTEM)
  acción   : powershell -NoProfile -ExecutionPolicy Bypass -File tfg_keepalive_windows.ps1 -Loop
  disparador: AL ARRANCAR  (+ StartWhenAvailable)
  ajustes  : MultipleInstances=IgnoreNew · ExecutionTimeLimit=0
             RestartCount=3 · RestartInterval=1 min
```

Dentro del script (`-Loop`):

```
1) mutex global  Global\TFG-WinLegit-Keepalive
     · si ya existe → log "segunda_instancia" y exit 0   (no falla la tarea)
2) bucle:
     · Invoke-Ciclo        (disco, WU, cliente, rotación, latido POST, estado.json)
     · si existe stop.flag → log "parada_ordenada" y exit 0
     · dormir hasta el siguiente múltiplo de 5 min  (no Start-Sleep 300 a ciegas:
       se alinea al reloj para que los latidos caigan en :00/:05/:10…)
3) try/catch POR CICLO: una excepción se registra y el bucle CONTINÚA
   (una excepción no mata el proceso; el proceso solo muere por kill/crash duro)
```

- **Compatibilidad:** `tfg_keepalive_windows.ps1 -Once` conserva el comportamiento actual (un ciclo
  y `exit 0`). La evidencia de W3 y las pruebas manuales siguen funcionando.
- **Cero procesos externos por ciclo [D]:** el ciclo usa **solo cmdlets en proceso**
  (`Get-Service`, `Get-PSDrive`, `Get-CimInstance`, `Get-MpComputerStatus`, registro). `powercfg`
  se lee **una vez al arrancar** (1 `powercfg.exe`) y su valor viaja en el latido; `schtasks.exe`
  solo se invoca **en una recuperación** (0-2 veces en 72 h). Así el bucle no reintroduce los 288
  procesos/día que este cambio elimina.
- **`estado.json` cada 60 min**, no cada 5 (evita 288 recreaciones de fichero/día y el posible
  Sysmon 11). `keepalive.log` en **append** (no recrea).
- **Procesos reales del bucle:** **1 `powershell.exe`** (el proceso de trabajo) **+ 1 `conhost.exe`**
  que Windows crea una sola vez al arrancar la consola. Se cuentan y se declaran: **2 procesos en
  72 h**, no 864.
- **Recuperación del cliente:** igual que hoy (`schtasks /run /tn TFG-WinLegit-Actividad`), nunca
  lanzando `ghosts.exe` desde SYSTEM (rompería D4/`win_user=angel`).
- **Rotación de receta:** igual (solo con `TFG_MAPA_DIAS`).
- **Parada:** `stop.flag` en `C:\Users\angel\ghosts-client` → sale en el siguiente ciclo (≤ 5 min);
  `stop`/`cleanup` lo crean y **verifican** que el pid desaparece.

### 5.3 Reinicio si muere (lo que se puede y lo que no)

| Muerte | ¿Se reinicia solo? | Cómo se demuestra |
|---|---|---|
| **Crash** (excepción no capturada, salida ≠ 0) | **Sí**: `RestartCount=3`, `RestartInterval=1 min` | prueba: `Stop-Process -Force` **no** vale como crash; se simula con `exit 1` en un modo de prueba declarado |
| **Reinicio del invitado** | **Sí**: disparador **al arrancar** | prueba: revert+start ⇒ 1 instancia |
| **Kill duro** (`taskkill /f`) | **No** (Task Scheduler lo registra como terminado, no como fallo) | El `watch` **alarma** por `HB_EDAD_MIN > 12`; la recuperación es `schtasks /run` (acción **de incidencia**, declarada) |
| **Dos instancias** | **No arranca la segunda** (mutex) | prueba negativa: lanzar a mano ⇒ `segunda_instancia`, `ka_instancias=1` |

> **Se declara sin adornos:** el kill duro **no** se auto-reinicia; se **detecta** en ≤ 12 min y se
> recupera con `schtasks /run`. En la ventana real eso es una **incidencia declarada** (válida solo
> si el cliente no murió y el hueco es < 30 min). **No** se finge un watchdog que costaría 96-288
> procesos/día: eso reintroduciría el problema que este cambio elimina.

### 5.4 Prueba de **una sola instancia** (2 h + negativa)

| Prueba | Cómo | Criterio |
|---|---|---|
| **Positiva (2 h)** | El latido lleva `ka_pid` y `ka_instancias`; el host cuenta | `ka_instancias=1` en **24/24** latidos; **1 solo `ka_pid`** |
| **Negativa (duplicado)** | `schtasks /run` **con el bucle vivo** | La 2.ª instancia escribe `segunda_instancia` y sale; `ka_instancias` sigue **1** |
| **Independiente del latido** | En el invitado: `Get-CimInstance Win32_Process -Filter "Name='powershell.exe'"` filtrado por `tfg_keepalive_windows.ps1` | **exactamente 1** |
| **Tras reinicio** | Revert + arranque | **exactamente 1** (disparador de arranque + mutex) |

---

## 6. Estudio D — evidencia de las 2 h (actualizada al bucle)

### 6.1 Qué debe probar la evidencia

| Dato | Cómo se lee |
|---|---|
| **1 proceso** durante 2 h | `ka_instancias=1` y `ka_pid` único en `heartbeat.jsonl` + `keepalive.log` |
| Latidos cada 5 min **alineados**, sin huecos | `keepalive.log` (TSV) + `heartbeat.jsonl` (`seq` consecutivo) |
| **Muerte provocada del cliente** y recuperación ≤ 2 ciclos | `taskkill /f /im ghosts.exe` + `recovery.log` + `estado.json` |
| `win_user=angel` **después** de recuperar | `estado.json` + Sysmon EID 1 (extracto) |
| **Duplicado** rechazado | `segunda_instancia` en el log |
| **Sink caído** no pierde el dato | `hb=FAIL` + `estado.json` intacto + reanudación |
| Ruido del keepalive en 2 h | manager: alertas del `002` en `[inicio,fin]` |

### 6.2 Dónde vive y cómo se sella (orden **no negociable**)

| Copia | Ruta |
|---|---|
| **Primaria (fuera del repo y fuera de `D:\TFG-VMs\victima-windows`)** | `D:\TFG-VMs\legitimo-windows-<fecha>\keepalive_2h\` |
| **Sellada y versionable (repo, sin secretos)** | `Soporte/Laboratorio/windows/legit/evidencia/keepalive_2h/` |

```
1) prueba de 2 h + 1 muerte del cliente + 1 duplicado + 1 caída de sink
2) copiar los logs FUERA (scp / vmrun copyFileFromGuestToHost)  ← antes de CUALQUIER revert
3) sha256 de cada fichero + MANIFEST.tsv (fichero, bytes, sha256, primer/último ts)
4) MANIFEST.sha256 + test_2h_meta.md (horas UTC literales, pid, recuperación)
5) SOLO DESPUÉS: borrar logs del invitado, parar la VM y crear el snapshot v2
```

### 6.3 Cómo se demuestra que el snapshot **no** la contiene

1. `copiado_utc < snapshot_utc` (las dos se registran).
2. El snapshot se crea **con los logs del invitado borrados**: tras revertir, `keepalive.log` solo
   tiene líneas del arranque del snapshot; **0 líneas** en `[inicio_prueba, fin_prueba]`.
3. La copia primaria está **fuera del árbol de la VM**: ningún `revert`/consolidación la toca.

---

## 7. Estudio E — snapshot v2, controlador y cierre

### 7.1 Qué cambia en el snapshot v2

| Elemento | v1 | **v2** | Se toca |
|---|---|---|---|
| Cliente | 8.0.0/8.2.2 (ZIP 2024-10-15, Domain **8.2.1.0**) | **build 8.3.1** (o publicado, declarado) + `CLIENTE_*` | **sí** |
| `tfg_keepalive_windows.ps1` | un ciclo por tarea | **`-Loop`** (1 proceso, mutex, latido POST) + `-Once` compatible | **sí** |
| Tarea keepalive | `Once` + repetición 5 min | **Al arrancar** + `IgnoreNew` + `RestartCount=3` + `ExecutionTimeLimit=0` | **sí** |
| `verificar_windows.ps1` | sin Defender/sesión/manifiesto | + `DEFENDER_*`, `SESION_ANGEL`, `MANIFIESTO_SNAPSHOT` | **sí** |
| `windows_legit_host_control.ps1` | v3 | **v4**: `watch` sin SSH, `G-W13`, `arm` idempotente, `crudo`, `cleanup` bloqueado | **sí** |
| `heartbeat_sink.py` | — | **nuevo** | **sí** |
| Receta, campaña, tareas, hosts, powercfg, WU, Sysmon, agente `002` | congelados | **idénticos** | **no** |
| `-gui` y los 5 anteriores, **v1** | — | **intactos**; v1 se marca «superado», **no se borra** | **no** |

**Linaje:** revert a `-ataques-gui` → deploy final → **snapshot v2 hermano de v1**. Total: **8**
snapshots. La evidencia de W3 (cliente 8.0.0 + controlador v3) queda **superada, no borrada**.

### 7.2 Controlador v4 — cambios concretos

| # | Cambio | Por qué |
|---|---|---|
| C-1 | **`watch` sin SSH**: lee `heartbeat.jsonl` en local | 0 huellas en el invitado |
| C-2 | **`G-W13` (nuevo)**: frescura `HB_EDAD_MIN ≤ 12`, `seq` monótono, `ka_instancias=1` | el latido es la señal de vida |
| C-3 | **`arm` idempotente**: si `logall_json=yes`, **no** ejecuta `on` (que hace `rm -f archives.json`) | un 2.º `arm` destruye el archivo del día |
| C-4 | **Fase `crudo`**: copia `archives`+`alerts` a `D:\TFG-VMs\legitimo-windows-<t0>\crudo\`, `MANIFEST.tsv`+`sha256`, dedupe, `M` **de la copia**, `crudo.done` | regla dura (`state.md:8-18`) |
| C-5 | **`cleanup` bloqueado sin `crudo.done`** (`exit 84`) | hoy apaga `off` sin copiar |
| C-6 | `prep`: manifiesto + Defender + sesión + **sink arriba y POST de prueba**; aborta antes de `t0` | decisiones 3/6 |
| C-7 | `G-W7` añade **disco del manager** (≥ 3× la proyección de `M`) | R-W3 (lección L1) |
| C-8 | `stop`/`cleanup`: crear `stop.flag`, verificar que el bucle sale, parar el sink y retirar la regla de firewall | cierre limpio |
| C-9 | `status`: `CLIENTE_*`, `DEFENDER_*`, `SESION_ANGEL`, `HB_EDAD_MIN`, `KA_PID` | trazabilidad |
| C-10 | `arm` escribe `ventana_actual.json` (t0/t1/fecha) | `crudo`/`cleanup` sin parámetros a mano |

**Los 8 guardarraíles del `watch`:** G-W5 (manager + daemons + agente), G-W6 (sin ruta por defecto +
hosts + linux off), G-W7 (`logall_json` por ventana + disco manager), G-W8 (0 hijos `vmtoolsd`),
G-W9 (`powercfg`), G-W10 (disco invitado), G-W11 (1 `ghosts.exe` de `angel`), **G-W13** (latido:
frescura + `seq` + 1 instancia). G-W8/G-W9/G-W10/G-W11 los calcula el **bucle** y viajan en el
latido; el host no entra.

### 7.3 Integridad, Defender y arranque

- **Manifiesto esperado:** cliente + `config/` + `recetas/` + `campana/` + 2 tareas + keepalive +
  `heartbeat_sink.py` (host, no va en la VM) + `hosts` + `C:\lab-legit\tools` (`sha256`) +
  `Sysmon64`/`WazuhSvc` `Running` + `powercfg=0` + WU off + **Defender off**.
- **Lista negra:** `C:\lab-attack` no vacío · `TFG-Attack-*`/`TFG-Baseline-*`/`TFG-IL-*` ·
  `armado.flag` · marcas `inicio/fin/hecho` · `client.out` · `instance/` · `logs/*.log` con
  contenido · `HKCU\…\Run\ghosts` · `C:\Windows\Temp\tfg-*` · `%TEMP%\opencode\*` · `b10_*`.
- **Cuándo:** `prep` (tras arrancar, antes de `arm`), prueba de revert del snapshot y `cleanup`.
  Si `DIFIERE` ⇒ **`exit 46`** y **no se arma**.
- **Defender:** `Get-MpComputerStatus` + `Get-Service WinDefend`; esperado `RealTimeProtectionEnabled=False`,
  `BehaviorMonitorEnabled=False`, `IsTamperProtected=False`, `WinDefend=Stopped`. Si no ⇒ **`exit 47`**.

---

## 8. Ruido total del operador, doble FPR y comparabilidad con Linux

### 8.1 Presupuesto de ruido (estimación **[S]** que se mide)

| Fuente | v1 (72 h) | **v2 (72 h)** | % del total v2 |
|---|---|---|---|
| Receta (441 acciones/día × ~2 procesos) | ≈ 2.640 | ≈ 2.640 | — |
| **Keepalive** | **864** | **1-3** (1 proceso de trabajo + recuperaciones) | **< 0,1 %** |
| **`watch`** | **2.016** | **0** (sin SSH) | **0 %** |
| **Total** | ≈ 5.520 | ≈ 2.643 | **operador ≈ 0,1 %** |

> **Umbral 5 %:** se cumple con un margen de **~45×**. Si la medición real lo supera, **no se
> maquilla**: se publica y se abre incidencia (el diseño ya no tiene de dónde sacar ruido salvo
> que el propio `67027` cuente dos veces por proceso).

### 8.2 Doble FPR

| Cifra | Definición | Uso |
|---|---|---|
| **Canónico** | FPR con **todo** el operador contado (1-3 alertas) | Titular |
| **Sensibilidad `sin_operador`** | FPR excluyendo las alertas etiquetadas `operador_legit` | Comparación con Linux y con B1/B2 |

- Etiquetador **nuevo** `_artefactos/scripts/etiquetar_operador_legit.py` (no se toca
  `filtrar_ruido_windows.py`). Añade `operador_legit` + `motivo` a `alertas_detalle.csv`.
- Motivos: `keepalive` (`win_command_line` contiene `tfg_keepalive_windows.ps1`), `watch` (no debería
  existir en v2; si aparece, es un **fallo de diseño**), `deploy` (solo `prep`), `logon_operador`
  (predicado `OPERADOR_WIN` existente).
- **Se publican las dos cifras y el recuento filtrado.** Nunca se oculta.

### 8.3 Comparabilidad con Linux (declaración explícita)

| Dimensión | Linux (`legitimo-v3`) | **Windows v2** | ¿Comparable? |
|---|---|---|---|
| **Keepalive** | **servicio persistente** (`systemd`), late cada 5 min | **1 proceso persistente**, late cada 5 min | **Sí** (mismo patrón) |
| **`watch`** | cada 30 min; **leía el invitado por SSH** (`df -Pk /`, `legitimo_host_control.ps1:358`) | cada 30 min; **no toca el invitado** (push) | **Sí** en frecuencia; **mejor** en canal |
| **Ruido del operador** | ≈ **0,2 %** del denominador (`M`=342.966; ~576 execve) | ≈ **0,1 %** de las alertas (1-3) | **Sí** (orden de magnitud) |
| **Etiqueta** | `sin_operador` (sensibilidad de ataques) | `sin_operador` (canónico + sensibilidad) | **Sí** |
| **Unidad** | `FP/acción`, `FP/hora`, por técnica | `FP/acción`, `FP/hora`, por técnica | **Sí** |
| **`M` absoluto** | 342.966 eventos | **desconocido** hasta WE0-9 | **No** (telemetrías distintas; ya declarado) |
| **FPR crudo** | 0,857963 | se publica **per-plataforma** | **No** en crudo; **sí** en tasa y por técnica |

> **Conclusión que va a la memoria:** la comparación **se mantiene** porque (a) el patrón de
> keepalive es el mismo (persistente), (b) la frecuencia del `watch` es la misma (30 min), (c) la
> etiqueta `sin_operador` es la misma y (d) la unidad es la misma. Lo que **no** se compara es el
> `M` absoluto ni el FPR crudo, porque miden telemetrías distintas — y eso ya estaba declarado en
> `metrica_hids.md:66-68, 254-268`.

---

## 9. Tandas de trabajo (coste, prueba y CA)

> **Regla de oro:** ningún artefacto se estrena la noche de `t0`; todo se prueba dos veces y en un
> revert desechable.

### T1 — Cliente 8.3.1 · **2,5 h** (tope duro)

| Se hace | Se prueba | CA |
|---|---|---|
| Build Tools + `nuget restore` + `msbuild` x64; staging en `D:\TFG-VMs\material-ghosts\client-windows\build-8.3.1\` + `BUILD.md` + `MANIFEST.sha256` | `Ghosts.Domain.dll=8.2.0.0/8.2.7.90`; `ghosts.exe=8.2.2.0/8.0.0.0`; `sha256`; clon solo `bin/obj/packages` | **CA-W3b-01** |
| Si falla: publicado declarado | `cliente_origen=CMU Box`, `zip_sha256`, `Domain=8.2.1.0`, `motivo` | **CA-W3b-01b** |

### T2 — Chivato + bucle + controlador v4 · **5 h**

| Se hace | Se prueba | CA |
|---|---|---|
| `heartbeat_sink.py` (9095, JSONL, `sha256_prev`, `recv_utc`) | `POST` de prueba ⇒ 1 línea válida; cadena `sha256` OK; puerto ocupado ⇒ `exit 48` | **CA-W3b-20** |
| `tfg_keepalive_windows.ps1 -Loop` (mutex, alineado a 5 min, `try/catch` por ciclo, `stop.flag`, `estado.json` 60 min) | 2 ciclos; duplicado ⇒ `segunda_instancia`; `stop.flag` ⇒ sale ≤ 5 min | **CA-W3b-12b** |
| Tarea keepalive al arrancar + `IgnoreNew` + `RestartCount` | revert+start ⇒ 1 instancia | **CA-W3b-12b** |
| `windows_legit_host_control.ps1` v4 (C-1…C-10, **G-W13**) | `drytest` on/off 0 FALLO; `arm` 2 veces sin perder archivo; `cleanup` sin `crudo.done` ⇒ `exit 84` | **CA-W3b-09/10/14** |
| `verificar_windows.ps1` v4 (Defender, sesión, manifiesto) | salida literal `DEFENDER_OFF=1`, `SESION_ANGEL=1`, `MANIFIESTO_SNAPSHOT=OK` | **CA-W3b-07/08/17** |

### T3 — Ruido total y doble FPR · **1,5 h**

| Se hace | Se prueba | CA |
|---|---|---|
| 1 chequeo real (manager + invitado, fuera de ventana); `ruido_watch.csv` y `ruido_keepalive.csv` | **0 alertas nuevas** por el `watch`; keepalive ≤ 3 alertas en 72 h (proyección) | **CA-W3b-12** |
| Etiquetador + doble FPR sobre los diarios | canónico vs `sin_operador`; diferencia = recuento filtrado | **CA-W3b-13** |
| Tabla de comparabilidad Linux↔Windows firmada antes de `t0` | tabla §8.3 con cifras | **CA-W3b-19** |

### T4 — 2 h + cierre + snapshot v2 · **4,5 h** (2 h de reloj)

| Se hace | Se prueba | CA |
|---|---|---|
| Revert a `-gui`, deploy final, manifiesto + Defender + sesión + sink | `MANIFIESTO_SNAPSHOT=OK`, POST de prueba OK | **CA-W3b-17/20** |
| **WE0-2**: 5 acciones con el cliente final | **5/5**; `win_user=angel`, `win_cwd`, IL Medium | **CA-W3b-02** |
| **Ensayo del cierre** (15 min): `on` → `crudo` → `M` → `off` → `CONFIG_IDENTICA` | `crudo.done` + `MANIFEST.tsv` + `denominador_M.csv` + `logall_json=no` | **CA-W3b-11** |
| **2 h**: 1 proceso, 24/24 latidos, duplicado rechazado, cliente muerto y recuperado, sink caído y reanudado | `ka_instancias=1` 24/24; `segunda_instancia`; recuperación ≤ 2 ciclos; `hb=FAIL` + reanudación | **CA-W3b-04/12b/20** |
| **Copiar fuera + sellar** y **solo después** borrar logs, parar, snapshot v2 | `MANIFEST.sha256`; `copiado_utc < snapshot_utc` | **CA-W3b-04/05** |
| Revert + arranque del v2 | 6/6 + `keepalive.log` sin líneas de la prueba + 1 instancia | **CA-W3b-05/06/12b** |

### T5 — Documentación, sellado y CA · **1,5 h**

| Se hace | Se prueba | CA |
|---|---|---|
| `snapshot_windows_legit_v2.md`, `BUILD.md`, `ruido_*.csv`, `test_2h_meta.md`, `b10_windows_sellado.md`, `estado_crudo.md` | `sha256` de todo; `git status` acotado; plan v2 intacto | **CA-W3b-15/16** |
| Tabla de declaraciones para la memoria | revisión humana | **CA-W3b-18** |

**Coste total: 15 h** (T1 2,5 + T2 5 + T3 1,5 + T4 4,5 + T5 1,5) ≈ **2,5 jornadas** + 2 h de reloj.

---

## 10. Riesgos y casos límite (con mitigación y prueba)

| # | Caso límite | Impacto | Mitigación / decisión | Cómo se demuestra |
|---|---|---|---|---|
| **R1** | **La compilación falla** | Se queda el binario de 2024 | Tope 2,5 h / 2 intentos ⇒ **publicado declarado** (no bloquea) | `BUILD.md` + `motivo` (CA-W3b-01b) |
| **R2** | Compila pero **no reporta** las 5 acciones | Receta sin medir | **WE0-2 antes de las 2 h**; < 5/5 ⇒ volver al publicado | `history_timeline` (CA-W3b-02) |
| **R3** | **Autologon no arranca** ⇒ sin sesión ⇒ `Interactive` no corre | Ventana sin actividad | `SESION_ANGEL=1` en `prep`; 1 reintento con reinicio; si falla 2 veces ⇒ **abortar** | salida de `prep` (CA-W3b-08) |
| **R4** | **Defender se reactiva** | Cuarentena + FP falsos | `prep`/`cleanup`; `DEFENDER_OFF=1` o **`exit 47`**; WU `Disabled` + NAT off | `verificar_windows.ps1` (CA-W3b-07) |
| **R5** | **`logall_json` residual `yes`** | Un `arm` repetido borra `archives.json` | `arm` idempotente (C-3) | fichero de prueba sobrevive (CA-W3b-09) |
| **R6** | **Snapshot con residuos** | Medida contaminada | manifiesto + lista negra; `DIFIERE` ⇒ **parar antes de `t0`** | prueba negativa (CA-W3b-17) |
| **R7** | **Reloj** Δ > 2 s | Invalidez de tiempos | Δ en cada latido (`recv_utc − ts_utc`) + `prep`/cosecha; Δ > 5 s sostenido ⇒ inválida | `heartbeat.jsonl` (CA-W3b-20) |
| **R8** | **Sesión de `angel` cerrada** | Cliente muerto | El bucle detecta `SESION_ANGEL=0`, loguea `sin_sesion`; **no** puede reabrir sesión ⇒ **invalida** (W-V8) | `heartbeat.jsonl` (CA-W3b-12b) |
| **R9** | **`M` > 5 GB** | Disco del manager / agente muerto | WE0-9 + `G-W7` (≥ 3×) + fallback **`M=n/a`** (no se cambia la métrica) | proyección (CA-W3b-11) |
| **R10** | **`crudo` parcial** | Se apaga `off` sin copia | `cleanup` bloqueado (`exit 84`) | log del controlador (CA-W3b-10) |
| **R11** | **Evidencia de 2 h perdida** | Se repite el fallo de W3 | orden duro §6.2 (copiar + sellar antes de revertir) | `MANIFEST.sha256` (CA-W3b-04) |
| **R12** | **`eventcreate` a Medium falla** | Un caso se degrada | **tarea elevada pre-creada en `prep`**, disparada a la hora de W-10; **prohibido** sustituir por lectura | log de la tarea (CA-W3b-02) |
| **R13** | **Chivato caído** (sink) | `watch` sin señales del invitado | `hb=FAIL` + `estado.json` local + **ALARMA** por frescura; reanuda al volver | prueba de caída (CA-W3b-20) |
| **R14** | **Red caída (VMnet1)** | Sin latido **y** sin agente | doble alarma; **invalida** si > 30 min | log del manager (CA-W3b-20) |
| **R15** | **Sink ocupado** (9095) | No arranca | `prep` ⇒ **`exit 48`**; no se mata un proceso ajeno | salida de `prep` (CA-W3b-20) |
| **R16** | **Bucle duplicado** | Doble cliente/recuperaciones | mutex global + `ka_instancias` | prueba negativa (CA-W3b-12b) |
| **R17** | **Bucle muerto (kill duro)** | Sin latido ⇒ sin recuperación del cliente | **no** se auto-reinicia; **ALARMA ≤ 12 min** + `schtasks /run` (incidencia declarada) | prueba de kill (CA-W3b-12b) |
| **R18** | **Reinicio del invitado** | Ventana destruida | W-V8 (`LastBootUpTime < t0`, 0 `1074/6005/6006/41`); el bucle arranca solo (1 instancia) | `Get-WinEvent` (CA-W3b-05) |
| **R19** | **Dos `arm` seguidos** | Archivo del día borrado | C-3 + prueba | CA-W3b-09 |
| **R20** | **Confusión v1/v2** | Se arma el snapshot viejo | `G-W2` exige v2; v1 marcado «superado»; `status` lo muestra | `vmrun listSnapshots` (CA-W3b-05) |
| **R21** | **`TFG_MANAGER_PW` ausente** | Manager `SKIP` silencioso | se exporta antes de `arm`/`watch`/`crudo`/`cleanup`; sin ella ⇒ `SKIP` **declarado** | log (CA-W3b-10) |
| **R22** | **El cliente 8.3.1 vacía `%TEMP%`** | Scripts de apoyo desaparecen | el deploy usa `C:\Windows\Temp` (ya resuelto en W3) | manifiesto (CA-W3b-17) |

---

## 11. Qué se declara en la memoria (lista cerrada)

| # | Declaración |
|---|---|
| **M-1** | **Cliente**: `release v8.3.1` (commit `4d2e1608`, 2025-05-29) · `assembly 8.0.0.0/8.2.2.0` · **origen** (build local o CMU Box) · `sha256` · **y que el ZIP del release es de 2024-10-15 (Domain 8.2.1.0), no del tag** |
| **M-2** | **`watch` de 8 guardarraíles vs 9 señales de Linux** (7 del v1 + **G-W13** del chivato), con la tabla de sustitución y las señales **post-hoc** (`doing_age`, `sin_eventos`, recuperaciones) |
| **M-3** | **`Interactive`**: sesión 1 (consola), **IL Medium**, depende de la sesión de `angel`; logoff/reinicio **invalida** |
| **M-4** | **`M` desconocido** hasta WE0-9; per-plataforma, no comparable en crudo; fallback `M=n/a` si > 5 GB |
| **M-5** | **Keepalive de 1 proceso de trabajo** (`powershell.exe` + `conhost.exe` una vez; bucle persistente, mutex, reinicio en crash/arranque); **kill duro no se auto-reinicia**: se detecta ≤ 12 min y se recupera con `schtasks /run` (incidencia declarada) |
| **M-6** | **Chivato por red**: el invitado empuja cada 5 min; el `watch` **no** toca el invitado; **1 chequeo ⇒ 0 alertas nuevas** |
| **M-7** | **Ruido total del operador** medido (watch + keepalive) con umbral **5 %**; **doble FPR** (canónico + `sin_operador`) con recuentos |
| **M-8** | **Comparabilidad con Linux**: mismo patrón de keepalive (persistente), misma frecuencia de `watch` (30 min), misma etiqueta y unidad; **no** se compara `M` absoluto ni FPR crudo |
| **M-9** | **Snapshot v2 hijo de `-ataques-gui`** (nombre heredado), verificado limpio con manifiesto + lista negra; 6 previos y v1 intactos |
| **M-10** | **Defender OFF** es control ambiental declarado; verificado en cada arranque; riesgo de reactivación |
| **M-11** | **`eventcreate` (W-10)**: si a `Medium` falla, **solo esa acción** elevada (tarea pre-creada) y declarada; **nunca** sustituida por lectura |
| **M-12** | **Evidencia de 2 h** fuera de la VM y sellada; el snapshot **no** la contiene (horas + logs borrados tras el sello) |
| **M-13** | **El `watch` de Linux también leía el invitado por SSH** (`df`); el v2 **no** lo hace: diferencia de canal declarada, **no** de métrica |

---

## 12. Criterios de aceptación (verificables por el tester)

| # | CA | Verificación (comando / fichero) | Evidencia |
|---|---|---|---|
| **CA-W3b-01** | **Cliente 8.3.1 compilado** desde `4d2e1608`: `Ghosts.Domain.dll=8.2.0.0/8.2.7.90`, `ghosts.exe=8.2.2.0/8.0.0.0`, `sha256`, `MSBuild` ≥ 17, clon solo `bin/obj/packages` | `Get-FileHash` + `git status` del clon | `BUILD.md` + `MANIFEST.sha256` |
| **CA-W3b-01b** | **Fallback declarado**: `cliente_origen=CMU Box`, `zip_sha256=01a58c46…`, `Domain=8.2.1.0`, `motivo` | ficha | `BUILD.md` |
| **CA-W3b-02** | **5/5 acciones** con el cliente final; `win_user=angel`, `win_cwd≠System32`, **IL Medium**; **W-10** con su vía (Medium o tarea elevada pre-creada) | `history_timeline` + Sysmon EID 1 | `ensayo_WE0.md` (W4) |
| **CA-W3b-03** | **Deploy idempotente**: 2 applies = **mismo** `MANIFEST_SHA256`; `TAREAS_FINGERPRINT` igual | salida literal | `snapshot_windows_legit_v2.md` |
| **CA-W3b-04** | **2 h + 1 muerte con evidencia sellada**: `MANIFEST.tsv` + `sha256` + `copiado_utc < snapshot_utc`; recuperación ≤ 2 ciclos; `win_user=angel` | `sha256sum -c` + `test_2h_meta.md` | `legit/evidencia/keepalive_2h/` |
| **CA-W3b-05** | **Snapshot v2** presente (**8** snapshots; 6 previos + v1 intactos); revert+arranque **6/6** | `vmrun listSnapshots` + salida | doc v2 |
| **CA-W3b-06** | El snapshot **no** contiene la evidencia de 2 h (`0` líneas en la ventana) y **0** residuos de la lista negra | `Select-String` + manifiesto | doc v2 |
| **CA-W3b-07** | **Defender OFF** en `prep` y `cleanup` (`DEFENDER_OFF=1`, `Tamper=False`, `WinDefend=Stopped`); WU off; `powercfg=0` | salida literal | `verificar_windows.ps1` |
| **CA-W3b-08** | **Sesión `angel`** activa (`SESION_ANGEL=1`) y tarea `Interactive` `Ready` | salida | `prep` |
| **CA-W3b-09** | **`arm` idempotente**: 2.º `arm` **no** ejecuta `on` y un fichero de prueba en `archives` **sobrevive** | log + `sha256` del fichero | control v4 |
| **CA-W3b-10** | **`cleanup` bloqueado** sin `crudo.done` (`exit 84`) y correcto después (`logall_json=no` + `CONFIG_IDENTICA`) | `exit` + log | control v4 |
| **CA-W3b-11** | **`crudo` sellado**: `archives`+`alerts` copiados, `MANIFEST.tsv`+`sha256`, dedupe, `M` **de la copia** con `--estricto --agent-id 002` | `denominador_M.csv` + `MANIFEST` | `crudo_meta.md` |
| **CA-W3b-12** | **Chivato 0 huellas**: 1 chequeo ⇒ **0 alertas nuevas**; `HB_EDAD_MIN ≤ 12`; **0** SSH del host; `HIJOS_VMTOOLSD=0`; 1 conexión `:9095` (nivel 0) | `extraer_alertas_windows.py` + `heartbeat.jsonl` + log del invitado | `ruido_watch.csv` |
| **CA-W3b-12b** | **Keepalive 1 proceso**: `ka_instancias=1` en **24/24** latidos de las 2 h; duplicado ⇒ `segunda_instancia`; kill ⇒ **ALARMA ≤ 12 min** + recuperación declarada; tras reinicio **1** instancia | `heartbeat.jsonl` + `Get-CimInstance Win32_Process` | `ruido_keepalive.csv` |
| **CA-W3b-13** | **Doble FPR**: canónico y `sin_operador`, con recuentos; **ruido total ≤ 5 %** (esperado < 0,2 %); `sha256` de ambos CSV | `etiquetar_operador_legit.py` + `contar_denominador.py` | `alertas_detalle_operador.csv` |
| **CA-W3b-14** | **`drytest` PASS** VM on/off con el controlador v4: 0 FALLO, 0 falsas alarmas | `drytest.log` | `legit/evidencia/` |
| **CA-W3b-15** | **Higiene**: 0 secretos; `git status` acotado; plan v2 **intacto** (`sha256`); prohibidos sin tocar | `git status` + `sha256` | repo |
| **CA-W3b-16** | **Docs**: `snapshot_windows_legit_v2.md` + puntero en v1; `BUILD.md`; `b10_windows_sellado.md`; `estado_crudo.md` | revisión | repo |
| **CA-W3b-17** | **Manifiesto en cada arranque**: `prep` aborta (`exit 46`) si `DIFIERE`; prueba negativa con un fichero prohibido | prueba reproducible | control v4 |
| **CA-W3b-18** | **Declaraciones M-1…M-13** escritas y revisadas | §11 | este plan + memoria |
| **CA-W3b-19** | **Comparabilidad Linux↔Windows** firmada antes de `t0`: tabla §8.3 con cifras y conclusión | ficha | `comparabilidad_windows.md` |
| **CA-W3b-20** | **Sink resiliente**: caída ⇒ `hb=FAIL` + `estado.json` intacto + ALARMA; vuelta ⇒ reanuda; puerto ocupado ⇒ `exit 48`; `sha256_prev` encadenado | prueba de caída + `heartbeat.jsonl` | `heartbeat_sink.log` |
| **CA-W3b-21** | **Reloj continuo**: Δ(`recv_utc`, `ts_utc`) ≤ 2 s en el 99 % de los latidos; > 5 s sostenido ⇒ inválida | `heartbeat.jsonl` | `ventana_meta.md` |

---

## 13. Ficheros que se tocarán

| Ruta | Tipo | Qué |
|---|---|---|
| `_fases/windows-legit-prep/plan_w3bis.md` | **nuevo** | este plan (v2) |
| `Soporte/Laboratorio/windows/host/heartbeat_sink.py` | **nuevo** | sink 9095 (JSONL + `sha256_prev` + `recv_utc`) |
| `Soporte/Laboratorio/windows/guest/tfg_keepalive_windows.ps1` | mod | `-Loop` + `-Once` + mutex + latido + `estado.json` 60 min |
| `Soporte/Laboratorio/windows/guest/instalar_tareas_windows.ps1` | mod | tarea al arrancar + `IgnoreNew` + `RestartCount` |
| `Soporte/Laboratorio/windows/guest/verificar_windows.ps1` | mod | Defender, sesión, manifiesto |
| `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` | mod | v4: `watch` sin SSH, `G-W13`, `arm` idempotente, `crudo`, `cleanup` bloqueado |
| `Soporte/Laboratorio/windows/deploy_windows.ps1` | mod | `-ClienteDir`, versión, `sha256` |
| `Soporte/Laboratorio/windows/guest/manifiesto_snapshot.ps1` | **nuevo** | manifiesto + lista negra |
| `_artefactos/scripts/etiquetar_operador_legit.py` + `tests/` | **nuevo** | `sin_operador` de la ventana legítima |
| `Soporte/Laboratorio/windows/legit/snapshot_windows_legit_v2.md` | **nuevo** | doc del v2 |
| `Soporte/Laboratorio/windows/legit/BUILD.md` | **nuevo** | procedencia del cliente |
| `Soporte/Laboratorio/windows/legit/evidencia/keepalive_2h/` | **nuevo** | evidencia sellada (sin secretos) |
| `Soporte/Laboratorio/windows/legit/evidencia/{ruido_watch,ruido_keepalive}.csv` | **nuevo** | medición del ruido |
| `Soporte/Laboratorio/windows/legit/comparabilidad_windows.md` | **nuevo** | tabla §8.3 firmada |
| `Soporte/Laboratorio/windows/legit/snapshot_windows_legit.md` | mod | **una línea** de puntero al v2 |
| `Soporte/Laboratorio/crudo/estado_crudo.md` | mod | nota del `crudo` de la ventana Windows |
| `state.md`, `roadmap.md` | mod | **orquestador** |

**No se toca:** plan v2, plan de Linux, `_recursos/`, `Hojas/`, `Dataset/`, `Soporte/Metrica/`,
corpus, ruleset, config de Sysmon, `contar_denominador.py`, `extraer_alertas.py`,
`exportar_acciones.sh`, `campana*.py`, `filtrar_ruido_windows.py`, `sink_http.py`,
`legitimo_host_control.ps1`, recetas, campaña.

---

## 14. Lo que queda por decidir (poco)

| # | Pregunta | Mi recomendación |
|---|---|---|
| **Q1** | **Puerto del chivato:** ¿**9095** dedicado (recomendado) o reutilizar 9090 (sink de ataques, apagado fuera de ataque)? | **9095**: evita colisiones y deja 9090/9091/9092 para ataques |
| **Q2** | **Kill duro del bucle:** ¿aceptas que **no** se auto-reinicie (Task Scheduler no lo considera fallo) y que la garantía sea **ALARMA ≤ 12 min + `schtasks /run`** como incidencia declarada? La alternativa (watchdog cada 5 min) reintroduce 288 procesos/día | **Sí** a la primera. Es la única opción que mantiene «1 proceso» |
| **Q3** | **Snapshot:** ¿`lab-listo-windows-legit-v2` **hermano** de v1, v1 intacto y **8** snapshots? | **Sí** |
| **Q4** | **`eventcreate`:** ¿tarea elevada **pre-creada en `prep`** si a `Medium` falla? | **Sí** |
| **Q5** | **Prueba de 2 h:** ¿con el **cliente final** y **antes** del snapshot, sellando antes de borrar los logs? | **Sí** |

> Si no hay objeción a Q1-Q5, el plan queda **listo para ejecutar** en cuanto lo apruebes.
> **Nada se ejecuta hasta entonces.**

---

## 15. Veredicto del planificador

> **El v2 arregla la raíz, no el síntoma.** El v1 intentaba **medir** el ruido y convivir con él;
> el v2 lo **elimina en origen**: un solo proceso de keepalive (1 `powershell.exe` en 72 h) y un
> `watch` que **no entra** en el invitado (0 procesos). El ruido del operador pasa de **16-36 %** a
> **< 0,2 %**, y el umbral del 5 % se cumple con **~45× de margen**.
>
> **Lo que sigue siendo cierto y no se maquilla:** el kill duro del bucle no se auto-reinicia (se
> detecta y se declara), el `M` de Windows sigue siendo desconocido hasta WE0-9, y el snapshot v2
> cuelga de un padre que se llama «ataques» (se demuestra limpio con manifiesto + lista negra).
>
> **Coste:** **15 h** ≈ 2,5 jornadas + 2 h de reloj. **Riesgo residual:** bajo, y los tres que más
> preocupan (cliente que no reporta, `crudo` sin sellar, chivato caído) tienen prueba y mitigación
> escritas.

---

## 16. Enmiendas aprobadas por el humano (2026-11-10)

> Añadidas por el orquestador tras la aprobación. **No cambian el diseño**; atan dos fugas
> detectadas en la revisión final.

### 16.1 `FIM`/`Sysmon`: los logs del keepalive no se vigilan

El keepalive escribe en `C:\Users\angel\ghosts-client\logs\` (`keepalive.log`, `recovery.log`)
y `estado.json`/`heartbeat.jsonl`. `estado.json` ya se escribe **cada 60 min** (§4.2-bis) para no
disparar `Sysmon 11`; pero un **append** sigue generando **eventos de contenido** si el FIM
vigila esa ruta.

**Regla (CA-W3b-22):**
1. **Antes** de sellar el v2, comprobar en la config de `syscheck` del agente `002` si alguna de
   esas rutas está vigilada.
2. Si lo está, **excluirla** (o mover los logs a una ruta no vigilada) y **re-sellar** el snapshot.
3. **Prueba:** 2 ciclos del keepalive ⇒ **0** alertas `550/553/554` sobre esas rutas.
4. Se declara en `snapshot_windows_legit_v2.md`.

### 16.2 Unidad de FP: la misma que Linux

La métrica de Linux cuenta `FP_uni` por **línea de `archives`**. Windows debe usar **la misma
unidad**, no "alerta".

**Regla (CA-W3b-23):**
1. `M` y `FP_uni` de Windows se calculan sobre **líneas de `archives`** (`contar_denominador.py`
   con `--agent-id 002`), igual que Linux.
2. El **doble FPR** (canónico y `sin_operador`) se expresa en esa unidad.
3. **Prueba:** recalcular el FPR de Linux (`legitimo-analisis`) con la **misma** unidad y
   comprobar que reproduce `0,857963` / `0,664693`; si no, el desajuste se declara **antes** de
   publicar nada de Windows.
4. La comparación Linux↔Windows se hace con la **sensibilidad `sin_operador`**, no con el
   canónico.
