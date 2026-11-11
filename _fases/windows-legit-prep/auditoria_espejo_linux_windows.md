---
bloque: windows-legit-prep-w3bis
nombre: Auditoría comparativa Linux ↔ Windows del espejo legítimo (divergencias y validador)
version: 2
status: pending_human
fecha: 2026-11-11
autor: tfg-planner
ronda_2: >-
  Barrido adversarial de tests, validadores, sellos, evidencias, ventana, campaña y plan.
  **Hallazgos nuevos: D-08** (el sello `sha256sums.txt` está **obsoleto en 9 entradas Windows** y
  **no cubre 4 artefactos esenciales**), **D-09** (la invariante **L-1** no se valida en Windows;
  el test que la menciona mide Linux), **D-10** (la receta Windows **no tiene lista blanca de
  binarios**), **D-11** (`n_acciones` de la campaña no se compara con el esperado), **D-12**
  (supuestos falsos que siguen escritos en los planes) y **D-13** (el gate del manifiesto no
  nombra el fichero que difiere). Se corrigen además dos imprecisiones de la ronda 1.
depende_de: >-
  `_fases/windows-legit-prep/plan_w3bis.md` **v2** (`4237a16`, aprobado) · T1/T2b-1/T2b-2/T3
  PASA · T4 **parado en WE0-2 (4/5)** (`Soporte/Laboratorio/windows/legit/evidencia/t4/README.md`) ·
  `_fases/legitimo-v3/plan.md` v5 · `_fases/legitimo-analisis/plan.md` ·
  `Soporte/Laboratorio/legitimo_72h/{prueba_en_seco.md,prueba_en_seco_v3.md,README.md,sha256sums.txt}` ·
  `Dataset/Legitimo/legitimo_72h/` · clon GHOSTS `v8.3.1` (`4d2e1608`)
no_toca: >-
  `_recursos/` · `Hojas/` · `Dataset/` · `Soporte/Metrica/` · corpus · ruleset · config de Sysmon ·
  planes aprobados · recetas `w1/w2/w3` · `bloques_windows.env` · `casos_windows.md` ·
  `campana_windows.csv` · `Soporte/Ataques/receiver/sink_http.py` · `filtrar_ruido_windows.py` ·
  `contar_denominador.py` · `extraer_alertas.py` · `exportar_acciones.sh` · snapshots
ejecuta_ahora: >-
  NADA. Auditoría de solo lectura. No se ejecuta ninguna VM, ataque, compilación ni corrección.
---

# auditoria_espejo_linux_windows.md — ¿está Windows repitiendo fallos que Linux ya cerró?

> **Convención:** **[H]** hecho comprobado con fuente `fichero:línea` · **[D]** juicio de esta
> auditoría · **[S]** duda que exige una comprobación.

---

## 0. Resumen en diez líneas

1. **Sí, hay un patrón**: Windows **rebaja** invariantes de Linux con una justificación
   plausible, y luego **escribe un test que consagra la rebaja**. El caso del `|` es el ejemplo
   perfecto: Linux prohíbe **cualquier** pipe (`construir_receta_legitima.py:1317`,
   `campana.py:149`); Windows lo permite **dentro de PowerShell** (`:1420`, `_sin_ps`) y **lo exige**
   en un test (`test_campana_windows.py:103-110`). WE0-2 lo desmintió: 4/5.
2. **La causa raíz del 4/5 está en el servidor**, no en el cliente: `QueueSyncService.cs:178`
   parte la línea de resultado por `|`; un `|` dentro del comando rompe el JSON y **pierde el
   reporte** (la acción **sí** se ejecuta).
3. **Segundo fallo real, silencioso**: el `M` de Windows se sella con **`boveda_version=2`**
   (el defecto de Linux) porque `crudo` no pasa `--boveda-version 3`
   (`contar_denominador.py:50`; `windows_legit_host_control.ps1:1115`;
   `D:\TFG-VMs\legitimo-windows-2026-11-11\crudo\denominador_M.csv:1`).
4. **Tercer fallo real**: el `crudo` selecciona ficheros con `find -newermt "<fecha local>"`
   en vez de por día UTC como Linux (`exportar_denominador.sh:58-81`); si el manager no está en
   UTC, `M` puede perder horas.
5. **Cuarto**: el sink `:9095` **no gestiona regla de firewall** (`Start-Sink`,
   `windows_legit_host_control.ps1:397-421`), aunque el plan v2 **C-8** promete retirarla sin que
   ninguna fase la cree; el cierre puede dejar residuo o el arranque limpio puede quedar bloqueado.
6. **Quinto**: Windows **no tiene** equivalentes de `verificar_validez_ventana.py` ni
   `promover_ventana_legitimo.py`; la validez W-V y la promoción serían **manuales**.
7. **Lo que está bien y es mejor que Linux**: chivato por red (0 huellas), keepalive de 1 proceso,
   `arm` idempotente, `crudo` bloqueando `cleanup`, 14 guardarraíles, manifiesto + lista negra,
   y la unidad de `M` = línea de `archives` (la misma que Linux).
8. **La medición de ruido es prometedora pero incompleta**: 0/365 en 41,5 min con 3 chequeos
   ad-hoc (no 30 min) y `G-W7` en SKIP por no haber `arm` (`resumen_ruido.md`).
9. **La ronda 2 encontró el fallo que faltaba**: **el sello global no certifica el código**
   (9 entradas obsoletas + 4 artefactos sin sellar; D-08), **L-1 no se valida en Windows**
   (D-09), **no hay lista blanca de binarios** (D-10) y **`n_acciones` no se compara** (D-11).
10. **El coste de corregir antes de T4 es ~14 h**; el coste de **no** corregir es una campaña
    con `n_acciones=0` en W-07, un `M` con la bóveda equivocada y un sello que no certifica el
    código que midió la ventana.
11. **No he tocado nada**: solo lectura; el fichero que escribo es este.

### 0.4 Ronda 2 en una tabla

| # | Hallazgo nuevo | Gravedad | Evidencia |
|---|---|---|---|
| **D-08** | El sello `sha256sums.txt` está **obsoleto en 9 entradas Windows** y **no cubre 4 artefactos esenciales**; ningún gate lo compara | **ALTA** | `sha256sums.txt` vs `Get-FileHash` (9/178); `G-W4:522` |
| **D-09** | **L-1** no se valida en Windows; el test que la menciona mide Linux | **MEDIA-ALTA** | `construir_receta_legitima.py:1403` vs `construir_receta_legitima_windows.py` |
| **D-10** | La receta Windows **no tiene lista blanca de binarios** | **MEDIA** | `construir_receta_legitima.py:1335-1337` vs `:1398-1433` |
| **D-11** | `n_acciones` de la campaña **no se compara** con el esperado | **MEDIA** | `extraer_campana_windows.py:611` |
| **D-12** | Supuestos **falsos/caducados** en los planes (pipes, B-1, 8 guardarraíles) | **MEDIA (docs)** | W0 §4.5; `BUILD.md` §2.1; control v4 |
| **D-13** | El gate del manifiesto **no nombra** el fichero que difiere | **BAJA** | `windows_legit_host_control.ps1:297-308` |

---

## 1. Método y alcance

Leído (solo lectura): plan v2 y README de T4; `construir_receta_legitima.py`,
`construir_receta_legitima_windows.py`, `verificar_espejo.py`, `campana.py`, `campana_windows.py`,
`contar_denominador.py`, `verificar_validez_ventana.py`, `promover_ventana_legitimo.py`;
`windows_legit_host_control.ps1`, `verificar_windows.ps1`, `tfg_keepalive_windows.ps1`,
`heartbeat_sink.py`, `deploy_windows.ps1`; recetas `w1/w2/w3.json`, `campana_windows.csv`;
evidencias T3/T4; `exportar_denominador.sh`, `legitimo_host_control.ps1`,
`prueba_en_seco{,_v3}.md`, `sha256sums.txt`; tests; clon `QueueSyncService.cs`.
**Ronda 2 (adversarial):** además, los 8 ficheros de `_artefactos/scripts/tests/` que tocan
receta/campaña/espejo/ejecución/etiquetador; **las 178 líneas del sello** comparadas una a una
con `Get-FileHash`; `BUILD.md`; `manifiesto_esperado.json`; `despliegue_actual.json`;
`instalar_tareas_windows.ps1`; `manifiesto_snapshot.ps1`; el plan W0 §4.5/WE0-2/CA-W1 y el plan
W3-bis §3.2/§7.2.
**No se ha ejecutado ninguna VM, ataque ni compilación.**

---

## 2. Comparación por dimensión

| # | Dimensión | Linux (`legitimo-v3`) | Windows (`windows-legit-prep`) | Veredicto |
|---|---|---|---|---|
| 1 | **Generación de receta** | `construir_receta_legitima.py`: 147/153/141 = 441 acciones, jitter literal | `construir_receta_legitima_windows.py`: traslado por ranuras, 163/178/163 = **504** | **OK** (espejo 504=504) |
| 2 | **Validador: pipes** | **0 `\|` en cualquier comando** (`:1317`); test `test_campana.py:105` | **0 `\|` solo fuera de PowerShell** (`:1420`, `_sin_ps`); tests que **exigen** el pipe permitido | **FALLO (D-01)** |
| 3 | **Validador: random/mutantes** | 0 `random`, 0 `sudo`, 0 comillas dobles, 0 `echo -e` | 0 `%RANDOM%`/`Get-Random`, 0 mutantes, 0 `^`, 0 backtick, 0 evasión | **OK** |
| 4 | **Validador: errores** | 10/día, `$?` exacto, `printf` con comillas (F-1), pares fallo→reintento | 10/día, `if errorlevel`, TSV 5 campos, pares, familias | **OK con diferencia declarada** (rc `ge1` vs exacto) |
| 5 | **Espejo** | — | 504=504, `DelayAfter` idéntico, fan-out 12 | **OK en conteo**; semántica **manual** [S] |
| 6 | **Campaña** | 11 casos, 22 marcas, 63 acciones, separación 180 s, **0 pipes** (`campana.py:149`) | 11/22/63, separación 180 s, **0 pipes fuera de PS** (`:874`), rutas/efectos declarados | **FALLO (D-01, mismo pipe)** |
| 7 | **Controlador** | 7 fases, 12 guardarraíles, `arm`/`stop`/`cleanup`, `cosecha.done` | 8 fases (+`crudo`), **14** guardarraíles, `arm` idempotente, `cleanup` bloqueado | **OK / mejor** |
| 8 | **`M`** | `logall_json`, unidad = línea de `archives`, agente `001`, `--boveda-version 2` | mismo script, agente `002`, **pero `--boveda-version` omitido ⇒ 2** | **FALLO (D-02)** |
| 9 | **Aislamiento del agente** | VM Linux apagada | `G-W6` exige `victima-linux` off + sin ruta por defecto | **OK** |
| 10 | **Crudo** | `copiar-ventana`: días **UTC** `D..D+2`, `.gz`+`.sum`+plano+vivo, `MANIFEST.tsv` + dedupe (`exportar_denominador.sh:50-103`) | `find -newermt` con **fecha local**, `.gz`+vivo, `MANIFEST.tsv`, `M` de la copia, `crudo.done` | **FALLO (D-03)** + gaps (D-04) |
| 11 | **Ruido del operador** | **Invisible** por `auditd` (H-COMP-1; 0/294.257) | **Visible** ⇒ chivato por red; medido **0/365** en 41,5 min | **OK / mejor**, medición parcial [S] |
| 12 | **Keepalive** | servicio `systemd` persistente; `STALE=30` | bucle persistente, mutex, `RestartCount`, al arrancar; rotación solo al cambiar día | **OK** (kill duro no auto-reinicia, declarado) |
| 13 | **Evidencias** | `sha256sums.txt` (178 líneas), `ventana_meta.md`, `MANIFEST` | `MANIFEST.sha256`, `manifiesto_esperado.json`, `despliegue_actual.json`, `crudo.done` | **FALLO (D-08)**: sello obsoleto/incompleto |
| 14 | **Validadores automáticos** | `verificar_validez_ventana.py` (V1-V7, V9) + `promover_ventana_legitimo.py` + auditor L-1 + lista blanca | **No hay** validez/promoción; **no hay** auditor L-1; **no hay** lista blanca en la receta | **GAP (D-06) + FALLO (D-09/D-10)** |
| 15 | **Cierre** | 0 VMs, 0 tareas, 0 reglas, servicios, variables | 0 VMs, 0 tareas, servicios, variables; **regla de firewall no gestionada** | **DUDA (D-07)** |
| 16 | **Sellos y cobertura** | 178 líneas; todo cuadra | **9 entradas Windows obsoletas** y **4 artefactos esenciales sin sellar**; `sha256sum -c` fallaría | **FALLO (D-08)** |
| 17 | **L-1 (huella escrita antes de leerse)** | `auditar_huellas_escritas` dentro de `validar` (`construir_receta_legitima.py:1403`) | **no se llama**; el test L-1 mide la receta **Linux** | **FALLO (D-09)** |
| 18 | **Lista blanca de binarios** | `BINARIOS_OK` (`:1335-1337`) | **no existe** en la receta Windows | **FALLO (D-10)** |
| 19 | **Ejecución de la campaña** | `n_acciones` informativo | `n_acciones` **no** se compara con el esperado | **DUDA (D-11)** |

---

## 3. Divergencias

### 3.1 (a) Fallos reales a corregir antes de T4

> **Prioridad:** **D-01** (pipe) y **D-02** (`boveda_version`) son **bloqueantes** de T4;
> **D-03** (UTC) y **D-07** (firewall) son bloqueantes del **cierre**; **D-04** es mejora;
> **D-05** es proceso; **D-06** es el gap que se cierra con el validador.

#### D-01 — El pipe: invariante de Linux rebajado, y **consagrado en tests** — **CRÍTICO**

| Qué | Evidencia |
|---|---|
| **Linux prohíbe cualquier `\|`** | `construir_receta_legitima.py:1312-1318` (`if "\|" in cmd: fallo`), `campana.py:149` (`RE_PIPE`), test `tests/test_campana.py:105` (`assert not C.RE_PIPE.search(cmd)`) |
| **Linux lo cerró con H-1** | `prueba_en_seco_v3.md:216-218`: «GHOSTS no reportaba comandos con `\|`… receta y campaña reescritas sin `\|`… validador rechaza cualquier `\|`… **147/147**» |
| **Windows lo permite** | `construir_receta_legitima_windows.py:1420` (`if "\|" in cmd and "powershell" not in cmd`), `verificar_espejo.py:207`, `campana_windows.py:874` (`if "\|" in _sin_ps(cmd)`) |
| **Windows lo documenta como seguro** | `campana_windows.py:21` («0 pipes **fuera de** `powershell -Command`»), `:206` («el pipe vive **dentro** de `powershell -Command`») |
| **Windows lo exige en tests** | `tests/test_campana_windows.py:103-110` (`assert "\|" not in _sin_ps` y `assert "powershell" in cmd`), `tests/test_construir_receta_legitima_windows.py:124`, `tests/test_verificar_espejo.py:97`, `cobertura_herramientas_windows.py:54` (fixture con el pipe) |
| **El artefacto lo contiene** | `recetas/w2.json` **#175** (W-07); `campana_windows.csv` fila W-07, 3.ª línea |
| **WE0-2 lo desmiente** | `evidencia/t4/README.md:37-45` (4 filas), `:52-64` (causa: `QueueSyncService.cs:193`, `position 108` = primer `\|`), `:66-75` (cualquier `\|` pierde el reporte; un `Bad line` no bloquea las siguientes) |
| **La causa es del servidor** | `QueueSyncService.cs:178` (`line.Split(Convert.ToChar("\|"))`) |

**Juicio [D]:** es **el mismo fallo que Linux ya había cerrado**, reintroducido por una premisa
falsa: «el pipe va dentro de un intérprete, luego el cliente captura la salida». El **cliente**
lo ejecuta y lo registra (`guest_app_we02.txt`), pero el **servidor** parte la **línea de
resultado** por `|`, y el JSON se trunca. No importa quién interpreta el comando.

**Por qué es grave aunque solo afecte a 1 de 504:** rompe la **unidad** («1 acción = 1 report»)
en el punto exacto que la campaña mide (`n_acciones` de W-07 = 0), y el test que debería
protegerlo **afirma lo contrario**. Los **419 tests en verde** no valen para este invariante.

#### D-02 — El `M` de Windows se sella con **`boveda_version=2`** — **ALTO**

| Qué | Evidencia |
|---|---|
| `contar_denominador.py` tiene **defecto Linux** `VERSION_BOVEDA = 2` | `contar_denominador.py:47-50` |
| `crudo` **no** pasa `--boveda-version` | `windows_legit_host_control.ps1:1115` (`$argsM` solo lleva agente, `--estricto`, `--out`, `--manifest`) |
| El `M` de la prueba salió con **2** | `D:\TFG-VMs\legitimo-windows-2026-11-11\crudo\denominador_M.csv:1` (`boveda_version=2`), `:3-4` (`1,2,total…`) |
| El plan exige **3** | `plan_w3bis.md` v2 §7.2 C-4 y CA-W3b-11; B10-W `boveda_version=3` |

**Juicio [D]:** un **defecto de Linux** se cuela en Windows por no sobrescribir el parámetro.
La CA pasó porque **solo miró los números** (34.820/30.041), no la cabecera. Es el segundo
ejemplo del patrón: *«lo que Linux hace por defecto no es lo que Windows necesita»*.

#### D-03 — `crudo` selecciona por `mtime` en **hora local**, no por día UTC — **MEDIO-ALTO**

| Qué | Evidencia |
|---|---|
| Linux: días **UTC** `D..D+2` con `date -u` | `exportar_denominador.sh:57-74` |
| Windows: `find -newermt "<yyyy-MM-dd HH:mm:ss>"` | `windows_legit_host_control.ps1:1067-1069` |
| La cadena **no lleva zona**; `find` la interpreta en la **local del manager** | `:1067` (`ToString('yyyy-MM-dd HH:mm:ss')` tras `ToUniversalTime`) |

**Juicio [D]:** si el manager está en UTC (probable), no hay daño; si está en otra zona, `M`
puede **perder horas** del principio o incluir de más. Linux lo evita **por construcción**. Es
una divergencia no declarada. **[S]** comprobar `date +%Z` en el manager y, si no es UTC, fijar
`TZ=UTC` o pasar a selección por día como Linux.

#### D-04 — `crudo` no copia `.sum` ni el plano diario — **BAJO**

| Qué | Evidencia |
|---|---|
| Linux copia `.gz` **+ `.gz.sum`** y el plano `ossec-archive-NN.json` si existe | `exportar_denominador.sh:64-73` |
| Windows copia solo `.gz` + `archives.json` vivo | `windows_legit_host_control.ps1:1069` (patrón: `archives.json`, `alerts.json`, `ossec-archive-*.json.gz`, `ossec-alert-*.json.gz`) |

**Juicio [D]:** el `.gz.sum` es la huella **de Wazuh**; perderla no impide el `M` (calculamos
nuestro `sha256`), pero **debilita la cadena**. El plano es redundante con el `.gz`. Se
recomienda **añadir `.sum`** (1 línea) y **declarar** el plano.

#### D-05 — El sello global no se actualiza tras la corrección — **CONFIRMADO por D-08**

`Soporte/Laboratorio/legitimo_72h/sha256sums.txt` (178 líneas) incluye las entradas Windows
(`campana_windows.csv`, `casos_windows.md`, `w1/w2/w3.json`, `bloques_windows.env`,
`calendario_windows.json`, `receta_windows_resumen.md` y los scripts). **La ronda 2 comprueba que
9 de esas entradas ya están obsoletas** (D-08), no solo que lo estarán tras corregir W-07.

#### D-06 — No hay validador de **validez de ventana** ni de **promoción** para Windows — **MEDIO (gap)**

| Linux | Windows |
|---|---|
| `verificar_validez_ventana.py` (V1-V7, V9; `:1-15`) | **no existe**; W-V1…W-V9 se comprueban a mano |
| `promover_ventana_legitimo.py` (`--check`/`--apply`, cabecera `#` de procedencia; `:1-20`) | **no existe**; la promoción a `Dataset/Legitimo/windows/` sería manual |

**Juicio [D]:** después de 72 h, la diferencia entre «ventana válida» y «ventana con incidencia»
depende de un checker que en Linux es **ejecutable** y en Windows sería **una lectura humana**.
No bloquea T4, pero **sí** bloquea el cierre con la misma calidad.

#### D-07 — La regla de firewall del sink no se gestiona — **MEDIO (cierre / arranque limpio)**

`Start-Sink` (`windows_legit_host_control.ps1:397-421`) arranca el sink y comprueba el puerto,
pero **no crea** `New-NetFirewallRule`; el plan v2 **C-8** dice «retirar la regla de firewall»,
pero **ninguna fase la crea** (§4.2 solo exige que el puerto esté libre). T3/T4 funcionaron (el
POST del invitado llegó), así que o el perfil permite Python o hay una regla creada a mano.
**[S]** comprobar `Get-NetFirewallRule -DisplayName 'TFG-hb-*'` y el perfil de VMnet1; si existe
una regla manual, **retirarla** en `cleanup`; si no existe, **declarar** por qué funciona y
**crear la regla** para que un arranque limpio no dependa de la suerte.

> **Corrección a la ronda 1 (precisión):** el puerto correcto es **9095** (no 9090) y el plan
> **no** prometía crearla en §4.2: solo C-8 promete **retirarla**. La divergencia real es que
> **no se crea ni se retira**; el resto del juicio se mantiene.

#### D-08 — El **sello global está obsoleto e incompleto** — **ALTA (evidencia)**

| Qué | Evidencia |
|---|---|
| **9 entradas Windows del sello no coinciden con el fichero real** | `sha256sums.txt` vs `Get-FileHash`: `bloques_windows.env` (`1a008ae3…`→`9a10ae35…`), `calendario_windows.json` (`f306c2a9…`→`fbc692e3…`), `extraer_alertas_windows.py` (`d5f67ea3…`→`5924c255…`), `test_extraer_alertas_windows.py` (`7d84610f…`→`541ff6d3…`), `windows_legit_host_control.ps1` (`220d7c70…`→`1f390bfa…`), `deploy_windows.ps1` (`c84395ce…`→`c70453a0…`), `instalar_tareas_windows.ps1` (`762b345e…`→`d7c17a3f…`), `tfg_keepalive_windows.ps1` (`15a82b71…`→`c05aed58…`), `verificar_windows.ps1` (`0b5cf4b1…`→`c07ef524…`) |
| **Solo las 9 Windows están obsoletas** | de **178** entradas, las **169** restantes (Linux + herramientas Python + tests) **cuadran**. Es un fallo **específico de Windows**, no una práctica general |
| **4 artefactos esenciales no están en el sello** | `legit/heartbeat_sink.py` (chivato), `_artefactos/scripts/etiquetar_operador_legit.py` (doble FPR), `Soporte/Laboratorio/windows/manifiesto_snapshot.ps1` (genera el sello del snapshot) y `legit/BUILD.md` (procedencia del cliente) |
| **Nada compara el sello con el código** | `G-W4` (`windows_legit_host_control.ps1:522`) imprime el `sha256` de `w1/w2/w3` (que **sí** cuadran) y no recorre `sha256sums.txt`; ningún test hace `sha256sum -c` |

**Juicio [D]:** el sello es la prueba de **qué código midió la ventana**. Hoy certifica una
versión **anterior** de los 4 scripts que ejecutan `prep`/`arm`/`crudo`/`cleanup` y del entorno
que fija `boveda_version` y el mapa de días. Es el mismo patrón que D-01: una comprobación que
**parece** integridad (imprime hashes) pero **no compara** con el sello, y un sello que nadie
regenera. **Bloqueante de T4** (el snapshot v2 y B10-W se sellarían con hashes viejos).

#### D-09 — La invariante **L-1** no se valida en Windows; el test mide Linux — **MEDIA-ALTA**

| Qué | Evidencia |
|---|---|
| Linux exige que **toda huella leída se haya escrito antes** | `auditar_huellas_escritas` (`construir_receta_legitima.py:1213`) y **se llama** en `validar` (`:1403`) |
| Windows **no** lo comprueba | `construir_receta_legitima_windows.py` no contiene `auditar`/`huellas_escritas`; su `validar` (1219-1395) no lo llama |
| El test que menciona L-1 **mide Linux** | `test_ejecucion_windows.py:227-252`: `test_linux_la_huella_de_la_copia_se_redirige` usa `L.componer_dia(1)` y las recetas `d1/d2/d3.json`; el negativo `test_el_auditor_l1_detecta…` llama `L.auditar_huellas_escritas` con comandos `sha256sum`/`cat` |
| El equivalente Windows existe pero **no se audita** | `certutil -hashfile … > …sha256` (`:298-302`) y `type …sha256` (`:342,377`); si se pierde el `>`, `--check` y los tests siguen en verde |

**Juicio [D]:** es el patrón exacto: **una invariante de Linux sin equivalente en Windows y un
test con nombre tranquilizador que mide la función Linux**. El fallo de L-1 en Linux fue real
(«`cat` de una huella que nadie crea, todos los días»); en Windows la regresión sería silenciosa
(el `type` fallaría en la ventana y la acción no se reportaría o se reportaría con error).

#### D-10 — La receta Windows **no tiene lista blanca de binarios** — **MEDIA**

| Qué | Evidencia |
|---|---|
| Linux valida `binarios_de(cmd) ⊆ BINARIOS_OK` | `construir_receta_legitima.py:1335-1337`; `BINARIOS_OK` (34) y `BINARIOS_CAMPANA` (`:161-172`) |
| Windows **no** valida ninguna lista | `validar_comando` (`construir_receta_legitima_windows.py:1398-1433`) no tiene lista; `validar` (1219-1395) tampoco |
| La **campaña** sí declara binarios por caso | `campana_windows.py:1027-1040` (`sobran`/`faltan`), pero la **receta** no |

**Juicio [D]:** una herramienta no declarada podría entrar en la receta de 72 h y pasar `--check`
y `verificar_espejo`; solo la revisión humana o `cobertura_herramientas_windows.py` (que mide
cobertura, no lista blanca) lo notaría. Rompe el argumento «las herramientas salen del ruleset y
del inventario». **No es bloqueante de T4**, pero debe corregirse antes de `t0`.

#### D-11 — `n_acciones` de la campaña **no se compara** con el esperado — **MEDIA**

`extraer_campana_windows.py:611` escribe `n_acciones` desde `history_timeline`, pero **no lo
compara** con las acciones pre-registradas del caso; `esperado_cumplido` es `SI` si aparece
`67027` y `level < 7` (`:20`), y `NO_EJECUTADO` solo si **no hay marcas**. Con W-07 reportando
4 de 5, la tabla diría `SI` y `n_acciones=4` sin marcar nada. **Linux tiene la misma lógica**
(`extraer_campana.py:483`), pero **no lo necesitaba** porque H-1 eliminó los pipes; Windows sí.
**No es una rebaja respecto de Linux, es una brecha compartida que en Windows se vuelve
peligrosa.** Propuesta: `REPORTE_INCOMPLETO` si `n_acciones < esperadas` (con el esperado leído
de `campana_windows.csv`).

#### D-12 — Supuestos **falsos o caducados** que siguen escritos en los planes — **MEDIA (documentación)**

| Dónde | Qué dice | Realidad |
|---|---|---|
| **W0 `plan.md` §4.5** (`:205-206, 347`) | «los pipes **dentro** de `powershell -Command` **sí** se permiten» | **Falso**: el servidor parte la línea por `\|` (`QueueSyncService.cs:178`); WE0-2 4/5 |
| **W0 `plan.md` WE0-2** (`:519`) | «incluye una con `\|` … si < 5/5 ⇒ **se prohíben los pipes internos** y se declara» | **Es exactamente lo que toca ahora**: la opción A **ya estaba prevista** en el plan aprobado |
| **W0 `plan.md` CA-W1** (`:682`) | «**0 pipes de `cmd`**» | Se interpretó como «fuera de PowerShell»; debe leerse **0 pipes en todo el texto** |
| **W3-bis `plan_w3bis.md` §3.2 B-1** (`:129`) | «VS Build Tools 2022 + targeting pack + `nuget.exe`» | **No se usó**: `BUILD.md` §2.1 documenta `dotnet msbuild` + *reference assemblies* NuGet (mejor y ya hecho) |
| **W3-bis `plan_w3bis.md` §7.2/M-2** (`:353, 509`) | «**8** guardarraíles del `watch`» | El controlador v4 evalúa **9** en `watch` (`G-W5…G-W14`) y **14** en total (`G-W1…G-W14`) |

**Juicio [D]:** el ejecutor **cumplió el plan**; el plan contenía la premisa falsa. No se
reescribe un plan aprobado: se añade una **nota de corrección** (como §16.4 del W0) que
sustituya §4.5/CA-W1, fije B-1 como superado y declare **9/14** guardarraíles. Sin esa nota, el
tester y la memoria seguirían citando 8 y «pipes permitidos».

#### D-13 — El gate del manifiesto **no nombra el fichero** que difiere — **BAJA (mejora)**

`Test-ManifiestoEsperado` (`windows_legit_host_control.ps1:297-308`) compara **solo**
`MANIFEST_SHA256`; el `manifiesto_esperado.json` tiene la lista por fichero (`ficheros`) pero no
se usa para el `diff`. El gate **falla cerrado** (bien), pero un `DIFIERE` no dice **qué** fichero
sobra o cambia, y en la ventana eso cuesta tiempo. Además, el sello actual es de **304** ficheros
(base `v1`) y el v2 dará **294** (base `-ataques-gui`): hay que regenerarlo para el v2 (ya
previsto en A-05). **No bloquea**, pero mejora el diagnóstico.

### 3.2 (b) Diferencias aceptadas y declaradas (no son fallos)

| # | Diferencia | Por qué se acepta | Dónde está declarada |
|---|---|---|---|
| A-01 | `Interactive` (IL Medium) vs tarea de Linux | Windows no tiene el equivalente; medido con `test_il.ps1` | `snapshot_windows_legit.md` §6.3 |
| A-02 | `M` absoluto no comparable; unidad `FP/acción`/`FP/hora` | Telemetrías distintas | `comparabilidad_windows.md`; `metrica_hids.md:66-68` |
| A-03 | 9 guardarraíles en `watch` (G-W5/G-W7/G-W8/G-W9/G-W10/G-W11/G-W12/G-W13/G-W14) vs 9 señales de Linux | La **composición** cambia: G-W13 (latido) y G-W14 (Defender) no tienen pareja exacta; `doing_age`/`sin_eventos` post-hoc | plan v2 §7.2 (dice «8»: **D-12**); `snapshot…` D7 |
| A-04 | El operador es **invisible** en Linux y **visible** en Windows | `auditd` no audita VMware Tools (H-COMP-1); de ahí el chivato | `comparabilidad_windows.md` H-COMP-1 |
| A-05 | `v1` tiene **10 ficheros viejos** del cliente 8.0.0 (294 vs 304) | `robocopy` no purga; v2 usa la base limpia `-ataques-gui` | `t4/README.md:24-27` |
| A-06 | El manager sigue encendido en `cleanup` | Hace falta para `logall_json off` + `CONFIG_IDENTICA` | control v4 (C-1) |
| A-07 | `eventcreate` puede exigir elevación | Opción A: tarea elevada pre-creada, declarada | plan v2 R12 |
| A-08 | `rc=ge1` en vez del `$?` exacto | `cmd` no da el código sin una acción extra | plan v2 §4.4 |
| A-09 | 3 chequeos T3 ad-hoc (18/23 min) y `G-W7` SKIP | No había `arm`/`ventana_actual.json`; T4 haría el real | `resumen_ruido.md`; `comparabilidad…` |
| A-10 | `findstr` rc 1 no es error | Coincidencia vacía legítima | plan v2 §4.4 |

### 3.3 (c) Dudas que hay que resolver con una comprobación (no con una opinión)

| # | Duda | Comprobación concreta | Impacto si sale mal |
|---|---|---|---|
| S-01 | **Zona horaria del manager** | en `crudo`: `date +%Z` y `date -u`; si no es UTC, `M` puede perder horas | `M` mal |
| S-02 | **Regla/perfil de firewall del sink** | `Get-NetFirewallRule -DisplayName 'TFG-hb-*'`; perfil de VMnet1 | latido bloqueado o residuo |
| S-03 | **`find -newermt` incluye el `.gz` de D+3** | comparar `MANIFEST` con la lista de días `D..D+2` | crudo con datos post-`t1` (se filtran por `--hasta`, pero el MANIFEST los lista) |
| S-04 | **`MANIFEST.tsv` con BOM/CRLF** | `Format-Hex` de las primeras líneas; `Get-Content` desde Python | parsers que esperan ASCII |
| S-05 | **`verificar_espejo` no compara semántica** | revisión humana del cambio W-07 (misma transformación CSV) | un cambio «equivalente» que no lo sea |
| S-06 | **`stop` acepta `cosecha.done` heredado** | `windows_legit_host_control.ps1:1144`; decidir si se restringe a `crudo.done` | parar la VM antes del crudo (el manager sigue on; riesgo bajo) |
| S-07 | **El `M` de la prueba usó un día completo** | `denominador_M.csv:1` (`00:00:00Z..23:59:59Z`), no la ventana | el `crudo` real debe usar `ventana_actual.json` (T4 lo verifica) |

---

## 4. Decisión del pipe (WE0-2 4/5): **opción A, confirmada**

### 4.1 Comando exacto

**Antes** (`recetas/w2.json` #175; `campana_windows.csv` W-07, 3.ª línea):

```
cd /d C:\lab-legit\campana\W-07 && powershell -NoProfile -Command "(Get-Content -LiteralPath 'C:\lab-legit\campana\W-07\export.csv') -replace ';',',' | Set-Content -LiteralPath 'C:\lab-legit\campana\W-07\export.csv'"
```

**Después** (sin `|`, misma semántica, mismo proceso):

```
cd /d C:\lab-legit\campana\W-07 && powershell -NoProfile -Command "$c = (Get-Content -LiteralPath 'C:\lab-legit\campana\W-07\export.csv') -replace ';',','; Set-Content -LiteralPath 'C:\lab-legit\campana\W-07\export.csv' -Value $c"
```

**Comprobaciones del comando nuevo [D]:**

| Regla | Resultado |
|---|---|
| `0` `\|` en todo el texto | **sí** |
| Prefijo `cd /d <carpeta> &&` | **sí** (misma carpeta del caso) |
| Comillas dobles compensadas | **2** (las del argumento de `-Command`) |
| `cmd /c` de primer nivel | **no** (lo pone el handler) |
| `^`, backtick, `%RANDOM%`, mutantes, evasión | **no** |
| `;` dentro de comillas | `cmd` no lo parte; PowerShell lo usa como separador de sentencias |
| `$c` | `cmd` no expande `$`; PowerShell sí |
| Procesos | **1** `powershell.exe` (igual que antes) |
| Efecto | lee `export.csv`, sustituye `;`→`,`, reescribe el mismo fichero (idéntico) |

**Alternativa descartada:** `-replace ... | Out-File` (sigue teniendo pipe) y `cmd /c
for /f ...` (rompe la unidad de 1 proceso y añade ruido). La forma con variable es la mínima.

> **Por qué NO se vuelve al cliente publicado (R2-b):** la causa está en el **servidor**
> (`QueueSyncService.cs:178`), no en el binario. El cliente 8.2.1.0 usa **el mismo formato de
> cola**, así que volver atrás **no** arreglaría el 5.º reporte; solo perdería el 8.3.1. La
> opción A es la única que corrige la causa.

### 4.2 Radio de impacto (lo que hay que cambiar, no solo el JSON)

| # | Artefacto | Cambio | Evidencia |
|---|---|---|---|
| 1 | `construir_receta_legitima_windows.py` | regla `_c_sed_i` (`:610-614`) sin `\|`; docstring «W-07: `\|` dentro de `-Command`» fuera | `:610-614` |
| 2 | `recetas/w2.json` | regenerar (1 acción) | `w2.json` #175 |
| 3 | `campana_windows.csv` | regenerar (fila W-07) | CSV, columna `comandos` |
| 4 | `casos_windows.md` | regenerar si incluye el comando; cambia `sha256_casos_md` de la cabecera del CSV | `campana_windows.py:532-536` |
| 5 | `construir_receta_legitima_windows.py:1420` | `if "\|" in cmd:` (sin excepción de PowerShell) | `:1420` |
| 6 | `verificar_espejo.py:207` | ídem | `:207` |
| 7 | `campana_windows.py:874` y `:21`/`:206` | `if "\|" in cmd:` + docstring | `:21,206,874` |
| 8 | `tests/test_construir_receta_legitima_windows.py:124` | invertir: **0 pipes** en toda la receta | `:124` |
| 9 | `tests/test_campana_windows.py:103-110` | invertir: **0 pipes** en toda la campaña | `:103-110` |
| 10 | `tests/test_verificar_espejo.py:97` | el mutante debe ser un pipe **en cualquier sitio** | `:97` |
| 11 | `cobertura_herramientas_windows.py:54` | quitar el fixture con pipe | `:54` |
| 12 | `sha256sums.txt` | re-sellar las 3 entradas cambiadas | 178 líneas |

### 4.3 Impacto en el espejo

**Nulo, y a mejor.** No se añade ni se quita ninguna acción: siguen **504** (163/178/163) y los
`DelayAfter` son idénticos. No cambia el número de procesos (1 `powershell.exe`), ni las reglas
esperadas (`67027` + `91801-91846`), ni el efecto (normalización del CSV). El `|` era un
**artefacto de traducción**, no parte de la técnica T1565.001; el equivalente Linux
(`sed -i 's/;/,/g'`) **no tiene pipe**. El espejo queda **más** fiel después.

**Lo que sí cambia:** `sha256` de `w2.json`, `campana_windows.csv` y `casos_windows.md`; por
tanto, el sello B10-W y el snapshot v2 deben generarse **después** del cambio. El `M` de 72 h
**no** cambia por esto (el pipe ejecutaba; solo se perdía el reporte de 1 acción).

### 4.4 Coste de la corrección del pipe

| Paso | Coste |
|---|---|
| Regla del generador + docstrings | 15 min |
| Campaña (meta, doc, CSV) | 30 min |
| 4 tests invertidos + 1 test negativo nuevo («pipe en cualquier sitio ⇒ fallo») | 45 min |
| Regenerar + `--check` + `--no-mutacion` + `verificar_espejo` + `pytest` | 30 min |
| **WE0-2 5/5** con evidencia | 45 min |
| Re-sellar `sha256sums.txt` + manifiesto | 15 min |
| **Total** | **~3 h** |

---

## 5. Validador propuesto para Windows (que estos fallos no vuelvan)

### 5.1 `verificar_paridad_windows.py` (nuevo, 4 bloques)

**Bloque 1 — Paridad diferencial de invariantes (el que habría cazado el pipe).**
No basta con «el validador de Windows pasa»: hay que demostrar que es **al menos tan estricto**
como el de Linux. Se define una tabla de invariantes compartidos y se ejecuta **el mismo corpus
de mutaciones** contra los dos validadores:

| Invariante | Linux | Windows | Prueba diferencial |
|---|---|---|---|
| `0 pipes` | `:1317` | `:1420` | inyectar `\| more` **dentro** de `powershell -Command` ⇒ **los dos** deben fallar |
| `0 random` | receta | `:1409` | inyectar `%RANDOM%` ⇒ los dos fallan |
| `0 mutante` | `campana.py:483` | `MUTANTES` | inyectar `schtasks /create` ⇒ los dos fallan |
| `0 evasión` | — | `:1411` | inyectar `-EncodedCommand` ⇒ Windows falla |
| `cd` por acción | `:1321` | `:1424` | quitar el prefijo ⇒ los dos fallan |
| Pares error/reintento | `campana.py` | `:1289-1309` | quitar un reintento ⇒ los dos fallan |
| Conteos | 441 | 504 | `--check` + `verificar_espejo` |

**Criterio:** si un invariante falla en Linux y **no** en Windows, el script **falla** (la
divergencia es un bug, no una decisión). Si es una diferencia **deliberada**, debe estar en una
lista `DIVERGENCIAS_DECLARADAS` con su justificación **y su test**.

**Bloque 2 — Sellos y metadatos (el que habría cazado `boveda_version=2`).**

| Comprobación | Cómo |
|---|---|
| `denominador_M.csv` con `metrica_version=1` y **`boveda_version=3`** | `Select-String` de la línea `#` |
| `cliente_version` coherente (`release`, `assembly`, `Domain`) | leer `BUILD.md` + `despliegue_actual.json` + `manifiesto_esperado.json` |
| **`sha256sums.txt` cuadra con TODO** | `sha256sum -c`; **hoy fallarían 9** (D-08) |
| **`sha256sums.txt` cubre TODO** | lista blanca de rutas: recetas, campaña, scripts, tests, `heartbeat_sink.py`, `etiquetar_operador_legit.py`, `manifiesto_snapshot.ps1`, `BUILD.md` |
| `manifiesto_esperado.json` presente y coincide con el `-Manifiesto` del invitado | `prep -SoloManifiesto`; y **diff por fichero** (D-13) |
| `crudo.done.manifest_sha256` == `sha256(MANIFEST.tsv)` | recomputar |

**Bloque 2b — L-1 en Windows (el que habría cazado D-09).** Portar `auditar_huellas_escritas`:
recorrer cada día en orden y exigir que todo `type <f>.sha256` tenga un
`certutil -hashfile <f> SHA256 > <f>.sha256` **anterior** en la misma jornada. Test negativo:
quitar el `>` de `B5#1` ⇒ el validador **falla**. Hoy no existe (§D-09).

**Bloque 2c — Lista blanca de binarios (D-10).** Declarar `BINARIOS_W` (las herramientas del
ruleset/inventario) y validar `binarios_de(cmd) ⊆ BINARIOS_W` en la receta, como Linux
(`:1335-1337`). Test negativo: añadir `whoami2.exe` ⇒ falla.

**Bloque 2d — `n_acciones` de la campaña (D-11).** Comparar las acciones reportadas por caso con
las pre-registradas en `campana_windows.csv`; si `n_acciones < esperadas` ⇒
`REPORTE_INCOMPLETO` (no `SI`).

**Bloque 3 — Reportabilidad en ejecución (canary, el que caza un parser nuevo).**
El generador conoce las **plantillas** de comando (~20 formas: `cmd` simple, redirección,
`&&`, `if errorlevel`, `for /L`, PowerShell con comillas, `eventcreate`, `robocopy`, `curl`,
`certutil`, `schtasks`, `reg query`…). El canary envía **una timeline con 1 evento por
plantilla** y exige `history_timeline == enviados`; si falta uno, **falla cerrado** y lista la
plantilla. Es lo que WE0-2 hizo a mano; automatizado, se ejecuta en `prep`/`WE0-2` y **antes**
de la ventana. Coste: ~1,5 h; 20 eventos.

**Bloque 4 — Validez y promoción (el gap D-06).**
Portar `verificar_validez_ventana.py` a Windows (W-V1…W-V9 leyendo `alertas_detalle.csv`,
`ghosts_acciones.csv`, `denominador_M.csv`, `heartbeat.jsonl`, `manifiesto`) y un
`promover_ventana_windows.py` con la misma cabecera `#` de procedencia. Coste: ~1,5 h. Se puede
hacer **después** de la ventana, pero **antes** de promover.

### 5.2 Regla de proceso

> **[D] Cualquier divergencia con un invariante de Linux debe entrar en
> `DIVERGENCIAS_DECLARADAS` con (1) la razón, (2) la prueba de que es segura y (3) el test que
> la protege. Si no tiene las tres, es un bug.** Es la única forma de que «Windows está peor
> que Linux» no vuelva a pasar sin que nadie lo vea.

---

## 6. Plan de corrección mínimo antes de T4

> **Orden:** **C1 → C2 → C7 → C5 → C6** para reanudar T4 (el pipe, la bóveda y el validador
> deben estar antes del nuevo WE0-2). **C3, C4 y C8** van antes de `t0` y pueden ir en paralelo.
> Nada de VMs hasta C6; todo lo demás es estático.

| Tanda | Qué | Coste | CA |
|---|---|---|---|
| **C1** | **Pipe**: generador + receta + campaña + 3 validadores + 4 tests + regenerar + `--check` + `--no-mutacion` + `verificar_espejo` + `pytest` | **3 h** | **CA-AUD-01**: `--check` y `--no-mutacion` PASA con **0 pipes en todo el texto** (receta y campaña); `verificar_espejo` 504=504; test negativo (pipe dentro de PowerShell ⇒ fallo) |
| **C2** | **`boveda_version=3`**: `$argsM += '--boveda-version','3'`; test que lee la cabecera | **0,5 h** | **CA-AUD-02**: `denominador_M.csv` línea `#` con `metrica_version=1 boveda_version=3` |
| **C7** | **Nota de corrección de los planes**: sustituir W0 §4.5/CA-W1 (0 pipes **totales**), fijar B-1 como superado (`dotnet msbuild` + refasm) y declarar **9/14** guardarraíles | **0,5 h** | **CA-AUD-07**: nota en `plan_w3bis.md` + puntero a W0 §4.5; el tester lee 0 pipes y 9/14 |
| **C5** | **Validador de paridad**: bloques 1, 2, **2b (L-1)**, **2c (lista blanca)**, **2d (`n_acciones`)** y 3 (canary) | **6 h** | **CA-AUD-05**: el corpus de mutaciones hace fallar a **los dos**; L-1 Windows falla al quitar `>`; binario no declarado falla; `n_acciones < esperadas` ⇒ `REPORTE_INCOMPLETO`; canary **N/N** |
| **C6** | **Re-WE0-2** (5/5 + canary), re-sellar `sha256sums.txt`, regenerar `manifiesto_esperado.json` del v2, **reanudar T4** | **1,5 h** + 2 h de reloj | **CA-AUD-06**: 5/5; 504/504; `sha256sum -c` **0 fallos**; WE0-2 ≤ 7 días antes de `t0` |
| **C3** | **`crudo` por día UTC**: `TZ=UTC` o `date -u` + `D..D+2`; copiar `.sum`; declarar el plano | **1 h** | **CA-AUD-03**: `crudo` imprime `TZ` y la lista de días; `MANIFEST` incluye `.sum`; `M` idéntico antes/después sobre los mismos datos |
| **C4** | **Firewall** `TFG-hb-9095` (crear en `prep`, retirar en `cleanup`) o declarar el perfil | **0,5 h** | **CA-AUD-04**: regla presente durante y **ausente** en el cierre; `Get-NetFirewallRule` vacío |
| **C8** | **Re-sello completo y cobertura**: regenerar `sha256sums.txt` con **todas** las rutas (incl. `heartbeat_sink.py`, `etiquetar_operador_legit.py`, `manifiesto_snapshot.ps1`, `BUILD.md`) + `verificar_sellos_windows.py` que corre `sha256sum -c` y comprueba la lista de rutas; **`prep` lo ejecuta y aborta si falla** | **1 h** | **CA-AUD-08**: 178+ nuevas entradas, **0 fallos** de `-c`, cobertura = lista blanca; `prep` aborta con un fichero alterado (prueba negativa) |
| | **Total** | **~14 h** + 2 h de reloj | ≈ **2 jornadas** |

**Lo que NO se hace en C1-C8:** no se toca el cliente 8.3.1, ni la receta de 72 h (salvo la
acción W-07), ni la campaña (salvo esa acción), ni la métrica, ni el ruleset, ni Sysmon.

---

## 7. Qué debe declararse en la memoria (lista cerrada)

| # | Declaración |
|---|---|
| **AU-1** | **El pipe**: Windows había rebajado el invariante de Linux («0 pipes fuera de PowerShell»); WE0-2 lo desmintió (4/5, el servidor parte la línea en `QueueSyncService.cs:178`); corregido a **0 pipes en todo el texto**, receta y campaña regeneradas, **WE0-2 5/5** |
| **AU-2** | **El test que consagraba la rebaja** se ha invertido; los 419 tests anteriores **no** protegían ese invariante |
| **AU-3** | **`M` de Windows** sellado con **`boveda_version=3`** (no 2); cabecera del `denominador_M.csv` verificada |
| **AU-4** | **`crudo`** por día **UTC** (no `mtime` local) y con `.sum`; el plano diario se declara |
| **AU-5** | **Regla de firewall `TFG-hb-9095`** gestionada en `prep`/`cleanup` (o perfil declarado) |
| **AU-6** | **Validador de paridad** diferencial Linux↔Windows: un invariante que falla en Linux y no en Windows **falla** |
| **AU-7** | **Canary de reportabilidad**: 1 evento por plantilla, `history_timeline` = enviados, antes de `t0` |
| **AU-8** | **Validez y promoción** de Windows: `verificar_validez_ventana` + `promover_ventana_windows` (o se declara manual) |
| **AU-9** | **Ruido del operador**: 0/365 en 41,5 min (3 chequeos ad-hoc, `G-W7` SKIP); el chequeo real de 30 min es de T4 |
| **AU-10** | **`v1` tiene 10 ficheros viejos** (294 vs 304); el v2 se construye desde `-ataques-gui` limpio |
| **AU-11** | **El operador de Linux era invisible** por `auditd` (H-COMP-1); en Windows es visible y por eso hay chivato; **no** se recalcula Linux |
| **AU-12** | **Divergencias aceptadas** (A-01…A-10) con su razón; ninguna es un fallo |
| **AU-13** | **El sello `sha256sums.txt` estaba obsoleto en 9 entradas Windows y no cubría 4 artefactos esenciales**; regenerado y verificado con `sha256sum -c` + lista de cobertura; **ningún gate lo comparaba** |
| **AU-14** | **L-1 en Windows**: la invariante «toda huella leída se escribió antes» **no se validaba**; el test que la menciona mide Linux; portada al validador Windows con test negativo |
| **AU-15** | **Lista blanca de binarios**: la receta Windows no la tenía; añadida (`BINARIOS_W`) y validada; una herramienta no declarada ya no pasa `--check` |
| **AU-16** | **`n_acciones` de la campaña**: si un caso reporta menos acciones de las pre-registradas, se marca `REPORTE_INCOMPLETO`; no se da por bueno con las marcas |
| **AU-17** | **Supuestos corregidos**: 0 pipes **totales** (no «fuera de PowerShell»), B-1 superado (`dotnet msbuild` + *reference assemblies*) y **9** guardarraíles en `watch` / **14** en total |
| **AU-18** | **El manifiesto** del snapshot v2 se regenera para la base `-ataques-gui` (**294**, no 304) y el gate nombra el fichero que difiere |

---

## 8. Veredicto

> **Windows no está repitiendo *todos* los fallos de Linux, pero sí el patrón que los produce:
> reimplementar en vez de portar, y rebajar el invariante cuando la reimplementación choca.**
>
> - **El pipe** es el caso de libro: Linux lo cerró con H-1, lo puso en el validador y en el
>   test; Windows lo permitió «porque va dentro de PowerShell», lo **exigió** en un test y lo
>   metió en la receta. WE0-2 lo cazó —para eso estaba—, pero **después** de 4 pasos de tanda.
> - **El `boveda_version=2`** es más silencioso: un defecto de Linux que viaja por no pasar el
>   parámetro. No lo caza ningún test; lo caza leer la cabecera.
> - **El `crudo` por `mtime` local** y **la regla de firewall** son del mismo género: detalles
>   que Linux resolvió por construcción y Windows resolvió «a mano».
> - **La ronda 2 añade el fallo que faltaba**: **el sello no certifica el código** (D-08). 9 de
>   las 178 entradas están obsoletas y 4 artefactos esenciales no están; **ningún gate compara**
>   el sello con lo que corre. Es la misma enfermedad que el pipe: una comprobación que **parece**
>   integridad y no lo es.
> - **Y dos invariantes de Linux sin equivalente en Windows**: **L-1** (D-09) y la **lista blanca
>   de binarios** (D-10). La primera tiene un test que **mide Linux**; la segunda no existe. Con
>   ellas, la campaña puede dar por bueno un caso con **4 de 5** reportes (D-11).
>
> **Lo que está bien es mucho y no se toca:** chivato 0 huellas, keepalive 1 proceso, `arm`
> idempotente, `crudo` antes del `off`, `cleanup` bloqueado, 9 guardarraíles en `watch` / 14 en
> total, manifiesto + lista negra, y la unidad de `M` = línea de `archives`.
>
> **Recomendación:** **no reanudar T4** hasta **C1, C2, C7 y C5** (pipe, bóveda, nota de plan y
> validador con L-1/lista blanca/sellos). C3, C4 y C8 antes de `t0`. **C5 es la inversión que
> evita la tercera ronda**: sin él, los fallos se siguen cazando a mano y tarde.
> Coste total: **~14 h** + 2 h de reloj; el coste de no hacerlo es una campaña con W-07 a 0, un
> `M` con la bóveda equivocada y un sello que **no** certifica el código que midió la ventana.

---

## 9. Ronda 2 — método y barrido (qué se revisó y qué **no** dio hallazgo)

### 9.1 Qué se revisó

| Bloque | Ficheros / artefactos | Resultado |
|---|---|---|
| **Tests Windows** | `test_construir_receta_legitima_windows.py`, `test_campana_windows.py`, `test_verificar_espejo.py`, `test_ejecucion_windows.py`, `test_etiquetar_operador_legit.py`, `test_cobertura_herramientas_windows.py`, `test_extraer_alertas_windows.py`, `test_filtrar_ruido_windows.py` | **D-01** (tests que consagran el pipe), **D-09** (test L-1 mide Linux); el resto, correcto |
| **Validadores** | `construir_receta_legitima_windows.py` (`validar`/`validar_comando`), `verificar_espejo.py` (`comparar`), `campana_windows.py` (`validar`/`validar_comando`) | **D-01/D-09/D-10**; el resto de invariantes, correcto |
| **Sellos y metadatos** | `sha256sums.txt` (178), `manifiesto_esperado.json`, `despliegue_actual.json`, `BUILD.md`, cabeceras CSV | **D-08** (9 obsoletas + 4 ausentes), **D-13** (gate agregado); `boveda_version=3` y `cliente_version`, correctos |
| **Evidencias** | `t3/` (ruido, etiquetador), `t4/` (WE0-2, prep, deploy, MANIFEST) | **D-01** (WE0-2 4/5); el resto, coherente |
| **Ventana** | validez W-V, promoción, criterios V1–V9 | **D-06** (sin equivalentes) |
| **Campaña** | 11 casos, 22 marcas, 63 acciones, B6, W-07 | **D-11** (`n_acciones` no comparado); el resto, correcto |
| **Plan** | W0 §4.5/WE0-2/CA-W1; W3-bis §3.2 B-1 y §7.2 | **D-12** (supuestos falsos/caducados) |

### 9.2 Revisado **sin** hallazgo (para que se vea el barrido)

- **`test_etiquetar_operador_legit.py`**: prueba que `67028` **sin** `logon_type=3`/IP/`sshd_<pid>`
  **no** marca, y **con** contexto **sí**. Es la corrección de T3b, no una rebaja.
- **`test_ejecucion_windows.py`** (W-1…W-4): ejecuta de verdad el fan-out (12 ficheros), los 20
  errores/reintentos, el `fin.txt` y el `md` repetido. **No** contradice ningún invariante; **no**
  cubre el pipe (por eso D-01 no lo cazó antes), pero no lo afirma seguro.
- **`campana_windows.validar`**: marcas, evidencia, metadatos, binarios declarados, rutas,
  destinos de escritura, mutación, comandos repetidos y separación 180 s. **Sólido.**
- **`construir_receta_legitima_windows.validar`**: conteos, ventanas, handlers, `DelayAfter`,
  10 errores/día con pares y 5 campos, PowerShell solo en los 7 casos declarados, calendario y
  `bloques_windows.env` (`TFG_BOVEDA_VERSION=3`, `TFG_CAMPANA_CASOS=11`, `TFG_CAMPANA_MARCAS=22`,
  mapa de días). **Sólido** salvo L-1 y lista blanca.
- **`verificar_espejo.comparar`**: 504=504, `DelayAfter`, `HandlerType`/`Loop`/`HandlerArgs`,
  ventanas, `cmd /c`, `start`, fan-out 12, comillas. **Sólido** salvo el pipe (D-01).
- **`calendario_windows.json` y `bloques_windows.env`**: `boveda_version=3`, cuentas y mapa
  correctos; el problema es que el **sello** está obsoleto (D-08), no el contenido.
- **`campana_windows.csv`**: `sha256_casos_md` **coincide** con `casos_windows.md`
  (`7ed97cae…`), `boveda_version=3`, `corpus_windows=NO_EXISTE`, 11/22/63. **Correcto.**
- **`manifiesto_esperado.json`**: incluye `ghosts.exe`/`Domain` con versiones y `sha256`, el
  commit en `Domain` (`4d2e1608…`), `excluidos` y 304 ficheros. **Correcto** (salvo regenerar
  para el 294 del v2, A-05/D-13).
- **`heartbeat_sink.py`**: cadena `sha256_prev`, `seq`, `ROTA_SEQ`, `REINICIO_BUCLE`, `/test` sin
  contaminar, lock. **Correcto.**
- **`tfg_keepalive_windows.ps1`**: mutex con ACL, `-Once` **no** emite latido (F-1), rotación
  solo al cambiar día (`dia_aplicado.txt`), `powercfg` una vez. **Correcto.**
- **`windows_legit_host_control.ps1`**: `arm` idempotente (C-3), `crudo` antes del `off`,
  `cleanup` bloqueado (`exit 84`), `G-W13/G-W14`. **Correcto** salvo D-03/D-07/D-08.
- **Cabeceras de los CSV intermedios** (`alertas_detalle_operador.csv`): **no** llevan
  `metrica_version`/`boveda_version`, pero **tampoco** las lleva el `alertas_detalle.csv` de
  Linux **antes de la promoción**; la cabecera la añade el promotedor. No es una divergencia:
  es el mismo diseño, y el promotedor de Windows es D-06.
- **`Dataset/Legitimo/legitimo_72h/*`**: productos Linux; no se tocan y no se comparan en crudo.
- **Clon GHOSTS**: `QueueSyncService.cs` tiene un cambio **preexistente** (saltos de línea
  `Environment.NewLine` → `"\r\n","\n"`); **no** toca el `Split('|')` y no entra en el cliente
  Windows (`BUILD.md` §1.1). La traza de T4 (`QueueSyncService.cs:193`) coincide con el fuente.
  **Sin hallazgo.**
- **`BUILD.md`**: procedencia real (commit, tag, `dotnet msbuild`, *reference assemblies*,
  `sha256` de `ghosts.exe`/`Domain`). **Correcto**; solo el plan B-1 está caducado (D-12).

### 9.3 Respuesta a la pregunta del humano

> **Sí, quedaba al menos un fallo, y era del mismo patrón**: **el sello global no certifica el
> código que va a medir la ventana** (D-08), y **dos invariantes de Linux no tienen equivalente
> en Windows** (L-1, D-09; lista blanca de binarios, D-10). Ninguno de los tres lo caza un test:
> el de L-1 mide Linux, y el sello no lo compara nadie. La ronda 2 también confirma que el resto
> del aparato (tests de ejecución, validador de campaña, manifiesto, chivato, keepalive) está
> **bien construido** y no ha dado más hallazgos.

---

## 10. Nota de corrección de los planes (tanda 1, 2026-11-11)

> **Esta nota no reescribe los planes aprobados** (`_fases/windows-legit-prep/plan.md` W0 v2 y
> `plan_w3bis.md` v2). Fija las correcciones que **anulan** los supuestos falsos o caducados, para
> que el tester y la memoria no sigan citándolos. **El ejecutor cumplió el plan**; la premisa
> falsa estaba en el plan aprobado, no en la ejecución.

| # | Supuesto del plan | Corrección vigente | Dónde se implementa |
|---|---|---|---|
| **1** | W0 §4.5 y CA-W1: «0 pipes de `cmd`; los pipes **dentro** de `powershell -Command` **sí** se permiten» | **0 pipes totales**: ningún `|` en ninguna posición del comando, **también dentro de `-Command`**. Motivo: `QueueSyncService.cs:178` parte la línea de resultado por `|` y pierde el reporte (WE0-2, 4/5). Regla aplicada en los 3 validadores y exigida por los tests (4 invertidos + 1 negativo con el pipe **dentro** de PowerShell). | `construir_receta_legitima_windows.py` (`validar_comando`), `verificar_espejo.py`, `campana_windows.py`; `tests/test_{construir_receta_legitima_windows,campana_windows,verificar_espejo}.py` |
| **2** | W3-bis §3.2 **B-1**: «VS Build Tools 2022 + targeting pack + `nuget.exe`» | **Superado**: se compiló con **.NET SDK 8 + *reference assemblies*** (`dotnet msbuild`), sin VS Build Tools. | `Soporte/Laboratorio/windows/legit/BUILD.md` §2.1 |
| **3** | W3-bis §7.2 / M-2: «**8** guardarraíles del `watch`» | **9 en `watch`** (`G-W5`, `G-W7`…`G-W14`) y **14 en total** (`G-W1`…`G-W14`). | `Soporte/Laboratorio/windows/windows_legit_host_control.ps1` (control v4) |
| **4** | Atribución del fallo | **El ejecutor cumplió el plan**; la premisa falsa (pipes internos seguros, B-1 con VS Build Tools, 8 guardarraíles) estaba **en el plan**. No se reescribe un plan aprobado: se anula con esta nota. | este documento |

**Estado tras la tanda 1**: **C1** (pipe) y **C2** (`boveda_version=3`) ejecutados. La receta y la
campaña regeneradas tienen **0 pipes** en los **504** comandos (y en los **63** de la campaña),
**504 = 504**, `DelayAfter` y ventanas intactos; `construir_receta_legitima_windows.py --check`,
`campana_windows.py --check`, `--no-mutacion` y `verificar_espejo.py` **PASAN**. El `M` calculado
con `contar_denominador.py --boveda-version 3` sobre el crudo de prueba sella
`boveda_version=3`. **C3–C6 y C8 siguen pendientes** (tandas siguientes).
