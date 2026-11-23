# Resultado de la auditoría de los «ojos» de Velociraptor (Linux) — 2026-11-23

Plan: `_fases/velociraptor-ojos/plan.md` · Sondas de mecanismo: `SONDAS.md` · Datos: `cfgS/` (índice, logs, meta) y, fuera del repo, `D:\TFG-VMs\ataques-velociraptor-linux-ojos\{raw,crudo}`
Scripts: `orquestar_velociraptor_ojos.py` (pasada), `analizar_ojos_velociraptor.py` (comparación), `verificar_ojos_velociraptor.py` (verificación independiente → `VERIFICACION_OJOS.md`: **OK, sin fallos**).

## Qué se hizo
Una sola pasada con **todos los ojos activos a la vez** (EBPF con todos los eventos + subida de `audit.log*` al final de cada ventana; auditd con sus 5 reglas intactas).
9 casos × 2 iteraciones = **18 ventanas, 18 OK** (~5 min cada una): los 6 del piloto (ATA001, 002, 008, 009, 011, 012) + 3 de ampliación elegidos por regla objetiva (ATA003 borra/inhibe recuperación, ATA035 permisos/atributos, ATA026 conexión de red con `nc`).
Las vistas se sacan **después, filtrando**: **A** = EBPF de fábrica, **B** = EBPF afinado (sin `security_file_open`, con renombrado y `mkdir`), **AU** = auditd (los mismos bytes que lee Wazuh).

## Resultado 1 — procesos (anclas de la verdad esperada, en vocabulario auditd)
Las 18 ventanas traen las anclas con **iteración 1 = iteración 2** (determinista) y las marcas de inicio y fin.
| Caso | Anclas EBPF (exec con éxito) | Anclas AU | Diferencia |
|---|---|---|---|
| ATA001, 002, 003, 008, 009, 011, 035 | = | = | ninguna |
| ATA012 | find 23, cwd 12 | find 26, cwd 15 | AU cuenta **3 intentos de `execve` fallidos** (`find -exec cp` busca `cp` en `/usr/local/sbin`…); EBPF solo ve los que arrancan |
| ATA026 | nc 3, cwd 17 | nc **0**, cwd 20 | el ejecutable real es `/usr/bin/nc.openbsd` (auditd guarda el nombre real; EBPF el `argv[0]`=`nc`); AU también cuenta 3 intentos fallidos |

Los procesos que arrancan con éxito en el conjunto del ataque son **idénticos** en A, B y AU (ver `comparacion_vistas.md`). Lo único distinto es lo anterior (nombre real del binario e intentos fallidos).

## Resultado 2 — ficheros y red (misma actividad: procesos del ataque y sus descendientes)
Filtros declarados: ficheros = solo rutas bajo `/home/angel`, `/etc`, `/tmp`; red = solo AF_INET.
| Vista | Ficheros | Red | Volumen típico por ventana |
|---|---|---|---|
| **A** EBPF de fábrica | 17–47 (hasta 438 en ATA012), **casi todo `security_file_open`** (lecturas/aperturas) | ve la conexión (ATA008: 1, ATA009: 1, ATA026: 3) | 9 000–12 700 filas |
| **B** EBPF afinado | **0** en todos los casos (el borrado con `rm` es `unlinkat` y no hay renombrados; sin `file_open` no queda nada) | igual que A | 1 500–2 300 filas |
| **AU** auditd (5 reglas) | 0–10: crear/renombrar/borrar solo donde las reglas miran (ATA002: 2, ATA003: 10, ATA008: 1, ATA012: 1) | **0** (no hay regla de red) | 600–1 000 eventos (3 700–6 100 líneas) |

## Lectura en llano
- **Procesos**: los tres ojos ven lo mismo. Para detectar «se ejecutó `curl`/`find`/`dd`…» da igual cuál usemos.
- **Ficheros**: EBPF de fábrica ve más porque registra *aperturas* (mucho ruido); auditd con nuestras 5 reglas ve poco (por diseño mínimo). El afinado B no aporta nada en estos casos.
- **Red**: solo EBPF la ve; auditd con estas reglas no.
- **Determinismo**: lo visto es idéntico entre iteraciones en los 9 casos.

## Decisión según los criterios fijados antes de ver datos
Filtro: pasan A, B y AU (marcas, anclas del piloto, iter1 = iter2). Orden: 1º mismos ojos que Wazuh → **AU**; 2º cobertura → A es la más amplia (red y ficheros); 3º de fábrica → A y AU (ambos sin código propio); 4º volumen → AU el menor.
**Recomendación:** ojo principal para la comparación Wazuh↔Velociraptor = **auditd (AU)** — mismos bytes que Wazuh, así lo que difiere es el «cerebro» y no el sensor; y **seguir guardando EBPF en la misma pasada** (no cuesta ataques extra y es el único que ve red). B se descarta (no aporta). Decisión final pendiente de confirmación del humano antes de lanzar V1 (55 × 2).

## Límites y riesgos (declarados)
- 9 casos y 2 iteraciones; mide **mecanismo y cobertura**, no la tasa de detección global.
- **Rotación de `audit.log`**: la subida puntual funciona en ventanas de 5 min, pero **no vale para las 72 h de V1-L** (el log rota a ~8,4 MB y solo se conserva un `.1`); para V1-L hay que leer auditd en continuo (artifact `watch_syslog`/`audit()`, ya probados en las sondas) o ampliar la retención de auditd (cambio declarado en la VM).
- El propio cliente de Velociraptor mete ruido en auditd (`comm="velociraptor"`).
- La entrega es **por lotes**: la marca FIN es obligatoria antes de cortar una ventana.
- Las anclas están en vocabulario auditd (`audit_exe`): con EBPF el nombre sale de `argv[0]` y puede no coincidir con el nombre real del binario (caso `nc`).
- EBPF ≠ auditd en el modelo de eventos (EBPF no ve `unlinkat` ni `chmod`; auditd con 5 reglas no ve red).
- Reglas de auditd mínimas a propósito; una variante «más completa» queda como trabajo futuro.
