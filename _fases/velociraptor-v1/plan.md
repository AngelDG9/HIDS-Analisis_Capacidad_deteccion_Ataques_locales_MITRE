---
nombre: Velociraptor Linux - V1 (55 casos x 2) con auditd principal y EBPF guardado
fecha: 2026-11-23
estado: PROPUESTO - pendiente del OK del humano para lanzar la pasada (la preparacion y el ensayo no necesitan lanzarla)
depende_de: Dataset/Ataques/Resultados/Velociraptor/linux_ojos/RESULTADO_OJOS.md (decision de los ojos) · _fases/velociraptor-linux/plan.md (V1)
---

# V1 - medida de Velociraptor en Linux

## 1. Para que
Medir a Velociraptor (version virgen, sin reglas de deteccion propias) frente a los **55 ataques de Linux x 2 iteraciones**, con los mismos casos, lanzador, ventana y metrica que Wazuh, **guardando todo el crudo**.
Los «ojos» ya estan decididos (auditoria de hoy): **auditd = ojo principal de la comparacion** (mismos bytes que Wazuh) y **EBPF = ojo nativo, guardado de forma complementaria** (unico que ve red).

## 2. Decisiones (y por que)
| # | Decision | Por que |
|---|---|---|
| D1 | Misma configuracion que la pasada de ojos (cfg S): tabla del servidor = EBPF con todos los eventos activados (los de fabrica + `security_inode_rename` + `mkdir`) y subida de `audit.log*` al final de cada ventana | Probada 18/18; los ojos no se pueden repetir sobre datos guardados |
| D2 | Los 55 casos `variante == base` de `cargar_especificaciones()`, x 2 iteraciones, cada una desde `lab-listo-vr` revertido | Misma unidad que Wazuh |
| D3 | Se **reutiliza** la infraestructura ya probada con Wazuh (lanzador `systemd-run`, sumideros de red `SINK_ATAS`, extras previos, reinicios `esperar_reinicio`) | No reinventar; mismo comportamiento del ataque |
| D4 | Ventana: t0 = marca `T0=`, t1 = fin del lanzamiento + 30 s, recorte [t0-60 s, t1+120 s]; marcas INI y FIN obligatorias (la ventana FALLA si no llegan) y reintento unico por ventana, registrado | Igual que piloto y ojos |
| D5 | Guardar: recortes gz (EBPF, `audit.log*` completo, auditd de la ventana) + meta + sha256, y al final **copia integra** del datastore del cliente y de las colecciones (`--fase post`) con `MANIFEST.tsv` | Regla del usuario: guardar todo |
| D6 | Un caso que **reinicia la VM** o instala paquetes necesita comprobar que el cliente de Velociraptor y las 5 reglas de auditd vuelven a estar activos antes de dar la ventana por buena; si no, FALLA | Evita ventanas «OK» sin ojos |

## 3. Pasos y criterios de aceptacion (fijados antes de ejecutar)
| Paso | Que | Criterio de aceptacion |
|---|---|---|
| V1-0 | Parametrizar el orquestador de ojos para los 55 casos (`--only` por defecto = todos) sin cambiar su comportamiento en los 9 ya medidos | los 9 casos de la pasada de ojos siguen produciendo el mismo `meta` en un dry-run de seleccion; tests existentes pasan |
| V1-1 | **Ensayo** de 1 ventana por cada tipo especial (sumidero de red, reinicio de VM, instalacion de paquetes, extras previos): se identifican leyendo `SINK_ATAS`, `extras_pre`, `esperar_reinicio` | cada una: estado OK, marcas INI/FIN, 5 reglas de auditd antes y despues, cliente conectado; si alguna falla se arregla **antes** de lanzar |
| V1-2 | Pasada completa 110 ventanas (~9 h) | `indice.csv` con 110 filas; las no-OK se listan con su causa y se reintentan una vez; ninguna se oculta |
| V1-3 | Copia integra (`--fase post`) | `MANIFEST.tsv`, sha256 de cada fichero verificados |
| V1-4 | **Verificacion independiente**: nuevo `verificar_v1_velociraptor.py`, a partir de `verificar_ojos_velociraptor.py`, con codigo propio sobre el crudo | sha256 de recortes y crudo; marcas; recorte EBPF recomputado == guardado; anclas de auditd recomputadas == meta; determinismo iter1 vs iter2 **listando** los casos que difieran (no se supone igualdad) |
| V1-5 | Resultado: tabla caso x vista (procesos / ficheros / red) con las mismas definiciones y filtros que `analizar_ojos_velociraptor.py`, y `RESULTADO_V1.md` | todo numero del documento sale de un script reproducible; limites declarados |

## 4. Cambios en VM / servidor (declarados)
Ninguno nuevo respecto a la pasada de ojos: snapshot `lab-listo-vr`, 5 reglas de auditd intactas, tabla del servidor gestionada con `add_client_monitoring`/`rm_client_monitoring`, contrasena solo en `TFG_MANAGER_PW` (nunca en ficheros ni en git).

## 5. Riesgos
- **Volumen**: ~1,2 MB gz por ventana en los 9 casos medidos -> ~130 MB de recortes y ~1,5 GB de crudo para 110 ventanas. Se comprueba el espacio libre antes de lanzar.
- **Casos con reinicio o con un cambio de reglas/servicios** pueden alterar auditd o el cliente: criterio D6.
- **Ventanas largas** (algunos ataques duran mas): el timeout se mantiene en 900 s y se registra.
- **El PC debe estar encendido ~9 h** y las VMs sin tocar.
- **Rotacion de `audit.log`**: valida para ventanas de 5 min; no para 72 h (V1-L, plan aparte).

## 6. Lo que NO es V1
No mide falsas alarmas (V1-L), no incluye reglas de deteccion externas (C2/C3, se repetiran sobre este crudo), ni Windows.
