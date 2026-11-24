# Resultado de V1 — Velociraptor (virgen) en Linux, 55 casos × 2 — 2026-11-23/24

Plan: `_fases/velociraptor-v1/plan.md` · Datos: `cfgS/` (índice, `Logs/<caso>/`), `analisis/` (tablas) y, fuera del repo, `D:\TFG-VMs\ataques-velociraptor-linux-v1\{raw,crudo}` (+ segunda copia en `C:\TFG-copia\velociraptor-v1\`).
Scripts: `orquestar_velociraptor_v1.py` · `comprobar_tanda_v1.py` (integridad tras cada tanda) · `analizar_v1_velociraptor.py` (tablas) · `verificar_v1_velociraptor.py` (verificación independiente → `VERIFICACION_V1.md`).

## Qué es y qué NO es
**Mide visibilidad** (nivel 1 de la métrica): ¿llega a Velociraptor la huella de cada ataque?, con dos «ojos» a la vez: **auditd** (principal para comparar con Wazuh: mismos bytes que lee Wazuh) y **EBPF** (el sensor propio de Velociraptor en Linux).
**NO mide detección** (nivel 2) **ni falsas alarmas** (nivel 3): Velociraptor virgen **no trae reglas de comportamiento** (solo 3 artifacts «Detection» de ficheros/YARA, que no están activados y no evalúan estos ataques), y en V1 **no hemos puesto ninguna capa que filtre o puntúe eventos**. Esa capa («el cerebro») son las reglas externas C2/C3 (Sigma o artifacts de detección), que se aplicarán después **sobre estos mismos datos guardados**, sin repetir ataques. Los falsos positivos salen de V1-L (72 h de actividad normal).

## Ejecución
- **110 ventanas de 110 OK** (55 casos × 2 iteraciones), en 4 tandas, **0 fallos y 0 reintentos**. Comprobación de integridad tras cada tanda: completo (2 158 ficheros del crudo con sha256 correcto).
- Casos especiales incluidos (reinicio ATA038, rsync ATA039/040, receptor en la víctima ATA047, rclone ATA049, paquetes ATA051–053): todos OK. En cada ventana las **5 reglas de auditd** eran las mismas antes y después.
- **Verificación independiente: OK, sin fallos** (`VERIFICACION_V1.md`): sha256 de los 2 158 ficheros del crudo y de todos los recortes; 110 ventanas OK con marcas de inicio y fin presentes en el `audit.log` guardado; recorte de EBPF recalculado desde el crudo = lo guardado; y las señales de auditd y de EBPF **recalculadas desde el crudo con código distinto** = las de `analisis/`.

## Resultado 1 — visibilidad de las señales del caso (vocabulario auditd)
Cada caso declara «señales» de tipo `deteccion` (programa que debe ejecutarse o directorio de trabajo del ataque; `rule_id`, propio de Wazuh, se excluye). 54 de los 55 casos tienen señales; **ATA034 no tiene ninguna por diseño** (archiva solo con *builtins* de bash, sin `execve`: punto ciego declarado de antemano). Total: 155 señales por iteración (310 en las dos).
| | auditd (5 reglas) | EBPF |
|---|---|---|
| Señales vistas (de 310) | **302** | **310** |
| Casos (iter. 1) con **todas** sus señales | 50 de 54 | 54 de 54 |
| Casos con **alguna** señal | 53 de 54 | 54 de 54 |

Lo que auditd no ve (8 señales = 4 por iteración) **es siempre un problema de nombre, no de datos**: el binario real tiene otro nombre en auditd (`python3` → `python3.12`, `nc` → `nc.openbsd` en dos casos, `mkfs.ext4` → `mke2fs`). EBPF registra el nombre con que se invocó. Con una comparación «por palabra completa» (la que usaba la medida de Wazuh) estas señales casarían. **Esto es una propiedad de la señal estricta, no un fallo de auditd.**

## Resultado 2 — dónde difieren auditd y EBPF cuando ambos ven la señal
Por señal e iteración (310): **237 iguales**; **56** difieren porque **auditd apunta intentos de `execve` fallidos** (p. ej. `find -exec cp` o `useradd` buscando el binario en cada carpeta del PATH) que EBPF no ve (si se cuentan solo los `execve` con éxito, coinciden); **9 en las que EBPF cuenta menos que auditd con éxito** (ver abajo); 8 por nombre (arriba).
**EBPF pierde eventos en ráfagas** (hipótesis más probable; no demostrada con un contador de pérdidas): ATA047 (inundación de `curl`): auditd 402 ejecuciones, EBPF 252 (iter. 1; 292 en iter. 2 → la pérdida varía); ATA052 (221 vs 219/221), ATA049 (13 vs 12/13), y ATA038 (reinicio de la víctima): `systemctl` 13 vs 8 (aquí es esperable: el cliente no recoge mientras la máquina se reinicia). Para una señal «¿se ejecutó el programa?» basta con que llegue una vez, así que no cambia la visibilidad; **sí importaría para contar eventos**.

## Resultado 3 — qué ve cada ojo además de procesos (iter. 1, 55 casos; mismo conjunto del ataque y mismos filtros que en la auditoría)
| Vista | Casos con actividad de **ficheros** (rutas de `/home/angel`, `/etc`, `/tmp`) | Casos con **red** (AF_INET) | Filas por ventana (mediana / máx.) |
|---|---|---|---|
| EBPF de fábrica (A) | 55 | 21 | 9 750 / 33 088 |
| EBPF afinado (B, sin `security_file_open`) | 13 | 21 | 1 650 / 5 449 |
| auditd (5 reglas) | 30 | **0** | 657 / 4 775 |
Lectura: con **procesos** los dos ojos coinciden; **red** solo la ve EBPF (no hay regla de red en nuestras 5); **ficheros**: EBPF de fábrica ve actividad en todos los casos (casi todo `security_file_open`, mucho ruido); auditd solo donde nuestras reglas miran (/etc, `lab-legit` y las llamadas de crear/renombrar/borrar), sin `chmod`.

## Determinismo (iteración 1 frente a 2)
Las señales de auditd y EBPF son iguales entre iteraciones en **49 de 55 casos**; difieren 6: ATA021 (auditd y EBPF coinciden entre sí en 74 frente a 21 en el directorio del ataque: el propio ataque ejecuta un número distinto de veces), ATA045, ATA047, ATA049, ATA052 y ATA054 (diferencias pequeñas de EBPF, coherentes con la pérdida en ráfagas). Detalle en `VERIFICACION_V1.md`.

## Corrección hecha durante el análisis (declarada)
La primera medida «estricta» comparaba solo el **nombre** del programa; 14 señales cuyo patrón es una **ruta completa** (`/usr/bin/cp`, `/usr/bin/tar`…) salían «0 en los dos ojos». Se corrigió el extractor (ruta completa si la señal lleva barra; con tests) y las cifras de este documento y de `analisis/` están **recalculadas desde lo guardado** con la regla corregida. Los `lanzamiento.json` de cada ventana conservan la cifra antigua (registro de lo que se midió en el momento) y **no se usan** para este análisis. Los datos crudos no se tocaron.

## Límites y riesgos (declarados)
- Es **visibilidad**, no detección; sin capa de reglas (C2/C3) ni falsas alarmas (V1-L).
- Auditd con **5 reglas mínimas** a propósito: no cubre red, lecturas ni `chmod`. Una variante más completa queda como trabajo futuro.
- La pérdida de EBPF en ráfagas es una **hipótesis**; no se midió con un contador de pérdidas.
- El propio cliente de Velociraptor mete ruido en auditd (`comm="velociraptor"`); la entrega es por lotes (la marca FIN es obligatoria).
- 2 iteraciones por caso; un solo entorno (VM Ubuntu 24.04).
