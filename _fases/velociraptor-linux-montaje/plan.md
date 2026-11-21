# Plan — montar Velociraptor sobre Linux (V0a–V0c + prueba de humo) · 2026-11-21

> Objetivo: dejar **montado** Velociraptor «virgen» sobre la víctima Linux: servidor en el PC, cliente inscrito en la VM,
> recogida de un artifact de prueba funcionando y el inventario real de artifacts de Linux. **No** se hacen aún los ataques (V1) ni la ventana (V1-L).
> Base de diseño: `_fases/velociraptor-linux/plan.md` (decisiones del humano: servidor en el PC, ventanas separadas de Wazuh, lanzador local D8/Q2).
> **La documentación puede estar desactualizada: cada afirmación de abajo se comprueba contra la máquina real y se anota el resultado.**

## 0. Hechos comprobados hoy (2026-11-21)
| Hecho | Cómo se comprobó |
|---|---|
| Última versión estable de Velociraptor: **v0.77.3** (2026-10-05; 0.77.2/0.76.7 son anteriores) | API de GitHub Releases |
| Binarios descargados a `D:\TFG-VMs\material-velociraptor\`: `velociraptor.exe` (Windows, 73 422 840 B) y `velociraptor-linux-amd64` (78 329 008 B) | descargados de la release; `sha256` de los `.gz` y de los binarios en `prestaging_material.md` (V0a) |
| `velociraptor.exe` **pide elevación** (manifiesto `requireAdministrator`): desde una sesión no elevada falla con «requiere elevación» | ejecución real |
| Se puede arrancar **sin administrador** con `__COMPAT_LAYER=RunAsInvoker` (`version` → 0.77.3, go1.27.1) | ejecución real |
| El servidor de Velociraptor NO necesita Wazuh ni el manager: solo la VM víctima Linux + el PC | diseño |
| RAM: con manager + VM Windows el PC queda con ~300–500 MB libres → **Velociraptor se monta cuando esas VMs estén apagadas** | medido |

## 1. Decisiones (con su porqué)
- **D1 servidor en el PC** (decidido por el humano): datastore en `D:\TFG-VMs\velociraptor-server\` (fuera del repo). Frontend escucha en la IP del PC en VMnet1 (`192.168.65.1`), GUI solo en `127.0.0.1`.
- **D2 puerto del frontend**: el firewall de Windows no se puede tocar sin administrador. Se **comprueba** qué reglas `TFG-*` existen y se elige un puerto ya permitido a `192.168.65.0/24` (p. ej. 9090/9092) **o** se pide elevar al humano. Se anota el resultado.
- **D3 sin secretos en el repo**: las claves/CA del servidor y el `client.config.yaml` viven en `D:\TFG-VMs\velociraptor-server\` y `material-velociraptor\`. En el repo solo irán hashes, versiones y comandos. La contraseña de la GUI (si se crea) se muestra una vez en el terminal y **no se guarda**.
- **D4 víctima «virgen» Linux**: partir de `lab-listo` (auditd con las mismas reglas que usó Wazuh) y **sin Wazuh**: se comprueba qué trae `lab-listo` (agente, auditd, reglas) y se quita el agente de Wazuh; snapshot nuevo **`lab-listo-vr`**. `lab-listo` no se toca.
- **D5 un solo modo de lanzar ataques para todos los HIDS** (Q2): el lanzador local (`systemd-run`) ya existe (`orquestar_ataques_linux.py`); en V1 se reutiliza. No se lanza ningún ataque en esta fase.

## 2. Pasos (cada uno con su puerta)
### V0a · Material (pre-staging)
1. Descomprimir y calcular `sha256` (hecho para los `.gz`; falta documentarlo en `Soporte/Laboratorio/velociraptor/prestaging_material.md`).
2. **Puerta:** `velociraptor.exe version` = 0.77.3; los dos `sha256` quedan anotados con URL y fecha.

### V0b · Laboratorio
3. Generar `server.config.yaml` (`config generate`), ajustar `Frontend.hostname/bind_address/bind_port`, GUI `127.0.0.1:8889`, datastore y logs en `D:\TFG-VMs\velociraptor-server\`.
4. Arrancar el servidor (proceso del PC, sin elevar, con `RunAsInvoker`); comprobar puertos (`netstat`) y que responde por HTTPS.
5. `config client` → `client.config.yaml` apuntando a `https://192.168.65.1:<puerto>/`.
6. Víctima Linux: revertir a `lab-listo`, **inspeccionar** (wazuh-agent, auditd, reglas, versión del SO), desinstalar el agente Wazuh, copiar el binario y el `client.config.yaml`, crear servicio `systemd` (`velociraptor_client`), arrancar, snapshot `lab-listo-vr`.
7. **Puerta:** el cliente aparece como inscrito en el servidor (consulta a la datastore); alcance de red comprobado desde la VM (`curl -k` al frontend); sin Wazuh en la VM; reloj de la VM sincronizado.

### V0c · Inventario real de artifacts de Linux
8. `artifacts list` del cliente y del servidor: lista **real** de artifacts `Linux.*` y `Generic.*` aplicables; clasificarlos en **detección / telemetría / dudoso** con un criterio escrito.
9. Medir volumen en reposo 15–30 min de los artifacts de telemetría candidatos y **de dónde leen** (auditd / journal / procfs).
10. **Puerta:** `inventario_artifacts_linux.csv` con versión, parámetros por defecto, coste y origen de datos.

### Prueba de humo (no es V0d)
11. Programar una colección de 2–3 artifacts baratos (p. ej. `Linux.Sys.Pslist`, `Generic.Client.Info`) sobre el cliente, esperar el resultado y comprobar que vuelve a la datastore y que se puede exportar (filas con hash).
12. **Puerta:** colección completada, filas legibles, tiempo y tamaño anotados.

## 3. Ronda de verificación y testeo (obligatoria antes del commit)
- V-1. Reiniciar servidor y cliente: el cliente vuelve a inscribirse solo (persistencia).
- V-2. Revertir la VM a `lab-listo-vr`, arrancarla y comprobar que el cliente conecta **sin intervención**.
- V-3. Comprobar que la VM **no** tiene Wazuh (paquete, servicio, procesos) y que auditd conserva las mismas reglas que `lab-listo` (diff de `/etc/audit/rules.d`).
- V-4. Comprobar que no queda ninguna clave, contraseña ni `*.config.yaml` dentro del repo (`git grep`); `git status` limpio salvo los ficheros previstos.
- V-5. Contrarrevisión: un agente independiente repite el inventario sin ver mis conclusiones y se comparan.

## 4. Límites declarados
- No se hacen ataques ni ventana legítima de Velociraptor (V1 / V1-L).
- El firewall del PC solo se modifica si hay permisos; si no, se documenta y se deja la orden exacta para el humano.
- La GUI queda solo local; no se expone nada fuera de `192.168.65.0/24`.
