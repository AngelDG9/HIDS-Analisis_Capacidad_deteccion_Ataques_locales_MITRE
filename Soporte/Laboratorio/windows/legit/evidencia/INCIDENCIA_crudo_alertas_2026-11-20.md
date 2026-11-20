# Incidencia: la fase `crudo` no copio las alertas de la ventana (2026-11-17 -> 2026-11-20)

**Que paso.** `windows_legit_host_control.ps1 -Phase crudo` (lineas ~1517-1531) busca
`ossec-alert-DD.json.gz` (sin la *s*) y `ossec-alert-DD.json.gz.sum`. En Wazuh 4.14.7 los
ficheros se llaman `ossec-alerts-DD.json.gz` y `ossec-alerts-DD.json.sum` (tambien
`ossec-archive-DD.json.sum` en archives). Resultado: el crudo solo trajo `alerts.json` (el de
hoy, fuera de ventana) y el primer informe automatico salio con **alertas = 0** (A5 = ND).
Las alertas NO se perdieron: seguian en el manager.

**Como se arreglo (2026-11-20 ~01:35 local).** Copiadas con `sudo cat` desde
`/var/ossec/logs/alerts/2026/Nov/` los dias 17, 18 y 19 (.json.gz, .log.gz y sus .sum) y los
tres `.json.sum` de archives, mas los logs internos del manager (`wazuh/` y `api/`) y el
`ossec.log` del dia. Integridad: MD5/SHA1 del contenido descomprimido == "Current checksum"
de cada `.sum`; tamanos identicos a los del manager. Quedan en `crudo/alerts/`,
`crudo/archives/`, `crudo/alerts_manager/` (copia) y `crudo/manager_logs/`; listado con sha256 en
`crudo/MANIFEST_COMPLEMENTO_2026-11-20.tsv`. El `MANIFEST.tsv` original no se toca.

**Informe.** Repetido el analisis con alertas: `informe_VENTANA_2026-11-17.md` (RESULT=PASS,
alertas=6344, A5 operador 6/6344 = 0,09 %). El primero se conserva como
`informe_VENTANA_2026-11-17_PRIMERA_SIN_ALERTAS.md`.

**Corregido en el controlador (2026-11-20, tras la ventana).** `ossec-alert` -> `ossec-alerts`, `.json.gz.sum` ->
`.json.sum`, se copian tambien `alerts.log.gz` (+ `.sum`) y los logs internos del manager (`logs/wazuh/` y
`logs/api/`, que tambien se buscaban en una ruta inexistente). El test unitario imitaba el nombre erroneo y se
corrigio con los nombres reales de Wazuh 4.14.7. Resellado con `resellar_windows.py` (2 entradas; hash anterior del
controlador `2ffbc01d...` en `ventana_2026-11-17/SELLO_ANTES_DE_RESELLAR.txt`). **El codigo que ejecuto la ventana
fue el sellado anterior**; el cambio es posterior y solo afecta a que ficheros copia la fase `crudo`.
