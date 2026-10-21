# `MANIFEST.md` - evidencia del fallo de la ventana L1 (19-20/10/2026)

> Bloque `legitimo-fix`. **Nada se destruye**: el estado completo de la victima rota
> (incluido `ghasts.out` de **4 783 345 664 B**) esta en el snapshot
> **`fallo-2026-10-19-disco-lleno-NO-USAR`** de `victima-linux` (VM apagada).
> Este directorio guarda **extractos legibles** (<= ~5 MB) con sus huellas.

## Que hay aqui

| Fichero | Bytes | `sha256` |
|---|---|---|
| `app_log_tail.txt` | 6426 | `9448014a5673020063dab1cf99ba41a731ed230ea6a85a0d15edbca15f90ec62` |
| `client_ctl_original.sh.txt` | 967 | `fd310198db369b59e7ad7041e2f1045fb623bcad51564a1fa924d20000ec13dc` |
| `df_h.txt` | 936 | `b877e881e29ce10d875e65ab131249adfd6723853de655039b751cc495da3ca0` |
| `df_series_agente_001.tsv` | 12250 | `c97df4fca41d15143d903b6d35982b1df258e60ff8e46c81f6f8369af7f6b6c0` |
| `dmesg_T.txt` | 145235 | `87835bb9938fe728b319f5b7ad9221f9c0781ddf12f49400206fd33c19d5c6f0` |
| `ghasts_out_head.txt` | 4330 | `9c7836fc4c9fd4019a2ef745c5a00bbb9419b8e9413dfca31d785594a82a3e9d` |
| `ghasts_out_nospace.txt` | 2516 | `751d526b73bcf93d720731ac74242e0d50731626b9774b69dd0b15df4b386e2e` |
| `ghasts_out_tail.txt` | 23967 | `666617548b1578b30a8d4f65e3e6d1b69929ddeee7f456a089dbc2e45f845776` |
| `keepalive_log.txt` | 54 | `df7deb86114d5e330eeada21adef23639e18cc422b12ba54a3e03abf51b5dabe` |
| `nlog_config_original.txt` | 1367 | `6e1b08d7e89ae8a17edbde13cd4a4a49f4e042496daaa4d626382b904ddaa92e` |
| `stat_ghasts.txt` | 563 | `5571f0a531f5c5ed77c400acb0c6d69f0f9e706d94251440deec36a0aeeedb15` |
| `timeline_activa.txt` | 6337 | `b47d7ddf5fdc348e40e192d5bfb638d9b7a7c519df654d15cd8dbb2003de9fda` |
| `wc_sha_estado.txt` | 246 | `74edc27dca08f57994a9f1587b11600f17aed9fea02d8dde2aadf78428fbb333` |
| `legitimo_host_control.log` | 94409 | `5551bf99bf6c888b0cfd0f6e517bc509c6973007fbaeeb861dcbf2736b66c538` |
| `vigilancia_legitimo.log` | 9948 | `147f5af30b2702eaefcbc7e92960d9db2bcf7e1fdf55c05212f36cc0d5a53050` |
| `ventana_meta_INVALIDA_2026-10-19.md` | 4815 | `061d555bebc923369c7a4f48dca6db9be5122324b21c3284beafc1dfe3b2451a` |

## Contenido y valor probatorio

- `ghasts_out_head.txt` / `ghasts_out_tail.txt`: primeras 40 y ultimas 80 lineas del
  stdout sin tope (**4,78 GB**, 86 174 lineas) que lleno el disco.
- `ghasts_out_nospace.txt`: **92** lineas `No space left on device`; la primera a las
  **14:02:45Z** del 19/10 (16:02:45 local, CEST).
- `df_h.txt`: `/` al **100 %** (9,8 G) y **16 %** de inodos usados.
- `stat_ghasts.txt` / `wc_sha_estado.txt`: tamano exacto, `mtime` y `sha256` del
  fichero completo (`0c0a5a2d...e968f`), 86 174 lineas.
- `app_log_tail.txt`: ultimas lineas de `logs/app.log` (motor de la timeline).
- `dmesg_T.txt`: buffer del kernel del arranque (1708 lineas); el fallo **no** fue OOM
  (no hay trazas de `Out of memory`).
- `nlog_config_original.txt` y `client_ctl_original.sh.txt`: la **causa** (consola a
  `Trace` + redireccion sin tope a `ghasts.out`).
- `timeline_activa.txt`: la timeline del intento (`timeline_72h.json`) y `instance/id.json`.
- **`df_series_agente_001.tsv`**: la serie **`df -P` del agente** (H-H): **220 muestras**
  de la raiz, `2026-10-19T00:03:17Z` -> `2026-10-19T21:57:51Z`; **100 % desde
  `14:03:39Z`** (a las `13:03:36Z` quedaban **1 165 972 KB**). Es la senal que existia y
  nadie leia.
- `keepalive_log.txt`: el keepalive v1 solo comprobaba `pgrep`.
- `legitimo_host_control.log` / `vigilancia_legitimo.log`: trazas host-side del intento,
  **movidas aqui con verificacion de sha256** (ya no estan en el directorio de trabajo).
- `ventana_meta_INVALIDA_2026-10-19.md`: la **ficha de la ventana invalida**, retirada de
  `Dataset/Legitimo/legitimo_72h/` (movida con verificacion de sha256; hash identico
  `061d555b...451a`) para que **no se confunda con una medida**.

## Lo que NO se versiona

- El fichero completo `ghasts.out` (4,78 GB): **solo** en el snapshot de evidencia.
- Los datos del denominador del intento (`ossec-archive-19.json.gz`, 27,7 MB): siguen
  **fuera del repo** en `%TEMP%\tfg-legit-72h-fallo\`. Se usan **solo** como banco de
  pruebas de la extraccion (DT8) y **no** como medida.

## Verificacion

```powershell
Get-FileHash Soporte\Laboratorio\legitimo_72h\fallo_2026-10-19\evidencia\* -Algorithm SHA256
```