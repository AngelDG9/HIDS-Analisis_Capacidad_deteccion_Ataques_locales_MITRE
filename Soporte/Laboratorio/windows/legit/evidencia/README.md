# evidencia/ — W3 (corrección 2026-11-10)

> Bloque `windows-legit-prep` (W3). **Sin secretos.** La contraseña del invitado se pasó
> siempre por STDIN y no se escribió en ningún fichero, log ni script.

## `test_il.ps1` + `test_il_salida.txt`

- `test_il.ps1` es la versión **corregida** del script que estaba en el temp del host: el
  original registraba la tarea `Password` sin credencial y fallaba
  (`The user name or password is incorrect`). Aquí se registra con `-User/-Password`.
- `test_il_salida.txt` es la **salida literal** del invitado recién revertido al snapshot
  `lab-listo-windows-legit`.
- Resultado: **Interactive = Medium (S-1-16-8192)** y **Password = High (S-1-16-12288)**.
  Es la evidencia de **D-W3-3** (la tarea de actividad debe ir `Interactive`).

## `keepalive.log`, `recovery.log`, `estado.json`

- Copiados del invitado tras **arrancar** el snapshot el **2026-11-10** (último latido
  copiado: `12:05:46Z`).
- **Procedencia:** los generó la tarea `TFG-WinLegit-Keepalive` durante **ese arranque**,
  no durante la prueba de 2 h de §5.4.
- **Lo que demuestran:** la tarea keepalive existe y está `Ready`, corre como `angel`,
  late cada 5 min, mantiene `wuauserv` `Stopped/Disabled`, el disco en ~21,3 GB y, fuera
  de ventana, `armado=False` / `cliente_vivo=False`.
- **Lo que NO demuestran:** las 2 h, la muerte provocada de `10:02:11Z`, la recuperación
  de `10:05:08Z` ni `win_user=angel` con el cliente vivo. **El snapshot no contiene esos
  logs**: el `revert + apply` de las `11:28Z` borró `C:\Users\angel\ghosts-client` antes de
  sellar el snapshot y la tarea volvió a crear `keepalive.log`/`estado.json` al arrancar.
  Esa laguna **no se puede cerrar con este snapshot** (ver `snapshot_windows_legit.md` §5.4).
