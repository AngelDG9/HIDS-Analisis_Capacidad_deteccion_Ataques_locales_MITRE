# Evidencias del ensayo E0 (v5) — 2026-10-28

**Qué es esto.** Copia de las **salidas literales** del ensayo E0 del bloque `legitimo-v3`,
tal como se citan en `../ensayo_E0_v5.md`. Se copian **sin recortar** (el documento las
recorta donde lo dice). Origen: `%TEMP%\opencode\e0_v5\` (efímero); aquí quedan congeladas.

**No hay secretos**: no aparece `TFG_GUEST_PW` ni `TFG_MANAGER_PW` (se pasan por `stdin` a los
scripts remotos y nunca se escriben en fichero ni en log).

## Mapa fichero → sección del documento

| Fichero | Qué es | Sección |
|---|---|---|
| `p0_cleanup.out.txt` / `.err.txt` / `.rc.txt` | `cleanup` de partida (rc=0). El `.err` solo tiene el `pg_ctl: PID no existe` **inocuo** | §2.1 |
| `p2_prep.out.txt` / `.err.txt` / `.rc.txt` | `prep` completo (G-1…G-12, deploy, G-8 con los 3 puertos) | §2.3 |
| `p4_arm.out.txt` / `.err.txt` / `.rc.txt` | `arm`; el `.err` conserva el **error de comillas de H-1** (`El término '^' no se reconoce`) | §2.5, §5 H-1 |
| `timer.txt`, `timer2.txt` | `systemctl list-timers` tras `arm` (`NEXT = T0−5`) y tras pararlo | §2.5, §5 H-5 |
| `p1_*.txt`, `p1_db_cmds.tsv`, `p1_d1.uno.json` | tramo **P1**: arranque/parada del cliente, `audit`, comandos vistos por auditd y la timeline usada (`sha256 b4735ceb…`) | §3.1, §3.2, §3.3 |
| `p2_*.txt`, `p2_db_cmds.tsv`, `p2_b6.json` | tramo **P2** (campaña B6): ídem + diagnóstico de los `rm`/`xargs` propios (`sha256 010e58bf…`) | §3.1, §3.3, §3.5 |
| `p6_stop.*`, `p6_cleanup.*` | `stop` + `cleanup` (67 s; `stderr` vacío; `CONFIG_IDENTICA`) | §2.7 |
| `p7_verificar.txt` | `verificar_arreglos.sh` tras el revert a `lab-listo-legit-v3` (`RESULT=PASS`) | §2.8 |
| `e0_cmp.py` | comparación multiconjunto timeline vs BD (147/147 y 63/63, 0 pipes) | §3.1 |
| `e0_audit_cwd.py`, `e0_audit_exe.py` | recuento de `cwd` y de binarios en `archives.json` | §3.3 |
| `campana_fp.tgz` | árbol de `campana_fp/` al cerrar la campaña (11 casos × `inicio|fin|hecho`) | §3.5, §3.6 |

## Lo que **no** se copia

- Intermedios de trabajo (`p1_d1.dry.json`, `status_probe*.txt`, `run_to.ps1`, `sha_head.txt`):
  eran andamios, no evidencia.
- Nada del invitado que contenga credenciales ni líneas de `sudo -S`.
