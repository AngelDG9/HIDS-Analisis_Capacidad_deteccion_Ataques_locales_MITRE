# ATA048 · T1498.001 — Direct Network Flood (flood TCP acotado al receptor local, custom)

> Artefacto del bloque `fase-03-p1-cierre`, **tanda A** (5.º de 5). Redactado el **2026-10-02**
> con los datos del **paso 0** y las señales esperadas **antes de ejecutar nada**. Validación
> humana: **APROBADO 2026-10-02**. **No contiene secretos.**

## 1. Identificación

| Campo | Valor |
|---|---|
| ATA | **ATA048** |
| Técnica | **T1498.001 — Network DoS: Direct Network Flood** |
| Táctica | Impact |
| Sistema | Linux (`victima-linux`, Ubuntu Server 24.04.5) |
| Vía | **manual / custom** (ART no trae prueba de T1498) |
| Ejecución | usuario `angel`, **sin `sudo`** |

## 2. Qué hace y dónde escribe

- **Qué hace:** genera un **flood de red volumétrico ACOTADO** (8 conexiones TCP concurrentes ×
  8 MiB = **64 MiB**) contra el **receptor del laboratorio** (`192.168.65.1:9091`, modo TCP crudo
  de `sink_http.py`), bajo `timeout`.
- **Destino:** SOLO el receptor del HOST en VMnet1. **NUNCA** el manager (`192.168.65.128`) ni
  servicios reales.
- **Capa del HIDS que ejercita:** **`execve`** (`nc.openbsd`/`head`/`timeout`). El HIDS de host
  **no ve la red**; la prueba es el `sink.log` del HOST (bytes recibidos).

## 3. Herramienta, dependencias y elevación

| Elemento | Valor (verificado en el paso 0, 2026-10-02) |
|---|---|
| Herramientas | `nc` (→ `/usr/bin/nc.openbsd`), `head`, `timeout` (de serie) |
| Dependencias | ninguna nueva |
| Elevación | **no** (usuario `angel`) |
| Guardarraíl | destino FIJO `192.168.65.1:9091`; `CONN ≤ 8`; `TOTAL ≤ 128 MiB`; `MAX_TIME ≤ 15 s` |

## 4. Cómo se ejecuta

1. **En el HOST**, *antes de `t0`*, levantar el receptor en modo TCP (§6).
2. (Tras revert a `lab-listo`) `scp` del directorio a `/home/angel/lab-attack/ATA048/`.
3. `cd /home/angel/lab-attack/ATA048 && bash ATA048_ataque.sh 2>&1 | tee ejecucion.out`.
4. Parar el receptor tras `t1`.

## 5. Señales esperadas (convención H4)

`ATA048_esperado.csv` (todas `deteccion`):

- `T1498.001-S1..S3` `audit_exe ∈ {nc.openbsd, head, timeout}` (`80792`).
- `T1498.001-S4` `audit_cwd=/home/angel/lab-attack/ATA048/*` — ancla H4.

> **Binario real:** `nc` → `/usr/bin/nc.openbsd` (lección del corpus); se declara el nombre real.

## 6. Receptor — cómo se levanta y se retira

```powershell
# Levantar (HOST), ANTES de t0 (modo HTTP 9090 + TCP crudo 9091):
python "Soporte\Ataques\receiver\sink_http.py" --bind 192.168.65.1 --port 9090 --tcp-port 9091 `
  --log "Dataset\Ataques\Resultados\Wazuh\linux\Logs\ATA048_iter1\sink.log"
# Parar tras t1: Ctrl+C / matar el proceso python de sink_http.py
```

## 7. Prueba de éxito (independiente de la alerta)

El `sink.log` del HOST registra las conexiones `TCP from=192.168.65.129 len=... sha256=...`; la
**suma de `len` == 64 MiB** enviados ⇒ el flood salió y llegó al receptor. Evidencia en
`Logs/ATA048_iter*/` (`sink.log` + `ejecucion.out`).

## 8. Reversión e higiene

- **Reversión:** revertir la víctima a **`lab-listo`**. El manager **no** se revierte.
- **Higiene:** flood **acotado** (64 MiB, ≤15 s); `timeout` por conexión; `trap` que mata `nc`;
  **0** procesos residuales. Sin NAT.

## 9. Alcance y limitación declarada (realismo acotado)

> **La técnica y el comando son reales; el alcance es de laboratorio**: el flood va al **receptor
> local simulado** del laboratorio (VMnet1), **acotado** y **sin NAT**; **el entorno no tiene
> usuarios/servicios reales** y **las rutas del ataque son conocidas por el analista**.
