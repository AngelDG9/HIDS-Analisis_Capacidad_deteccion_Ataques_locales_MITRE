# change-doc — Bloque `fase-03-piloto`: primer ciclo completo de ataque (T-09/T-10/T-11)

> Cierre del bloque. Fecha: **2026-09-26**. Estado: **CERRADO** (verificación `tfg-tester`: **15/16 PASA**
> + la única FALLA —el registro del gate humano— **subsanada y comprobada**).
> Plan de referencia: `plan.md` (v2, `status: approved_by_human`; gate (b) cumplido el 2026-09-25).

---

## 1. Qué se ha hecho

Ejecutar **3 ataques reales × 2 iteraciones = 6 ventanas**, recorriendo por primera vez el **ciclo
completo** (T-09/T-10/T-11), y dejar el **procedimiento reutilizable** para el escalado:

```
revert a lab-listo → t0 (UTC) → copia por scp → ataque → scan FIM forzado → t1 (UTC)
→ espera 60 s (2ª consulta 300 s) → extraer del FICHERO DIARIO --detail
→ filtrar por agente → filtrar/etiquetar con el esperado → fila + ficha + bitácora
```

---

## 2. 🎯 Resultados: la primera medición real del TFG

| ATA | Técnica (táctica) | Detecciones | Estado |
|---|---|---|---|
| **ATA002** | T1485 Data Destruction (*Impact*) | **4 · 4** (idénticas) | `review` |
| **ATA008** | T1048.002 Exfil. Over Alt. Protocol (*Exfiltration*) | **2 · 2** (idénticas) | `review` |
| **ATA013** | T1560.002 Archive Collected Data (*Collection*) | **0 · 0** | `review` |

- **ATA002 y ATA008: Wazuh los detecta con su ruleset de fábrica** (RS2): `80792` (execve),
  `80790` (fichero creado), `80781` (escritura), `80791` (borrado). Todo por `audit_exe=/usr/bin/dd`
  y `/usr/bin/wget`.
- **ATA008: la exfiltración está confirmada de verdad** → el `sink.log` del receptor registra el
  `POST` desde `192.168.65.129` con **`sha256` idéntico** al del artefacto.
- **ATA013: NO detectado**, con **causa raíz demostrada** (ver §3).

**Los 3 quedan en `review`** — **no por las detecciones** (idénticas), sino porque **las sanidades
del criterio de doble iteración** (§6 del plan) se disparan por el **ruido de arranque** de la
primera iteración.

---

## 3. ⭐ Hallazgo principal: un punto ciego de FÁBRICA (enmascaramiento)

> **ATA013 no se detecta porque una regla DEL PROPIO Wazuh lo silencia.**

- El `execve` de `python3` **sí se captura** en `audit.log` de la víctima (`key="audit-wazuh-c"`).
- Pero la regla **`92600`** (nivel **0**, *"Executed python script"*, en
  `/var/ossec/ruleset/rules/0850-audit_rules.xml`) casa el mismo evento y **suprime** la base
  `80792` (*Audit: Command*) → **no se emite ninguna alerta**.
- **Es el mismo fenómeno "regla hermana que suprime la base"** que demostró el pre-flight (A2.2)…
  pero aquí lo produce **el ruleset de fábrica**, sin que intervenga ninguna regla nuestra.
  *(Precisión verificada por el tester: `92600` usa `<if_group>audit</if_group>` → es **hermana**
  de `80792`, no hija.)*

**Consecuencia metodológica:** el **pre-flight C1** comprueba *nuestras* reglas contra la base,
**no base-contra-base** → **mejora anotada para el escalado**.

---

## 4. Otros hallazgos del piloto (mejoras para el escalado)

| # | Hallazgo | Mejora propuesta |
|---|---|---|
| **H2** | El **ruido de arranque** domina las ventanas cortas (1ª iteración tras el revert) → dispara las sanidades del §6 y obliga a `review`. | Comparar solo lo relevante, o excluir el churn de arranque de las sanidades. |
| **H3** | El **`sin_campos`** del filtro convierte en `dudosa` toda alerta sin campos `audit.*`, y las **sesiones SSH del operador** (PAM/sshd) ni el **SCA del propio HIDS** (`19004`) los tienen → **dudosas sistemáticas** (habría cientos en el escalado). | Reconocer y excluir las sesiones del operador y el SCA del propio HIDS. |
| **H4** | Las **señales esperadas** se basan en el **nombre del proceso** (`dd`/`wget`/`python3`), que es genérico. | Hacerlas **más específicas** (añadir la **carpeta del ataque** como señal). |

---

## 5. Verificación (`tfg-tester`) — sin lanzar ataques

**15 de 16 comprobaciones PASA**; la única **FALLA** fue **CA5** (no había **registro** de que el
humano validara los `esperado`, aunque la validación **sí ocurrió**). **Subsanada**: los 3 CSV
registran *"Gate humano: validado el 2026-09-25"*, `plan.md` lo refleja, y los artefactos afectados
se **regeneraron** (los `-Audited.csv` llevan en cabecera el `sha256` del esperado → actualizado;
**determinismo re-verificado**).

Comprobado además de forma independiente: artefactos coherentes con el clon de ART (**GUID/path/commit**),
**esperados escritos antes** del primer `t0`, **15 columnas exactas** con `modo=ataque`, conteos de
cabecera = reales, **`dudosa=0`** en las 6, **determinismo** (3 ventanas regeneradas → mismo `sha256`),
`t0`/`t1` UTC coherentes con la ventana, **aislamiento por agente** (0 filas de `wazuh-server`),
**doble iteración** recomputada, **sin instalaciones** (`lab-listo` prístino), **sin secretos**,
**solo 3 filas** de `ATA_index.csv` tocadas, `pytest` **58 en verde**, `_recursos/` intacto.

**El hallazgo `92600` fue auditado a fondo** por el tester (regla + `audit.log` + `wazuh-logtest`) y
**se sostiene**: con una línea `ls` el mismo `key` **sí** genera `80792`; con `python3`, **no**.

---

## 6. Decisiones humanas (2026-09-25)

| # | Decisión |
|---|---|
| 1 | **Validar los 3 `ATA<NNN>_esperado.csv`** tal como estaban (y anotar H4). |
| 2 | **Aceptar la desviación de ATA002**: escribir en `lab-legit` en vez de `/etc` (no se puede escribir en `/etc` sin elevación; el plan prohíbe `sudo` para no meter ruido). Se pierde la señal FIM. |
| 3 | **177 dudosas de ATA002 → `ruido`** (señal ambigua demasiado amplia; ninguna toca la carpeta del ataque; reglas ya en el catálogo). |
| 4 | **7 dudosas de ATA008 → `ruido`** (sesiones SSH del propio operador). |
| 5 | **`19004` (SCA) → `ruido`** (autoevaluación del propio HIDS, ajena al ataque). |
| 6 | **Aceptar `review`** en los 3 ataques y **anotar** que el criterio es demasiado estricto para ventanas cortas tras revert. |

---

## 7. Entregables

| Qué | Dónde |
|---|---|
| Artefactos (R-13): README + script + esperado | `Dataset/Ataques/Comandos/T1485-Data_Destruction/`, `…/T1048-Exfiltration_Over_Alternative_Protocol/`, `…/T1560-Archive_Collected_Data/` |
| Detalle por alerta | `Dataset/Ataques/Resultados/Wazuh/linux/CSV/ATA<NNN>_iterN-Detalle.csv` (+ `_raw`) |
| Auditado + revisión | `…/linux/Auditado/ATA<NNN>_iterN-Audited.csv` (+ `-Revision.csv`) |
| Evidencia | `…/linux/Logs/ATA<NNN>_iterN/` (`times.log`, `ejecucion.out`, `ps_*`, `deps.txt`, `sha256_artefacto.txt`, `sink.log`, `artefacto_salida.txt`) |
| Fichas | `…/linux/ATA<NNN>_meta.md` |
| Bitácoras | `Bitacora/ATA002.json`, `ATA008.json`, `ATA013.json` |
| Índice | `Hojas/ATA_index.csv` (**solo** esas 3 filas, `review`) |
| Runbook reutilizable | `Soporte/Ataques/piloto_procedimiento.md` |
| Receptor | `Soporte/Ataques/receiver/{README.md,sink_http.py}` |

---

## 8. Cierre operativo (ejecutado y verificado)

- **Regla de firewall `TFG-sink-9090` retirada** (verificado: ya no existe).
- **Receptor parado** (sin proceso).
- **Víctima revertida a `lab-listo`**: arranca, agente `active`/`Active`, `/home/angel/lab-attack` **no existe**.
- **NAT desconectado** en todo el bloque · **sin instalaciones** · **sin** reglas RS3/RS4 · **VMs encendidas**.

---

## 9. Cabos y siguientes pasos

- **Deudas anotadas para el escalado:** H2 (criterio de sanidad), H3 (`sin_campos`: operador + SCA),
  H4 (señales genéricas) y **el pre-flight sin cobertura base-contra-base** (H1).
- **Comprobar en el escalado** el **solapamiento de rangos** del manifiesto (cabo de A2.2).
- **`push`**: los commits son locales; publicar es tarea del humano.
- **Siguiente:** el **escalado** de los ataques (las 10 técnicas restantes del corpus, con los
  artefactos y las señales ya afinadas) y, en paralelo, la **tutoría (H1/H2)**.
