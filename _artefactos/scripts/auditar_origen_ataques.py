#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""auditar_origen_ataques.py — Auditoría 1x1 del origen de los 43 ataques (T1).

Herramienta READ-ONLY del bloque `fase-03-auditoria-metodologica`. Extrae las
columnas **factuales** del origen de cada ataque cruzando las fuentes del repo:

  - `Bitacora/ATA<NNN>.json`  (bloque `atomic`: fuente / guid / path / commit / nota)
  - `Hojas/ATA_index.csv`     (tactica, tecnica, descripcion, artefacto)
  - `Hojas/cobertura_atomic.csv`  (mapa de cobertura ART regenerado; T1)
  - `Dataset/Ataques/Comandos/*/README.md`  (fila `Via`)

Las columnas de **juicio** (`como_se_construyo`, `se_sustituyo`, `material_externo`,
`motivo_codigo`, `motivo_detalle`, `citas`) NO se inventan aquí: van en una tabla de
decisiones declarada en el módulo (`DECISIONES`) y se contrastan, celda a celda, con
la bitácora y el README.

Cada cita del campo `citas` **resuelve contra el fichero citado**:
  - `fichero:<linea>[-<linea>]`  -> la línea existe en el fichero;
  - `fichero §<n>[, §<m>]`        -> el encabezado `## <n>.` existe en el README;
  - `fichero.json (campo, campo)` -> las claves existen en el JSON;
  - `cobertura_atomic.csv (ATA<NNN> ...)` -> la fila existe y la nota/tests citados coinciden.
  Lo comprueba `verificar_citas_auditoria.py` (43/43).

El CSV final se escribe **UTF-8 sin BOM y con LF** y de forma **determinista**
(sin fecha); lleva una **nota de cabecera** (`#`) que fija la semántica de `motivo_codigo`
(por qué NO se usó ART; no aplica a `ART_tal_cual`/`ART_adaptado` -> `na_art_usado`).

Uso:
    python _artefactos/scripts/auditar_origen_ataques.py
    python _artefactos/scripts/auditar_origen_ataques.py --out Hojas/auditoria_origen.csv
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BITACORA = REPO_ROOT / "Bitacora"
INDEX = REPO_ROOT / "Hojas" / "ATA_index.csv"
COBERTURA = REPO_ROOT / "Hojas" / "cobertura_atomic.csv"
COMANDOS = REPO_ROOT / "Dataset" / "Ataques" / "Comandos"
DEFAULT_OUT = REPO_ROOT / "Hojas" / "auditoria_origen.csv"

HEADER = [
    "ata_id",
    "tecnica",
    "fuente",
    "art_disponible",
    "tests_plataforma",
    "art_usado",
    "motivo_codigo",
    "motivo_detalle",
    "como_se_construyo",
    "se_sustituyo",
    "material_externo",
    "citas",
    "candidato_repetir_art",
    "candidato_repetir_prestaging",
]

# Nota de cabecera (se escribe como primera línea, prefijada con `#`).
HEADER_NOTE = (
    "# auditoria_origen.csv | T2 del bloque fase-03-auditoria-metodologica. "
    "motivo_codigo = por qué NO se usó ART; en fuente=ART_tal_cual/ART_adaptado ese motivo no "
    "aplica -> na_art_usado (motivo_detalle='se usó ART'). "
    "art_disponible/tests_plataforma provienen de Hojas/cobertura_atomic.csv (plataforma=Linux). "
    "candidato_repetir_art/candidato_repetir_prestaging segun "
    "_fases/fase-03-auditoria-metodologica/auditoria_decisiones.md (Listas A y B)."
)

# Fuentes normalizadas (columna `fuente`).
ART_TAL_CUAL = "ART_tal_cual"
ART_ADAPTADO = "ART_adaptado"
PROPIO = "propio"

NO_CONSTA = "no_consta"
NA_ART_USADO = "na_art_usado"
SE_USO_ART = "se usó ART"

# Candidatos de repetición (T3) — codificados de `auditoria_decisiones.md`.
# Lista A (repetir por ART): propio + tests_linux>=1 + offline + mismo mecanismo.
CAND_ART = {"ATA024", "ATA029", "ATA030", "ATA038"}
# Lista B (repetir por pre-staging): siembra el activo legítimo dentro de [t0,t1]
# sin que esa siembra sea la técnica.
CAND_PRESTAGING = {"ATA014", "ATA016", "ATA029", "ATA035", "ATA036", "ATA037", "ATA038"}


def _read_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_corpus() -> list[dict]:
    with open(INDEX, "r", encoding="utf-8", newline="") as fh:
        lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
    return [r for r in csv.DictReader(lines) if (r.get("ata_id") or "").strip()]


def load_cobertura() -> dict[str, dict]:
    with open(COBERTURA, "r", encoding="utf-8", newline="") as fh:
        return {r["ata_id"]: r for r in csv.DictReader(fh)}


def load_bitacoras() -> dict[str, dict]:
    out = {}
    for p in sorted(BITACORA.glob("ATA*.json")):
        d = _read_json(p)
        out[d.get("ata_id")] = d
    return out


def readme_path(artefacto: str) -> Path | None:
    """A partir del `artefacto` del corpus, localiza el README del comando."""
    if not artefacto:
        return None
    base = REPO_ROOT / artefacto
    if base.is_dir():
        rm = base / "README.md"
        if rm.is_file():
            return rm
    return None


def readme_via(readme: Path) -> str:
    """Extrae la fila `| Vía | ... |` del README (columna `Vía`)."""
    try:
        txt = readme.read_text(encoding="utf-8")
    except OSError:
        return ""
    for ln in txt.splitlines():
        if re.match(r"^\|\s*V[ií]a\s*\|", ln, flags=re.IGNORECASE):
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if len(cells) >= 2:
                return cells[1]
    return ""


# --------------------------------------------------------------------------
# Tabla de DECISIONES (juicio humano, con cita). Una entrada por ATA.
# `fuente`      -> ART_tal_cual | ART_adaptado | propio
# `motivo`      -> codigo de la lista cerrada (por que NO se uso ART;
#                  NO aplica a las filas ART -> na_art_usado)
# `detalle`     -> frase obligatoria segun el codigo
# `construyo`   -> como se construyo (con cita)
# `sustituyo`   -> que se sustituyo respecto al enfoque de ART (o "(ninguno)")
# `externo`     -> material traido de fuera (o "(ninguno)")
# `citas`       -> citas que RESUELVEN contra el fichero citado
#                  (`README.md §<n>`, `fichero:linea`, `json (campo)`).
# --------------------------------------------------------------------------
DECISIONES: dict[str, dict[str, str]] = {
    "ATA001": {
        "fuente": ART_TAL_CUAL,
        "motivo": NA_ART_USADO,
        "detalle": SE_USO_ART,
        "construyo": "Se usa la atómica de ART T1486 tal cual (test #4 'Encrypt files using openssl'); "
                     "se desvía el cifrado a `openssl enc` (AES simétrico) declaradamente.",
        "sustituyo": "RSA (`genrsa`+`rsautl`) de la atómica -> `openssl enc` AES-256-CBC (declarado; no soporta entradas largas y `rsautl` está deprecado)",
        "externo": "Prueba de ART (guid 142752dc...); sin payloads externos",
        "citas": "Bitacora/ATA001.json (atomic.guid, atomic.nota); "
                 "Dataset/Ataques/Comandos/T1486-Data_Encrypted_for_Impact/README.md §2, §4",
    },
    "ATA002": {
        "fuente": ART_TAL_CUAL,
        "motivo": NA_ART_USADO,
        "detalle": SE_USO_ART,
        "construyo": "Atómica de ART T1485 ('Overwrite file with DD'), con el destino re-parametrizado a `lab-legit` (D1) por no poder escribir en /etc sin sudo.",
        "sustituyo": "Destino `/etc/tfg_lab_scratch_dd.txt` -> `lab-legit/ATA002_scratch_dd.txt` (imposible sin sudo; declarado). Sustitución de destino, no de técnica.",
        "externo": "Prueba de ART (guid 38deee99...); uso de `dd` coreutils",
        "citas": "Bitacora/ATA002.json (atomic.guid, atomic.path); "
                 "Dataset/Ataques/Comandos/T1485-Data_Destruction/README.md §2, §4",
    },
    "ATA003": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "ART solo trae 12 pruebas Windows (tests_linux=0): la técnica sí aplica a Linux; se escribe a mano un borrado de copias mock. Se omite a propósito la variante `systemctl` (ya cubierta por ATA004).",
        "construyo": "Guion propio: `rm -rf` sobre copias de seguridad mock en `lab-legit/copias_seguridad/`.",
        "sustituyo": "(ninguno: no se partió de una atómica ejecutable)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA003.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1490-Inhibit_System_Recovery/README.md §2, §3; "
                 "Hojas/cobertura_atomic.csv (ATA003 solo_windows)",
    },
    "ATA004": {
        "fuente": ART_TAL_CUAL,
        "motivo": NA_ART_USADO,
        "detalle": SE_USO_ART,
        "construyo": "Atómica de ART T1489 ('Linux - Stop service using systemctl') tal cual, con `service_name=cron` fijado.",
        "sustituyo": "(ninguno respecto al comando); el cleanup de ART no se ejecuta (el revert restaura el servicio)",
        "externo": "Prueba de ART (guid 42e3a5bd...); requiere elevación",
        "citas": "Bitacora/ATA004.json (atomic.guid, atomic.nota); "
                 "Dataset/Ataques/Comandos/T1489-Service_Stop/README.md §2",
    },
    "ATA005": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "ART no trae ninguna prueba (ni Linux ni Windows) para T1561 (tests_linux=0, sin_pruebas): la técnica sí aplica a Linux; se escribe a mano una simulación segura sobre un fichero de trabajo.",
        "construyo": "Guion propio: `dd if=/dev/urandom` + `shred` sobre un fichero de trabajo de 32 MiB en `lab-attack`. Guardarraíles duros: nunca un disco real.",
        "sustituyo": "(ninguno: no había atómica)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA005.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1561-Disk_Wipe/README.md §2, §3; "
                 "Hojas/cobertura_atomic.csv (ATA005 sin_pruebas)",
    },
    "ATA006": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "ART no trae ninguna prueba (ni Linux ni Windows) para T1565 (sin_pruebas): la técnica sí aplica a Linux; se escribe a mano la alteración de contenido. Se retiran `touch`/`chmod` (T1070.006 Timestomp, otra técnica).",
        "construyo": "Guion propio: `sed -i` que altera el contenido de un fichero de datos mock en `lab-legit`.",
        "sustituyo": "(ninguno: no había atómica); se retiran `touch`/`chmod` del alcance (decisión humana)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA006.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1565-Data_Manipulation/README.md §2, §3; "
                 "Hojas/cobertura_atomic.csv (ATA006 sin_pruebas)",
    },
    "ATA007": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "ART solo trae pruebas Windows para T1491 (tests_linux=0): la técnica sí aplica a Linux; se escribe a mano el defacement (no se copia de ART).",
        "construyo": "Guion propio: `cp` de un HTML de defacement sobre el `index.html` de una página mock en `lab-legit`.",
        "sustituyo": "(ninguno: no había atómica Linux)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA007.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1491-Defacement/README.md §2; "
                 "Hojas/cobertura_atomic.csv (ATA007 solo_windows)",
    },
    "ATA008": {
        "fuente": ART_TAL_CUAL,
        "motivo": NA_ART_USADO,
        "detalle": SE_USO_ART,
        "construyo": "Atómica de ART T1048.002 ('Exfiltrate data over HTTPS using wget') con el endpoint re-apuntado al receptor local del HOST (HTTP simple, sin certificados).",
        "sustituyo": "Endpoint `https://example.com/` -> receptor local del HOST (`192.168.65.1:9090`); se conserva `--no-check-certificate` (inerte en HTTP). Sustitución de destino, no de técnica.",
        "externo": "Prueba de ART (guid 7ccdfcfa...) con su `src/artifact`",
        "citas": "Bitacora/ATA008.json (atomic.guid, atomic.path); "
                 "Dataset/Ataques/Comandos/T1048-Exfiltration_Over_Alternative_Protocol/README.md §2",
    },
    "ATA009": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "ART trae 3 pruebas Linux de T1567, pero usan `rclone` contra la nube o `terraform`+AWS: no ejecutables sin NAT ni sin credenciales.",
        "construyo": "Guion propio: `curl` POST de un fichero al receptor local del HOST (`/api/upload`), reutilizando el receptor del piloto.",
        "sustituyo": "Servicio web en la nube -> receptor local simulado (declarado)",
        "externo": "Receptor `Soporte/Ataques/receiver/sink_http.py` (infraestructura local del laboratorio)",
        "citas": "Bitacora/ATA009.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1567-Exfiltration_Over_Web_Service/README.md §2; "
                 "_fases/fase-03-escalado/plan.md:59",
    },
    "ATA010": {
        "fuente": PROPIO,
        "motivo": "art_no_prueba_plataforma",
        "detalle": "solo la otra",
        "construyo": "Guion propio: `curl` POST de un beacon al receptor local del HOST (`/c2/beacon`), reutilizando el receptor del piloto (D4-A).",
        "sustituyo": "Canal C2 real -> receptor local simulado (declarado; D4 opción A)",
        "externo": "Receptor `Soporte/Ataques/receiver/sink_http.py`",
        "citas": "Bitacora/ATA010.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1041-Exfiltration_Over_C2_Channel/README.md §2, §4; "
                 "Hojas/cobertura_atomic.csv (ATA010 solo_windows)",
    },
    "ATA011": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "ART trae 1 prueba Linux de T1074 que descarga datos de GitHub: no ejecutable sin NAT.",
        "construyo": "Guion propio: `mkdir -p` + `cp` para reunir datos simulados en un directorio de staging, con manifiesto sha256.",
        "sustituyo": "Descarga de datos de GitHub -> datos de juguete sembrados en la carpeta del ataque (declarado)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA011.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1074-Data_Staged/README.md §2; "
                 "_fases/fase-03-escalado/plan.md:61",
    },
    "ATA012": {
        "fuente": PROPIO,
        "motivo": "art_no_prueba_plataforma",
        "detalle": "solo la otra",
        "construyo": "Guion propio: `find`+`cp`+`tar` que recolecta ficheros legibles del sistema y los empaqueta en la carpeta del ataque.",
        "sustituyo": "(ninguno: no había atómica Linux)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA012.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1119-Automated_Collection/README.md §2, §3; "
                 "Hojas/cobertura_atomic.csv (ATA012 solo_windows)",
    },
    "ATA013": {
        "fuente": ART_TAL_CUAL,
        "motivo": NA_ART_USADO,
        "detalle": SE_USO_ART,
        "construyo": "Atómica de ART T1560.002 ('Compressing data using GZip in Python') con la salida re-apuntada a la carpeta del ataque; `python3` fijo.",
        "sustituyo": "Salida `/tmp/passwd.gz` -> `lab-attack/ATA013/passwd.gz`; `which python || which python3` -> `python3` fijo. Sustitución de destino/parametrización, no de técnica.",
        "externo": "Prueba de ART (guid 391f5298...)",
        "citas": "Bitacora/ATA013.json (atomic.guid, atomic.path); "
                 "Dataset/Ataques/Comandos/T1560-Archive_Collected_Data/README.md §2, §4",
    },
    "ATA014": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "ART no trae prueba Linux utilizable sin red para T1114.",
        "construyo": "Guion propio: siembra un mbox simulado en `lab-legit`, lo lee/parsea (`grep`) y copia los mensajes a la carpeta del ataque.",
        "sustituyo": "(ninguno: la prueba ART no era utilizable)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA014.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1114-Email_Collection/README.md §2",
    },
    "ATA015": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "El mecanismo es la persistencia de reenvío (`.forward`/`.procmailrc`), distinto de leer el buzón (ATA014); sin red.",
        "construyo": "Guion propio: escribe `.forward`/`.procmailrc` (regla de reenvío) en `lab-legit` y copia la regla a la carpeta del ataque.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA015.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1114.003-Email_Forwarding_Rule/README.md §2",
    },
    "ATA016": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "La prueba ART de T1213 depende de repositorios en red/SaaS (no viable sin NAT).",
        "construyo": "Guion propio: siembra una BD SQLite real con la stdlib de `python3` (punto ciego 92600 declarado) y recolecta con `cp`/`grep`.",
        "sustituyo": "Repositorio en red/SaaS -> BD SQLite local simulada (declarado)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA016.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1213.006-Databases/README.md §3",
    },
    "ATA017": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "La prueba ART de T1657 depende de servicios/red; sin NAT se escribe a mano.",
        "construyo": "Guion propio: modifica un libro de cuentas local simulado y sustrae una cartera simulada (datos de juguete).",
        "sustituyo": "Servicios/red -> datos de juguete locales (declarado)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA017.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1657-Financial_Theft/README.md §2",
    },
    "ATA018": {
        "fuente": ART_ADAPTADO,
        "motivo": NA_ART_USADO,
        "detalle": SE_USO_ART,
        "construyo": "Guion propio (contenido): wrapper que registra la entrada de una sesión simulada a un fichero en `lab-attack` y persiste con `logger`.",
        "sustituyo": "Auditoría de PAM/TTY real -> captura de una sesión simulada de juguete (contención declarada)",
        "externo": "Enfoque de una prueba de ART ('Logging bash history to syslog')",
        "citas": "Bitacora/ATA018.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1056.001-Keylogging/README.md §3",
    },
    "ATA019": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "La prueba ART de T1048.001 no trae una prueba Linux ejecutable sin NAT (cifrado simétrico + protocolo alternativo).",
        "construyo": "Guion propio: `openssl enc` (AES simétrico) + envío TCP crudo al receptor del HOST (modo `--tcp-port`).",
        "sustituyo": "Nube/receptor externo -> receptor local con modo TCP (declarado)",
        "externo": "Receptor `sink_http.py` (modo TCP añadido en el bloque)",
        "citas": "Bitacora/ATA019.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1048.001-Symmetric_Encrypted_Non-C2/README.md §2",
    },
    "ATA020": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "El fenómeno de la técnica es la automatización (bucle que exfiltra sin intervención), distinto de ATA009 (un fichero) y ATA010 (un canal C2).",
        "construyo": "Guion propio: bucle que recorre un staging y hace `curl` POST por fichero al receptor local.",
        "sustituyo": "(ninguno)",
        "externo": "Receptor `sink_http.py`",
        "citas": "Bitacora/ATA020.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1020-Automated_Exfiltration/README.md §2",
    },
    "ATA021": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "El mecanismo es programar la transferencia (crontab de usuario) para que la ejecute cron dentro de la ventana; distinto de un envío directo.",
        "construyo": "Guion propio: instala una entrada de cron de usuario que exfiltra un dato al receptor y la retira al terminar.",
        "sustituyo": "(ninguno)",
        "externo": "Receptor `sink_http.py`",
        "citas": "Bitacora/ATA021.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1029-Scheduled_Transfer/README.md §2",
    },
    "ATA022": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "El mecanismo es `git push` a un repositorio de código; sin NAT se usa un `git` bare LOCAL (guardarraíl R6: jamás un remoto real).",
        "construyo": "Guion propio: `git init`/`commit`/`push` a un repositorio bare local (`file://`) dentro de `lab-attack`.",
        "sustituyo": "Repositorio remoto real (GitHub/GitLab) -> repo `git` bare local (declarado; guardarraíl)",
        "externo": "(ninguno; repo desechable local)",
        "citas": "Bitacora/ATA022.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1567.001-Exfiltration_To_Code_Repository/README.md §2, §4",
    },
    "ATA023": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "La técnica sí aplica a Linux, pero ART no trae prueba Linux utilizable sin NAT; el consumo de banda se simula con una transferencia acotada al receptor local.",
        "construyo": "Guion propio: flujo de 32 MiB de ceros (`head -c /dev/zero`) volcado al receptor local (`curl`), acotado.",
        "sustituyo": "Saturación de red real -> transferencia acotada a receptor local (declarado)",
        "externo": "Receptor `sink_http.py`",
        "citas": "Bitacora/ATA023.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1496.002-Bandwidth_Hijacking/README.md §2, §4",
    },
    "ATA024": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Sabotaje de una cuenta desechable (`useradd`/`passwd -l`/`userdel`) para tocar las capas auth/PAM/syslog y los ficheros de cuentas; guardarraíl: jamás cuentas reales.",
        "construyo": "Guion propio: crea el usuario desechable `tfg-victim01`, lo bloquea y lo elimina (con `trap` de limpieza).",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA024.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1531-Account_Access_Removal/README.md §2",
    },
    "ATA025": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "«Minería» simulada con carga de CPU acotada; Wazuh no tiene reglas de recursos -> se espera detección solo por `execve`.",
        "construyo": "Guion propio: 2 procesos `yes` bajo `timeout 10s` (cota dura WORKERS<=4 / DURATION<=15s).",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA025.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1496.001-Compute_Hijacking/README.md §2",
    },
    "ATA026": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Manipulación del dato EN TRÁNSITO (proxy local `nc|sed|nc`): el efecto es la alteración, no el robo.",
        "construyo": "Guion propio: proxy local en loopback que reescribe el cuerpo antes de reenviarlo al receptor del HOST.",
        "sustituyo": "(ninguno)",
        "externo": "Receptor `sink_http.py` (modo TCP)",
        "citas": "Bitacora/ATA026.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1565.002-Transmitted_Data_Manipulation/README.md §2",
    },
    "ATA027": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Borrado de la ESTRUCTURA de una imagen de fichero desechable (tabla MBR + ext4 + wipefs), mecanismo distinto de ATA005 (contenido); guardarraíl duro: nunca un disco real.",
        "construyo": "Guion propio sobre `lab-attack/ATA027/disk.img`: `sfdisk`+`mkfs.ext4`+`mount loop`+`wipefs`+`dd` de ceros sobre la cabecera.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA027.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1561.002-Disk_Structure_Wipe/README.md §2",
    },
    "ATA028": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Portal falso LOCAL (loopback) que captura el POST de credenciales de juguete; se sirve con `nc` (no `python3`) para evitar el punto ciego 92600.",
        "construyo": "Guion propio: listener `nc -l 127.0.0.1` que registra el POST + cliente `curl` con credenciales de juguete.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno; portal local en loopback)",
        "citas": "Bitacora/ATA028.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1056.003-Web_Portal_Capture/README.md §2",
    },
    "ATA029": {
        "fuente": PROPIO,
        "motivo": "no_se_comprobo",
        "detalle": "Hueco declarado: el mapa da prueba Linux (tests_linux=1) y el plan la marcaba como ART adaptable, pero no consta en el repo que se comprobara ni ejecutara la atómica; se ejecutó guion propio.",
        "construyo": "Recolección dirigida (lista declarada de 3 ficheros) de `lab-legit/srv_data` a la carpeta del ataque con `cp`. El plan la marca como ART adaptable, pero se ejecutó guion propio (no se usó la atómica).",
        "sustituyo": NO_CONSTA,
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA029.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1005-Data_from_Local_System/README.md §1, §2; "
                 "_fases/fase-03-ampliacion-2/plan.md:116; "
                 "Hojas/cobertura_atomic.csv (ATA029 cubierta, tests_linux=1)",
    },
    "ATA030": {
        "fuente": PROPIO,
        "motivo": "no_se_comprobo",
        "detalle": "Hueco declarado: el mapa da prueba Linux (tests_linux=5) y el plan la marcaba como ART adaptable, pero no consta en el repo que se comprobara ni ejecutara la atómica; se ejecutó guion propio.",
        "construyo": "Archivado con utilidad (`tar -czf`) sobre material de juguete; el plan la marca como ART adaptable (5 pruebas Linux), pero se ejecutó guion propio.",
        "sustituyo": NO_CONSTA,
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA030.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1560.001-Archive_via_Utility/README.md §1, §2; "
                 "_fases/fase-03-ampliacion-2/plan.md:117; "
                 "Hojas/cobertura_atomic.csv (ATA030 cubierta, tests_linux=5)",
    },
    "ATA031": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Saturación de un Maildir simulado por volumen (25 entregas `cp` acotadas); sin MTA ni `sudo`.",
        "construyo": "Guion propio: N=25 entregas `cp` en `lab-legit/Maildir/new` (cota dura N<=50).",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA031.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1667-Email_Bombing/README.md §2",
    },
    "ATA032": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Manipulación EN REPOSO de un ledger simulado (`sed -i`), distinta de ATA026/T1565.002 (en tránsito).",
        "construyo": "Guion propio: `sed -i` (replace+append) sobre el ledger de `lab-legit/finanzas`.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA032.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1565.001-Stored_Data_Manipulation/README.md §2",
    },
    "ATA033": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Defacement INTERNO del webroot de una intranet simulada; las atómicas de ART son Windows.",
        "construyo": "Guion propio: `cp` de `deface_internal.html` sobre el `index.html` del portal simulado en `lab-legit/intranet_web`.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA033.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1491.001-Internal_Defacement/README.md §2; "
                 "Hojas/cobertura_atomic.csv (ATA033 solo_windows)",
    },
    "ATA034": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Archivado por MÉTODO PROPIO con builtins de bash (contenedor casero), sin tar/zip/gzip en el bucle; punto ciego por ausencia de telemetría.",
        "construyo": "Guion propio: contenedor `ATA034-CUSTOM-ARCHIVE v1` construido solo con builtins (el bucle corre con PATH=/nonexistent).",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA034.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1560.003-Archive_via_Custom_Method/README.md §2, §5",
    },
    "ATA035": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Hook de API por `LD_PRELOAD` sobre un binario de laboratorio; el payload se compila fuera (la víctima no tiene compilador) y viaja como `.b64`.",
        "construyo": "Guion propio: `hook.so` + `credfetch` (C propio) precompilados, transportados como `.b64` y decodificados.",
        "sustituyo": "(ninguno; atómicas de ART son Windows)",
        "externo": "Payload precompilado propio (`hook.so`/`credfetch`, C del TFG) versionado como `.c`/`.b64`",
        "citas": "Bitacora/ATA035.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1056.004-Credential_API_Hooking/README.md §2; "
                 "Hojas/cobertura_atomic.csv (ATA035 solo_windows)",
    },
    "ATA036": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Manipulación de un dato EN MEMORIA de un proceso de laboratorio por `ptrace`; la víctima no tiene `gcc`/`gdb`, el payload viaja como `.b64`.",
        "construyo": "Guion propio: `memedit` (C propio) se adjunta por `PTRACE_ATTACH` al `target` y sobrescribe el dato con `PTRACE_POKEDATA`.",
        "sustituyo": "(ninguno)",
        "externo": "Payload precompilado propio (`memedit`/`target`, C del TFG) versionado como `.c`/`.b64`",
        "citas": "Bitacora/ATA036.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1565.003-Runtime_Data_Manipulation/README.md §2",
    },
    "ATA037": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Borrado del CONTENIDO de una imagen de fichero desechable sin dañar la estructura; contraste con ATA027 (estructura); guardarraíl duro: nunca un disco real.",
        "construyo": "Guion propio sobre `lab-attack/ATA037/disk.img`: `dd` ceros + `mkfs.ext4` + `mount loop` + `dd` de `urandom` in place.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA037.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1561.001-Disk_Content_Wipe/README.md §2",
    },
    "ATA038": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Reinicio de la VM víctima (`sudo shutdown -r +1`) para ver el ciclo de arranque; guardarraíl duro: hostname/IP de la víctima, jamás el manager.",
        "construyo": "Guion propio: programa el reinicio de la VM víctima; `t1` lo sella el operador tras la reconexión.",
        "sustituyo": "(ninguno)",
        "externo": "(ninguno)",
        "citas": "Bitacora/ATA038.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1529-System_Shutdown_Reboot/README.md §2, §4",
    },
    "ATA039": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Recolección de un recurso compartido LOCAL servido por el manager con daemon `rsync` (no hay cliente NFS/SMB offline); dirección remoto->local.",
        "construyo": "Guion propio: cliente `rsync` que copia el módulo `share` del manager a la carpeta del ataque.",
        "sustituyo": "Recurso NFS/SMB real -> daemon `rsync` local en VMnet1 (declarado; no hay cliente NFS/SMB offline)",
        "externo": "Recurso compartido servido por el manager (daemon `rsync`, puerto 9873)",
        "citas": "Bitacora/ATA039.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1039-Data_from_Network_Shared_Drive/README.md §3",
    },
    "ATA040": {
        "fuente": PROPIO,
        "motivo": "propio_por_diseno",
        "detalle": "Staging REMOTO: copia el material ya recolectado al recurso remoto local; dirección local->remoto (hermano de ATA011/T1074.001 local).",
        "construyo": "Guion propio: cliente `rsync` que copia el staging local al módulo escribible `incoming` del manager.",
        "sustituyo": "Destino remoto real -> daemon `rsync` local en VMnet1 (declarado)",
        "externo": "Recurso remoto servido por el manager (daemon `rsync`, módulo `incoming`)",
        "citas": "Bitacora/ATA040.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1074.002-Remote_Data_Staging/README.md §3",
    },
    "ATA041": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "ART trae pruebas de T1048.002 basadas en servicios cloud (file.io), no viables sin NAT.",
        "construyo": "Guion propio: par RSA efímero + `pkeyutl -encrypt` + envío HTTP del blob cifrado al receptor local + round-trip.",
        "sustituyo": "Servicio cloud (file.io) -> receptor local (declarado)",
        "externo": "Receptor `sink_http.py`",
        "citas": "Bitacora/ATA041.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1048.002-Asymmetric_Encrypted_Non-C2/README.md §2",
    },
    "ATA042": {
        "fuente": PROPIO,
        "motivo": "art_mecanismo_no_coincide",
        "detalle": "ART trae pruebas Linux (HTTP/python) que requieren `python3` (punto ciego 92600) o servicios externos; se ejecuta con `nc.openbsd` (TCP crudo) para evitar el punto ciego. Contraste en claro de las variantes cifradas.",
        "construyo": "Guion propio: envío del fichero EN CLARO por TCP crudo (`nc.openbsd`) al receptor del HOST.",
        "sustituyo": "HTTP/python de ART -> `nc.openbsd` TCP crudo (mecanismo distinto, declarado)",
        "externo": "Receptor `sink_http.py` (modo TCP)",
        "citas": "Bitacora/ATA042.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1048.003-Unencrypted_Non-C2/README.md §2, §4",
    },
    "ATA043": {
        "fuente": PROPIO,
        "motivo": "art_requiere_red_nube",
        "detalle": "ART trae pruebas Windows/Linux que apuntan a servicios cloud (no viables sin NAT).",
        "construyo": "Guion propio: POST de un payload JSON al endpoint webhook LOCAL del receptor (`/hook`) con `wget --post-file`.",
        "sustituyo": "Servicio cloud (Slack/Teams tipo) -> webhook local (declarado)",
        "externo": "Receptor `sink_http.py` (handler `do_POST` genérico; sin código nuevo)",
        "citas": "Bitacora/ATA043.json (atomic.nota); "
                 "Dataset/Ataques/Comandos/T1567.004-Exfiltration_Over_Webhook/README.md §2",
    },
}


def build_rows() -> list[dict]:
    corpus = load_corpus()
    cobertura = load_cobertura()
    bitacoras = load_bitacoras()
    rows: list[dict] = []
    for c in corpus:
        ata = (c.get("ata_id") or "").strip()
        dec = DECISIONES.get(ata)
        if dec is None:
            raise SystemExit(f"[ERROR] Falta la decisión de {ata} en DECISIONES")
        mapa = cobertura.get(ata)
        if mapa is None:
            raise SystemExit(f"[ERROR] {ata} no está en Hojas/cobertura_atomic.csv")
        art_disponible = mapa["prueba_art"]
        tests_plataforma = mapa["tests_linux"]
        art_usado = "sí" if dec["fuente"] in (ART_TAL_CUAL, ART_ADAPTADO) else "no"
        rows.append(
            {
                "ata_id": ata,
                "tecnica": (c.get("tecnica") or "").strip(),
                "fuente": dec["fuente"],
                "art_disponible": art_disponible,
                "tests_plataforma": tests_plataforma,
                "art_usado": art_usado,
                "motivo_codigo": dec["motivo"],
                "motivo_detalle": dec["detalle"],
                "como_se_construyo": dec["construyo"],
                "se_sustituyo": dec["sustituyo"],
                "material_externo": dec["externo"],
                "citas": dec["citas"],
                "candidato_repetir_art": "sí" if ata in CAND_ART else "no",
                "candidato_repetir_prestaging": "sí" if ata in CAND_PRESTAGING else "no",
            }
        )
    # Orden estable por número de ATA.
    rows.sort(key=lambda r: int(re.match(r"ATA(\d+)", r["ata_id"]).group(1)))
    return rows


def write_rows(rows: list[dict], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(HEADER_NOTE + "\n")
        w = csv.DictWriter(fh, fieldnames=HEADER, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    return out_path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Auditoría del origen de los 43 ataques (T1).")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args(argv)
    rows = build_rows()
    out = write_rows(rows, Path(args.out))
    n_tal = sum(1 for r in rows if r["fuente"] == ART_TAL_CUAL)
    n_ada = sum(1 for r in rows if r["fuente"] == ART_ADAPTADO)
    n_pro = sum(1 for r in rows if r["fuente"] == PROPIO)
    print(f"[OK] {out} ({len(rows)} filas)")
    print(f"[INFO] ART_tal_cual={n_tal} | ART_adaptado={n_ada} | propio={n_pro}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
