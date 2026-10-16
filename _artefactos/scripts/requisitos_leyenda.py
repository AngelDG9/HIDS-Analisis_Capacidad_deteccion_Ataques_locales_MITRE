#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""requisitos_leyenda.py — "Requisitos de estudios" + "Leyenda" del TFG HIDS (R2 §4.6–§4.7).

- `Hojas/requisitos_estudio.csv`: 6 requisitos (analogía directa con el P-Excel), con
  `n_casos_que_no_lo_cumplen` **calculado** sobre `Hojas/ATA_index.csv` + cobertura + bitácoras.
- `Hojas/leyenda.csv`: **columna a columna** cada tabla (T1–T5 + Requisitos), el glosario de
  unidades y equivalencias (`SID↔rule.id`, `pcap↔ATA`, `flujo↔unidad`, `red↔host`, `pcap↔paquete`),
  el **bloque de fórmulas** (§2.5) y la **definición de "virgen"** (§3.1).

Determinismo: sin reloj, orden estable, LF, UTF-8 sin BOM.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import metrica_hids as M  # noqa: E402
import tabla_comun as TC  # noqa: E402
import tabla1_clasificacion as T1  # noqa: E402
import tabla2_ataques as T2  # noqa: E402
import tabla3_legitimo as T3  # noqa: E402
import tabla4_rendimiento as T4  # noqa: E402
import tabla5_pruning as T5  # noqa: E402

DEFAULT_ATA_INDEX = "Hojas/ATA_index.csv"
DEFAULT_COBERTURA = "Hojas/cobertura_p1_linux.csv"
DEFAULT_BITACORA = "Bitacora"
DEFAULT_AUDITADO = "Dataset/Ataques/Resultados/Wazuh/linux/Auditado"
DEFAULT_OUT_REQ = "Hojas/requisitos_estudio.csv"
DEFAULT_OUT_LEY = "Hojas/leyenda.csv"

REQ_HEADER = ["requisito", "columna_para_filtrar", "wazuh", "velociraptor", "n_casos_que_no_lo_cumplen", "nota"]
LEY_HEADER = ["tabla", "columna", "significado", "equivalencia_nids", "unidad", "nota"]


# --------------------------------------------------------------------------
# Requisitos (R2 §4.6) — 6 filas, analogía directa con el P-Excel
# --------------------------------------------------------------------------
def _casos(ata_index):
    _, rows = TC.read_csv_rows(ata_index)
    return rows


def _canonical_detected(auditado_dir, repeticiones, ata_id):
    """True si la ventana canónica tiene ≥1 alerta `categoria=deteccion` (recorte, no métrica)."""
    win = M.ventana_canonica(ata_id, repeticiones)
    p = os.path.join(auditado_dir, f"{ata_id}_{win}-Audited.csv")
    if not os.path.isfile(p):
        # si no existe la canónica, cualquier ventana sirve para el requisito (existencia)
        hits = sorted(glob.glob(os.path.join(auditado_dir, f"{ata_id}_*-Audited.csv")))
        if not hits:
            return False, ata_id
        p = hits[0]
    _, rows = TC.read_csv_rows(p)
    return any(r.get("categoria") == M.CATEGORIA_DETECCION for r in rows), ata_id


def requisitos(args):
    casos = _casos(os.path.join(TC.ROOT, args.ata_index))
    n = len(casos)
    _, rep_rows = TC.read_csv_rows(os.path.join(TC.ROOT, "Hojas/repeticiones.csv"))
    repeticiones = {r["ata_id"].strip() for r in rep_rows}
    auditado_dir = os.path.join(TC.ROOT, args.auditado)
    sin_ficha = 0
    sin_audited = 0
    sin_deteccion = 0
    sin_paquete = 0
    no_detectados = []
    for c in casos:
        ata = c["ata_id"]
        if not os.path.isfile(os.path.join(TC.ROOT, "Dataset/Ataques/Resultados/Wazuh/linux", f"{ata}_meta.md")):
            sin_ficha += 1
        if not glob.glob(os.path.join(auditado_dir, f"{ata}_*-Audited.csv")):
            sin_audited += 1
        det, _ = _canonical_detected(auditado_dir, repeticiones, ata)
        if not det:
            sin_deteccion += 1
            no_detectados.append(ata)
        if not str(c.get("artefacto", "")).strip():
            sin_paquete += 1
    _, cob = TC.read_csv_rows(os.path.join(TC.ROOT, args.cobertura))
    no_factible = sum(1 for r in cob if r.get("estado") == "no_factible")

    filas = [
        {
            "requisito": "Técnica detectable por host",
            "columna_para_filtrar": "host_eligible_v191",
            "wazuh": "SI",
            "velociraptor": "?",
            "n_casos_que_no_lo_cumplen": 0,
            "nota": f"los {n} casos del corpus son host-eligible (equivalente a 'detectable por red' en el NIDS)",
        },
        {
            "requisito": "Marcado manual de ataques (acciones/instancias)",
            "columna_para_filtrar": "analisis_manual",
            "wazuh": "SI",
            "velociraptor": "?",
            "n_casos_que_no_lo_cumplen": sin_ficha,
            "nota": f"ficha ATA<NNN>_meta.md presente en {n - sin_ficha}/{n} casos",
        },
        {
            "requisito": "Asociación manual TP/FP por rule.id (en cada RS)",
            "columna_para_filtrar": "categoria/rule.id",
            "wazuh": "SI",
            "velociraptor": "?",
            "n_casos_que_no_lo_cumplen": sin_audited,
            "nota": f"-Audited.csv presente en {n - sin_audited}/{n} casos (pertenencia de Fase 3)",
        },
        {
            "requisito": "Ataque detectable por patrones/reglas",
            "columna_para_filtrar": "Detection",
            "wazuh": "SI",
            "velociraptor": "?",
            "n_casos_que_no_lo_cumplen": sin_deteccion,
            "nota": f"{n - sin_deteccion}/{n} detectados; no detectados: {', '.join(no_detectados) if no_detectados else '—'} (punto ciego de fábrica)",
        },
        {
            "requisito": "Cubren todas las técnicas P1",
            "columna_para_filtrar": "estado_cobertura",
            "wazuh": "NO",
            "velociraptor": "?",
            "n_casos_que_no_lo_cumplen": no_factible,
            "nota": f"{no_factible} técnicas P1-Linux no factibles de {len(cob)} (R0 §3.5); cobertura parcial en T1498/T1499",
        },
        {
            "requisito": "Paquete pcap completo (contexto + acciones + telemetría)",
            "columna_para_filtrar": "paquete_pcap",
            "wazuh": "SI",
            "velociraptor": "?",
            "n_casos_que_no_lo_cumplen": sin_paquete,
            "nota": f"carpeta-paquete declarada en {n - sin_paquete}/{n} casos (criterio ART)",
        },
    ]
    return filas


# --------------------------------------------------------------------------
# Leyenda (R2 §4.7)
# --------------------------------------------------------------------------
def _d(tabla, col, sig, equiv="", unidad="", nota=""):
    return {
        "tabla": tabla,
        "columna": col,
        "significado": sig,
        "equivalencia_nids": equiv,
        "unidad": unidad,
        "nota": nota,
    }


DESC = {
    ("T1", "tactica"): ("táctica principal (v19.1)", "—", "—", "P-Excel TÁCTICA"),
    ("T1", "otras_tacticas"): ("resto de tácticas", "—", "—", "P-Excel OTRAS TÁCTICAS"),
    ("T1", "id_tactica"): ("id TAxxxx (v17)", "—", "—", "P-Excel ID TÁCTICA"),
    ("T1", "tecnica"): ("nombre de la técnica", "—", "—", "P-Excel TÉCNICA"),
    ("T1", "id_tecnica"): ("id Txxxx(.yyy)", "—", "—", "P-Excel ID TÉCNICA"),
    ("T1", "subtecnica"): ("nombre de la subtécnica", "—", "—", "P-Excel SUBTÉCNICA"),
    ("T1", "id_subtecnica"): ("id Txxxx.yyy", "—", "—", "P-Excel ID SUBTÉCNICA"),
    ("T1", "plataformas"): ("plataformas MITRE", "—", "—", "de corpus_host.csv"),
    ("T1", "p1_res"): ("P1 si Impact/Exfil/Collection", "—", "—", "priority de corpus_host.csv"),
    ("T1", "only_network_detection_v17"): ("solo detectable por red (v17)", "Only Network Detection", "—", "P-Excel"),
    ("T1", "network_detection_v17"): ("detectable por red (v17)", "Network Detection", "—", "P-Excel"),
    ("T1", "host_eligible_v191"): ("elegible por host (v19.1)", "NOT(Only Network Detection)", "—", "de corpus_host.csv"),
    ("T1", "dc_host"): ("nº Data Components host", "—", "—", "de corpus_host.csv"),
    ("T1", "dc_red"): ("nº Data Components red", "—", "—", "de corpus_host.csv"),
    ("T1", "cubierta_en_corpus"): ("ATA<NNN> que la mide", "pcap", "caso", "de cobertura/inventario"),
    ("T1", "estado_cobertura"): ("medida|cubierta_madre|cubierta_por_ata|cubierta_parcial|no_factible|no_linux", "—", "—", "de cobertura_p1_linux.csv"),
    ("T1", "nota_desfase"): ("discrepancia v17↔v19.1 declarada", "—", "—", "T1029/T1602.*/T1567.003"),
    ("T2", "n"): ("Nº de caso (1..55)", "—", "—", "P-Excel Nº"),
    ("T2", "ata_id"): ("identificador del caso", "pcap", "caso", "nuevo"),
    ("T2", "id_tecnica"): ("id de la técnica", "Nº Technique/Technique", "—", "P-Excel"),
    ("T2", "subtecnica"): ("nombre de la subtécnica", "—", "—", "nuevo"),
    ("T2", "tactica"): ("táctica", "—", "—", "de ATA_index.csv"),
    ("T2", "plataforma"): ("linux|windows", "—", "—", "—"),
    ("T2", "paquete_pcap"): ("carpeta-paquete (contexto+acciones+telemetría)", "pcapng (SubTechnique-Attack)", "—", "P-Excel; R0 §5.2"),
    ("T2", "herramienta"): ("herramienta/s usadas", "HERRAMIENTA", "—", "de la bitácora"),
    ("T2", "n_acciones_k"): ("acciones cubiertas k", "#Attack_Flows", "acción", "de metrico_o2"),
    ("T2", "n_acciones_m"): ("acciones totales m", "#Attack_Flows", "acción", "de metrico_o2"),
    ("T2", "t0_utc"): ("inicio de la ventana canónica", "—", "UTC", "de la bitácora"),
    ("T2", "t1_utc"): ("fin de la ventana canónica", "—", "UTC", "de la bitácora"),
    ("T2", "duracion_s"): ("t1 - t0", "—", "s", "nuevo (fleco 3)"),
    ("T2", "ventana_canonica"): ("iter1|rev1", "—", "—", "R2 §2.7"),
    ("T2", "doble_iteracion"): ("iguales|review", "—", "—", "C1'/C2'/C3'"),
    ("T2", "analisis_manual"): ("cita de verificación del efecto", "ANÁLISIS…", "—", "ficha ATA<NNN>_meta.md"),
    ("T2", "config"): ("C0|C1|C2|C3", "RS", "—", "R2 §2.6"),
    ("T2", "umbral"): ("N∈{0,3,7,10,12}", "Priority", "nivel", "R2 §2.6"),
    ("T2", "#Alertas"): ("alertas brutas del caso (detección)", "#Alerts", "alerta", "doble conteo D2"),
    ("T2", "#rule.id_distintos"): ("rule.id distintos", "#SID", "rule.id", "doble conteo D2"),
    ("T2", "#Alertas_correlacionadas"): ("rule.id distintos del caso", "#Flow-correlated Alerts", "rule.id", "D2"),
    ("T2", "#Alertas_correlacionadas_total"): ("corr (raw)", "#Flow-correlated Alerts (total)", "alerta", "D2"),
    ("T2", "#acciones_cubiertas"): ("acciones del ataque cubiertas k", "#Attack_Flows", "acción", "O2"),
    ("T2", "t_hasta_1a_deteccion_s"): ("t(1ª alerta detección) - t0", "—", "s", "nuevo"),
    ("T2", "primera_evidencia_rule_id"): ("rule.id de la 1ª detección", "—", "rule.id", "nuevo"),
    ("T2", "%Deteccion"): ("100% si TP, si no 0%", "%Detection_pcaps", "%", "—"),
    ("T2", "Detection"): ("SÍ|NO", "Detection", "—", "—"),
    ("T3", "seccion"): ("agregado|detalle_ruleid", "—", "—", "estructura del CSV"),
    ("T3", "corrida"): ("id de la corrida", "pcap (Nombre)", "—", "—"),
    ("T3", "hids"): ("wazuh|velociraptor", "—", "—", "—"),
    ("T3", "so"): ("linux|windows", "—", "—", "—"),
    ("T3", "tipo_trafico"): ("descripción (GHOSTS)", "Tipo de tráfico", "—", "—"),
    ("T3", "fuente_generadora"): ("GHOSTS|plan_B", "—", "—", "—"),
    ("T3", "inicio_utc"): ("inicio de la ventana", "—", "UTC", "—"),
    ("T3", "fin_utc"): ("fin de la ventana", "—", "UTC", "—"),
    ("T3", "duracion_h"): ("duración", "—", "h", "—"),
    ("T3", "tamano"): ("tamaño real (eventos/GB)", "Tamaño real del tráfico", "—", "—"),
    ("T3", "n_acciones_ghosts"): ("nº de acciones GHOSTS", "#Intentos Flujo (SYN)", "acción", "complemento D1"),
    ("T3", "n_ips_o_entidades"): ("nº de entidades distintas", "#IPs (sin repetición)", "—", "—"),
    ("T3", "#Unidades"): ("M = eventos decodificados", "#Flows", "unidad", "§2.2"),
    ("T3", "#Alertas"): ("alertas brutas en legítimo", "#Alerts", "alerta", "—"),
    ("T3", "#Alertas_correlacionadas"): ("Σ_unidades(rule.id distintos)", "#Flow-correlated Alerts", "rule.id", "D2"),
    ("T3", "#rule.id_distintos"): ("rule.id distintos", "#SIDs/#AttackID/#ThreatID", "rule.id", "—"),
    ("T3", "#Unidades_FP"): ("unidades con ≥1 alerta", "#Flows_FP", "unidad", "—"),
    ("T3", "#Unidades_TN"): ("M - #Unidades_FP", "#Flows_TN", "unidad", "—"),
    ("T3", "%Unidades_FP"): ("#Unidades_FP / #Unidades", "%Flows_FP", "%", "—"),
    ("T3", "%Unidades_TN"): ("1 - %Unidades_FP", "%Flows_TN", "%", "—"),
    ("T3", "#Alertas_FP"): ("alertas brutas (FP)", "—", "alerta", "—"),
    ("T3", "#Alertas_FP_sin_auto_ruido"): ("FP sin la auto-alerta del HIDS", "—", "alerta", "complemento L2"),
    ("T3", "FP_por_accion"): ("FP / n_acciones_ghosts", "—", "FP/acción", "complemento D1"),
    ("T3", "FP_por_hora"): ("FP / duracion_h", "—", "FP/h", "complemento D1"),
    ("T3", "rule.id"): ("rule.id de la regla", "#SID", "rule.id", "bloque detalle"),
    ("T3", "rule_level"): ("nivel de la regla", "Priority", "nivel", "bloque detalle"),
    ("T3", "groups"): ("grupos de la regla", "—", "—", "bloque detalle"),
    ("T3", "rs_origen"): ("RuleSet de origen", "RS", "—", "bloque detalle"),
    ("T3", "#alertas_legitimas"): ("alertas de la regla en legítimo", "#Alertas/SID", "alerta", "bloque detalle"),
    ("T3", "#unidades_con_la_regla"): ("unidades con la regla", "—", "unidad", "bloque detalle"),
    ("T3", "#alertas_correlacionadas"): ("unidades con la regla (corr)", "—", "rule.id", "bloque detalle"),
    ("T3", "es_TP_en_algun_ataque"): ("¿la regla es TP en algún ataque?", "—", "—", "bloque detalle"),
    ("T3", "veredicto"): ("solo_FP|mixta|auto_ruido|operador", "—", "—", "bloque detalle"),
}
# T4/T5 columnas (genéricas) + filas de leyenda por columna
for col, sig, equiv, unidad, nota in [
    ("metrica", "nombre de la métrica/fila", "—", "—", "T4"),
    ("excel_profesor", "nombre en el Excel del profesor", "—", "—", "T4"),
    ("formula_literal", "fórmula literal", "—", "—", "T4 §2.5"),
]:
    DESC[("T4", col)] = (sig, equiv, unidad, nota)
for col, sig, equiv, unidad, nota in [
    ("variante", "No Pruning|Pruning 500|…", "—", "—", "T5"),
    ("config", "C0|C1|C2|C3", "RS", "—", "R2 §2.6"),
    ("umbral", "N∈{0,3,7,10,12}", "Priority", "nivel", "R2 §2.6"),
    ("GM", "√(TPR·(1−FPR))", "GM", "—", "§2.5"),
    ("%Deteccion_casos", "100·TP/N", "%Detection_pcaps", "%", "—"),
    ("#reglas_quitadas", "nº de rule.id quitados", "#SIDs removed", "regla", "—"),
    ("lista_rule.id_quitados", "lista de rule.id quitados", "—", "rule.id", "—"),
    ("#Alertas_total", "alertas brutas totales", "#Alertas", "alerta", "—"),
    ("#Alertas_TP", "alertas TP", "#Alerts TP", "alerta", "—"),
    ("#Alertas_FP", "alertas FP", "#Alerts FP", "alerta", "—"),
    ("Usabilidad", "A_FP/A_TP", "Operational Usability", "—", "—"),
    ("paso", "nº de paso de la eliminación", "—", "—", "T5 steps"),
    ("rule.id_quitado", "rule.id quitado en el paso", "SID removed", "rule.id", "T5 steps"),
    ("TP_casos", "casos TP tras el paso", "#pcaps TP", "caso", "T5 steps"),
    ("FN_casos", "casos FN tras el paso", "#pcaps FN", "caso", "T5 steps"),
    ("TN_unidades", "unidades TN tras el paso", "#Flows TN", "unidad", "T5 steps"),
    ("FP_unidades", "unidades FP tras el paso", "#Flows FP", "unidad", "T5 steps"),
    ("TPR", "TP/N", "TPR", "—", "§2.5"),
    ("TNR", "1-FPR", "TNR", "—", "§2.5"),
    ("Alertas_TP", "alertas TP", "#Alerts TP", "alerta", "T5 steps"),
    ("Alertas_FP", "alertas FP", "#Alerts FP", "alerta", "T5 steps"),
]:
    DESC[("T5", col)] = (sig, equiv, unidad, nota)


def _leyenda_tabla(nombre, header):
    out = []
    for col in header:
        sig, equiv, unidad, nota = DESC.get((nombre, col), ("—", "—", "—", "—"))
        out.append(_d(nombre, col, sig, equiv, unidad, nota))
    return out


def leyenda():
    filas = []
    filas += _leyenda_tabla("T1", T1.HEADER)
    filas += _leyenda_tabla("T2", T2.HEADER)
    filas += _leyenda_tabla("T3", T3.HEADER)
    # T4: columnas dinámicas (metrica/excel_profesor/formula_literal + hids_config_umbral)
    t4_cols = ["metrica", "excel_profesor", "formula_literal"]
    t4_path = os.path.join(TC.ROOT, T4.DEFAULT_OUT)
    if os.path.isfile(t4_path):
        with open(t4_path, encoding="utf-8") as fh:
            lines = [ln for ln in fh if not ln.lstrip().startswith("#")]
        if lines:
            t4_cols = [c for c in lines[0].rstrip("\n").split(",")]
    filas += _leyenda_tabla("T4", [c for c in t4_cols if c in ("metrica", "excel_profesor", "formula_literal")])
    for col in t4_cols:
        if col not in ("metrica", "excel_profesor", "formula_literal"):
            filas.append(_d("T4", col, "columna de métrica (por HIDS×config×umbral)", "RS", "—", "ancho"))
    filas += _leyenda_tabla("T5", T5.HEADER)
    filas += _leyenda_tabla("T5_steps", T5.STEPS_HEADER)
    for col in REQ_HEADER:
        filas.append(
            _d("REQUISITOS", col, "columna de requisitos_estudio.csv", "—", "—", "R2 §4.6")
        )

    # Glosario de unidades y equivalencias (R2 §2.1, §2.8)
    glos = [
        ("caso", "ventana canónica ATA<NNN>", "pcap", "caso"),
        ("unidad", "evento/registro decodificado por el HIDS", "flujo", "unidad"),
        ("rule.id", "regla emitida por el HIDS / fila de artifact VR", "SID", "rule.id"),
        ("paquete", "contexto + acciones + telemetría", "pcap", "paquete"),
        ("red↔host", "equivalencia del espejo", "Only Network Detection", "—"),
        ("ATA<NNN>", "identificador de caso", "pcap (Nombre)", "caso"),
        ("M", "denominador del legítimo (eventos decodificados)", "#Clear flows", "unidad"),
        ("N", "nº de casos = 55", "#Attack flows", "caso"),
        ("A_TP/A_FP", "alertas TP/FP", "#Alerts TP/FP", "alerta"),
    ]
    for (col, sig, equiv, unidad) in glos:
        filas.append(_d("GLOSARIO", col, sig, equiv, unidad, "R2 §2.1/§2.8"))

    # Bloque de fórmulas (R2 §2.5) — literales
    for etiqueta, excel, formula, opt, fuente in [
        ("TPR", "B14 = B6/'T2…'!$D$79", "TP_ata / N", "→1", "P-Excel T4 (Rend)"),
        ("FPR", "B15 = B10/$B$4", "FP_uni / M", "→0", "P-Excel T4 (Rend)"),
        ("TNR", "%Flows_TN = 1 - %Flows_FP", "1 - FPR", "→1", "P-Excel T4 (Rend)"),
        ("Precisión", "P = TP/(TP+FP)", "A_TP / (A_TP + A_FP)", "→1", "P-Excel bloque fórmulas"),
        ("F1", "F1 = 2PR/(P+R)", "2·P·R / (P + R), R=TPR", "→1", "P-Excel bloque fórmulas"),
        ("GM", "B16 = SQRT(B14*(1-B15))", "√(TPR · (1 - FPR))", "→1", "P-Excel + hermano gm=sqrt(tpr*tnr)"),
        ("Usabilidad", "B17 = B12/B8", "A_FP / A_TP", "→0", "P-Excel + hermano usab=a_fp/a_tp"),
        ("Usabilidad^c", "B18 = B13/B9", "A_FP^c / A_TP^c", "→0", "P-Excel (correlated)"),
    ]:
        filas.append(_d("FORMULA", etiqueta, formula, excel, "—", f"óptimo {opt}; {fuente}"))

    # Definición de "virgen" (R2 §3.1)
    filas.append(_d("VIRGEN", "wazuh", "RS1+RS2 de fábrica, RS3=RS4=0", "—", "—", "C1 = {RS1,RS2}"))
    filas.append(_d("VIRGEN", "velociraptor", "artifacts públicos/nativos, sin propios", "—", "—", "placeholder V0"))
    filas.append(_d("VIRGEN", "telemetria", "auditd/Sysmon/FIM son FUENTE, no reglas", "—", "—", "sí se activan en virgen"))
    return filas


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Requisitos + Leyenda (R2 §4.6–§4.7).")
    ap.add_argument("--ata-index", default=DEFAULT_ATA_INDEX)
    ap.add_argument("--cobertura", default=DEFAULT_COBERTURA)
    ap.add_argument("--bitacora", default=DEFAULT_BITACORA)
    ap.add_argument("--auditado", default=DEFAULT_AUDITADO)
    ap.add_argument("--out-req", default=DEFAULT_OUT_REQ)
    ap.add_argument("--out-ley", default=DEFAULT_OUT_LEY)
    args = ap.parse_args(argv)

    req = requisitos(args)
    req_comment = "# " + " | ".join(
        [
            os.path.basename(args.out_req),
            "TFG HIDS - R2 Requisitos de estudios",
            f"metrica_version={M.VERSION_METRICA}",
            f"n_casos_corpus={len(_casos(os.path.join(TC.ROOT, args.ata_index)))}",
            "columnas=" + ",".join(REQ_HEADER),
        ]
    )
    TC.write_csv(os.path.join(TC.ROOT, args.out_req), REQ_HEADER, req, comment=req_comment)

    ley = leyenda()
    ley_comment = "# " + " | ".join(
        [
            os.path.basename(args.out_ley),
            "TFG HIDS - R2 Leyenda (columna a columna + glosario + formulas + virgen)",
            f"metrica_version={M.VERSION_METRICA}",
            f"n_filas={len(ley)}",
            "columnas=" + ",".join(LEY_HEADER),
        ]
    )
    TC.write_csv(os.path.join(TC.ROOT, args.out_ley), LEY_HEADER, ley, comment=ley_comment)
    print(f"Requisitos: {len(req)} filas -> {args.out_req} | Leyenda: {len(ley)} filas -> {args.out_ley}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
