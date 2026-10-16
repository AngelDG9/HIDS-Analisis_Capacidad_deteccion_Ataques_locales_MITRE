#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""metrica_hids.py — MÓDULO CONGELADO de la métrica del TFG HIDS (bloque `reencuadre-metrica`).

**Fuente única de verdad** de las fórmulas, unidades y constantes de la métrica de
resultado. Ningún script debe reimplementar estas fórmulas: todas importan de aquí.

Congelado en `Soporte/Metrica/metrica_hids.md` (version 1, `status: congelada`).

Unidades (plan R2 §2.1–§2.2):
    - Plano ATAQUE  : `caso` = ventana canónica `ATA<NNN>`; denominador `N = 55`.
    - Plano LEGÍTIMO : `unidad` = evento/registro decodificado por el HIDS; denominador `M`.
    - Plano ALERTA   : `rule.id` emitido / fila de artifact de VR; `A_TP`, `A_FP`.

Fórmulas (R2 §2.5; literales del P-Excel del profesor y del repo hermano):
    TPR  = TP_ata / N                                   ->1
    FPR  = FP_uni / M                                   ->0
    TNR  = 1 - FPR                                      ->1
    P    = A_TP / (A_TP + A_FP)                         ->1
    F1   = 2*P*R / (P + R),  R = TPR                    ->1
    GM   = sqrt(TPR * (1 - FPR))                        ->1
    Usab = A_FP / A_TP                                  ->0
    Usab^c = A_FP^c / A_TP^c                            ->0

Sin `main`. No lee ficheros. Sin dependencias salvo la stdlib.
"""

from __future__ import annotations

import math

# --------------------------------------------------------------------------
# Versiones (deben coincidir con los documentos congelados)
# --------------------------------------------------------------------------
VERSION_METRICA = 1
VERSION_BOVEDA = 1
FECHA_METRICA = "2026-10-16"

# --------------------------------------------------------------------------
# Unidades y planos (R2 §2.1)
# --------------------------------------------------------------------------
PLANO_ATAQUE = "ataque"      # unidad = caso (ventana canónica ATA<NNN>)
PLANO_LEGITIMO = "legitimo"  # unidad = evento/registro decodificado por el HIDS
PLANO_ALERTA = "alerta"      # unidad = rule.id emitido / fila de artifact

UNIDAD_ATAQUE = "caso"
UNIDAD_LEGITIMO = "unidad"   # = evento decodificado (logall_json/archives.json)
UNIDAD_ALERTA = "rule.id"

N_CASOS = 55                 # nº de casos del plano ataque (R2 §2.7)
N_UMBRAL_TITULAR = 0         # titular = C1 (virgen) x N=0
CONFIG_TITULAR = "C1"

# --------------------------------------------------------------------------
# Config x umbral (R2 §2.6)
# --------------------------------------------------------------------------
# C0 = {RS1} · C1 = {RS1, RS2} (virgen) · C2 = C1 U {RS3} · C3 = C2 U {RS4}
CONFIGS = {
    "C0": ("RS1",),
    "C1": ("RS1", "RS2"),
    "C2": ("RS1", "RS2", "RS3"),
    "C3": ("RS1", "RS2", "RS3", "RS4"),
}
UMBRALES = (0, 3, 7, 10, 12)
# `N=0` == "cualquier alerta emitida" (las reglas de nivel 0 no emiten alerta, L1).
# C2/C3 (RS3/RS4) están vacíos en virgen: sus bloques quedan vacíos hasta el gate (L8).
CONFIGS_VIRGEN = ("C0", "C1")

# --------------------------------------------------------------------------
# Categorías de pertenencia (Fase 3, v7) — se REUTILIZAN, no se reimplementan (R2 §7)
# --------------------------------------------------------------------------
# Orden de decisión congelado en `Soporte/Wazuh/Configuracion/politica_filtrado_ruido.md`.
CATEGORIAS = ("deteccion", "ruido_conocido", "auto_ruido", "dudosa", "artefacto_ataque")
CATEGORIA_DETECCION = "deteccion"
CATEGORIA_AUTO_RUIDO = "auto_ruido"

# --------------------------------------------------------------------------
# Redondeo y formato (R2 §6.8) — congelados, anti-deriva
# --------------------------------------------------------------------------
DEC_PCT = 4          # porcentajes en T3/T4 (profesor: 4.3095 %)
DEC_RATIO = 6        # ratios GM/TPR/FPR (hermano: :.6f)
DEC_USAB = 4         # Usabilidad (hermano: round(...,4))
DEC_DET = 2          # %Deteccion en T2/T5 (hermano: 55.45 %)

FORMATO_N_A = "n/a"  # valor no publicable (p. ej. M sin instrumentar, L11)


# --------------------------------------------------------------------------
# Fórmulas puras (R2 §2.5) — las 7 (+ la variante correlacionada)
# --------------------------------------------------------------------------
def tpr(tp_ata: float, n: int = N_CASOS) -> float:
    """TPR (Recall) = TP_ata / N."""
    return (tp_ata / n) if n else 0.0


def fpr(fp_uni: float, m: float) -> float:
    """FPR = FP_uni / M. Si `M` no es publicable (None/nan/0) -> devuelve None."""
    if m is None:
        return None
    if isinstance(m, str):
        return None
    if not m:
        return None
    return fp_uni / m


def tnr(fpr_: float | None) -> float | None:
    """TNR (Especificidad) = 1 - FPR."""
    if fpr_ is None:
        return None
    return 1.0 - fpr_


def precision(a_tp: float, a_fp: float) -> float:
    """Precisión = A_TP / (A_TP + A_FP)."""
    denom = a_tp + a_fp
    return (a_tp / denom) if denom else 0.0


def f1(p: float, r: float) -> float:
    """F1 = 2*P*R / (P + R), con R = TPR."""
    denom = p + r
    return (2.0 * p * r / denom) if denom else 0.0


def gm(tpr_: float, tnr_: float | None) -> float | None:
    """GM = sqrt(TPR * (1 - FPR)) = sqrt(TPR * TNR)."""
    if tnr_ is None:
        return None
    prod = tpr_ * tnr_
    if prod < 0:
        return None
    return math.sqrt(prod)


def usabilidad(a_fp: float, a_tp: float) -> float:
    """Usabilidad (FTTAR) = A_FP / A_TP."""
    return (a_fp / a_tp) if a_tp else 0.0


# --------------------------------------------------------------------------
# Ventana canónica por caso (R2 §2.7, decisión D3)
# --------------------------------------------------------------------------
def ventana_canonica(ata_id: str, repeticiones) -> str:
    """`rev1` si el ATA está en `repeticiones.csv` (9 casos); si no, `iter1`."""
    return "rev1" if ata_id in set(repeticiones) else "iter1"


def ventana_control(ata_id: str, repeticiones) -> str:
    """Segunda ventana (control de reproducibilidad C1'/C2'): `rev2` o `iter2`."""
    return "rev2" if ata_id in set(repeticiones) else "iter2"


# --------------------------------------------------------------------------
# Variantes de pruning (R2 §4.5; pipeline del repo hermano `optimo_Snort_GM_v4.py`)
# --------------------------------------------------------------------------
PRUNING_VARIANTES = (
    "No Pruning",
    "Pruning 500",
    "Pruning 1000",
    "Conservative",
    "Generalized Conservative",
    "Aggressive (G-Mean)",
)
PRUNING_N = {"Pruning 500": 500, "Pruning 1000": 1000}


def reglas_pruning_no_pruning(sids_activos):
    return set(sids_activos)


def reglas_pruning_n(sids_activos, leg_diff_counts, n):
    """Pruning N — quitar reglas con `#alertas_correlacionadas` FP > N.

    Hermano: `sids = {s for s in sids_activos if leg_diff_counts[s] <= 500}`.
    """
    return {s for s in sids_activos if leg_diff_counts.get(s, 0) <= n}


def reglas_pruning_conservative(sids_activos, sids_legitimo, sids_ataque):
    """Conservative — quitar reglas que son FP y nunca TP.

    Hermano: `ids_fp_exclusivos = sids_legitimo - sids_ataque`.
    """
    fp_exclusivos = set(sids_legitimo) - set(sids_ataque)
    return {s for s in sids_activos if s not in fp_exclusivos}


def reglas_pruning_generalized(sids_activos, sids_legitimo):
    """Generalized Conservative — quitar TODAS las FP (aunque sean TP)."""
    return {s for s in sids_activos if s not in set(sids_legitimo)}


# --------------------------------------------------------------------------
# Formateo determinista (R2 §6.8)
# --------------------------------------------------------------------------
def fmt_ratio(v) -> str:
    """Ratio con 6 decimales (punto decimal); `None` -> cadena vacía."""
    if v is None:
        return ""
    return f"{v:.{DEC_RATIO}f}"


def fmt_pct(v) -> str:
    """Porcentaje con 4 decimales (punto decimal); `None` -> cadena vacía."""
    if v is None:
        return ""
    return f"{v:.{DEC_PCT}f}"


def fmt_usab(v) -> str:
    """Usabilidad con 4 decimales; `None` -> cadena vacía."""
    if v is None:
        return ""
    return f"{v:.{DEC_USAB}f}"


def fmt_det(v) -> str:
    """%Deteccion con 2 decimales; `None` -> cadena vacía."""
    if v is None:
        return ""
    return f"{v:.{DEC_DET}f}"


__all__ = [
    "VERSION_METRICA",
    "VERSION_BOVEDA",
    "FECHA_METRICA",
    "PLANO_ATAQUE",
    "PLANO_LEGITIMO",
    "PLANO_ALERTA",
    "UNIDAD_ATAQUE",
    "UNIDAD_LEGITIMO",
    "UNIDAD_ALERTA",
    "N_CASOS",
    "N_UMBRAL_TITULAR",
    "CONFIG_TITULAR",
    "CONFIGS",
    "UMBRALES",
    "CONFIGS_VIRGEN",
    "CATEGORIAS",
    "CATEGORIA_DETECCION",
    "CATEGORIA_AUTO_RUIDO",
    "DEC_PCT",
    "DEC_RATIO",
    "DEC_USAB",
    "DEC_DET",
    "FORMATO_N_A",
    "tpr",
    "fpr",
    "tnr",
    "precision",
    "f1",
    "gm",
    "usabilidad",
    "ventana_canonica",
    "ventana_control",
    "PRUNING_VARIANTES",
    "PRUNING_N",
    "reglas_pruning_no_pruning",
    "reglas_pruning_n",
    "reglas_pruning_conservative",
    "reglas_pruning_generalized",
    "fmt_ratio",
    "fmt_pct",
    "fmt_usab",
    "fmt_det",
]
