#!/usr/bin/env bash
# ============================================================================
# TFG · HIDS — Generador del manifiesto `active_ruleset.txt` (RS1..RS4)
# ============================================================================
# Fase 2 · tarea 2.8 (T-07 · R-09). Diseño: rulesets_diseno.md §1/§4/§5/§6.
#
# Qué hace:
#   Recorre los ficheros de reglas REALMENTE activos en el manager
#   (/var/ossec/ruleset/rules/*.xml y /var/ossec/etc/rules/*.xml), extrae de
#   cada uno sus `rule.id` reales y calcula MIN_ID, MAX_ID y N_RULES,
#   asignándolo a su RuleSet (RS) según el diseño.
#
# Guardas (exit != 0 => NO activar / avisar):
#   1) Colisiones  : RS3∩RS4, IDs duplicados entre ficheros, invasión de
#                    subrangos (fichero default en 80700-80799 o en 100000-101000).
#   2) Active-resp : si algún fichero de reglas contiene `<active-response`,
#                    el script FALLA (modo detección-only, R-06).
#
# Salida: manifiesto determinista y re-ejecutable en el fichero indicado
#   (por defecto `active_ruleset.txt` en el directorio actual).
#
# Uso:
#   sudo bash generar_active_ruleset.sh [RUTA_SALIDA]
#
# Ejecutar en el MANAGER (necesita leer /var/ossec/... como root).
# Las rutas son sobreescribibles por variables de entorno (para tests):
#   TFG_RULESET_DIR, TFG_ETC_RULES_DIR
# ============================================================================
set -u
LC_ALL=C

RULESET_DIR="${TFG_RULESET_DIR:-/var/ossec/ruleset/rules}"
ETC_RULES_DIR="${TFG_ETC_RULES_DIR:-/var/ossec/etc/rules}"
OUT="${1:-active_ruleset.txt}"

AUDITD_BASENAME="0365-auditd_rules.xml"
LOCAL_BASENAME="local_rules.xml"

# Rangos (diseño §4)
RS2_MIN=80700; RS2_MAX=80799
RS3_MIN=100000; RS3_MAX=100499
RS4_MIN=100500; RS4_MAX=101000

TMPD="$(mktemp -d)"
trap 'rm -rf "$TMPD"' EXIT

FILES_LIST="$TMPD/files.list"
PER_FILE="$TMPD/per_file.tsv"     # rs \t min \t max \t n \t fichero
PAIRS="$TMPD/pairs.tsv"           # rs \t id
: > "$PER_FILE"
: > "$PAIRS"

# ---------------------------------------------------------------- inventario
{
  find "$RULESET_DIR" -maxdepth 1 -type f -name '*.xml' 2>/dev/null
  find "$ETC_RULES_DIR" -maxdepth 1 -type f -name '*.xml' 2>/dev/null
} | sort > "$FILES_LIST"

# ------------------------------------------------ guarda 2: active-response
AR_HITS="$(grep -rl '<active-response' "$RULESET_DIR" "$ETC_RULES_DIR" 2>/dev/null | sort)"
if [ -n "$AR_HITS" ]; then
  {
    echo "FATAL (guarda active-response): hay ficheros de reglas con <active-response>:"
    echo "$AR_HITS"
    echo "Modo detección-only (R-06) roto. NO se genera manifiesto. Abortando."
  } >&2
  exit 2
fi

# --------------------------------------------------- clasificación por origen
while IFS= read -r f; do
  [ -f "$f" ] || continue
  dir="$(dirname "$f")"
  base="$(basename "$f")"

  case "$dir" in
    "$RULESET_DIR")
      if [ "$base" = "$AUDITD_BASENAME" ]; then rs="RS2"; else rs="RS1"; fi
      ;;
    "$ETC_RULES_DIR")
      if   [ "$base" = "$LOCAL_BASENAME" ]; then rs="RS3"
      elif printf '%s' "$base" | grep -q '^external_.*\.xml$'; then rs="RS4"
      else rs="UNKNOWN"; fi
      ;;
    *) rs="UNKNOWN" ;;
  esac

  ids="$(grep -o 'rule id="[0-9]*"' "$f" | grep -o '[0-9]*')"
  if [ -z "$ids" ]; then
    printf '%s\t%s\t%s\t%s\t%s\n' "$rs" "-" "-" "0" "$f" >> "$PER_FILE"
    continue
  fi
  n="$(printf '%s\n' "$ids" | wc -l)"
  mn="$(printf '%s\n' "$ids" | sort -n | head -1)"
  mx="$(printf '%s\n' "$ids" | sort -n | tail -1)"
  printf '%s\t%s\t%s\t%s\t%s\n' "$rs" "$mn" "$mx" "$n" "$f" >> "$PER_FILE"
  while IFS= read -r id; do
    [ -n "$id" ] && printf '%s\t%s\n' "$rs" "$id" >> "$PAIRS"
  done <<< "$ids"
done < "$FILES_LIST"

# ------------------------------------------------------ control de colisiones
COLLISION=0
NOTES=""

DUP_IDS="$(cut -f2 "$PAIRS" | sort -n | uniq -d)"
RS2_BAD="$(awk -F'\t' -v a="$RS2_MIN" -v b="$RS2_MAX" '$1=="RS2" && ($2<a || $2>b){print $2}' "$PAIRS" | sort -n | uniq)"
RS3_BAD="$(awk -F'\t' -v a="$RS3_MIN" -v b="$RS3_MAX" '$1=="RS3" && ($2<a || $2>b){print $2}' "$PAIRS" | sort -n | uniq)"
RS4_BAD="$(awk -F'\t' -v a="$RS4_MIN" -v b="$RS4_MAX" '$1=="RS4" && ($2<a || $2>b){print $2}' "$PAIRS" | sort -n | uniq)"
RS1_IN_RS2="$(awk -F'\t' -v a="$RS2_MIN" -v b="$RS2_MAX" '$1=="RS1" && $2>=a && $2<=b{print $2}' "$PAIRS" | sort -n | uniq)"
RS1_IN_USR="$(awk -F'\t' -v a="$RS3_MIN" -v b="$RS4_MAX" '$1=="RS1" && $2>=a && $2<=b{print $2}' "$PAIRS" | sort -n | uniq)"
UNK="$(awk -F'\t' '$1=="UNKNOWN"{print $2}' "$PAIRS" | sort -n | uniq)"
RS3_IDS="$(awk -F'\t' '$1=="RS3"{print $2}' "$PAIRS" | sort -n | uniq)"
RS4_IDS="$(awk -F'\t' '$1=="RS4"{print $2}' "$PAIRS" | sort -n | uniq)"
RS34_INT="$(comm -12 <(printf '%s\n' "$RS3_IDS") <(printf '%s\n' "$RS4_IDS") | sed '/^$/d')"

add_note() { NOTES="${NOTES}${1}"$'\n'; COLLISION=1; }
[ -n "$DUP_IDS" ]    && add_note "IDs duplicados entre ficheros: $(echo $DUP_IDS | tr '\n' ' ')"
[ -n "$RS2_BAD" ]    && add_note "RS2 (auditd) con IDs fuera de ${RS2_MIN}-${RS2_MAX}: $(echo $RS2_BAD | tr '\n' ' ')"
[ -n "$RS3_BAD" ]    && add_note "RS3 (local) con IDs fuera de ${RS3_MIN}-${RS3_MAX}: $(echo $RS3_BAD | tr '\n' ' ')"
[ -n "$RS4_BAD" ]    && add_note "RS4 (externas) con IDs fuera de ${RS4_MIN}-${RS4_MAX}: $(echo $RS4_BAD | tr '\n' ' ')"
[ -n "$RS1_IN_RS2" ] && add_note "Fichero default (RS1) invade el subrango de RS2 ${RS2_MIN}-${RS2_MAX}: $(echo $RS1_IN_RS2 | tr '\n' ' ')"
[ -n "$RS1_IN_USR" ] && add_note "Fichero default (RS1) invade la reserva de usuario ${RS3_MIN}-${RS4_MAX}: $(echo $RS1_IN_USR | tr '\n' ' ')"
[ -n "$RS34_INT" ]   && add_note "Colisión dura RS3∩RS4: $(echo $RS34_INT | tr '\n' ' ')"
[ -n "$UNK" ]        && add_note "IDs en ficheros con origen no clasificable (UNKNOWN): $(echo $UNK | tr '\n' ' ')"

# ------------------------------------------------------------------ resumen
summary_line() {  # $1=RS
  awk -F'\t' -v r="$1" '
    $1==r {
      if ($2!="-") {
        if (!(r in seen)) { seen[r]=1; mn=$2+0; mx=$3+0 }
        if ($2+0 < mn) mn=$2+0
        if ($3+0 > mx) mx=$3+0
      }
      n+=$4; files++
    }
    END {
      if (n==0) { printf "%s\t-\t-\t0\t%d\n", r, files }
      else { printf "%s\t%d\t%d\t%d\t%d\n", r, mn, mx, n, files }
    }' "$PER_FILE"
}

RS1_S="$(summary_line RS1)"; RS2_S="$(summary_line RS2)"
RS3_S="$(summary_line RS3)"; RS4_S="$(summary_line RS4)"

# ---------------------------------------------------------------- manifiesto
WV="$(grep -i '^VERSION' /var/ossec/etc/ossec-init.conf 2>/dev/null | cut -d'"' -f2)"
[ -n "${WV:-}" ] || WV="$(/var/ossec/bin/wazuh-control info 2>/dev/null | grep -i 'WAZUH_VERSION' | cut -d'"' -f2)"
[ -n "${WV:-}" ] || WV="desconocida"

{
  echo "# ============================================================================"
  echo "# active_ruleset.txt — Manifiesto de RuleSets activos (Fase 2 · tarea 2.8 · R-09)"
  echo "# ============================================================================"
  echo "# Generado por : Soporte/Wazuh/Scripts/generar_active_ruleset.sh"
  echo "# Ejecutado en : $(hostname) (manager)"
  echo "# Wazuh        : ${WV}"
  echo "# Fecha (UTC)  : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "# Determinista : sí (orden estable; re-ejecutable)"
  echo "#"
  echo "# Clasificación rule.id -> RS (rulesets_diseno.md §4), por ORIGEN de fichero:"
  echo "#   RS3  100000-100499  /var/ossec/etc/rules/local_rules.xml"
  echo "#   RS4  100500-101000  /var/ossec/etc/rules/external_*.xml"
  echo "#   RS2   80700-80799   /var/ossec/ruleset/rules/0365-auditd_rules.xml"
  echo "#   RS1   resto         /var/ossec/ruleset/rules/*.xml (excepto auditd)"
  echo "#   UNKNOWN             cualquier otro origen (se trata como colisión)"
  echo "#"
  echo "# NOTA DE REALIDAD: el ruleset default de Wazuh 4.14.7 incluye ficheros con"
  echo "# IDs > 101000 (fireeye 150100+, sysmon 184665+, unbound 500000+). Son del"
  echo "# paquete default y se clasifican como RS1 por ORIGEN. Ver"
  echo "# Soporte/Wazuh/Configuracion/rulesets_activacion.md."
  echo "#"
  echo "# --- RESUMEN POR RULESET ---"
  printf "# %-5s %-18s %8s %8s %8s %10s\n" "RS" "NOMBRE" "MIN_ID" "MAX_ID" "N_RULES" "N_FICHEROS"
  printf "%-5s %-18s %8s %8s %8s %10s\n" "RS1" "base(default)" "$(echo "$RS1_S" | cut -f2)" "$(echo "$RS1_S" | cut -f3)" "$(echo "$RS1_S" | cut -f4)" "$(echo "$RS1_S" | cut -f5)"
  printf "%-5s %-18s %8s %8s %8s %10s\n" "RS2" "auditd"        "$(echo "$RS2_S" | cut -f2)" "$(echo "$RS2_S" | cut -f3)" "$(echo "$RS2_S" | cut -f4)" "$(echo "$RS2_S" | cut -f5)"
  printf "%-5s %-18s %8s %8s %8s %10s\n" "RS3" "propias"       "$(echo "$RS3_S" | cut -f2)" "$(echo "$RS3_S" | cut -f3)" "$(echo "$RS3_S" | cut -f4)" "$(echo "$RS3_S" | cut -f5)"
  if [ "$(echo "$RS4_S" | cut -f4)" = "0" ]; then
    printf "%-5s %-18s %8s %8s %8s %10s   (vacía; reserva %s-%s, opción A/G2)\n" "RS4" "externas" "-" "-" "0" "$(echo "$RS4_S" | cut -f5)" "$RS4_MIN" "$RS4_MAX"
  else
    printf "%-5s %-18s %8s %8s %8s %10s\n" "RS4" "externas" "$(echo "$RS4_S" | cut -f2)" "$(echo "$RS4_S" | cut -f3)" "$(echo "$RS4_S" | cut -f4)" "$(echo "$RS4_S" | cut -f5)"
  fi
  echo "#"
  echo "# --- DETALLE POR FICHERO ---"
  echo "# RS   MIN_ID  MAX_ID  N_RULES  FICHERO"
  sort -t$'\t' -k1,1 -k5,5 "$PER_FILE" | awk -F'\t' '{printf "%s  %s  %s  %s  %s\n", $1, $2, $3, $4, $5}'
  echo "#"
  echo "# --- CONTROL DE COLISIONES (rulesets_diseno.md §4) ---"
  echo "# duplicate_ids          : $([ -n "$DUP_IDS" ] && echo $DUP_IDS | tr '\n' ' ' || echo 'ninguna')"
  echo "# rs2_out_of_range       : $([ -n "$RS2_BAD" ] && echo $RS2_BAD | tr '\n' ' ' || echo 'ninguna')"
  echo "# rs3_out_of_range       : $([ -n "$RS3_BAD" ] && echo $RS3_BAD | tr '\n' ' ' || echo 'ninguna')"
  echo "# rs4_out_of_range       : $([ -n "$RS4_BAD" ] && echo $RS4_BAD | tr '\n' ' ' || echo 'ninguna')"
  echo "# default_in_rs2_range   : $([ -n "$RS1_IN_RS2" ] && echo $RS1_IN_RS2 | tr '\n' ' ' || echo 'ninguna')"
  echo "# default_in_user_range  : $([ -n "$RS1_IN_USR" ] && echo $RS1_IN_USR | tr '\n' ' ' || echo 'ninguna')"
  echo "# rs3_inter_rs4          : $([ -n "$RS34_INT" ] && echo $RS34_INT | tr '\n' ' ' || echo 'vacío')"
  echo "# unknown_origin         : $([ -n "$UNK" ] && echo $UNK | tr '\n' ' ' || echo 'ninguno')"
  if [ "$COLLISION" -eq 0 ]; then
    echo "# RESULTADO: SIN COLISIONES"
  else
    echo "# RESULTADO: COLISIÓN DETECTADA — NO ACTIVAR"
    printf '%s' "$NOTES" | sed 's/^/#   ! /'
  fi
  echo "# --- CONTROL ACTIVE-RESPONSE (rulesets_diseno.md §5) ---"
  echo "# ficheros con <active-response> : ninguno"
  echo "# (guarda del generador: aborta con exit 2 si aparece alguno)"
  echo "# ============================================================================"
} > "$OUT"

# ------------------------------------------------------------------- salida
echo "Manifiesto escrito en: $OUT"
if [ "$COLLISION" -ne 0 ]; then
  echo "COLISIÓN DETECTADA:" >&2
  printf '%s' "$NOTES" >&2
  exit 1
fi
echo "Sin colisiones."
exit 0
