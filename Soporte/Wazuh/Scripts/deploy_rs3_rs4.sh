#!/bin/bash
# ============================================================================
# TFG — Despliegue de RS3 (reglas propias) y reserva de RS4 — Fase 2
# ============================================================================
# Idempotente y re-ejecutable. Ejecutar como root en el MANAGER.
#
# CAMBIO 2026-09-23: la regla *smoke* 100000 (hija de 5710) se RETIRÓ antes del
# baseline por ENMASCARAR la detección base 5710 (norma rulesets_diseno.md §9;
# evidencia en rulesets_activacion.md §11). Por tanto, en Fase 2 **RS3 = 0
# reglas** y este script NO despliega ninguna regla propia: garantiza que el
# manager NO tiene /var/ossec/etc/rules/local_rules.xml (con backup previo).
#
# Reglas duras:
#   - NUNCA desplegar un fichero de reglas sin <rule> ni con un <group> vacío:
#     un grupo sin reglas rompe el manager
#     ("Group 'group' without any rule" -> CRITICAL).
#   - RS4 (opción A, gate G2) queda VACÍA: no se despliega ningún external_*.xml.
#
# Uso:
#   sudo bash deploy_rs3_rs4.sh [RUTA_FICHERO_REGLAS]
#     - Sin argumento (Fase 2): NO despliega; retira cualquier local_rules.xml
#       desplegado (RS3 = 0).
#     - Con argumento: despliega ESE fichero SOLO si, ignorando comentarios,
#       contiene >=1 <rule> y ningún <group> vacío (para Fase 3, cuando el
#       esqueleto tenga reglas reales). Si no cumple, no despliega (RS3 = 0).
set -u
RULES_DIR=/var/ossec/etc/rules
SRC="${1:-}"
BAK_RETIRADA="$RULES_DIR/local_rules.xml.bak-retirada-100000"
DEPLOY=0

echo "=== [1/5] backup de la regla retirada (si aún está desplegada) ==="
if [ -f "$RULES_DIR/local_rules.xml" ]; then
  if [ -f "$BAK_RETIRADA" ]; then
    echo "backup ya existe; no se sobreescribe: $BAK_RETIRADA"
  else
    cp -a "$RULES_DIR/local_rules.xml" "$BAK_RETIRADA"
    echo "backup creado: $BAK_RETIRADA"
  fi
else
  echo "no hay local_rules.xml desplegado (nada que respaldar)"
fi

echo "=== [2/5] decidir despliegue de RS3 ==="
if [ -n "$SRC" ] && [ -f "$SRC" ]; then
  python3 - "$SRC" <<'PY'
import re, sys
txt = open(sys.argv[1], encoding="utf-8", errors="replace").read()
# ignorar comentarios XML (el esqueleto comenta la regla retirada)
limpio = re.sub(r"<!--.*?-->", "", txt, flags=re.S)
for m in re.finditer(r"<group\b[^>]*>(.*?)</group>", limpio, flags=re.S):
    if not re.search(r"<rule\b", m.group(1)):
        sys.exit(2)                   # <group> vacío -> no desplegar (rompe el manager)
if not re.search(r"<rule\b", limpio):
    sys.exit(1)                       # sin reglas -> no desplegar
sys.exit(0)
PY
  RC=$?
  case "$RC" in
    0) DEPLOY=1; echo "fuente con reglas reales y sin grupos vacios: $SRC -> se despliega" ;;
    2) echo "AVISO: $SRC tiene un <group> SIN reglas -> NO se despliega (romperia el manager)" ;;
    *) echo "sin reglas propias (Fase 2) -> NO se despliega; RS3 = 0" ;;
  esac
else
  echo "sin fichero fuente (Fase 2) -> NO se despliega; RS3 = 0"
fi

if [ "$DEPLOY" -eq 1 ]; then
  install -o wazuh -g wazuh -m 0660 "$SRC" "$RULES_DIR/local_rules.xml"
  echo "desplegado: $RULES_DIR/local_rules.xml"
else
  rm -f "$RULES_DIR/local_rules.xml"
  echo "garantizado: sin $RULES_DIR/local_rules.xml (RS3 = 0 reglas)"
fi

echo "=== [3/5] RS4: NO se despliega (vacía, documentada). Limpieza de restos ==="
rm -f "$RULES_DIR/external_reserved.xml"

ls -l "$RULES_DIR/"

echo "=== [4/5] validar XML si se desplegó ==="
if [ -f "$RULES_DIR/local_rules.xml" ]; then
  python3 - <<'PY'
import xml.dom.minidom as m
m.parse("/var/ossec/etc/rules/local_rules.xml")
print("XML OK: /var/ossec/etc/rules/local_rules.xml")
PY
else
  echo "sin local_rules.xml que validar (RS3 = 0)"
fi

echo "=== [5/5] reiniciar manager (deteccion-only: 0 active-response) ==="
systemctl restart wazuh-manager
sleep 10
echo -n "wazuh-manager: "; systemctl is-active wazuh-manager
# wazuh-execd: puede volver a arrancar tras el reinicio; es INERTE (no hay <active-response>).
# Su estado es informativo, NO la garantia. La garantia: 0 <active-response> (ossec.conf + reglas).
if ps -eo pid,cmd | grep -q '[w]azuh-execd'; then
  echo "wazuh-execd: corriendo (INERTE: 0 <active-response>) — OK"
else
  echo "wazuh-execd: sin proceso (tambien OK: no hay <active-response>)"
fi
echo "=== FIN RS3/RS4 ==="
