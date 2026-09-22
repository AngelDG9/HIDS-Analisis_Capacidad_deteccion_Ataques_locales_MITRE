#!/bin/bash
# ============================================================================
# TFG — Despliegue de RS3 (local_rules.xml) y reserva de RS4
# ============================================================================
# Idempotente y re-ejecutable. Ejecutar como root en el MANAGER.
# Requiere /tmp/local_rules.xml ya copiado.
#
# NOTA RS4 (opción A, gate G2): RS4 queda VACÍA. NO se despliega ningún
# `external_*.xml` porque Wazuh 4.14.7 rechaza ficheros de reglas sin reglas
# (un <group> vacío => "Group 'group' without any rule" => el manager no arranca).
# El punto de carga es el directorio /var/ossec/etc/rules/ (documentado).
set -u
RULES_DIR=/var/ossec/etc/rules

echo "=== [1/5] backup del local_rules.xml original ==="
if [ -f "$RULES_DIR/local_rules.xml.bak-tfg28" ]; then
  echo "backup ya existe; no se sobreescribe"
else
  cp -a "$RULES_DIR/local_rules.xml" "$RULES_DIR/local_rules.xml.bak-tfg28"
  echo "backup creado: $RULES_DIR/local_rules.xml.bak-tfg28"
fi

echo "=== [2/5] desplegar RS3 (local_rules.xml) ==="
install -o wazuh -g wazuh -m 0660 /tmp/local_rules.xml "$RULES_DIR/local_rules.xml"

echo "=== [3/5] RS4: NO se despliega (vacía, documentada). Limpieza de restos ==="
rm -f "$RULES_DIR/external_reserved.xml"

ls -l "$RULES_DIR/"

echo "=== [4/5] validar XML del fichero de reglas propio ==="
python3 - <<'PY'
import xml.dom.minidom as m
m.parse("/var/ossec/etc/rules/local_rules.xml")
print("XML OK: /var/ossec/etc/rules/local_rules.xml")
PY

echo "=== [5/5] reiniciar manager + re-parar execd (deteccion-only) ==="
systemctl restart wazuh-manager
sleep 10
echo -n "wazuh-manager: "; systemctl is-active wazuh-manager
pkill -TERM -x wazuh-execd 2>/dev/null || true
sleep 1
if ps -eo pid,cmd | grep -q '[w]azuh-execd'; then
  echo "wazuh-execd: SIGUE ARRANCADO"
else
  echo "wazuh-execd: sin proceso (OK)"
fi
echo "=== FIN RS3/RS4 ==="
