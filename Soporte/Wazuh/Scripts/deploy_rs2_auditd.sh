#!/bin/bash
# ============================================================================
# TFG — Despliegue de RS2 (auditd) en victima-linux
# ============================================================================
# Idempotente y re-ejecutable. Ejecutar como root en la víctima.
# Requiere: /tmp/auditd_tfg.rules y /tmp/patch_agent_audit.py ya copiados.
set -u
export DEBIAN_FRONTEND=noninteractive

echo "=== [1/6] apt install auditd audispd-plugins ==="
if dpkg -s auditd >/dev/null 2>&1; then
  echo "auditd ya instalado; se omite apt install"
else
  apt-get update -qq
  apt-get install -y -qq auditd audispd-plugins
fi
dpkg -l auditd audispd-plugins 2>/dev/null | grep '^ii' || true

echo "=== [2/6] crear /home/angel/lab-legit (ruta del corpus) ==="
install -d -o angel -g angel -m 0750 /home/angel/lab-legit
ls -ld /home/angel/lab-legit

echo "=== [3/6] desplegar reglas auditd -> /etc/audit/rules.d/tfg.rules ==="
install -o root -g root -m 0640 /tmp/auditd_tfg.rules /etc/audit/rules.d/tfg.rules
ls -l /etc/audit/rules.d/tfg.rules

echo "=== [4/6] cargar reglas (augenrules) + servicio auditd ==="
systemctl enable auditd >/dev/null 2>&1 || true
augenrules --load
systemctl restart auditd
sleep 2
echo -n "auditd: "; systemctl is-active auditd

echo "=== [5/6] reglas cargadas en el kernel (auditctl -l) ==="
auditctl -l

echo "=== [6/6] habilitar /var/log/audit/audit.log en el agente Wazuh ==="
[ -f /var/ossec/etc/ossec.conf.bak-tfg28 ] || cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-tfg28
python3 /tmp/patch_agent_audit.py
systemctl restart wazuh-agent
sleep 3
echo -n "wazuh-agent: "; systemctl is-active wazuh-agent
echo "=== localfile audit en el agente ==="
grep -A2 'log_format>audit' /var/ossec/etc/ossec.conf || echo "NO ENCONTRADO"
echo "=== FIN RS2 ==="
