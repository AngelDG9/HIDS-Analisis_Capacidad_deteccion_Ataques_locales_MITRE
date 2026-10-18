#!/bin/bash
# verificar_internet_local.sh — verificación de la "internet local" DESDE la víctima (L0).
#
# Comprueba (§4.3 del plan):
#   1) alias de dominios en /etc/hosts (si hace falta sudo, lee la contraseña por STDIN);
#   2) servicios locales POSITIVOS (web 8080, paste 9090, WebDAV 9092);
#   3) PRUEBA NEGATIVA: la víctima NO sale a internet;
#   4) la tabla de rutas (sin default => NAT off).
#
# Uso:  echo "<contraseña>" | ssh ... "bash /tmp/verificar_internet_local.sh"
#       (si ya hay sudo en caché o no se pasa contraseña, se intenta sudo -n).
# No escribe la contraseña en ningún fichero.

set -u

SUDOPW=""
if [ ! -t 0 ]; then read -r SUDOPW || true; fi

ALIAS_LINE="192.168.65.1  intranet.local portal.local nube.local"

echo "=== 1) /etc/hosts ==="
if ! grep -q "intranet.local" /etc/hosts; then
    if [ -n "$SUDOPW" ]; then
        printf '%s\n' "$SUDOPW" | sudo -S -p "" sh -c "echo '$ALIAS_LINE' >> /etc/hosts" 2>/dev/null \
            && echo "[hosts] alias anadido" || echo "[hosts] NO se pudo anadir (sudo)"
    else
        sudo -n sh -c "echo '$ALIAS_LINE' >> /etc/hosts" 2>/dev/null \
            && echo "[hosts] alias anadido" || echo "[hosts] NO se pudo anadir (sin sudo)"
    fi
fi
grep -E "intranet|nube" /etc/hosts || echo "[hosts] sin alias"

echo "=== 2) POSITIVAS ==="
curl -sS -o /dev/null -w "8080 root:     %{http_code}\n" http://intranet.local:8080/
curl -sS -o /tmp/x.pdf  -w "8080 pdf:      %{http_code} size=%{size_download}\n" http://intranet.local:8080/descargas/manual_empleado.pdf
curl -sS -o /tmp/x.zip  -w "8080 zip:      %{http_code} size=%{size_download}\n" http://intranet.local:8080/descargas/paquete_datos.zip
curl -sS -X POST -d hola http://intranet.local:9090/paste -o /dev/null -w "9090 paste:    %{http_code}\n"
curl -sS -T /etc/hostname http://nube.local:9092/nube/hostname -o /dev/null -w "9092 put:      %{http_code}\n"
curl -sS -X PROPFIND -H "Depth: 1" http://nube.local:9092/nube/ -o /dev/null -w "9092 propfind: %{http_code}\n"

echo "=== 3) NEGATIVA (debe FALLAR) ==="
curl --max-time 4 -sS http://example.com -o /dev/null -w "example.com: %{http_code}\n" || echo "example.com: FALLA (ok, aislado) exit=$?"
curl --max-time 4 -sS http://1.1.1.1 -o /dev/null -w "1.1.1.1:     %{http_code}\n" || echo "1.1.1.1: FALLA (ok, aislado) exit=$?"

echo "=== 4) RUTA ==="
ip route
echo "=== FIN ==="
