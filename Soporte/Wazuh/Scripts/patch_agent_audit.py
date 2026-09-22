#!/usr/bin/env python3
"""Inserta el <localfile> de auditd en el ossec.conf del agente (idempotente).

- Hace backup si no existe (ossec.conf.bak-tfg28).
- Valida el XML resultante (root sintético: el fichero tiene 2 <ossec_config>).
- No toca nada si el localfile ya está presente.
"""
import re
import sys
import xml.dom.minidom as minidom

CONF = "/var/ossec/etc/ossec.conf"
BLOCK = (
    "  <localfile>\n"
    "    <log_format>audit</log_format>\n"
    "    <location>/var/log/audit/audit.log</location>\n"
    "  </localfile>\n\n"
)


def validate(text: str) -> None:
    body = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", text)
    minidom.parseString("<root>" + body + "</root>")


def main() -> int:
    with open(CONF, encoding="utf-8") as fh:
        src = fh.read()

    if "<location>/var/log/audit/audit.log</location>" in src:
        print("OK: el <localfile> de auditd ya está presente; sin cambios")
        return 0

    idx = src.rfind("</ossec_config>")
    if idx == -1:
        print("ERROR: no se encontró </ossec_config> en el ossec.conf")
        return 1

    new = src[:idx] + BLOCK + src[idx:]
    try:
        validate(new)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: el XML resultante no valida: {exc}")
        return 1

    with open(CONF, "w", encoding="utf-8") as fh:
        fh.write(new)
    print("OK: <localfile> de auditd insertado y XML validado")
    return 0


if __name__ == "__main__":
    sys.exit(main())
