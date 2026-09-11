"""Lecture d'un export CSV produit par fortigate-policy-parser.

fortigate-policy-parser met à plat une sauvegarde FortiOS en une table
(`vdom, id, name, srcintf, dstintf, srcaddr, dstaddr, service, action, status,
nat, logtraffic, schedule, comments`), avec en option trois colonnes résolues
(`srcaddr_resolved, dstaddr_resolved, service_resolved`) quand il est lancé
avec `--resolve`. Ce module transforme chaque politique en une ou plusieurs
règles au format interne de fw-audit, pour que les contrôles s'appliquent
sans conversion manuelle.

Sans les colonnes résolues, les services prédéfinis FortiOS les plus courants
sont traduits ici ; un service personnalisé reste un nom (non audité sur le
port, mais toujours audité sur any→any et la documentation).
"""

import csv

FORTIGATE_HEADER = {"vdom", "id", "srcaddr", "dstaddr", "service", "action", "status"}

# Correspondance minimale des services prédéfinis FortiOS (protocole, ports).
# La liste complète vit dans fortigate-policy-parser ; --resolve la rend inutile ici.
PREDEFINED = {
    "ALL": [("any", "any")],
    "ALL_TCP": [("tcp", "1-65535")],
    "ALL_UDP": [("udp", "1-65535")],
    "ALL_ICMP": [("icmp", "any")],
    "PING": [("icmp", "any")],
    "HTTP": [("tcp", "80")],
    "HTTPS": [("tcp", "443")],
    "SSH": [("tcp", "22")],
    "TELNET": [("tcp", "23")],
    "FTP": [("tcp", "21")],
    "SMTP": [("tcp", "25")],
    "POP3": [("tcp", "110")],
    "IMAP": [("tcp", "143")],
    "DNS": [("tcp", "53"), ("udp", "53")],
    "NTP": [("udp", "123")],
    "SNMP": [("udp", "161-162")],
    "RDP": [("tcp", "3389")],
    "SMB": [("tcp", "445")],
    "SAMBA": [("tcp", "139")],
    "NetBIOS": [("tcp", "139"), ("udp", "137-138")],
    "LDAP": [("tcp", "389")],
    "LDAPS": [("tcp", "636")],
    "MYSQL": [("tcp", "3306")],
    "MS-SQL": [("tcp", "1433"), ("udp", "1434")],
    "KERBEROS": [("tcp", "88"), ("udp", "88")],
    "VNC": [("tcp", "5900")],
    "SQUID": [("tcp", "3128")],
}


def is_fortigate_header(row):
    """Vrai si la ligne d'en-tête est celle de fortigate-policy-parser."""
    return FORTIGATE_HEADER.issubset({c.strip().lower() for c in row})


def _addresses(row, column):
    """Adresses résolues si disponibles, sinon les noms d'objets ; « all » -> any."""
    resolved = row.get(column + "_resolved", "").strip()
    raw = (resolved or row.get(column, "")).split()
    if not raw or any(a.lower() == "all" for a in raw):
        return "any"
    return " ".join(raw)


def _services(row):
    """Liste de (protocole, port) pour une politique."""
    resolved = row.get("service_resolved", "").strip()
    pairs = []
    if resolved:
        for token in resolved.split():
            if token.lower() == "any":
                pairs.append(("any", "any"))
            elif "/" in token:
                proto, _, ports = token.partition("/")
                pairs.append((proto, ports))
            else:
                pairs.append(("", token.lstrip("?")))  # service non résolu
        return pairs
    for name in row.get("service", "").split():
        predefined = PREDEFINED.get(name)
        if predefined:
            pairs.extend(predefined)
        else:
            pairs.append(("", name))  # service personnalisé, non résolu
    return pairs or [("", "")]


def parse_fortigate_rows(rows):
    """Transforme les lignes d'un DictReader en règles fw-audit.

    Renvoie (règles, ignorées) : les politiques désactivées ne sont pas
    auditées (elles ne filtrent rien) mais sont comptées.
    """
    rules = []
    skipped = 0
    for lineno, row in rows:
        if row.get("status", "enable").strip().lower() == "disable":
            skipped += 1
            continue
        pid = row.get("id", "").strip()
        name = row.get("name", "").strip()
        vdom = row.get("vdom", "").strip()
        label = f"politique {pid}" + (f" « {name} »" if name else "")
        if vdom:
            label = f"{vdom} · " + label
        description = row.get("comments", "").strip() or name
        source = _addresses(row, "srcaddr")
        destination = _addresses(row, "dstaddr")
        for proto, port in _services(row):
            rules.append(
                {
                    "action": row.get("action", "").strip(),
                    "source": source,
                    "destination": destination,
                    "protocole": proto,
                    "port": port,
                    "description": description,
                    "logtraffic": row.get("logtraffic", "").strip().lower(),
                    "_line": lineno,
                    "_label": label,
                }
            )
    return rules, skipped


def parse_fortigate_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        rows = [(lineno, row) for lineno, row in enumerate(reader, start=2)]
    return parse_fortigate_rows(rows)
