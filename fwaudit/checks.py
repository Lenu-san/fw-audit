"""Contrôles d'audit appliqués à un jeu de règles de pare-feu.

Chaque contrôle produit un constat avec une sévérité, la règle concernée,
le problème et une recommandation — comme dans un rapport d'audit.
"""

# Valeurs qui signifient « n'importe quoi » selon les pare-feu.
ANY_VALUES = {"any", "*", "all", "0.0.0.0/0", "::/0", ""}
ALLOW_ACTIONS = {"allow", "permit", "accept", "pass", "autoriser"}

# Services sensibles à ne jamais exposer à une source quelconque.
RISKY_PORTS = {
    22: "SSH",
    23: "Telnet",
    21: "FTP",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    5985: "WinRM",
    5986: "WinRM",
    6379: "Redis",
    27017: "MongoDB",
}

# Protocoles en clair (données non chiffrées sur le réseau).
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}

SEVERITY_ORDER = {"CRITIQUE": 0, "ÉLEVÉE": 1, "MOYENNE": 2, "FAIBLE": 3, "INFO": 4}


def is_any(value):
    return value.strip().lower() in ANY_VALUES


def _port_int(port):
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def _port_range(port):
    """Renvoie (début, fin) pour une plage « 1000-2000 », sinon None."""
    if "-" not in port:
        return None
    lo, _, hi = port.partition("-")
    lo, hi = _port_int(lo.strip()), _port_int(hi.strip())
    if lo is None or hi is None or lo > hi:
        return None
    return lo, hi


def risky_ports_in_range(port):
    """Services sensibles contenus dans une plage de ports, triés par numéro."""
    bounds = _port_range(port)
    if bounds is None:
        return []
    lo, hi = bounds
    return [(p, RISKY_PORTS[p]) for p in sorted(RISKY_PORTS) if lo <= p <= hi]


def audit(rules):
    """Applique tous les contrôles, renvoie la liste des constats triés."""
    findings = []

    def add(severity, rule, issue, reco):
        findings.append(
            {
                "severity": severity,
                "line": rule["_line"],
                "rule": rule,
                "issue": issue,
                "reco": reco,
            }
        )

    for rule in rules:
        if rule["action"].strip().lower() not in ALLOW_ACTIONS:
            continue  # on n'audite que les règles qui AUTORISENT du trafic

        src_any = is_any(rule["source"])
        dst_any = is_any(rule["destination"])
        proto_any = is_any(rule["protocole"])
        port = rule["port"]
        port_any = is_any(port)
        pnum = _port_int(port)

        # 1. Règle totalement permissive
        if src_any and dst_any and (port_any or proto_any):
            add(
                "CRITIQUE",
                rule,
                "Règle permissive « any → any » (toute source vers toute destination)",
                "Restreindre source, destination et service au strict nécessaire.",
            )

        # 2. Service sensible exposé à toute source (port exact ou inclus dans une plage)
        if src_any and pnum in RISKY_PORTS:
            add(
                "ÉLEVÉE",
                rule,
                f"Service sensible {RISKY_PORTS[pnum]} (port {pnum}) exposé depuis n'importe quelle source",
                "Limiter la source aux adresses d'administration ; passer par un VPN ou un bastion.",
            )
        elif src_any and risky_ports_in_range(port):
            included = ", ".join(f"{name} ({num})" for num, name in risky_ports_in_range(port))
            add(
                "ÉLEVÉE",
                rule,
                f"Plage {port} exposée depuis n'importe quelle source et contenant des services sensibles : {included}",
                "Exclure les services sensibles de la plage ou restreindre la source aux adresses d'administration.",
            )

        # 3. Protocole en clair autorisé largement
        if pnum in CLEARTEXT_PORTS and (src_any or dst_any):
            add(
                "MOYENNE",
                rule,
                f"Protocole en clair {CLEARTEXT_PORTS[pnum]} (port {pnum}) autorisé largement",
                "Remplacer par une version chiffrée (SSH, HTTPS, FTPS...).",
            )

        # 4. Plage de ports trop large (uniquement une vraie plage numérique)
        if _port_range(port) is not None:
            add(
                "MOYENNE",
                rule,
                f"Plage de ports large ({port})",
                "Réduire la plage aux ports réellement nécessaires.",
            )

        # 5. Règle non documentée
        if not rule["description"].strip():
            add(
                "INFO",
                rule,
                "Règle non documentée (aucune description)",
                "Documenter la justification métier (traçabilité et conformité).",
            )

        # 6. Règle sans journalisation (uniquement si l'export le renseigne : FortiGate)
        if rule.get("logtraffic") == "disable":
            add(
                "FAIBLE",
                rule,
                "Règle d'autorisation sans journalisation du trafic",
                "Activer la journalisation (logtraffic all ou utm) : sans journaux, ni supervision ni investigation.",
            )

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["line"]))
    return findings
