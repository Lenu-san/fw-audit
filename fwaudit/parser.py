"""Lecture d'un jeu de règles de pare-feu au format CSV normalisé.

Format attendu (une règle par ligne) :
    action,source,destination,protocole,port,description

- Les lignes vides et celles commençant par # sont ignorées.
- Une éventuelle ligne d'en-tête (commençant par « action ») est ignorée.

Ce format neutre correspond à ce qu'un auditeur exporte depuis n'importe
quel pare-feu (pfSense, Fortinet, iptables...) avant analyse.
"""

import csv

from .fortigate import is_fortigate_header, parse_fortigate_csv

FIELDS = ["action", "source", "destination", "protocole", "port", "description"]


def detect_format(path):
    """« fortigate » si l'en-tête est celui de fortigate-policy-parser, sinon « csv »."""
    with open(path, newline="", encoding="utf-8-sig") as handle:
        for row in csv.reader(handle):
            if not row or row[0].strip().startswith("#"):
                continue
            return "fortigate" if is_fortigate_header(row) else "csv"
    return "csv"


def parse_ruleset(path, fmt="auto"):
    """Point d'entrée unique : renvoie (règles, politiques ignorées)."""
    if fmt == "auto":
        fmt = detect_format(path)
    if fmt == "fortigate":
        return parse_fortigate_csv(path)
    return parse_csv(path), 0


def parse_csv(path):
    """Renvoie une liste de dicts, un par règle, avec le numéro de ligne."""
    rules = []
    # utf-8-sig retire un éventuel BOM (fréquent sur les CSV exportés d'Excel),
    # sans quoi la première ligne serait mal interprétée.
    with open(path, newline="", encoding="utf-8-sig") as handle:
        for lineno, row in enumerate(csv.reader(handle), start=1):
            if not row or row[0].strip().startswith("#"):
                continue
            if row[0].strip().lower() == "action":
                continue  # en-tête
            # normalise à 6 colonnes (complète ou tronque)
            cells = [c.strip() for c in (row + [""] * 6)[:6]]
            rule = dict(zip(FIELDS, cells))
            rule["_line"] = lineno
            rules.append(rule)
    return rules
