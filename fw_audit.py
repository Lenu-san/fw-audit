#!/usr/bin/env python3
"""fw-audit — auditeur de règles de pare-feu.

Lit un jeu de règles au format CSV et signale les configurations à risque :
règles permissives, services sensibles exposés, protocoles en clair, plages
trop larges, règles non documentées.

Usage :
  python fw_audit.py samples/ruleset-exemple.csv
  python fw_audit.py mes-regles.csv --min-severite MOYENNE
  python fw_audit.py politiques-fortigate.csv          # CSV de fortigate-policy-parser, détecté automatiquement

Code de sortie : 2 si au moins un constat CRITIQUE, 1 si au moins un ÉLEVÉE,
0 sinon — pratique pour intégrer l'audit dans un pipeline.
"""

import argparse
import os
import sys

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass

from fwaudit import checks, parser as fw_parser

# Couleurs actives uniquement sur un vrai terminal (sinon la sortie
# capturée/redirigée contiendrait des codes d'échappement parasites).
USE_COLOR = sys.stdout.isatty()

COLORS = {
    "CRITIQUE": "\033[41m\033[97m",  # fond rouge
    "ÉLEVÉE": "\033[31m",
    "MOYENNE": "\033[33m",
    "FAIBLE": "\033[36m",
    "INFO": "\033[2m",
}
RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""


def color(text, sev):
    if not USE_COLOR:
        return text
    return f"{COLORS.get(sev, '')}{text}{RESET}"


def run(path, min_severity, fmt="auto"):
    rules, skipped = fw_parser.parse_ruleset(path, fmt)
    findings = checks.audit(rules)

    threshold = checks.SEVERITY_ORDER[min_severity]
    shown = [f for f in findings if checks.SEVERITY_ORDER[f["severity"]] <= threshold]

    ignored = f", {skipped} politique(s) désactivée(s) ignorée(s)" if skipped else ""
    print(f"Audit de {os.path.basename(path)} — {len(rules)} règle(s) analysée(s){ignored}\n")

    if not shown:
        print("Aucun constat au niveau de sévérité demandé.")
    for f in shown:
        rule = f["rule"]
        tag = color(f" {f['severity']} ", f["severity"])
        where = rule.get("_label") or f"ligne {f['line']}"
        print(f"{tag} {BOLD}{where}{RESET} — {f['issue']}")
        print(
            f"    règle : {rule['action']} {rule['source']} -> "
            f"{rule['destination']} {rule['protocole']}/{rule['port']}"
        )
        print(f"    conseil : {f['reco']}\n")

    # Décompte par sévérité (sur l'ensemble, pas seulement l'affiché)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    summary = "  ".join(
        f"{sev}: {counts[sev]}"
        for sev in checks.SEVERITY_ORDER
        if sev in counts
    )
    print(f"{BOLD}Bilan{RESET} — {summary or 'aucun constat'}")

    if counts.get("CRITIQUE"):
        return 2
    if counts.get("ÉLEVÉE"):
        return 1
    return 0


def main():
    ap = argparse.ArgumentParser(
        prog="fw-audit",
        description="Audit d'un jeu de règles de pare-feu au format CSV.",
    )
    ap.add_argument("ruleset", help="fichier CSV de règles")
    ap.add_argument(
        "--format",
        choices=["auto", "csv", "fortigate"],
        default="auto",
        help="format d'entrée : CSV normalisé, export de fortigate-policy-parser, ou détection (défaut)",
    )
    ap.add_argument(
        "--min-severite",
        choices=list(checks.SEVERITY_ORDER),
        default="INFO",
        help="n'affiche que les constats de cette sévérité ou plus grave",
    )
    args = ap.parse_args()

    if not os.path.isfile(args.ruleset):
        print(f"Fichier introuvable : {args.ruleset}", file=sys.stderr)
        sys.exit(1)

    sys.exit(run(args.ruleset, args.min_severite, args.format))


if __name__ == "__main__":
    main()
