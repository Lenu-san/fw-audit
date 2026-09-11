"""Tests unitaires de fw-audit : lecture du CSV et contrôles d'audit.

    python -m unittest discover -s tests -v
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fwaudit import checks, parser  # noqa: E402


def rule(action="allow", src="any", dst="any", proto="tcp", port="any", desc="doc", line=1):
    return {
        "action": action,
        "source": src,
        "destination": dst,
        "protocole": proto,
        "port": port,
        "description": desc,
        "_line": line,
    }


def issues(findings):
    return [(f["severity"], f["issue"]) for f in findings]


class ParserTests(unittest.TestCase):
    def _parse(self, text, encoding="utf-8"):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False, encoding=encoding, newline="") as handle:
            handle.write(text)
            path = handle.name
        try:
            return parser.parse_csv(path)
        finally:
            os.unlink(path)

    def test_ignore_header_comments_and_blank_lines(self):
        rules = self._parse(
            "action,source,destination,protocole,port,description\n"
            "# commentaire\n"
            "\n"
            "allow,any,10.0.0.5,tcp,3389,RDP\n"
        )
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["port"], "3389")
        self.assertEqual(rules[0]["_line"], 4)

    def test_excel_bom_is_stripped(self):
        rules = self._parse("allow,any,any,any,any,test\n", encoding="utf-8-sig")
        self.assertEqual(rules[0]["action"], "allow")

    def test_short_rows_are_padded_to_six_fields(self):
        rules = self._parse("allow,any,any\n")
        self.assertEqual(rules[0]["description"], "")
        self.assertEqual(rules[0]["port"], "")


class ChecksTests(unittest.TestCase):
    def test_deny_rules_are_not_audited(self):
        self.assertEqual(checks.audit([rule(action="deny")]), [])

    def test_any_to_any_is_critical(self):
        findings = checks.audit([rule(port="any", proto="any")])
        self.assertEqual(findings[0]["severity"], "CRITIQUE")

    def test_sensitive_service_exposed_to_any_source(self):
        findings = checks.audit([rule(dst="10.0.0.5", port="3389")])
        self.assertIn(("ÉLEVÉE", "Service sensible RDP (port 3389) exposé depuis n'importe quelle source"), issues(findings))

    def test_sensitive_service_inside_a_range_is_high(self):
        findings = checks.audit([rule(dst="10.0.0.5", port="20-25")])
        severities = [f["severity"] for f in findings]
        self.assertIn("ÉLEVÉE", severities)
        self.assertTrue(any("SSH (22)" in f["issue"] and "FTP (21)" in f["issue"] for f in findings))

    def test_range_from_internal_source_is_only_medium(self):
        findings = checks.audit([rule(src="10.0.0.0/8", dst="10.0.0.30", port="1000-2000")])
        self.assertEqual(issues(findings), [("MOYENNE", "Plage de ports large (1000-2000)")])

    def test_cleartext_protocol_widely_allowed(self):
        findings = checks.audit([rule(src="192.168.1.5", dst="any", port="80")])
        self.assertEqual(findings[0]["severity"], "MOYENNE")
        self.assertIn("HTTP", findings[0]["issue"])

    def test_undocumented_rule_is_info(self):
        findings = checks.audit([rule(src="10.0.0.1", dst="10.0.0.2", port="443", desc="  ")])
        self.assertEqual(issues(findings), [("INFO", "Règle non documentée (aucune description)")])

    def test_named_objects_are_not_any(self):
        findings = checks.audit([rule(src="LAN_admins", dst="dmz-web", port="22")])
        self.assertEqual(findings, [])

    def test_findings_sorted_by_severity_then_line(self):
        findings = checks.audit(
            [
                rule(src="10.0.0.1", dst="10.0.0.2", port="443", desc="", line=1),
                rule(port="any", proto="any", line=2),
                rule(dst="10.0.0.5", port="22", line=3),
            ]
        )
        self.assertEqual([f["severity"] for f in findings], ["CRITIQUE", "ÉLEVÉE", "INFO"])

    def test_sample_ruleset_totals(self):
        sample = os.path.join(os.path.dirname(__file__), "..", "samples", "ruleset-exemple.csv")
        findings = checks.audit(parser.parse_csv(sample))
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        self.assertEqual(counts, {"CRITIQUE": 1, "ÉLEVÉE": 3, "MOYENNE": 2, "INFO": 1})


if __name__ == "__main__":
    unittest.main()


class FortigateChainTests(unittest.TestCase):
    SAMPLE = os.path.join(os.path.dirname(__file__), "..", "samples", "fortigate-politiques.csv")

    def test_format_detected(self):
        self.assertEqual(parser.detect_format(self.SAMPLE), "fortigate")
        normal = os.path.join(os.path.dirname(__file__), "..", "samples", "ruleset-exemple.csv")
        self.assertEqual(parser.detect_format(normal), "csv")

    def test_disabled_policies_skipped_and_services_expanded(self):
        rules, skipped = parser.parse_ruleset(self.SAMPLE)
        self.assertEqual(skipped, 1)                       # politique 5 désactivée
        labels = {r["_label"] for r in rules}
        self.assertIn("root · politique 3", labels)
        self.assertEqual(len([r for r in rules if "politique 1" in r["_label"]]), 2)  # WEB = tcp/80 + tcp/443

    def test_findings_on_fortigate_sample(self):
        rules, _ = parser.parse_ruleset(self.SAMPLE)
        findings = checks.audit(rules)
        by_label = {}
        for f in findings:
            by_label.setdefault(f["rule"]["_label"], []).append(f["severity"])
        self.assertIn("CRITIQUE", by_label["root · politique 3"])   # any -> any en accept
        self.assertIn("FAIBLE", by_label["root · politique 3"])     # sans journalisation
        self.assertNotIn("INFO", by_label["root · politique 3"])    # commentée « regle temporaire debug » : documentée
        self.assertNotIn("root · politique 4 « Maj_editeur »", by_label)  # HTTPS vers un FQDN, journalisée : rien

    def test_unresolved_custom_service_is_not_a_range(self):
        from fwaudit import fortigate

        rules, _ = fortigate.parse_fortigate_rows(
            [(2, {"id": "9", "name": "x", "srcaddr": "all", "dstaddr": "SRV", "service": "APP-METIER", "action": "accept", "status": "enable", "logtraffic": "all", "comments": "ok"})]
        )
        self.assertEqual(rules[0]["port"], "APP-METIER")
        issues = [f["issue"] for f in checks.audit(rules)]
        self.assertFalse(any("Plage" in i for i in issues))

    def test_predefined_services_without_resolved_columns(self):
        from fwaudit import fortigate

        rules, _ = fortigate.parse_fortigate_rows(
            [(2, {"id": "1", "name": "", "srcaddr": "all", "dstaddr": "SRV", "service": "RDP DNS", "action": "accept", "status": "enable", "logtraffic": "all", "comments": ""})]
        )
        self.assertEqual([(r["protocole"], r["port"]) for r in rules], [("tcp", "3389"), ("tcp", "53"), ("udp", "53")])
        severities = [f["severity"] for f in checks.audit(rules)]
        self.assertIn("ÉLEVÉE", severities)   # RDP exposé depuis toute source
