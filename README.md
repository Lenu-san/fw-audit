# fw-audit

![Python 3.7+](https://img.shields.io/badge/Python-3.7%2B-3776AB?logo=python&logoColor=white) ![Bibliothèque standard](https://img.shields.io/badge/d%C3%A9pendances-aucune-2E7D32) ![Tests](https://img.shields.io/badge/tests-unittest-455A64) ![Licence MIT](https://img.shields.io/badge/licence-MIT-546E7A)

**FR** — Auditeur de règles de pare-feu en ligne de commande : lit un jeu de règles au format CSV et signale les configurations à risque, avec une sévérité et une recommandation par constat. Outil d'aide à l'audit de configuration, écrit en Python avec la bibliothèque standard uniquement.

**EN** — Command-line firewall rule auditor: reads a rule set in CSV format and flags risky configurations, with a severity and a recommendation for each finding. A configuration-audit helper written with the Python standard library only.

---

## Français

### Objectif

Passer automatiquement un jeu de règles de pare-feu au crible des erreurs de configuration classiques, pour ne pas les manquer lors de la relecture manuelle et laisser l'auditeur se concentrer sur l'analyse du contexte.

### Contexte cybersécurité

Lors d'un audit de configuration, on récupère l'export des règles d'un pare-feu (pfSense, FortiGate, Forcepoint, iptables…) sous forme de tableau. La lecture de plusieurs centaines de règles est longue et sujette à l'oubli. Ce projet est né de missions d'audit de pare-feux réalisées en alternance : il reproduit, en version simplifiée, les contrôles que je fais à la main sur un jeu de règles.

Outil défensif : il ne fait que lire un fichier local. À utiliser sur les pare-feux que vous êtes autorisé à auditer.

### Fonctionnalités

- Lecture d'un CSV normalisé (`action,source,destination,protocole,port,description`), en-tête et BOM Excel tolérés, lignes vides et commentaires `#` ignorés.
- Cinq contrôles d'audit, chacun avec sévérité, règle concernée, problème et recommandation.
- Seules les règles qui **autorisent** du trafic sont auditées (`allow`, `permit`, `accept`, `pass`, `autoriser`).
- Filtre d'affichage `--min-severite` ; le bilan compte toujours l'ensemble des constats.
- Code de sortie exploitable en CI : `2` si au moins un constat CRITIQUE, `1` si au moins un ÉLEVÉE, `0` sinon.
- **Lecture directe d'un export FortiGate** : le CSV produit par [fortigate-policy-parser](https://github.com/Lenu-san/fortigate-policy-parser) est reconnu automatiquement (`--format auto`), les politiques désactivées sont ignorées, les services prédéfinis FortiOS (HTTP, RDP, ALL_TCP…) et les colonnes résolues de `--resolve` sont traduits en protocole / port, et chaque constat est rattaché à l'identifiant de la politique.

| Sévérité | Contrôle | Condition exacte |
|---|---|---|
| CRITIQUE | Règle permissive « any → any » | source *et* destination à `any`, et service (port ou protocole) à `any` |
| ÉLEVÉE | Service sensible exposé à toute source | source à `any` et port dans la liste : SSH 22, Telnet 23, FTP 21, NetBIOS 139, SMB 445, RDP 3389, MySQL 3306, PostgreSQL 5432, MSSQL 1433, WinRM 5985/5986, Redis 6379, MongoDB 27017 — port exact **ou plage contenant** l'un de ces ports |
| MOYENNE | Protocole en clair autorisé largement | port FTP 21, Telnet 23, HTTP 80, POP3 110 ou IMAP 143, avec source *ou* destination à `any` |
| MOYENNE | Plage de ports large | le champ port contient un tiret (`1000-2000`) |
| INFO | Règle non documentée | description vide (traçabilité, conformité) |
| FAIBLE | Règle sans journalisation | `logtraffic disable` sur une règle d'autorisation — uniquement sur un export FortiGate, qui renseigne cette information |

Valeurs reconnues comme « any » : `any`, `*`, `all`, `0.0.0.0/0`, `::/0` et champ vide.

### Technologies et outils

- Python 3.7+ (modules `csv`, `argparse`, `os`, `sys` uniquement)
- Aucune dépendance externe, aucun accès réseau
- Tests : `unittest`

```
fw_audit.py           point d'entrée CLI (affichage, code de sortie)
fwaudit/
  parser.py           lecture du CSV normalisé
  checks.py           contrôles d'audit et sévérités
  fortigate.py        lecture d'un export de fortigate-policy-parser
tests/
  test_checks.py      tests unitaires (parser, contrôles, chaînage FortiGate)
samples/
  ruleset-exemple.csv        jeu de règles de démonstration (9 règles)
  fortigate-politiques.csv   export de fortigate-policy-parser --resolve (5 politiques)
```

### Compatibilité

Fonctionne sous Windows, Linux et macOS : Python 3.7 ou plus, bibliothèque standard uniquement, aucun paquet à installer. Seul le nom de la commande Python change selon le système.

| Système | Vérifier Python | Lancer l'outil | Lancer les tests |
|---|---|---|---|
| Windows (PowerShell ou Invite de commandes) | `py --version` ou `python --version` | `py fw_audit.py samples/ruleset-exemple.csv` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 fw_audit.py samples/ruleset-exemple.csv` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 fw_audit.py samples/ruleset-exemple.csv` | `python3 -m unittest discover -s tests -v` |

Les exemples ci-dessous utilisent `python` : remplacer par `py` ou `python3` si nécessaire. Sous Windows, préférer PowerShell ou Windows Terminal pour l'affichage correct des accents et des couleurs.

### Installation

```bash
git clone https://github.com/Lenu-san/fw-audit.git
cd fw-audit
python fw_audit.py samples/ruleset-exemple.csv
```

### Utilisation

```bash
python fw_audit.py samples/ruleset-exemple.csv
python fw_audit.py mes-regles.csv --min-severite MOYENNE
python fw_audit.py samples/fortigate-politiques.csv          # export FortiGate, détecté automatiquement
python -m unittest discover -s tests -v
```

Chaînage complet depuis une sauvegarde FortiGate, en deux commandes :

```bash
python fgt_parser.py sauvegarde.conf --resolve --csv politiques.csv   # dans fortigate-policy-parser
python fw_audit.py politiques.csv                                     # dans fw-audit
```

Format d'entrée, une règle par ligne : `action,source,destination,protocole,port,description` (voir [samples/ruleset-exemple.csv](samples/ruleset-exemple.csv)).

### Résultats

Sur le jeu d'exemple (9 règles) :

```
Audit de ruleset-exemple.csv — 9 règle(s) analysée(s)

 CRITIQUE  ligne 2 — Règle permissive « any → any » (toute source vers toute destination)
    règle : allow any -> any any/any
    conseil : Restreindre source, destination et service au strict nécessaire.

 ÉLEVÉE  ligne 3 — Service sensible RDP (port 3389) exposé depuis n'importe quelle source
    règle : allow any -> 10.0.0.5 tcp/3389
    conseil : Limiter la source aux adresses d'administration ; passer par un VPN ou un bastion.

Bilan — CRITIQUE: 1  ÉLEVÉE: 3  MOYENNE: 2  INFO: 1
```

Sur l'export FortiGate d'exemple (5 politiques, 1 désactivée ignorée) :

```
 CRITIQUE  root · politique 3 — Règle permissive « any → any » (toute source vers toute destination)
 MOYENNE  root · politique 1 « LAN_vers_Internet » — Protocole en clair HTTP (port 80) autorisé largement
 FAIBLE  root · politique 3 — Règle d'autorisation sans journalisation du trafic

Bilan — CRITIQUE: 1  MOYENNE: 1  FAIBLE: 1
```

18 tests unitaires couvrent la lecture des deux formats, chacun des contrôles et le chaînage FortiGate.

### Limites

Il s'agit d'une première passe, pas d'un analyseur de politique complet :

- **Format d'entrée** : CSV normalisé à produire à la main pour la plupart des pare-feux (pfSense, iptables, Forcepoint…). Seul FortiGate bénéficie d'une chaîne directe via fortigate-policy-parser.
- **Services FortiGate** : sans `--resolve`, seuls les services prédéfinis courants sont traduits en ports ; un service personnalisé reste un nom, audité sur any→any et la documentation mais pas sur le port.
- **Pas d'analyse de la politique dans son ensemble** : règles masquées, redondantes ou contradictoires non détectées ; chaque règle est évaluée isolément, sans tenir compte de l'ordre.
- **Objets et groupes non résolus** : une source nommée (`LAN_admins`, `dmz-web`) n'est pas « any », mais l'outil ne sait pas ce qu'elle contient.
- **Noms de services** (`ssh`, `https`) non traduits en numéros de port.
- **Listes fixes** : services sensibles et protocoles en clair sont codés en dur.

### Améliorations possibles

- Résolution des noms de services courants en numéros de port.
- Détection simple des règles masquées par une règle plus large placée avant.
- Convertisseurs depuis d'autres exports natifs (pfSense, Forcepoint SMC).
- Export des constats en CSV ou JSON pour intégration dans un rapport.

---

## English

### Objective

Automatically screen a firewall rule set for classic misconfigurations, so that none are missed during a manual review and the auditor can focus on analysing the context.

### Cybersecurity context

During a configuration audit, the firewall rule export (pfSense, FortiGate, Forcepoint, iptables…) is retrieved as a table. Reading several hundred rules is slow and error-prone. This project grew out of firewall audit assignments carried out during my apprenticeship: it reproduces, in a simplified form, the checks I perform by hand on a rule set.

Defensive tool: it only reads a local file. Use it on firewalls you are authorised to audit.

### Features

- Reads a normalised CSV (`action,source,destination,protocole,port,description`); header row and Excel BOM tolerated, blank lines and `#` comments ignored.
- Five audit checks, each with a severity, the rule concerned, the issue and a recommendation.
- Only rules that **allow** traffic are audited (`allow`, `permit`, `accept`, `pass`, `autoriser`).
- `--min-severite` display filter; the summary always counts every finding.
- CI-friendly exit code: `2` if at least one CRITICAL finding, `1` if at least one HIGH, `0` otherwise.
- **Direct FortiGate export support**: the CSV produced by [fortigate-policy-parser](https://github.com/Lenu-san/fortigate-policy-parser) is recognised automatically (`--format auto`), disabled policies are skipped, FortiOS predefined services (HTTP, RDP, ALL_TCP…) and the resolved columns from `--resolve` are translated into protocol / port, and every finding is tied to the policy id.

| Severity | Check | Exact condition |
|---|---|---|
| CRITIQUE (critical) | Permissive “any → any” rule | source *and* destination set to `any`, and service (port or protocol) set to `any` |
| ÉLEVÉE (high) | Sensitive service exposed to any source | source set to `any` and port in the list: SSH 22, Telnet 23, FTP 21, NetBIOS 139, SMB 445, RDP 3389, MySQL 3306, PostgreSQL 5432, MSSQL 1433, WinRM 5985/5986, Redis 6379, MongoDB 27017 — exact port **or a range containing** one of them |
| MOYENNE (medium) | Clear-text protocol widely allowed | FTP 21, Telnet 23, HTTP 80, POP3 110 or IMAP 143, with source *or* destination set to `any` |
| MOYENNE (medium) | Wide port range | the port field contains a dash (`1000-2000`) |
| INFO | Undocumented rule | empty description (traceability, compliance) |
| FAIBLE (low) | Rule without logging | `logtraffic disable` on an allow rule — FortiGate exports only, which carry that information |

Values recognised as “any”: `any`, `*`, `all`, `0.0.0.0/0`, `::/0` and an empty field.

### Technologies and tools

- Python 3.7+ (`csv`, `argparse`, `os`, `sys` modules only)
- No external dependency, no network access
- Tests: `unittest`

```
fw_audit.py           CLI entry point (output, exit code)
fwaudit/
  parser.py           normalised CSV reader
  checks.py           audit checks and severities
  fortigate.py        reader for fortigate-policy-parser exports
tests/
  test_checks.py      unit tests (parser, checks, FortiGate chaining)
samples/
  ruleset-exemple.csv        demonstration rule set (9 rules)
  fortigate-politiques.csv   fortigate-policy-parser --resolve export (5 policies)
```

### Compatibility

Runs on Windows, Linux and macOS: Python 3.7 or later, standard library only, nothing to install. Only the name of the Python command differs between systems.

| System | Check Python | Run the tool | Run the tests |
|---|---|---|---|
| Windows (PowerShell or Command Prompt) | `py --version` or `python --version` | `py fw_audit.py samples/ruleset-exemple.csv` | `py -m unittest discover -s tests -v` |
| Linux (Debian, Ubuntu…) | `python3 --version` | `python3 fw_audit.py samples/ruleset-exemple.csv` | `python3 -m unittest discover -s tests -v` |
| macOS | `python3 --version` | `python3 fw_audit.py samples/ruleset-exemple.csv` | `python3 -m unittest discover -s tests -v` |

The examples below use `python`: replace with `py` or `python3` where needed. On Windows, prefer PowerShell or Windows Terminal so that accented characters and colours display correctly.

### Installation

```bash
git clone https://github.com/Lenu-san/fw-audit.git
cd fw-audit
python fw_audit.py samples/ruleset-exemple.csv
```

### Usage

```bash
python fw_audit.py samples/ruleset-exemple.csv
python fw_audit.py my-rules.csv --min-severite MOYENNE
python fw_audit.py samples/fortigate-politiques.csv          # FortiGate export, detected automatically
python -m unittest discover -s tests -v
```

Full chain from a FortiGate backup, in two commands:

```bash
python fgt_parser.py backup.conf --resolve --csv policies.csv   # in fortigate-policy-parser
python fw_audit.py policies.csv                                 # in fw-audit
```

Input format, one rule per line: `action,source,destination,protocole,port,description` (see [samples/ruleset-exemple.csv](samples/ruleset-exemple.csv)). Output messages are in French.

### Results

On the sample set (9 rules), the summary line is `CRITIQUE: 1  ÉLEVÉE: 3  MOYENNE: 2  INFO: 1`. On the sample FortiGate export (5 policies, 1 disabled and skipped): one critical any→any policy, one clear-text HTTP rule, one allow rule without logging, each tied to its policy id (see the French section for the full output). 18 unit tests cover both input formats, each check and the FortiGate chaining.

### Limitations

A first pass, not a full policy analyser:

- **Input format**: the normalised CSV must be produced by hand for most firewalls (pfSense, iptables, Forcepoint…). Only FortiGate has a direct chain through fortigate-policy-parser.
- **FortiGate services**: without `--resolve`, only common predefined services are translated into ports; a custom service stays a name, audited for any→any and documentation but not for its port.
- **No whole-policy analysis**: shadowed, redundant or contradictory rules are not detected; each rule is evaluated on its own, regardless of order.
- **Objects and groups are not resolved**: a named source (`LAN_admins`, `dmz-web`) is not “any”, but the tool does not know what it contains.
- **Service names** (`ssh`, `https`) are not translated into port numbers.
- **Fixed lists**: sensitive services and clear-text protocols are hard-coded.

### Possible improvements

- Resolution of common service names into port numbers.
- Simple detection of rules shadowed by a wider rule placed earlier.
- Converters from other native exports (pfSense, Forcepoint SMC).
- CSV or JSON export of findings for inclusion in a report.

---

## Auteur / Author

**Lénusan Gunarajah** — ingénieur cybersécurité junior : audit de sécurité, sécurité des infrastructures et services managés. / Junior cybersecurity engineer: security auditing, infrastructure security and managed services.

- Portfolio : https://lenu-san.github.io
- GitHub : https://github.com/Lenu-san
- LinkedIn : https://www.linkedin.com/in/lenusan-gunarajah

## Licence / License

MIT
