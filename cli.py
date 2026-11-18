"""
Interface CLI pour analyser un fichier Python.
Usage : python cli.py samples/vulnerable_app.py
"""

import json
import argparse
from src.analyzer import PythonVulnerabilityScanner

def main():
    parser = argparse.ArgumentParser(description="Détecteur ML Hybride de vulnérabilités Python")
    parser.add_argument("target", help="Chemin vers le fichier .py à analyser")
    parser.add_argument("--json", action="store_true", help="Afficher le résultat au format JSON")
    args = parser.parse_args()

    with open(args.target, "r", encoding="utf-8") as f:
        code = f.read()

    scanner = PythonVulnerabilityScanner()
    report = scanner.scan_code(code)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return

    print("=" * 70)
    print(f"RAPPORT D'ANALYSE DE SÉCURITÉ : {args.target}")
    print("=" * 70)
    print(f"Blocs analysés : {report['total_blocks_analyzed']} | Vulnérabilités détectées : {report['vulnerabilities_found']}\n")

    if report["is_clean"]:
        print("[OK] Aucune vulnérabilité détectée. Le code semble sécurisé.")
        return

    for idx, item in enumerate(report["findings"], start=1):
        print(f"[{idx}] {item['title']} ({item['cwe']}) - Sévérité : {item['severity']}")
        print(f"    Localisation : {item['scope']} (lignes {item['start_line']}-{item['end_line']}) | Confiance ML : {item['confidence']}%")
        if item["dangerous_lines"]:
            print("    Lignes dangereuses identifiées :")
            for dl in item["dangerous_lines"]:
                print(f"      -> Ligne {dl['line_number']}: {dl['code'].strip()}")
        print(f"    Explication  : {item['description']}")
        print(f"    Solution     : {item['remediation']}")
        print(f"    Exemple sûr  : {item['secure_example']}")
        print("-" * 70)

if __name__ == "__main__":
    main()
