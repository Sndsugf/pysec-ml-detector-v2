"""
Base de connaissances des vulnérabilités Python couvertes par le modèle multiclasse hybride :
- SAFE : Code sain et sécurisé
- SQL_INJECTION (CWE-89) : Injection SQL via formatage de chaînes dans les requêtes
- COMMAND_INJECTION (CWE-78) : Injection de commandes système (os.system, subprocess avec shell=True)
- INSECURE_DESERIALIZATION (CWE-502) : Désérialisation non sécurisée (pickle, yaml.load, eval/exec)
- HARDCODED_SECRET (CWE-798) : Clés API, mots de passe ou tokens codés en dur
"""

import re
import ast

VULN_KNOWLEDGE_BASE = {
    "SAFE": {
        "cwe": "N/A",
        "severity": "Aucune",
        "title": "Code Sécurisé",
        "description": "Aucune vulnérabilité critique détectée sur ce bloc de code.",
        "remediation": "Continuez à appliquer les bonnes pratiques (requêtes paramétrées, variables d'environnement, validation des entrées).",
        "secure_example": "# Code conforme aux bonnes pratiques de sécurité."
    },
    "SQL_INJECTION": {
        "cwe": "CWE-89",
        "severity": "Critique",
        "title": "Injection SQL (SQL Injection)",
        "description": "Construction dynamique de requêtes SQL par concaténation (+), f-strings ou formatage (%) avec des variables non filtrées.",
        "remediation": "Utilisez systématiquement des requêtes paramétrées (placeholders `?` ou `%s` passés en tuple au curseur) ou un ORM sécurisé.",
        "secure_example": 'cursor.execute("SELECT * FROM users WHERE username = %s AND status = %s", (username, "active"))'
    },
    "COMMAND_INJECTION": {
        "cwe": "CWE-78",
        "severity": "Critique",
        "title": "Injection de Commandes Système (OS Command Injection)",
        "description": "Exécution de commandes système via `os.system()`, `os.popen()` ou `subprocess` avec `shell=True` incluant des entrées dynamiques.",
        "remediation": "Utilisez `subprocess.run()` avec une liste d'arguments (`shell=False` par défaut) et validez les entrées avec `shlex.quote()` ou une liste blanche.",
        "secure_example": 'subprocess.run(["ping", "-c", "4", target_ip], shell=False, check=True)'
    },
    "INSECURE_DESERIALIZATION": {
        "cwe": "CWE-502",
        "severity": "Élevée",
        "title": "Désérialisation / Évaluation Non Sécurisée",
        "description": "Utilisation de `pickle.loads()`, `yaml.load()` sans `SafeLoader`, `marshal.loads()` ou `eval()`/`exec()` sur des données externes.",
        "remediation": "Privilégiez des formats de données sûrs comme JSON (`json.loads()`), utilisez `yaml.safe_load()` pour YAML, et `ast.literal_eval()` pour les littéraux Python.",
        "secure_example": 'data = json.loads(raw_payload)  # ou yaml.safe_load(raw_yaml)'
    },
    "HARDCODED_SECRET": {
        "cwe": "CWE-798",
        "severity": "Élevée",
        "title": "Identifiants ou Secrets Codés en Dur",
        "description": "Présence de mots de passe, clés API, tokens JWT ou clés secrètes directement inscrits dans le code source.",
        "remediation": "Externalisez tous les secrets dans des variables d'environnement (`os.environ.get()`) ou un gestionnaire de secrets (Vault, AWS Secrets Manager).",
        "secure_example": 'API_KEY = os.environ.get("SERVICE_API_KEY")'
    }
}

LINE_PATTERNS = {
    "SQL_INJECTION": [
        re.compile(r'(execute|executemany)\s*\(\s*f["\']', re.IGNORECASE),
        re.compile(r'(execute|executemany)\s*\(.*(\+|%|\.format\s*\()', re.IGNORECASE),
        re.compile(r'(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(\+|%|\.format\s*\(|\{.*\})', re.IGNORECASE),
    ],
    "COMMAND_INJECTION": [
        re.compile(r'\bos\.(system|popen|spawn[a-z]*)\s*\('),
        re.compile(r'\bsubprocess\.(Popen|call|run|check_output|check_call)\s*\(.*shell\s*=\s*True'),
        re.compile(r'\bcommands\.(getoutput|getstatusoutput)\s*\('),
    ],
    "INSECURE_DESERIALIZATION": [
        re.compile(r'\b(pickle|cPickle|dill|shelve|marshal)\.(loads|load)\s*\('),
        re.compile(r'\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)'),
        re.compile(r'\b(eval|exec)\s*\('),
    ],
    "HARDCODED_SECRET": [
        re.compile(r'(?i)\b(password|passwd|pwd|secret|api_key|apikey|token|auth_token|private_key|db_pass)\s*=\s*["\'][^"\']{4,}["\']'),
        re.compile(r'["\'](sk_live_|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|eyJ[a-zA-Z0-9_-]{10,})'),
    ]
}

def normalize_code_whitespace(code: str) -> str:
    """
    Normalise les espaces et retours à la ligne afin d'aligner le format du code
    multi-lignes utilisateur avec les fonctions aplaties du dataset Zenodo.
    """
    if not isinstance(code, str):
        return ""
    return " ".join(code.split())

def locate_dangerous_lines(code_snippet: str, predicted_label: str, start_line_offset: int = 1):
    """
    Identifie précisément les numéros de lignes et extraits dangereux dans un bloc de code
    pour la catégorie de vulnérabilité prédite par le modèle ML.
    """
    if predicted_label == "SAFE" or predicted_label not in LINE_PATTERNS:
        return []

    dangerous_lines = []
    lines = code_snippet.splitlines()
    patterns = LINE_PATTERNS[predicted_label]

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pat in patterns:
            if pat.search(line):
                dangerous_lines.append({
                    "line_number": start_line_offset + idx,
                    "code": line.rstrip(),
                    "matched_rule": pat.pattern
                })
                break

    if not dangerous_lines:
        try:
            tree = ast.parse(code_snippet)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and hasattr(node, "lineno"):
                    func_name = ""
                    if isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    elif isinstance(node.func, ast.Name):
                        func_name = node.func.id

                    if predicted_label == "SQL_INJECTION" and func_name in ("execute", "executemany"):
                        dangerous_lines.append({
                            "line_number": start_line_offset + node.lineno - 1,
                            "code": lines[node.lineno - 1].rstrip(),
                            "matched_rule": "AST: appel execute() dynamique"
                        })
                    elif predicted_label == "COMMAND_INJECTION" and func_name in ("system", "popen", "Popen", "run", "call"):
                        dangerous_lines.append({
                            "line_number": start_line_offset + node.lineno - 1,
                            "code": lines[node.lineno - 1].rstrip(),
                            "matched_rule": f"AST: appel système {func_name}()"
                        })
                    elif predicted_label == "INSECURE_DESERIALIZATION" and func_name in ("loads", "load", "eval", "exec"):
                        dangerous_lines.append({
                            "line_number": start_line_offset + node.lineno - 1,
                            "code": lines[node.lineno - 1].rstrip(),
                            "matched_rule": f"AST: appel {func_name}()"
                        })
        except SyntaxError:
            pass

    return dangerous_lines
