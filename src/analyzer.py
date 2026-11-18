"""
Moteur d'analyse de sécurité Python :
- Découpe automatiquement un fichier Python complet en blocs logiques via AST.
- Normalise les espaces pour l'inférence ML (cohérence avec les fonctions réelles Zenodo),
  tout en conservant le code original numéroté pour pointer les lignes exactes dangereuses.
"""

import ast
import os
import joblib
import numpy as np
from src.vulnerabilities_kb import VULN_KNOWLEDGE_BASE, locate_dangerous_lines, normalize_code_whitespace
from src.train_model import MODEL_PATH, train_and_evaluate

class PythonVulnerabilityScanner:
    def __init__(self, model_path: str = MODEL_PATH):
        if not os.path.exists(model_path):
            train_and_evaluate()
        self.model = joblib.load(model_path)
        self.classes = list(self.model.classes_)

    def extract_code_blocks(self, source_code: str) -> list[dict]:
        lines = source_code.splitlines()
        if not lines:
            return []

        blocks = []
        covered_lines = set()
        import_lines = set()

        try:
            tree = ast.parse(source_code)
            for node in tree.body:
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    start = node.lineno
                    end = getattr(node, "end_lineno", start)
                    import_lines.update(range(start, end + 1))
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start = node.lineno
                    end = getattr(node, "end_lineno", start)
                    snippet = "\n".join(lines[start - 1:end])
                    blocks.append({
                        "scope": f"Fonction `{node.name}()`",
                        "start_line": start,
                        "end_line": end,
                        "code": snippet
                    })
                    covered_lines.update(range(start, end + 1))
                elif isinstance(node, ast.ClassDef):
                    for subnode in node.body:
                        if isinstance(subnode, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            start = subnode.lineno
                            end = getattr(subnode, "end_lineno", start)
                            snippet = "\n".join(lines[start - 1:end])
                            blocks.append({
                                "scope": f"Méthode `{node.name}.{subnode.name}()`",
                                "start_line": start,
                                "end_line": end,
                                "code": snippet
                            })
                            covered_lines.update(range(start, end + 1))
        except SyntaxError:
            return [{
                "scope": "Extrait de code",
                "start_line": 1,
                "end_line": len(lines),
                "code": source_code
            }]

        module_lines = []
        module_line_nums = []
        for idx, line in enumerate(lines, start=1):
            if idx not in covered_lines and idx not in import_lines and line.strip() and not line.strip().startswith("#"):
                module_lines.append(line)
                module_line_nums.append(idx)

        if module_lines:
            blocks.insert(0, {
                "scope": "Portée globale (Module)",
                "start_line": module_line_nums[0],
                "end_line": module_line_nums[-1],
                "code": "\n".join(module_lines),
                "exact_line_map": module_line_nums
            })

        return blocks if blocks else [{
            "scope": "Fichier complet",
            "start_line": 1,
            "end_line": len(lines),
            "code": source_code
        }]

    def scan_code(self, source_code: str, confidence_threshold: float = 0.55) -> dict:
        blocks = self.extract_code_blocks(source_code)
        findings = []
        summary_counts = {label: 0 for label in self.classes}

        for block in blocks:
            normalized_input = normalize_code_whitespace(block["code"])
            proba = self.model.predict_proba([normalized_input])[0]
            best_idx = int(np.argmax(proba))
            pred_label = self.classes[best_idx]
            confidence = float(proba[best_idx])

            if pred_label != "SAFE" and confidence < confidence_threshold:
                pred_label = "SAFE"

            summary_counts[pred_label] = summary_counts.get(pred_label, 0) + 1

            if pred_label != "SAFE":
                kb_info = VULN_KNOWLEDGE_BASE[pred_label]
                dangerous_lines = locate_dangerous_lines(
                    block["code"],
                    pred_label,
                    start_line_offset=block["start_line"]
                )
                if "exact_line_map" in block and dangerous_lines:
                    line_map = block["exact_line_map"]
                    for dl in dangerous_lines:
                        rel_idx = dl["line_number"] - block["start_line"]
                        if 0 <= rel_idx < len(line_map):
                            dl["line_number"] = line_map[rel_idx]

                findings.append({
                    "scope": block["scope"],
                    "start_line": block["start_line"],
                    "end_line": block["end_line"],
                    "vulnerability_type": pred_label,
                    "cwe": kb_info["cwe"],
                    "severity": kb_info["severity"],
                    "title": kb_info["title"],
                    "confidence": round(confidence * 100, 2),
                    "probabilities": {
                        cls: round(float(p) * 100, 2) for cls, p in zip(self.classes, proba)
                    },
                    "dangerous_lines": dangerous_lines,
                    "description": kb_info["description"],
                    "remediation": kb_info["remediation"],
                    "secure_example": kb_info["secure_example"],
                    "code_snippet": block["code"]
                })

        return {
            "total_blocks_analyzed": len(blocks),
            "vulnerabilities_found": len(findings),
            "is_clean": len(findings) == 0,
            "summary_counts": summary_counts,
            "findings": findings
        }
