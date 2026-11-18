"""
Moteur d'évaluation : adaptateurs (modèle / Bandit), métriques, rapport Markdown.

Modèle de matching
------------------
Vérité terrain : liste de (label, ligne).
Prédiction     : liste de Finding(label, start, end, lines).

  - détecté        : un finding de MÊME label couvre la ligne attendue
  - mal classé     : un finding d'un AUTRE label la couvre
  - manqué         : aucun finding ne la couvre
  - faux positif   : finding dont aucune ligne attendue de même label n'est couverte
  - localisé       : une "dangerous_line" du finding est à ± LINE_TOLERANCE de la ligne attendue
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

CLASSES = ["HARDCODED_SECRET", "INSECURE_DESERIALIZATION", "COMMAND_INJECTION", "SQL_INJECTION"]
LINE_TOLERANCE = int(os.getenv("LINE_TOLERANCE", "1"))
MARKER_RE = re.compile(r"\s*#\s*VULN:([A-Z_]+)\s*$")


# ───────────────────────────── structures ─────────────────────────────────────
@dataclass(frozen=True)
class Case:
    id: str
    category: str
    source: str
    description: str = ""


@dataclass
class Finding:
    label: str
    start: int
    end: int
    lines: list = field(default_factory=list)
    confidence: Optional[float] = None
    scope: str = ""
    probabilities: dict = field(default_factory=dict)
    fuzzy: bool = False  # True pour Bandit (finding ponctuel -> tolérance de lignes)


def parse_case(case: Case):
    """Retourne (code_sans_marqueurs, [(label, ligne), ...])."""
    clean, expected = [], []
    for i, line in enumerate(case.source.splitlines(), 1):
        m = MARKER_RE.search(line)
        if m:
            expected.append((m.group(1), i))
            line = line[: m.start()]
        clean.append(line)
    return "\n".join(clean) + "\n", expected


# ───────────────────────────── adaptateurs ────────────────────────────────────
def model_findings(scanner, code: str, threshold: float) -> list:
    result = scanner.scan_code(code, confidence_threshold=threshold)
    out = []
    for f in result.get("findings", []):
        out.append(
            Finding(
                label=f["vulnerability_type"],
                start=f["start_line"],
                end=f["end_line"],
                lines=[d["line_number"] for d in f.get("dangerous_lines", [])],
                confidence=f.get("confidence"),
                scope=f.get("scope", ""),
                probabilities=f.get("probabilities", {}),
            )
        )
    return out


BANDIT_MAP = {
    "B105": "HARDCODED_SECRET", "B106": "HARDCODED_SECRET", "B107": "HARDCODED_SECRET",
    "B301": "INSECURE_DESERIALIZATION", "B302": "INSECURE_DESERIALIZATION",
    "B506": "INSECURE_DESERIALIZATION",
    "B602": "COMMAND_INJECTION", "B604": "COMMAND_INJECTION",
    "B605": "COMMAND_INJECTION", "B609": "COMMAND_INJECTION",
    "B608": "SQL_INJECTION",
}


def bandit_available() -> bool:
    return importlib.util.find_spec("bandit") is not None


def bandit_findings(code: str) -> list:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "sample.py"
        p.write_text(code, encoding="utf-8")
        proc = subprocess.run(
            [sys.executable, "-m", "bandit", "-f", "json", "-q", str(p)],
            capture_output=True, text=True,
        )
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    out = []
    for r in data.get("results", []):
        label = BANDIT_MAP.get(r["test_id"])
        if not label:
            continue
        rng = r.get("line_range") or [r["line_number"]]
        out.append(Finding(label=label, start=min(rng), end=max(rng), lines=[r["line_number"]],
                           scope=r["test_id"], fuzzy=True))
    return out


# ───────────────────────────── évaluation ─────────────────────────────────────
def _covers(f: Finding, line: int, tol: int) -> bool:
    t = tol if f.fuzzy else 0
    return f.start - t <= line <= f.end + t


def evaluate_case(expected, findings, tol: int = LINE_TOLERANCE) -> dict:
    res = dict(detected=[], missed=[], misclassified=[], localized=[], unlocalized=[],
               false_positives=[], spurious=[], tp_findings=[], noisy_lines=0, total_lines=0)
    exp_by_label = defaultdict(list)
    for label, line in expected:
        exp_by_label[label].append(line)

    for label, line in expected:
        cover = [f for f in findings if _covers(f, line, tol)]
        same = [f for f in cover if f.label == label]
        if same:
            res["detected"].append((label, line))
            if any(f.fuzzy or any(abs(l - line) <= tol for l in f.lines) for f in same):
                res["localized"].append((label, line))
            else:
                res["unlocalized"].append((label, line))
        elif cover:
            res["misclassified"].append(((label, line), sorted({f.label for f in cover})))
        else:
            res["missed"].append((label, line))

    for f in findings:
        expected_lines = exp_by_label.get(f.label, [])
        if any(_covers(f, l, tol) for l in expected_lines):
            res["tp_findings"].append(f)
        else:
            res["false_positives"].append(f)
            all_lines = [l for ls in exp_by_label.values() for l in ls]
            if not any(_covers(f, l, tol) for l in all_lines):
                res["spurious"].append(f)
        for l in f.lines:
            res["total_lines"] += 1
            if not any(abs(l - e) <= tol for e in expected_lines):
                res["noisy_lines"] += 1

    res["ok"] = not (res["missed"] or res["misclassified"] or res["false_positives"])
    return res


def run_benchmark(cases, finder: Callable[[str], list]) -> dict:
    out = {}
    for case in cases:
        code, expected = parse_case(case)
        try:
            findings, err = finder(code), None
        except Exception as e:  # le scanner ne doit jamais planter
            findings, err = [], repr(e)
        r = evaluate_case(expected, findings)
        r.update(case=case, expected=expected, findings=findings, error=err)
        if err:
            r["ok"] = False
        out[case.id] = r
    return out


# ───────────────────────────── agrégation ─────────────────────────────────────
def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def aggregate(results: dict) -> dict:
    per = defaultdict(Counter)
    confusion = defaultdict(Counter)
    cats = defaultdict(lambda: [0, 0])
    conf_tp, conf_fp = [], []
    loc = Counter()

    for r in results.values():
        cats[r["case"].category][1] += 1
        cats[r["case"].category][0] += int(r["ok"])
        for lab, _ in r["detected"]:
            per[lab]["tp"] += 1
            confusion[lab][lab] += 1
        for (lab, _), pred in r["misclassified"]:
            per[lab]["fn"] += 1
            confusion[lab][pred[0]] += 1
        for lab, _ in r["missed"]:
            per[lab]["fn"] += 1
            confusion[lab]["NONE"] += 1
        for f in r["false_positives"]:
            per[f.label]["fp"] += 1
        for f in r["spurious"]:
            confusion["SAFE"][f.label] += 1
        conf_tp += [f.confidence for f in r["tp_findings"] if f.confidence is not None]
        conf_fp += [f.confidence for f in r["false_positives"] if f.confidence is not None]
        loc["detected"] += len(r["detected"])
        loc["localized"] += len(r["localized"])
        loc["lines"] += r["total_lines"]
        loc["noisy"] += r["noisy_lines"]

    metrics = {c: prf(per[c]["tp"], per[c]["fp"], per[c]["fn"]) for c in CLASSES}
    tp = sum(per[c]["tp"] for c in CLASSES)
    fp = sum(per[c]["fp"] for c in CLASSES)
    fn = sum(per[c]["fn"] for c in CLASSES)
    return dict(
        per=per, metrics=metrics, confusion=confusion, cats=dict(cats),
        micro=prf(tp, fp, fn), macro_f1=sum(m[2] for m in metrics.values()) / len(CLASSES),
        conf_tp=conf_tp, conf_fp=conf_fp, loc=loc,
        n_ok=sum(int(r["ok"]) for r in results.values()), n=len(results),
        n_findings=sum(len(r["findings"]) for r in results.values()),
    )


def threshold_sweep(cases, make_finder: Callable[[float], Callable], thresholds):
    rows = []
    for t in thresholds:
        agg = aggregate(run_benchmark(cases, make_finder(t)))
        p, r, f = agg["micro"]
        rows.append(dict(threshold=t, precision=p, recall=r, f1=f,
                         findings=agg["n_findings"], passed=agg["n_ok"], total=agg["n"]))
    return rows


def describe_failure(res: dict) -> list:
    parts = []
    if res.get("error"):
        parts.append(f"CRASH: {res['error']}")
    for lab, line in res["missed"]:
        parts.append(f"FN  {lab} ligne {line} : rien détecté")
    for (lab, line), pred in res["misclassified"]:
        parts.append(f"MAUVAISE CLASSE  {lab} ligne {line} -> prédit {', '.join(pred)}")
    for f in res["false_positives"]:
        conf = f" conf={f.confidence}%" if f.confidence is not None else ""
        parts.append(f"FP  {f.label} bloc {f.start}-{f.end} [{f.scope}]{conf}")
    for lab, line in res["unlocalized"]:
        parts.append(f"LOCALISATION  {lab} ligne {line} : bloc OK mais mauvaise ligne dangereuse")
    return parts


# ───────────────────────────── rapport ────────────────────────────────────────
def _table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def _mean(xs):
    return f"{sum(xs) / len(xs):.1f}" if xs else "n/a"


def render_report(model_res: dict, bandit_res: Optional[dict], sweep: list, threshold: float) -> str:
    m = aggregate(model_res)
    b = aggregate(bandit_res) if bandit_res else None
    L = ["# Rapport d'évaluation – PythonVulnerabilityScanner", ""]

    L += ["## 1. Résumé", "",
          f"- Scripts évalués : **{m['n']}** (seuil de confiance = {threshold})",
          f"- Scripts entièrement corrects : **{m['n_ok']}/{m['n']}** ({100 * m['n_ok'] / m['n']:.0f} %)"
          + (f" – Bandit : {b['n_ok']}/{b['n']} ({100 * b['n_ok'] / b['n']:.0f} %)" if b else ""),
          f"- F1 micro : **{m['micro'][2]:.2f}** · F1 macro : **{m['macro_f1']:.2f}**"
          + (f" – Bandit : micro {b['micro'][2]:.2f} / macro {b['macro_f1']:.2f}" if b else ""), ""]

    L += ["## 2. Précision / rappel / F1 par classe", ""]
    rows = []
    for c in CLASSES:
        p, r, f = m["metrics"][c]
        row = [c, f"{p:.2f}", f"{r:.2f}", f"{f:.2f}", m["per"][c]["tp"], m["per"][c]["fp"], m["per"][c]["fn"]]
        if b:
            bp, br, bf = b["metrics"][c]
            row += [f"{bp:.2f}", f"{br:.2f}", f"{bf:.2f}"]
        rows.append(row)
    hdr = ["Classe", "P", "R", "F1", "TP", "FP", "FN"] + (["Bandit P", "Bandit R", "Bandit F1"] if b else [])
    L += [_table(hdr, rows), ""]

    L += ["## 3. Taux de réussite par catégorie de scripts", ""]
    rows = []
    for cat in ["classic", "variant", "evasion", "mixed", "safe_trap", "bandit_blind", "bandit_noise"]:
        if cat in m["cats"]:
            ok, n = m["cats"][cat]
            row = [cat, f"{ok}/{n}", f"{100 * ok / n:.0f} %"]
            if b:
                bok, bn = b["cats"][cat]
                row.append(f"{bok}/{bn} ({100 * bok / bn:.0f} %)")
            rows.append(row)
    L += [_table(["Catégorie", "Modèle", "%"] + (["Bandit"] if b else []), rows), ""]

    L += ["## 4. Matrice de confusion (lignes = attendu, colonnes = prédit)", ""]
    cols = CLASSES + ["NONE"]
    rows = [[exp] + [m["confusion"][exp][c] for c in cols] for exp in CLASSES + ["SAFE"]]
    L += [_table(["attendu \\ prédit"] + cols, rows),
          "", "_NONE = rien détecté (faux négatif) ; ligne SAFE = faux positifs sur du code sain._", ""]

    loc = m["loc"]
    L += ["## 5. Localisation des lignes dangereuses", "",
          f"- Vulnérabilités détectées avec la bonne ligne : **{loc['localized']}/{loc['detected']}**",
          f"- Lignes dangereuses « parasites » : **{loc['noisy']}/{loc['lines']}** "
          f"({100 * loc['noisy'] / loc['lines']:.0f} %)" if loc["lines"] else "- Aucune ligne dangereuse renvoyée", ""]

    L += ["## 6. Calibration de la confiance", "",
          f"- Confiance moyenne des vrais positifs : **{_mean(m['conf_tp'])} %**",
          f"- Confiance moyenne des faux positifs : **{_mean(m['conf_fp'])} %**",
          "_Si les deux sont proches, la confiance ne permet pas de filtrer les erreurs._", ""]

    L += ["## 7. Sensibilité au seuil de confiance", "",
          _table(["Seuil", "Précision", "Rappel", "F1", "Findings", "Scripts OK"],
                 [[s["threshold"], f"{s['precision']:.2f}", f"{s['recall']:.2f}", f"{s['f1']:.2f}",
                   s["findings"], f"{s['passed']}/{s['total']}"] for s in sweep]), ""]

    L += ["## 8. Échecs détaillés du modèle", ""]
    fails = [r for r in model_res.values() if not r["ok"] or r["unlocalized"]]
    if not fails:
        L.append("Aucun échec 🎉")
    for r in fails:
        c = r["case"]
        bstat = ""
        if bandit_res:
            bstat = " · Bandit : " + ("✅" if bandit_res[c.id]["ok"] else "❌")
        L.append(f"### `{c.id}` ({c.category}){bstat}")
        L.append(f"_{c.description}_")
        L += [f"- {p}" for p in describe_failure(r)]
        L.append("")

    if bandit_res:
        only_bandit = [i for i in model_res if bandit_res[i]["ok"] and not model_res[i]["ok"]]
        only_model = [i for i in model_res if model_res[i]["ok"] and not bandit_res[i]["ok"]]
        L += ["## 9. Comparaison avec Bandit", "",
              f"- Réussis par Bandit mais **pas** par le modèle ({len(only_bandit)}) : "
              + (", ".join(f"`{i}`" for i in only_bandit) or "—"),
              f"- Réussis par le modèle mais **pas** par Bandit ({len(only_model)}) : "
              + (", ".join(f"`{i}`" for i in only_model) or "—"), ""]
    if bandit_res:
        c = complementarity(model_res, bandit_res)
        L += ["## 10. Complémentarité modèle + Bandit", "",
              _table(["Métrique", "Valeur"], [
                  ["Vulnérabilités attendues (total)", c["total"]],
                  ["Trouvées par Bandit seul", f"{c['bandit']} ({100 * c['bandit'] / max(c['total'], 1):.0f} %)"],
                  ["Trouvées par le modèle seul", f"{c['model']} ({100 * c['model'] / max(c['total'], 1):.0f} %)"],
                  ["Trouvées par l'union", f"{c['union']} ({100 * c['union'] / max(c['total'], 1):.0f} %)"],
                  ["**Prises uniques du modèle** (Bandit les rate)", c["unique_model"]],
                  ["Prises uniques de Bandit (le modèle les rate)", c["unique_bandit"]],
                  ["Faux positifs – modèle", c["fp_model"]],
                  ["Faux positifs – Bandit", c["fp_bandit"]],
                  ["Faux positifs ajoutés par le modèle (là où Bandit est muet)", c["fp_added_by_model"]],
              ]), "",
              "_Le modèle est un bon complément s'il a beaucoup de prises uniques ET peu de faux positifs ajoutés._", ""]
        if c["unique_model_ids"]:
            L += ["Prises uniques du modèle : " + ", ".join(f"`{i}`" for i in c["unique_model_ids"]), ""]
    return "\n".join(L)


def complementarity(model_res: dict, bandit_res: dict) -> dict:
    out = Counter()
    unique_ids = []
    for cid, r in model_res.items():
        br = bandit_res[cid]
        exp = set(r["expected"])
        md, bd = set(r["detected"]), set(br["detected"])
        out["total"] += len(exp)
        out["model"] += len(md)
        out["bandit"] += len(bd)
        out["union"] += len(md | bd)
        um = md - bd
        out["unique_model"] += len(um)
        out["unique_bandit"] += len(bd - md)
        if um:
            unique_ids.append(cid)
        out["fp_model"] += len(r["false_positives"])
        out["fp_bandit"] += len(br["false_positives"])
        if not br["findings"]:  # Bandit muet sur ce script : tout FP du modèle est du bruit ajouté
            out["fp_added_by_model"] += len(r["false_positives"])
    out = dict(out)
    for k in ("total", "model", "bandit", "union", "unique_model", "unique_bandit",
              "fp_model", "fp_bandit", "fp_added_by_model"):
        out.setdefault(k, 0)
    out["unique_model_ids"] = unique_ids
    return out


def write_report(path: Path, text: str, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.with_suffix(".json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
