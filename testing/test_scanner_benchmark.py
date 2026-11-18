"""
Benchmark du scanner sur le corpus annoté.

  - test_script[...]      : 1 test par script -> chaque échec = un défaut concret à corriger
  - test_global_metrics   : seuils minimaux globaux + génération du rapport Markdown/JSON
  - test_*_invariant      : propriétés qui doivent toujours être vraies (indépendantes du corpus)
  - test_no_crash_edge    : entrées dégénérées
"""
import os

import pytest

import evaluation as ev
from corpus import CASES

MIN_MACRO_F1 = float(os.getenv("MIN_MACRO_F1", "0.70"))
MIN_RECALL = float(os.getenv("MIN_RECALL", "0.60"))
MAX_SAFE_FP_RATE = float(os.getenv("MAX_SAFE_FP_RATE", "0.20"))


# ─────────────────────────── 1 test par script ────────────────────────────────
@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_script(case, model_results, bandit_results):
    res = model_results[case.id]
    problems = ev.describe_failure(res)
    if bandit_results is not None:
        b = bandit_results[case.id]
        problems.append("Bandit : " + ("OK" if b["ok"] else "échec aussi → " + "; ".join(ev.describe_failure(b))))
    # les échecs de localisation seuls sont signalés mais ne font pas échouer le test
    blocking = res["missed"] or res["misclassified"] or res["false_positives"] or res.get("error")
    assert not blocking, f"[{case.category}] {case.description}\n  " + "\n  ".join(problems)


# ─────────────────────────── métriques globales ───────────────────────────────
def test_global_metrics(scanner, model_results, bandit_results, threshold, report_dir):
    sweep = ev.threshold_sweep(
        CASES,
        lambda t: (lambda code: ev.model_findings(scanner, code, t)),
        [0.30, 0.40, 0.50, 0.55, 0.60, 0.70, 0.80, 0.90],
    )
    report = ev.render_report(model_results, bandit_results, sweep, threshold)
    agg = ev.aggregate(model_results)
    ev.write_report(
        report_dir / "benchmark_report.md", report,
        {"macro_f1": agg["macro_f1"], "micro": agg["micro"], "metrics": agg["metrics"],
         "passed": agg["n_ok"], "total": agg["n"], "sweep": sweep},
    )
    print(f"\nRapport écrit dans {report_dir / 'benchmark_report.md'}")

    weak = {c: round(agg["metrics"][c][1], 2) for c in ev.CLASSES if agg["metrics"][c][1] < MIN_RECALL}
    safe = [r for r in model_results.values() if r["case"].category == "safe_trap"]
    safe_fp_rate = sum(1 for r in safe if r["false_positives"]) / max(len(safe), 1)

    assert agg["macro_f1"] >= MIN_MACRO_F1, f"F1 macro {agg['macro_f1']:.2f} < {MIN_MACRO_F1}"
    assert not weak, f"Rappel sous {MIN_RECALL} pour : {weak}"
    assert safe_fp_rate <= MAX_SAFE_FP_RATE, f"{safe_fp_rate:.0%} des scripts SAFE génèrent un faux positif"


# ─────────────────────────── invariants ───────────────────────────────────────
@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_output_invariant(case, scanner, threshold):
    code, _ = ev.parse_case(case)
    n_lines = len(code.splitlines())
    result = scanner.scan_code(code, confidence_threshold=threshold)
    for f in result["findings"]:
        assert 1 <= f["start_line"] <= f["end_line"] <= n_lines, f"bornes de bloc invalides : {f['start_line']}-{f['end_line']}"
        assert f["vulnerability_type"] in ev.CLASSES, f"label inattendu {f['vulnerability_type']}"
        assert f["confidence"] >= threshold * 100 - 0.01, "finding renvoyé sous le seuil"
        assert abs(sum(f["probabilities"].values()) - 100) < 0.5, "probabilités ≠ 100 %"
        assert abs(f["confidence"] - max(f["probabilities"].values())) < 0.01, "confidence ≠ proba max"
        for d in f["dangerous_lines"]:
            assert f["start_line"] <= d["line_number"] <= f["end_line"], (
                f"ligne dangereuse {d['line_number']} hors du bloc {f['start_line']}-{f['end_line']}"
            )


@pytest.mark.parametrize("case", [c for c in CASES if c.category != "safe_trap"], ids=lambda c: c.id)
def test_threshold_monotonic_invariant(case, scanner):
    """Monter le seuil ne doit jamais créer de nouveaux findings."""
    code, _ = ev.parse_case(case)
    counts = [len(scanner.scan_code(code, confidence_threshold=t)["findings"]) for t in (0.0, 0.3, 0.55, 0.8, 0.99)]
    assert counts == sorted(counts, reverse=True), f"non monotone : {counts}"


def test_determinism_invariant(scanner, threshold):
    case = next(c for c in CASES if c.id == "mixed_flask_app")
    code, _ = ev.parse_case(case)
    a = scanner.scan_code(code, confidence_threshold=threshold)
    b = scanner.scan_code(code, confidence_threshold=threshold)
    assert a["findings"] == b["findings"]


# ─────────────────────────── entrées dégénérées ───────────────────────────────
EDGE_INPUTS = {
    "empty": "",
    "newline_only": "\n\n\n",
    "comment_only": "# nothing to see here\n",
    "syntax_error": "def f(:\n    os.system('ls ' + x\n",
    "python2_print": "print 'hello'\nos.system 'ls'\n",
    "unicode": "mot_de_passe = 'é€漢字'\nprint('héllo')\n",
    "crlf": "import os\r\ndef f(h):\r\n    os.system('ping ' + h)\r\n",
    "tabs": "import os\n\ndef f(h):\n\tos.system('ping ' + h)\n",
    "very_long_line": "x = [" + ", ".join(str(i) for i in range(20000)) + "]\n",
    "many_functions": "\n".join(f"def f{i}(a):\n    return a + {i}\n" for i in range(500)),
    "deep_nesting": "".join("    " * i + f"if x{i}:\n" for i in range(40)) + "    " * 40 + "pass\n",
}


@pytest.mark.parametrize("name", EDGE_INPUTS)
def test_no_crash_edge(name, scanner, threshold):
    result = scanner.scan_code(EDGE_INPUTS[name], confidence_threshold=threshold)
    assert isinstance(result, dict) and "findings" in result


def test_crlf_and_tabs_still_detected(scanner, threshold):
    for key in ("crlf", "tabs"):
        labels = {f.label for f in ev.model_findings(scanner, EDGE_INPUTS[key], threshold)}
        assert labels == {"COMMAND_INJECTION"}, f"{key}: {labels}"
