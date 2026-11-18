"""
Tests de robustesse (métamorphiques).

Principe : on transforme un script SANS changer sa sémantique de sécurité.
Le verdict (ensemble des labels détectés) doit rester identique à la vérité terrain.
Un échec montre que le modèle s'appuie sur des détails superficiels
(nom de variable, indentation, longueur du bloc...) plutôt que sur la vulnérabilité.
"""
import ast
import re

import pytest

import evaluation as ev
from corpus import CASES

SECRET_RE = re.compile(r"pass|secret|token|key|auth|cred", re.I)


# ─────────────────────────── transformations ──────────────────────────────────
def reformat(src: str) -> str:
    """Réécriture canonique via l'AST (guillemets, parenthèses, espaces)."""
    return ast.unparse(ast.parse(src)) + "\n"


def rename_identifiers(src: str) -> str:
    """Renomme variables locales et arguments (sauf noms évoquant un secret)."""
    tree = ast.parse(src)
    local = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    local |= {a.arg for a in ast.walk(tree) if isinstance(a, ast.arg)}
    local -= {"self", "cls"}
    mapping = {n: f"var_{i}" for i, n in enumerate(sorted(x for x in local if not SECRET_RE.search(x)))}

    class R(ast.NodeTransformer):
        def visit_Name(self, node):
            node.id = mapping.get(node.id, node.id)
            return node

        def visit_arg(self, node):
            node.arg = mapping.get(node.arg, node.arg)
            return node

    return ast.unparse(R().visit(tree)) + "\n"


def reindent_2_spaces(src: str) -> str:
    def repl(m):
        return "  " * (len(m.group(1)) // 4)

    return re.sub(r"(?m)^((?:    )+)", repl, src)


def comment_before_def(src: str) -> str:
    return re.sub(r"(?m)^(\s*)((?:async )?def )", r"\1# helper function\n\1\2", src)


def noise_functions(src: str) -> str:
    pre = "\n".join(f"def _noise_a{i}(x):\n    return x * {i} + 1\n" for i in range(15))
    post = "\n".join(f"def _noise_b{i}(items):\n    return [i for i in items if i > {i}]\n" for i in range(15))
    return pre + "\n" + src + "\n" + post


def crlf(src: str) -> str:
    return src.replace("\n", "\r\n")


MUTATIONS = {
    "reformat_ast": reformat,
    "rename_identifiers": rename_identifiers,
    "reindent_2_spaces": reindent_2_spaces,
    "comment_before_def": comment_before_def,
    "noise_functions": noise_functions,
    "crlf": crlf,
}


def _expected_labels(case):
    _, expected = ev.parse_case(case)
    return {lab for lab, _ in expected}


@pytest.mark.parametrize("mutation", MUTATIONS)
@pytest.mark.parametrize("case", CASES, ids=[c.id for c in CASES])
def test_verdict_stable_under_mutation(case, mutation, scanner, threshold):
    code, _ = ev.parse_case(case)
    expected = _expected_labels(case)

    # on ne teste que les scripts que le modèle gère déjà à l'état brut :
    # on isole ainsi l'effet de la mutation (et pas un défaut préexistant)
    base = {f.label for f in ev.model_findings(scanner, code, threshold)}
    if base != expected:
        pytest.skip(f"échec déjà présent sans mutation (prédit {sorted(base)}, attendu {sorted(expected)})")

    try:
        mutated = MUTATIONS[mutation](code)
    except SyntaxError:
        pytest.skip("script non parsable par ast")

    got = {f.label for f in ev.model_findings(scanner, mutated, threshold)}
    assert got == expected, (
        f"Mutation '{mutation}' change le verdict : attendu {sorted(expected)}, obtenu {sorted(got)}\n"
        f"--- code muté ---\n{mutated}"
    )


# ─────────────────────────── dilution ─────────────────────────────────────────
VULN_LINES = {
    "SQL_INJECTION": "    cur.execute(\"SELECT * FROM t WHERE n = '\" + user + \"'\")",
    "COMMAND_INJECTION": '    os.system("ping " + user)',
    "INSECURE_DESERIALIZATION": "    obj = pickle.loads(user)",
    "HARDCODED_SECRET": '    password = "Sup3rS3cret!2024"',
}


def _diluted(label: str, n_noise: int) -> str:
    noise = [f"    total_{i} = sum(x * {i} for x in items if x > {i})" for i in range(n_noise)]
    half = n_noise // 2
    body = noise[:half] + [VULN_LINES[label]] + noise[half:]
    return "import os\nimport pickle\n\n\ndef handler(items, user, cur):\n" + "\n".join(body) + "\n    return items\n"


@pytest.mark.parametrize("n_noise", [0, 10, 40, 150])
@pytest.mark.parametrize("label", list(VULN_LINES))
def test_vulnerability_diluted_in_large_function(label, n_noise, scanner, threshold):
    """Une ligne vulnérable noyée dans une grosse fonction doit rester détectée."""
    code = _diluted(label, n_noise)
    findings = ev.model_findings(scanner, code, threshold)
    got = {f.label for f in findings}
    assert label in got, (
        f"{label} non détecté avec {n_noise} lignes de bruit "
        f"(labels prédits : {sorted(got) or 'aucun'}) → le classifieur travaille au niveau bloc entier "
        f"et la ligne vulnérable est diluée."
    )
    assert got <= {label}, f"faux labels en plus : {sorted(got - {label})}"


@pytest.mark.parametrize("n_noise", [10, 150])
def test_safe_large_function_stays_safe(n_noise, scanner, threshold):
    noise = [f"    total_{i} = sum(x * {i} for x in items if x > {i})" for i in range(n_noise)]
    code = "def handler(items):\n" + "\n".join(noise) + "\n    return items\n"
    got = [f.label for f in ev.model_findings(scanner, code, threshold)]
    assert got == [], f"faux positifs sur code arithmétique sain : {got}"


# ─────────────────────────── localisation ─────────────────────────────────────
@pytest.mark.parametrize("label", list(VULN_LINES))
def test_dangerous_line_points_to_right_line_in_large_function(label, scanner, threshold):
    """Quand la vulnérabilité est détectée, la ligne dangereuse doit être la bonne."""
    n = 40
    code = _diluted(label, n)
    target = next(i for i, l in enumerate(code.splitlines(), 1) if l == VULN_LINES[label])
    findings = [f for f in ev.model_findings(scanner, code, threshold) if f.label == label]
    if not findings:
        pytest.skip("non détecté (couvert par test_vulnerability_diluted_in_large_function)")
    lines = [l for f in findings for l in f.lines]
    assert any(abs(l - target) <= ev.LINE_TOLERANCE for l in lines), (
        f"ligne vulnérable = {target}, lignes dangereuses renvoyées = {lines}"
    )
    assert len(lines) <= 3, f"{len(lines)} lignes dangereuses renvoyées pour 1 vraie ligne : {lines}"
