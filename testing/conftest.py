import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, Path(__file__).resolve().parent):
    sys.path.insert(0, str(p))

import evaluation as ev  # noqa: E402
from corpus import CASES  # noqa: E402

THRESHOLD = float(os.getenv("CONF_THRESHOLD", "0.55"))
REPORT_DIR = Path(__file__).resolve().parent / "reports"


@pytest.fixture(scope="session")
def threshold():
    return THRESHOLD


@pytest.fixture(scope="session")
def scanner():
    """Instancie le scanner. ADAPTER ICI si le constructeur prend des arguments."""
    from src.analyzer import PythonVulnerabilityScanner

    model_path = os.getenv("VULN_MODEL_PATH")
    return PythonVulnerabilityScanner(model_path) if model_path else PythonVulnerabilityScanner()


@pytest.fixture(scope="session")
def model_results(scanner):
    return ev.run_benchmark(CASES, lambda code: ev.model_findings(scanner, code, THRESHOLD))


@pytest.fixture(scope="session")
def bandit_results():
    if not ev.bandit_available():
        return None
    return ev.run_benchmark(CASES, ev.bandit_findings)


@pytest.fixture(scope="session")
def report_dir():
    return REPORT_DIR
