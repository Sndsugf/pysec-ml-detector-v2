"""
Constructeur de dataset multiclasse hybride et équilibré (Option 1) :
- Charge les données réelles issues de Zenodo (`data/raw/zenodo_python.csv`).
- Nettoie rigoureusement les données réelles :
    1. Suppression des fonctions de tests unitaires (`test_*` / fichiers `*test*`).
    2. Déduplication exacte sur le code source pour éviter toute fuite train/test.
    3. Normalisation des espaces (`normalize_code_whitespace`) pour harmoniser le format
       entre les fonctions Zenodo (aplaties sur une ligne) et les extraits Python standards.
- Extrait les vulnérabilités réelles correspondantes (CWE-89 -> SQL_INJECTION,
  CWE-78 -> COMMAND_INJECTION, CWE-502 -> INSECURE_DESERIALIZATION) ainsi que les
  correctifs réels (`patch`) pour la classe `SAFE`.
- Complète chaque classe jusqu'à `target_per_class` (par défaut 180 échantillons/classe = 900 au total)
  avec des variantes synthétiques réalistes pour garantir un équilibre parfait (20% par classe).
"""

import os
import random
import pandas as pd
from src.vulnerabilities_kb import normalize_code_whitespace

SEED = 42
ZENODO_RAW_PATH = "data/raw/zenodo_python.csv"
OUTPUT_DATASET_PATH = "data/python_vuln_hybrid_dataset.csv"

CWE_TO_LABEL = {
    "CWE-89": "SQL_INJECTION",
    "CWE-78": "COMMAND_INJECTION",
    "CWE-502": "INSECURE_DESERIALIZATION",
}

VAR_NAMES = ["user_id", "username", "email", "item_id", "query_param", "filename", "host", "payload", "raw_data", "account", "order_id", "target"]
TABLES = ["users", "accounts", "orders", "products", "sessions", "invoices", "logs", "employees"]
COLUMNS = ["id", "username", "email", "role", "status", "created_at", "balance", "department"]
FUNCS = ["fetch_record", "process_input", "handle_request", "get_user_data", "run_task", "load_config", "sync_account", "verify_client"]

def load_clean_zenodo_samples(zenodo_path: str = ZENODO_RAW_PATH, rng: random.Random = None) -> dict[str, list[str]]:
    """
    Extrait et nettoie les échantillons réels depuis le CSV Zenodo.
    """
    if rng is None:
        rng = random.Random(SEED)

    real_buckets = {
        "SAFE": [],
        "SQL_INJECTION": [],
        "COMMAND_INJECTION": [],
        "INSECURE_DESERIALIZATION": [],
        "HARDCODED_SECRET": [],
    }

    if not os.path.exists(zenodo_path):
        return real_buckets

    df = pd.read_csv(zenodo_path)
    # 1. Filtrer les fonctions de test
    is_test = (
        df["method_name"].astype(str).str.startswith("test_", na=False)
        | df["file_name"].astype(str).str.contains("test", case=False, na=False)
    )
    clean_df = df[~is_test].drop_duplicates(subset=["vul_code"]).copy()

    # 2. Extraire les vulnérabilités réelles mappées
    for cwe_id, target_label in CWE_TO_LABEL.items():
        subset = clean_df[clean_df["cwe_id"] == cwe_id]
        for code in subset["vul_code"].tolist():
            norm = normalize_code_whitespace(code)
            if len(norm) >= 20:
                real_buckets[target_label].append(norm)

    # 3. Extraire des correctifs réels (colonne `patch`) pour enrichir la classe SAFE
    # On privilégie les patches issus des mêmes CWE + un échantillon diversifié d'autres correctifs propres
    same_cwe_patches = clean_df[clean_df["cwe_id"].isin(CWE_TO_LABEL.keys())]["patch"].tolist()
    other_patches = clean_df[~clean_df["cwe_id"].isin(CWE_TO_LABEL.keys())]["patch"].tolist()
    rng.shuffle(other_patches)

    candidate_patches = same_cwe_patches + other_patches[:120]
    seen_safe = set()
    for p_code in candidate_patches:
        norm = normalize_code_whitespace(p_code)
        if len(norm) >= 20 and norm not in seen_safe:
            seen_safe.add(norm)
            real_buckets["SAFE"].append(norm)

    return real_buckets

def generate_synthetic_for_class(label: str, count: int, rng: random.Random) -> list[str]:
    if count <= 0:
        return []

    templates_map = {
        "SAFE": [
            lambda v, t, c, fn: f"def {fn}(cursor, {v}):\n    query = 'SELECT {c} FROM {t} WHERE {c} = %s'\n    cursor.execute(query, ({v},))\n    return cursor.fetchall()",
            lambda v, t, c, fn: f"def {fn}(conn, {v}):\n    cur = conn.cursor()\n    cur.execute('UPDATE {t} SET status = ? WHERE id = ?', ('active', {v}))\n    conn.commit()",
            lambda v, t, c, fn: f"import subprocess\ndef {fn}({v}):\n    res = subprocess.run(['ls', '-la', {v}], capture_output=True, text=True, check=True)\n    return res.stdout",
            lambda v, t, c, fn: f"import subprocess\ndef {fn}({v}):\n    return subprocess.call(['ping', '-c', '2', str({v})], shell=False)",
            lambda v, t, c, fn: f"import json\ndef {fn}({v}):\n    data = json.loads({v})\n    return data.get('{c}', None)",
            lambda v, t, c, fn: f"import yaml\ndef {fn}({v}):\n    return yaml.safe_load({v})",
            lambda v, t, c, fn: f"import ast\ndef {fn}({v}):\n    return ast.literal_eval({v})",
            lambda v, t, c, fn: f"import os\ndef {fn}():\n    api_key = os.environ.get('APP_API_KEY')\n    return bool(api_key)",
        ],
        "SQL_INJECTION": [
            lambda v, t, c, fn: f"def {fn}(cursor, {v}):\n    sql = f'SELECT * FROM {t} WHERE {c} = {{{v}}}'\n    cursor.execute(sql)\n    return cursor.fetchall()",
            lambda v, t, c, fn: f"def {fn}(conn, {v}):\n    cur = conn.cursor()\n    cur.execute('SELECT id, {c} FROM {t} WHERE {c} = \"' + str({v}) + '\"')\n    return cur.fetchone()",
            lambda v, t, c, fn: f"def {fn}(cursor, {v}):\n    query = 'DELETE FROM {t} WHERE {c} = %s' % {v}\n    cursor.execute(query)",
            lambda v, t, c, fn: f"def {fn}(db, {v}):\n    q = 'UPDATE {t} SET {c} = 1 WHERE id = {{}}'.format({v})\n    db.execute(q)",
            lambda v, t, c, fn: f"def {fn}(cursor, {v}):\n    cursor.execute(f'INSERT INTO {t} ({c}) VALUES ({{{v}}})')",
        ],
        "COMMAND_INJECTION": [
            lambda v, t, c, fn: f"import os\ndef {fn}({v}):\n    os.system('ping -c 1 ' + str({v}))",
            lambda v, t, c, fn: f"import os\ndef {fn}({v}):\n    cmd = f'cat /var/log/{{{v}}}.log'\n    return os.popen(cmd).read()",
            lambda v, t, c, fn: f"import subprocess\ndef {fn}({v}):\n    subprocess.run(f'rm -rf /tmp/{{{v}}}', shell=True)\n    return True",
            lambda v, t, c, fn: f"import subprocess\ndef {fn}({v}):\n    p = subprocess.Popen('grep ' + {v} + ' data.txt', shell=True, stdout=subprocess.PIPE)\n    return p.communicate()[0]",
            lambda v, t, c, fn: f"import subprocess\ndef {fn}({v}):\n    return subprocess.check_output('nslookup {{}}'.format({v}), shell=True)",
        ],
        "INSECURE_DESERIALIZATION": [
            lambda v, t, c, fn: f"import pickle\ndef {fn}({v}):\n    return pickle.loads({v})",
            lambda v, t, c, fn: f"import pickle\ndef {fn}(filepath):\n    with open(filepath, 'rb') as f:\n        return pickle.load(f)",
            lambda v, t, c, fn: f"import yaml\ndef {fn}({v}):\n    return yaml.load({v}, Loader=yaml.FullLoader)",
            lambda v, t, c, fn: f"import yaml\ndef {fn}({v}):\n    return yaml.load({v})",
            lambda v, t, c, fn: f"def {fn}({v}):\n    return eval({v})",
            lambda v, t, c, fn: f"import marshal\ndef {fn}({v}):\n    exec(marshal.loads({v}))",
        ],
        "HARDCODED_SECRET": [
            lambda v, t, c, fn: f"def {fn}():\n    api_key = 'sk_live_51N9x8K2eZvKYlo2C98aBcDeFgH'\n    return connect_service(api_key)",
            lambda v, t, c, fn: f"DB_PASSWORD = 'SuperSecretPass2026!'\ndef {fn}({v}):\n    return f'postgres://admin:{{DB_PASSWORD}}@localhost/db'",
            lambda v, t, c, fn: f"class Config:\n    SECRET_KEY = 'AKIAIOSFODNN7EXAMPLE99'\n    DEBUG = False",
            lambda v, t, c, fn: f"def {fn}({v}):\n    auth_token = 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456'\n    return {{'Authorization': f'Bearer {{auth_token}}'}}",
            lambda v, t, c, fn: f"def {fn}():\n    password = 'P@ssw0rd_Pr0duct10n_DB_99'\n    return authenticate('root', password)",
            lambda v, t, c, fn: f"PRIVATE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0'\ndef {fn}({v}):\n    return sign_payload({v}, PRIVATE_KEY)",
        ]
    }

    templates = templates_map[label]
    samples = []
    for i in range(count):
        tpl = templates[i % len(templates)]
        raw = tpl(rng.choice(VAR_NAMES), rng.choice(TABLES), rng.choice(COLUMNS), f"{rng.choice(FUNCS)}_{i}")
        samples.append(normalize_code_whitespace(raw))
    return samples

def build_hybrid_balanced_dataset(
    target_per_class: int = 180,
    zenodo_path: str = ZENODO_RAW_PATH,
    output_csv: str = OUTPUT_DATASET_PATH
) -> tuple[pd.DataFrame, dict]:
    """
    Construit le dataset hybride équilibré et retourne le DataFrame ainsi que les statistiques de provenance.
    """
    rng = random.Random(SEED)
    real_buckets = load_clean_zenodo_samples(zenodo_path=zenodo_path, rng=rng)

    rows = []
    provenance_stats = {}

    for label in ["SAFE", "SQL_INJECTION", "COMMAND_INJECTION", "INSECURE_DESERIALIZATION", "HARDCODED_SECRET"]:
        real_items = real_buckets[label]
        rng.shuffle(real_items)
        selected_real = real_items[:target_per_class]
        needed_synth = max(0, target_per_class - len(selected_real))
        synth_items = generate_synthetic_for_class(label, needed_synth, rng)

        for code in selected_real:
            rows.append({"code": code, "label": label, "source": "zenodo_real"})
        for code in synth_items:
            rows.append({"code": code, "label": label, "source": "synthetic_balanced"})

        provenance_stats[label] = {
            "zenodo_real": len(selected_real),
            "synthetic_balanced": len(synth_items),
            "total": len(selected_real) + len(synth_items)
        }

    df = pd.DataFrame(rows).sample(frac=1.0, random_state=SEED).reset_index(drop=True)
    os.makedirs(os.path.dirname(output_csv), exist_ok=True)
    df.to_csv(output_csv, index=False, encoding="utf-8")
    return df, provenance_stats

if __name__ == "__main__":
    df, stats = build_hybrid_balanced_dataset()
    print("Dataset hybride généré :", df.shape)
    print(pd.DataFrame(stats).T)
