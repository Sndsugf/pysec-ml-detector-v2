"""
Corpus de scripts Python annotés pour évaluer PythonVulnerabilityScanner.

Vérité terrain : chaque ligne vulnérable porte un marqueur de fin de ligne
    # VULN:<LABEL>
Les marqueurs sont retirés avant le scan (le modèle ne les voit jamais) et
transformés en couples (label, numéro_de_ligne).
Un script sans marqueur est attendu 100 % SAFE.

Catégories :
  classic    : cas d'école, le modèle DOIT les trouver
  variant    : même vulnérabilité, API / syntaxe différente
  evasion    : obfuscation, alias, construction indirecte (cas difficiles)
  safe_trap  : code SAFE qui ressemble à du code vulnérable (faux positifs)
  mixed      : scripts réalistes mêlant plusieurs fonctions / vulnérabilités
"""
from __future__ import annotations

import textwrap

from evaluation import Case

CASES: list[Case] = []


def _add(id: str, category: str, description: str, source: str) -> None:
    CASES.append(Case(id, category, textwrap.dedent(source).strip("\n") + "\n", description))


# ═════════════════════════════════════════════════════════════════════════════
# SQL INJECTION
# ═════════════════════════════════════════════════════════════════════════════
_add("sqli_concat", "classic", "Concaténation +", r'''
import sqlite3

def get_user(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '" + name + "'")  # VULN:SQL_INJECTION
    return cur.fetchone()
''')

_add("sqli_fstring", "classic", "f-string", r'''
def find_order(cursor, order_id):
    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")  # VULN:SQL_INJECTION
    return cursor.fetchall()
''')

_add("sqli_percent", "classic", "Formatage %", r'''
def delete_user(cursor, username):
    cursor.execute("DELETE FROM users WHERE username = '%s'" % username)  # VULN:SQL_INJECTION
''')

_add("sqli_format", "classic", "str.format", r'''
def search(cursor, term):
    query = "SELECT * FROM products WHERE title LIKE '%{}%'".format(term)  # VULN:SQL_INJECTION
    cursor.execute(query)
    return cursor.fetchall()
''')

_add("sqli_prebuilt_query", "variant", "Requête construite sur une ligne, exécutée sur la suivante", r'''
def login(cursor, user, pwd):
    query = "SELECT * FROM accounts WHERE user='" + user + "' AND pwd='" + pwd + "'"  # VULN:SQL_INJECTION
    cursor.execute(query)
    return cursor.fetchone() is not None
''')

_add("sqli_multiline_concat", "variant", "Requête multi-lignes avec +=", r'''
def report(cursor, year, region):
    sql = "SELECT region, SUM(amount) FROM sales "  # VULN:SQL_INJECTION
    sql += "WHERE year = " + str(year) + " "
    sql += "AND region = '" + region + "' "
    sql += "GROUP BY region"
    cursor.execute(sql)
    return cursor.fetchall()
''')

_add("sqli_sqlalchemy_text", "variant", "SQLAlchemy text() + f-string", r'''
from sqlalchemy import text

def by_email(session, email):
    return session.execute(text(f"SELECT * FROM users WHERE email = '{email}'")).fetchall()  # VULN:SQL_INJECTION
''')

_add("sqli_django_raw", "variant", "Django Model.objects.raw()", r'''
from app.models import Article

def articles_by_author(author):
    return Article.objects.raw(f"SELECT * FROM app_article WHERE author = '{author}'")  # VULN:SQL_INJECTION
''')

_add("sqli_order_by", "variant", "Injection dans ORDER BY", r'''
def list_users(cursor, sort_column):
    cursor.execute(f"SELECT id, name FROM users ORDER BY {sort_column}")  # VULN:SQL_INJECTION
    return cursor.fetchall()
''')

_add("sqli_cursor_alias", "evasion", "Curseur renommé, méthode appelée via variable", r'''
def run(db, tbl, ident):
    c = db.cursor()
    runner = c.execute
    runner("UPDATE " + tbl + " SET seen = 1 WHERE id = " + ident)  # VULN:SQL_INJECTION
''')

_add("sqli_no_select_keyword_lowercase", "evasion", "SQL en minuscules", r'''
def get(cur, uid):
    cur.execute("select * from users where id = " + uid)  # VULN:SQL_INJECTION
    return cur.fetchone()
''')

# ═════════════════════════════════════════════════════════════════════════════
# COMMAND INJECTION
# ═════════════════════════════════════════════════════════════════════════════
_add("cmd_os_system", "classic", "os.system + concaténation", r'''
import os

def ping(host):
    os.system("ping -c 1 " + host)  # VULN:COMMAND_INJECTION
''')

_add("cmd_subprocess_shell_fstring", "classic", "subprocess shell=True + f-string", r'''
import subprocess

def list_dir(path):
    return subprocess.check_output(f"ls -la {path}", shell=True)  # VULN:COMMAND_INJECTION
''')

_add("cmd_popen_shell", "classic", "Popen shell=True avec commande variable", r'''
import subprocess

def run_user_cmd(cmd):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)  # VULN:COMMAND_INJECTION
    return p.communicate()[0]
''')

_add("cmd_os_popen", "classic", "os.popen", r'''
import os

def show(filename):
    return os.popen("cat " + filename).read()  # VULN:COMMAND_INJECTION
''')

_add("cmd_percent", "variant", "os.system + formatage %", r'''
import os

def greet(user):
    os.system("echo Hello %s" % user)  # VULN:COMMAND_INJECTION
''')

_add("cmd_run_multiline", "variant", "subprocess.run shell=True sur plusieurs lignes", r'''
import subprocess

def backup(name):
    subprocess.run(  # VULN:COMMAND_INJECTION
        "tar czf /backups/" + name + ".tgz /data",
        shell=True,
        check=True,
    )
''')

_add("cmd_asyncio_shell", "variant", "asyncio.create_subprocess_shell", r'''
import asyncio

async def run(cmd):
    proc = await asyncio.create_subprocess_shell(cmd)  # VULN:COMMAND_INJECTION
    await proc.wait()
''')

_add("cmd_import_alias", "evasion", "from subprocess import check_output as co", r'''
from subprocess import check_output as co

def whois(domain):
    return co("whois " + domain, shell=True)  # VULN:COMMAND_INJECTION
''')

_add("cmd_sh_c_list", "evasion", "Liste mais via sh -c (injection quand même)", r'''
import subprocess

def resolve(host):
    subprocess.run(["sh", "-c", "nslookup " + host])  # VULN:COMMAND_INJECTION
''')

# ═════════════════════════════════════════════════════════════════════════════
# INSECURE DESERIALIZATION
# ═════════════════════════════════════════════════════════════════════════════
_add("deser_pickle_loads", "classic", "pickle.loads sur données réseau", r'''
import pickle

def handle(request):
    obj = pickle.loads(request.data)  # VULN:INSECURE_DESERIALIZATION
    return obj
''')

_add("deser_pickle_load_file", "classic", "pickle.load sur fichier", r'''
import pickle

def load_session(path):
    with open(path, "rb") as f:
        return pickle.load(f)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_yaml_load", "classic", "yaml.load sans Loader", r'''
import yaml

def read_config(text):
    return yaml.load(text)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_marshal", "variant", "marshal.loads", r'''
import marshal

def run_blob(blob):
    return marshal.loads(blob)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_yaml_full_loader_unsafe", "variant", "yaml.load avec yaml.Loader (non sûr)", r'''
import yaml

def parse(stream):
    return yaml.load(stream, Loader=yaml.Loader)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_pandas_read_pickle", "variant", "pandas.read_pickle", r'''
import pandas as pd

def load_df(path):
    return pd.read_pickle(path)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_alias_module", "evasion", "import pickle as pkl", r'''
import pickle as pkl

def restore(data):
    return pkl.loads(data)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_alias_function", "evasion", "from pickle import loads as ld", r'''
from pickle import loads as ld

def restore(data):
    return ld(data)  # VULN:INSECURE_DESERIALIZATION
''')

_add("deser_jsonpickle_dill", "evasion", "jsonpickle / dill", r'''
import dill
import jsonpickle

def a(raw):
    return jsonpickle.decode(raw)  # VULN:INSECURE_DESERIALIZATION

def b(raw):
    return dill.loads(raw)  # VULN:INSECURE_DESERIALIZATION
''')

# ═════════════════════════════════════════════════════════════════════════════
# HARDCODED SECRET
# ═════════════════════════════════════════════════════════════════════════════
_add("secret_password", "classic", "Mot de passe en constante", r'''
import psycopg2

DB_PASSWORD = "Sup3rS3cret!2024"  # VULN:HARDCODED_SECRET

def connect():
    return psycopg2.connect(host="db", user="app", password=DB_PASSWORD)
''')

_add("secret_api_key", "classic", "Clé API", r'''
import requests

API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"  # VULN:HARDCODED_SECRET

def charge(amount):
    return requests.post("https://api.example.com/charge", auth=(API_KEY, ""), data={"amount": amount})
''')

_add("secret_aws", "classic", "Clés AWS", r'''
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # VULN:HARDCODED_SECRET
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # VULN:HARDCODED_SECRET

def client():
    return boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
''')

_add("secret_dict_token", "variant", "Token dans un dict de config", r'''
CONFIG = {
    "host": "api.internal",
    "timeout": 10,
    "token": "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",  # VULN:HARDCODED_SECRET
}
''')

_add("secret_class_attr", "variant", "Attribut de classe", r'''
class Settings:
    DEBUG = False
    SECRET_KEY = "d41d8cd98f00b204e9800998ecf8427e"  # VULN:HARDCODED_SECRET
    ALLOWED_HOSTS = ["example.com"]
''')

_add("secret_default_arg", "variant", "Valeur par défaut d'un argument", r'''
def connect(host, user="admin", password="hunter2hunter2"):  # VULN:HARDCODED_SECRET
    return (host, user, password)
''')

_add("secret_jwt_inline", "variant", "Secret JWT passé en littéral", r'''
import jwt

def make_token(payload):
    return jwt.encode(payload, "my-super-secret-signing-key", algorithm="HS256")  # VULN:HARDCODED_SECRET
''')

_add("secret_bearer_header", "variant", "Bearer token dans un header", r'''
import requests

def fetch(url):
    headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"}  # VULN:HARDCODED_SECRET
    return requests.get(url, headers=headers)
''')

_add("secret_connection_string", "variant", "Mot de passe dans une URL de connexion", r'''
from sqlalchemy import create_engine

engine = create_engine("postgresql://admin:Sup3rPass99@db.internal:5432/app")  # VULN:HARDCODED_SECRET
''')

_add("secret_private_key_pem", "variant", "Clé privée PEM", r'''
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----  # VULN:HARDCODED_SECRET
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
-----END RSA PRIVATE KEY-----"""
''')

_add("secret_non_obvious_name", "evasion", "Secret dans une variable au nom anodin", r'''
import requests

x = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"  # VULN:HARDCODED_SECRET

def go():
    return requests.get("https://api.example.com", headers={"X-Auth": x})
''')

_add("secret_split_concat", "evasion", "Secret découpé en deux littéraux", r'''
PASSWORD = "Sup3r" + "S3cret!" + "2024"  # VULN:HARDCODED_SECRET
''')

_add("secret_base64", "evasion", "Secret encodé base64 en dur", r'''
import base64

PASSWORD = base64.b64decode("U3VwM3JTM2NyZXQhMjAyNA==").decode()  # VULN:HARDCODED_SECRET
''')

# ═════════════════════════════════════════════════════════════════════════════
# SAFE  (pièges à faux positifs)
# ═════════════════════════════════════════════════════════════════════════════
_add("safe_sql_parametrized_percent", "safe_trap", "Requête paramétrée (%s)", r'''
def get_user(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
    return cursor.fetchone()
''')

_add("safe_sql_parametrized_qmark", "safe_trap", "Requête paramétrée (?)", r'''
def get_order(conn, order_id):
    return conn.execute("SELECT * FROM orders WHERE id = ?", (order_id,)).fetchone()
''')

_add("safe_sql_constant", "safe_trap", "Requête 100 % constante", r'''
def count_users(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")
    return cursor.fetchone()[0]
''')

_add("safe_sql_allowlist", "safe_trap", "Colonne validée par liste blanche", r'''
ALLOWED = {"id", "name", "created_at"}

def list_users(cursor, column):
    if column not in ALLOWED:
        column = "id"
    cursor.execute(f"SELECT id, name FROM users ORDER BY {column}")
    return cursor.fetchall()
''')

_add("safe_sql_orm", "safe_trap", "ORM SQLAlchemy", r'''
from sqlalchemy import select
from app.models import User

def by_email(session, email):
    return session.execute(select(User).where(User.email == email)).scalars().first()
''')

_add("safe_cmd_list", "safe_trap", "subprocess avec liste, shell=False", r'''
import subprocess

def ping(host):
    return subprocess.run(["ping", "-c", "1", host], capture_output=True, check=True)
''')

_add("safe_cmd_constant", "safe_trap", "os.system sur commande constante", r'''
import os

def clear():
    os.system("clear")
''')

_add("safe_cmd_shlex_quote", "safe_trap", "Argument échappé via shlex.quote", r'''
import shlex
import subprocess

def show(path):
    return subprocess.check_output("cat " + shlex.quote(path), shell=True)
''')

_add("safe_pickle_dumps", "safe_trap", "pickle.dumps (sérialisation, pas désérialisation)", r'''
import pickle

def save(obj, path):
    with open(path, "wb") as f:
        pickle.dump(obj, f)
''')

_add("safe_yaml_safe_load", "safe_trap", "yaml.safe_load", r'''
import yaml

def read_config(text):
    return yaml.safe_load(text)
''')

_add("safe_yaml_safe_loader_kw", "safe_trap", "yaml.load avec SafeLoader", r'''
import yaml

def read_config(stream):
    return yaml.load(stream, Loader=yaml.SafeLoader)
''')

_add("safe_json_loads", "safe_trap", "json.loads", r'''
import json

def parse(payload):
    return json.loads(payload)
''')

_add("safe_secret_env", "safe_trap", "Secret lu depuis l'environnement", r'''
import os

DB_PASSWORD = os.environ["DB_PASSWORD"]
API_KEY = os.getenv("API_KEY", "")
''')

_add("safe_secret_getpass", "safe_trap", "Mot de passe demandé à l'utilisateur", r'''
import getpass

def ask():
    password = getpass.getpass("Password: ")
    return password
''')

_add("safe_secret_empty_placeholder", "safe_trap", "Valeurs vides / None / noms de champs", r'''
password = ""
token = None
PASSWORD_FIELD = "password"
PASSWORD_MIN_LENGTH = 12
SECRET_HEADER_NAME = "X-Secret"
''')

_add("safe_docstring_comment_mentions", "safe_trap", "Docstring et commentaires qui parlent de vulnérabilités", r'''
def run(cmd_list):
    """Never use os.system("rm -rf " + path) or pickle.loads(data) here.

    Example of bad config: password = "hunter2"
    """
    # SELECT * FROM users WHERE name = ' + name  <- do not do this
    import subprocess
    return subprocess.run(cmd_list, check=True)
''')

_add("safe_logging_sql_words", "safe_trap", "Mots SQL dans des messages utilisateur", r'''
def menu():
    print("Select an option:")
    print("1) Update profile")
    print("2) Delete account")
    return input("> ")
''')

_add("safe_utility_module", "safe_trap", "Module utilitaire sans rapport", r'''
import hashlib
import math
from dataclasses import dataclass

@dataclass
class Point:
    x: float
    y: float

    def dist(self, other):
        return math.hypot(self.x - other.x, self.y - other.y)

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]
''')

# ═════════════════════════════════════════════════════════════════════════════
# MIXED  (scripts réalistes)
# ═════════════════════════════════════════════════════════════════════════════
_add("mixed_flask_app", "mixed", "Appli Flask : 4 classes de vulns + routes saines", r'''
import os
import sqlite3
import subprocess
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-key-7f3a9c1e5b2d4086"  # VULN:HARDCODED_SECRET


def db():
    return sqlite3.connect("app.db")


@app.route("/users")
def users():
    name = request.args.get("name", "")
    cur = db().cursor()
    cur.execute(f"SELECT id, name FROM users WHERE name = '{name}'")  # VULN:SQL_INJECTION
    return jsonify(cur.fetchall())


@app.route("/users/<int:uid>")
def user(uid):
    cur = db().cursor()
    cur.execute("SELECT id, name FROM users WHERE id = ?", (uid,))
    return jsonify(cur.fetchone())


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)  # VULN:COMMAND_INJECTION
    return out


@app.route("/health")
def health():
    return {"status": "ok", "debug": os.environ.get("DEBUG", "0")}


@app.route("/import", methods=["POST"])
def import_data():
    import pickle
    obj = pickle.loads(request.data)  # VULN:INSECURE_DESERIALIZATION
    return jsonify({"items": len(obj)})
''')

_add("mixed_class_service", "mixed", "Classe de service : méthodes saines et vulnérables", r'''
import os
import subprocess
import yaml


class Deployer:
    TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"  # VULN:HARDCODED_SECRET

    def __init__(self, repo):
        self.repo = repo

    def clone(self):
        return subprocess.run(["git", "clone", self.repo], check=True)

    def checkout(self, branch):
        os.system("git checkout " + branch)  # VULN:COMMAND_INJECTION

    def load_manifest(self, text):
        return yaml.safe_load(text)

    def load_manifest_legacy(self, text):
        return yaml.load(text)  # VULN:INSECURE_DESERIALIZATION
''')

_add("mixed_two_vulns_same_function", "mixed", "Deux vulnérabilités distinctes dans la même fonction", r'''
import os

def export(cursor, table, dest):
    cursor.execute("SELECT * FROM " + table)  # VULN:SQL_INJECTION
    rows = cursor.fetchall()
    os.system("cp /tmp/out.csv " + dest)  # VULN:COMMAND_INJECTION
    return rows
''')

_add("mixed_module_level_script", "mixed", "Code vulnérable au niveau module (hors fonction)", r'''
import os
import pickle
import sys

host = sys.argv[1]
os.system("nslookup " + host)  # VULN:COMMAND_INJECTION

with open(sys.argv[2], "rb") as f:
    state = pickle.load(f)  # VULN:INSECURE_DESERIALIZATION

print(state)
''')

_add("mixed_async_nested", "mixed", "Fonction imbriquée, async, décorateur", r'''
import functools
import subprocess

def logged(fn):
    @functools.wraps(fn)
    def wrapper(*a, **kw):
        print("calling", fn.__name__)
        return fn(*a, **kw)
    return wrapper

@logged
async def handler(request):
    def inner(name):
        return subprocess.getoutput("id " + name)  # VULN:COMMAND_INJECTION
    return inner(request.query["user"])
''')

_add("mixed_safe_after_vuln_neighbour", "mixed", "Fonction saine collée à une fonction vulnérable", r'''
def safe_lookup(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))
    return cursor.fetchone()

def unsafe_lookup(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = " + uid)  # VULN:SQL_INJECTION
    return cursor.fetchone()

def safe_count(cursor):
    cursor.execute("SELECT COUNT(*) FROM users")
    return cursor.fetchone()[0]
''')

_add("mixed_many_safe_one_vuln", "mixed", "Beaucoup de code sain, une seule ligne vulnérable", r'''
import json
import logging
import math

log = logging.getLogger(__name__)

def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0

def stddev(xs):
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / len(xs)) if xs else 0.0

def normalize(xs):
    m, s = mean(xs), stddev(xs) or 1.0
    return [(x - m) / s for x in xs]

def to_json(obj):
    return json.dumps(obj, sort_keys=True, indent=2)

def audit(cursor, actor, action):
    cursor.execute("INSERT INTO audit(actor, action) VALUES ('" + actor + "', '" + action + "')")  # VULN:SQL_INJECTION
    log.info("audit %s %s", actor, action)

def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def chunks(seq, n):
    return [seq[i:i + n] for i in range(0, len(seq), n)]
''')


# ═════════════════════════════════════════════════════════════════════════════
# BANDIT_BLIND : vulnérabilités qu'un outil statique à règles ne voit pas
# ─────────────────────────────────────────────────────────────────────────────
# Bandit raisonne sur un appel / une expression isolée, avec des noms qualifiés
# et des regex. Ces cas contournent ce mécanisme : flux sur plusieurs
# statements, alias de variable, import dynamique, API hors liste de sinks,
# secrets reconnaissables à leur VALEUR plutôt qu'à leur nom.
# ═════════════════════════════════════════════════════════════════════════════

# ── SQL : la requête n'est jamais un littéral SQL unique dans une expression ──
_add("bb_sqli_split_where", "bandit_blind", "Base et WHERE dans deux variables, concaténées à l'exécution", r'''
def find_user(cur, name):
    base = "SELECT id, email FROM users"
    where = " WHERE name = '" + name + "'"  # VULN:SQL_INJECTION
    cur.execute(base + where)
    return cur.fetchall()
''')

_add("bb_sqli_join_conditions", "bandit_blind", "Conditions assemblées via une liste et str.join", r'''
def search(cur, filters):
    parts = ["SELECT * FROM items"]
    conds = []
    for col, val in filters.items():
        conds.append(col + " = '" + val + "'")  # VULN:SQL_INJECTION
    if conds:
        parts.append("WHERE " + " AND ".join(conds))
    cur.execute(" ".join(parts))
    return cur.fetchall()
''')

_add("bb_sqli_string_template", "bandit_blind", "string.Template : le littéral SQL est constant, la substitution est dangereuse", r'''
from string import Template

def get(cur, table, uid):
    tpl = Template("SELECT * FROM $table WHERE id = $uid")
    cur.execute(tpl.substitute(table=table, uid=uid))  # VULN:SQL_INJECTION
    return cur.fetchone()
''')

_add("bb_sqli_filter_helper", "bandit_blind", "Fragment injectable construit dans une autre fonction", r'''
def build_filter(field, value):
    return " WHERE " + field + " = '" + value + "'"  # VULN:SQL_INJECTION

def fetch(cur, field, value):
    base = "SELECT * FROM logs"
    cur.execute(base + build_filter(field, value))
    return cur.fetchall()
''')

# ── Commandes : pas de shell=True ni de os.system littéral ───────────────────
_add("bb_cmd_alias_variable", "bandit_blind", "sh = os.system puis sh(...)", r'''
import os

sh = os.system

def ping(host):
    sh("ping -c 1 " + host)  # VULN:COMMAND_INJECTION
''')

_add("bb_cmd_getattr", "bandit_blind", "Fonction récupérée via getattr", r'''
import os

def run(program, arg):
    fn = getattr(os, "system")
    fn(program + " " + arg)  # VULN:COMMAND_INJECTION
''')

_add("bb_cmd_dynamic_import", "bandit_blind", "Import dynamique de os", r'''
import importlib

def disk_usage(path):
    return importlib.import_module("os").system("du -sh " + path)  # VULN:COMMAND_INJECTION
''')

_add("bb_cmd_fabric_run", "bandit_blind", "Exécution distante via Fabric", r'''
from fabric import Connection

def deploy(host, branch):
    c = Connection(host)
    c.run("git -C /srv/app checkout " + branch)  # VULN:COMMAND_INJECTION
''')

# ── Désérialisation : sinks hors de la liste pickle/yaml/marshal ─────────────
_add("bb_deser_joblib", "bandit_blind", "joblib.load (pickle sous le capot)", r'''
import joblib

def load_user_model(path):
    return joblib.load(path)  # VULN:INSECURE_DESERIALIZATION
''')

_add("bb_deser_numpy_allow_pickle", "bandit_blind", "numpy.load avec allow_pickle=True", r'''
import numpy as np

def load_array(path):
    return np.load(path, allow_pickle=True)  # VULN:INSECURE_DESERIALIZATION
''')

_add("bb_deser_cloudpickle", "bandit_blind", "cloudpickle.loads", r'''
import cloudpickle

def receive(payload):
    return cloudpickle.loads(payload)  # VULN:INSECURE_DESERIALIZATION
''')

_add("bb_deser_dynamic_import", "bandit_blind", "__import__('pickle').loads", r'''
def restore(blob):
    return __import__("pickle").loads(blob)  # VULN:INSECURE_DESERIALIZATION
''')

_add("bb_deser_ruamel_unsafe", "bandit_blind", "ruamel.yaml en mode unsafe", r'''
from ruamel.yaml import YAML

def parse(text):
    yaml = YAML(typ="unsafe")
    return yaml.load(text)  # VULN:INSECURE_DESERIALIZATION
''')

# ── Secrets : reconnaissables à la valeur, nom de variable sans indice ───────
_add("bb_secret_slack_webhook", "bandit_blind", "Webhook Slack (secret dans l'URL)", r'''
import requests

NOTIFY_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"  # VULN:HARDCODED_SECRET

def notify(msg):
    return requests.post(NOTIFY_URL, json={"text": msg})
''')

_add("bb_secret_google_key", "bandit_blind", "Clé Google (préfixe AIza)", r'''
MAPS = "AIzaSyA-1234567890abcdefghijklmnopqrstu"  # VULN:HARDCODED_SECRET

def geocode_url(address):
    return f"https://maps.googleapis.com/maps/api/geocode/json?address={address}&key={MAPS}"
''')

_add("bb_secret_client_api_key_kwarg", "bandit_blind", "api_key= en littéral dans un constructeur", r'''
from openai import OpenAI

client = OpenAI(api_key="sk-proj-abcdEFGH1234ijklMNOP5678qrstUVWX9012")  # VULN:HARDCODED_SECRET
''')

_add("bb_secret_tuple_unpack", "bandit_blind", "Identifiants dans un unpacking de tuple", r'''
def creds():
    user, pw = "admin", "Sup3rS3cret!2024"  # VULN:HARDCODED_SECRET
    return user, pw
''')

_add("bb_secret_sentry_dsn", "bandit_blind", "DSN Sentry avec clé publique/privée", r'''
import sentry_sdk

sentry_sdk.init(dsn="https://abc123def4567890abc123def4567890@o123456.ingest.sentry.io/1234567")  # VULN:HARDCODED_SECRET
''')

_add("bb_secret_aws_access_key_id", "bandit_blind", "AWS Access Key ID seul (AKIA...)", r'''
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # VULN:HARDCODED_SECRET

def session():
    return boto3.Session(aws_access_key_id=AWS_ACCESS_KEY_ID)
''')

_add("bb_secret_dsn_keyword_string", "bandit_blind", "Mot de passe dans une chaîne de connexion libpq", r'''
import psycopg2

def connect():
    return psycopg2.connect("host=db user=app password=Sup3rS3cret!2024 dbname=app")  # VULN:HARDCODED_SECRET
''')

_add("bb_secret_x_api_key_header", "bandit_blind", "Clé dans un header X-API-Key", r'''
import requests

def fetch(url):
    headers = {"X-API-Key": "7f3a9c1e5b2d4086a1b2c3d4e5f60718"}  # VULN:HARDCODED_SECRET
    return requests.get(url, headers=headers)
''')

_add("bb_mixed_service", "bandit_blind", "Script réaliste : 4 vulns que Bandit ne voit pas + code sain", r'''
import os
import joblib
import requests
from string import Template

sh = os.system
HOOK = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"  # VULN:HARDCODED_SECRET


def notify(msg):
    return requests.post(HOOK, json={"text": msg})


def restart(service):
    sh("systemctl restart " + service)  # VULN:COMMAND_INJECTION


def load_model(path):
    return joblib.load(path)  # VULN:INSECURE_DESERIALIZATION


def report(cur, table, uid):
    tpl = Template("SELECT * FROM $table WHERE owner = $uid")
    cur.execute(tpl.substitute(table=table, uid=uid))  # VULN:SQL_INJECTION
    return cur.fetchall()


def safe_report(cur, uid):
    cur.execute("SELECT * FROM reports WHERE owner = %s", (uid,))
    return cur.fetchall()
''')

# ═════════════════════════════════════════════════════════════════════════════
# BANDIT_NOISE : code SAFE que Bandit signale à tort (heuristiques sur les noms)
# Le modèle doit rester muet : c'est sa valeur ajoutée comme filtre de FP.
# ═════════════════════════════════════════════════════════════════════════════
_add("bn_password_named_constants", "bandit_noise", "Noms 'password/token/secret' mais valeurs non secrètes", r'''
PASSWORD_PROMPT = "Enter your password: "
TOKEN_URL = "https://auth.example.com/oauth/token"
SECRET_NAME = "prod/db/credentials"
token_type = "Bearer"
RESET_PASSWORD_TEMPLATE = "emails/reset_password.html"
''')

_add("bn_sql_fstring_constant_table", "bandit_noise", "f-string SQL avec constante de module (aucune entrée externe)", r'''
AUDIT_TABLE = "audit_log"

def purge(cur):
    cur.execute(f"DELETE FROM {AUDIT_TABLE} WHERE created_at < datetime('now', '-90 day')")

def count(cur):
    cur.execute(f"SELECT COUNT(*) FROM {AUDIT_TABLE}")
    return cur.fetchone()[0]
''')

_add("bn_shell_true_literal", "bandit_noise", "shell=True sur commande 100 % littérale", r'''
import subprocess

def disk_free():
    return subprocess.run("df -h / | tail -n 1", shell=True, capture_output=True, text=True, check=True).stdout

def uptime():
    return subprocess.check_output("uptime -p", shell=True, text=True)
''')

_add("bn_secret_from_vault_names", "bandit_noise", "Variables 'secret/token' alimentées dynamiquement", r'''
import os
import secrets

def new_session_token():
    token = secrets.token_urlsafe(32)
    return token

def load_secret(client, name):
    secret = client.get_secret_value(SecretId=name)["SecretString"]
    return secret

API_TOKEN = os.environ.get("API_TOKEN", "")
''')
