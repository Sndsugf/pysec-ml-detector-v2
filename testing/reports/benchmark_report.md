# Rapport d'évaluation – PythonVulnerabilityScanner

## 1. Résumé

- Scripts évalués : **93** (seuil de confiance = 0.55)
- Scripts entièrement corrects : **46/93** (49 %) – Bandit : 53/93 (57 %)
- F1 micro : **0.64** · F1 macro : **0.58** – Bandit : micro 0.65 / macro 0.66

## 2. Précision / rappel / F1 par classe

| Classe | P | R | F1 | TP | FP | FN | Bandit P | Bandit R | Bandit F1 |
|---|---|---|---|---|---|---|---|---|---|
| HARDCODED_SECRET | 1.00 | 0.04 | 0.08 | 1 | 0 | 24 | 0.50 | 0.32 | 0.39 |
| INSECURE_DESERIALIZATION | 0.89 | 0.84 | 0.86 | 16 | 2 | 3 | 1.00 | 0.68 | 0.81 |
| COMMAND_INJECTION | 0.67 | 0.53 | 0.59 | 10 | 5 | 9 | 0.75 | 0.63 | 0.69 |
| SQL_INJECTION | 0.65 | 1.00 | 0.78 | 20 | 11 | 0 | 0.82 | 0.70 | 0.76 |

## 3. Taux de réussite par catégorie de scripts

| Catégorie | Modèle | % | Bandit |
|---|---|---|---|
| classic | 12/14 | 86 % | 13/14 (93 %) |
| variant | 9/18 | 50 % | 12/18 (67 %) |
| evasion | 5/10 | 50 % | 6/10 (60 %) |
| mixed | 1/7 | 14 % | 7/7 (100 %) |
| safe_trap | 9/18 | 50 % | 14/18 (78 %) |
| bandit_blind | 8/22 | 36 % | 0/22 (0 %) |
| bandit_noise | 2/4 | 50 % | 1/4 (25 %) |

## 4. Matrice de confusion (lignes = attendu, colonnes = prédit)

| attendu \ prédit | HARDCODED_SECRET | INSECURE_DESERIALIZATION | COMMAND_INJECTION | SQL_INJECTION | NONE |
|---|---|---|---|---|---|
| HARDCODED_SECRET | 1 | 0 | 0 | 0 | 24 |
| INSECURE_DESERIALIZATION | 0 | 16 | 0 | 0 | 3 |
| COMMAND_INJECTION | 0 | 1 | 10 | 1 | 7 |
| SQL_INJECTION | 0 | 0 | 0 | 20 | 0 |
| SAFE | 0 | 2 | 5 | 11 | 0 |

_NONE = rien détecté (faux négatif) ; ligne SAFE = faux positifs sur du code sain._

## 5. Localisation des lignes dangereuses

- Vulnérabilités détectées avec la bonne ligne : **42/47**
- Lignes dangereuses « parasites » : **18/60** (30 %)

## 6. Calibration de la confiance

- Confiance moyenne des vrais positifs : **81.9 %**
- Confiance moyenne des faux positifs : **83.1 %**
_Si les deux sont proches, la confiance ne permet pas de filtrer les erreurs._

## 7. Sensibilité au seuil de confiance

| Seuil | Précision | Rappel | F1 | Findings | Scripts OK |
|---|---|---|---|---|---|
| 0.3 | 0.69 | 0.60 | 0.65 | 72 | 46/93 |
| 0.4 | 0.69 | 0.60 | 0.65 | 72 | 46/93 |
| 0.5 | 0.71 | 0.57 | 0.63 | 66 | 46/93 |
| 0.55 | 0.72 | 0.57 | 0.64 | 65 | 46/93 |
| 0.6 | 0.72 | 0.53 | 0.61 | 61 | 45/93 |
| 0.7 | 0.71 | 0.45 | 0.55 | 52 | 40/93 |
| 0.8 | 0.71 | 0.35 | 0.47 | 41 | 36/93 |
| 0.9 | 0.70 | 0.19 | 0.30 | 23 | 32/93 |

## 8. Échecs détaillés du modèle

### `sqli_multiline_concat` (variant) · Bandit : ❌
_Requête multi-lignes avec +=_
- LOCALISATION  SQL_INJECTION ligne 2 : bloc OK mais mauvaise ligne dangereuse

### `cmd_asyncio_shell` (variant) · Bandit : ❌
_asyncio.create_subprocess_shell_
- FN  COMMAND_INJECTION ligne 4 : rien détecté

### `cmd_import_alias` (evasion) · Bandit : ✅
_from subprocess import check_output as co_
- LOCALISATION  COMMAND_INJECTION ligne 4 : bloc OK mais mauvaise ligne dangereuse

### `deser_pandas_read_pickle` (variant) · Bandit : ✅
_pandas.read_pickle_
- FN  INSECURE_DESERIALIZATION ligne 4 : rien détecté

### `deser_alias_function` (evasion) · Bandit : ✅
_from pickle import loads as ld_
- FN  INSECURE_DESERIALIZATION ligne 4 : rien détecté

### `deser_jsonpickle_dill` (evasion) · Bandit : ✅
_jsonpickle / dill_
- FN  INSECURE_DESERIALIZATION ligne 5 : rien détecté

### `secret_password` (classic) · Bandit : ✅
_Mot de passe en constante_
- LOCALISATION  HARDCODED_SECRET ligne 3 : bloc OK mais mauvaise ligne dangereuse

### `secret_api_key` (classic) · Bandit : ❌
_Clé API_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `secret_aws` (classic) · Bandit : ✅
_Clés AWS_
- FN  HARDCODED_SECRET ligne 3 : rien détecté
- FN  HARDCODED_SECRET ligne 4 : rien détecté

### `secret_dict_token` (variant) · Bandit : ✅
_Token dans un dict de config_
- FN  HARDCODED_SECRET ligne 4 : rien détecté

### `secret_class_attr` (variant) · Bandit : ✅
_Attribut de classe_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `secret_default_arg` (variant) · Bandit : ✅
_Valeur par défaut d'un argument_
- FN  HARDCODED_SECRET ligne 1 : rien détecté

### `secret_jwt_inline` (variant) · Bandit : ❌
_Secret JWT passé en littéral_
- FN  HARDCODED_SECRET ligne 4 : rien détecté

### `secret_bearer_header` (variant) · Bandit : ❌
_Bearer token dans un header_
- FN  HARDCODED_SECRET ligne 4 : rien détecté

### `secret_connection_string` (variant) · Bandit : ❌
_Mot de passe dans une URL de connexion_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `secret_private_key_pem` (variant) · Bandit : ❌
_Clé privée PEM_
- FN  HARDCODED_SECRET ligne 1 : rien détecté

### `secret_non_obvious_name` (evasion) · Bandit : ❌
_Secret dans une variable au nom anodin_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `secret_split_concat` (evasion) · Bandit : ❌
_Secret découpé en deux littéraux_
- FN  HARDCODED_SECRET ligne 1 : rien détecté

### `secret_base64` (evasion) · Bandit : ❌
_Secret encodé base64 en dur_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `safe_sql_parametrized_percent` (safe_trap) · Bandit : ✅
_Requête paramétrée (%s)_
- FP  SQL_INJECTION bloc 1-3 [Fonction `get_user()`] conf=92.54%

### `safe_sql_parametrized_qmark` (safe_trap) · Bandit : ✅
_Requête paramétrée (?)_
- FP  SQL_INJECTION bloc 1-2 [Fonction `get_order()`] conf=86.19%

### `safe_sql_constant` (safe_trap) · Bandit : ✅
_Requête 100 % constante_
- FP  SQL_INJECTION bloc 1-3 [Fonction `count_users()`] conf=91.72%

### `safe_sql_allowlist` (safe_trap) · Bandit : ❌
_Colonne validée par liste blanche_
- FP  SQL_INJECTION bloc 3-7 [Fonction `list_users()`] conf=80.82%

### `safe_cmd_constant` (safe_trap) · Bandit : ❌
_os.system sur commande constante_
- FP  COMMAND_INJECTION bloc 3-4 [Fonction `clear()`] conf=93.23%

### `safe_cmd_shlex_quote` (safe_trap) · Bandit : ❌
_Argument échappé via shlex.quote_
- FP  COMMAND_INJECTION bloc 4-5 [Fonction `show()`] conf=68.15%

### `safe_pickle_dumps` (safe_trap) · Bandit : ✅
_pickle.dumps (sérialisation, pas désérialisation)_
- FP  INSECURE_DESERIALIZATION bloc 3-5 [Fonction `save()`] conf=75.09%

### `safe_yaml_safe_loader_kw` (safe_trap) · Bandit : ✅
_yaml.load avec SafeLoader_
- FP  INSECURE_DESERIALIZATION bloc 3-4 [Fonction `read_config()`] conf=95.31%

### `safe_docstring_comment_mentions` (safe_trap) · Bandit : ✅
_Docstring et commentaires qui parlent de vulnérabilités_
- FP  COMMAND_INJECTION bloc 1-8 [Fonction `run()`] conf=82.49%

### `mixed_flask_app` (mixed) · Bandit : ✅
_Appli Flask : 4 classes de vulns + routes saines_
- FN  HARDCODED_SECRET ligne 7 : rien détecté
- FP  SQL_INJECTION bloc 23-26 [Fonction `user()`] conf=92.5%

### `mixed_class_service` (mixed) · Bandit : ✅
_Classe de service : méthodes saines et vulnérables_
- FN  HARDCODED_SECRET ligne 7 : rien détecté

### `mixed_two_vulns_same_function` (mixed) · Bandit : ✅
_Deux vulnérabilités distinctes dans la même fonction_
- MAUVAISE CLASSE  COMMAND_INJECTION ligne 6 -> prédit SQL_INJECTION

### `mixed_module_level_script` (mixed) · Bandit : ✅
_Code vulnérable au niveau module (hors fonction)_
- MAUVAISE CLASSE  COMMAND_INJECTION ligne 6 -> prédit INSECURE_DESERIALIZATION

### `mixed_async_nested` (mixed) · Bandit : ✅
_Fonction imbriquée, async, décorateur_
- FN  COMMAND_INJECTION ligne 14 : rien détecté

### `mixed_safe_after_vuln_neighbour` (mixed) · Bandit : ✅
_Fonction saine collée à une fonction vulnérable_
- FP  SQL_INJECTION bloc 1-3 [Fonction `safe_lookup()`] conf=86.46%
- FP  SQL_INJECTION bloc 9-11 [Fonction `safe_count()`] conf=87.79%

### `bb_sqli_join_conditions` (bandit_blind) · Bandit : ❌
_Conditions assemblées via une liste et str.join_
- LOCALISATION  SQL_INJECTION ligne 5 : bloc OK mais mauvaise ligne dangereuse

### `bb_sqli_filter_helper` (bandit_blind) · Bandit : ❌
_Fragment injectable construit dans une autre fonction_
- FP  SQL_INJECTION bloc 4-7 [Fonction `fetch()`] conf=73.48%
- LOCALISATION  SQL_INJECTION ligne 2 : bloc OK mais mauvaise ligne dangereuse

### `bb_cmd_alias_variable` (bandit_blind) · Bandit : ❌
_sh = os.system puis sh(...)_
- FN  COMMAND_INJECTION ligne 6 : rien détecté
- FP  COMMAND_INJECTION bloc 3-3 [Portée globale (Module)] conf=77.14%

### `bb_cmd_getattr` (bandit_blind) · Bandit : ❌
_Fonction récupérée via getattr_
- FN  COMMAND_INJECTION ligne 5 : rien détecté

### `bb_cmd_dynamic_import` (bandit_blind) · Bandit : ❌
_Import dynamique de os_
- FN  COMMAND_INJECTION ligne 4 : rien détecté

### `bb_cmd_fabric_run` (bandit_blind) · Bandit : ❌
_Exécution distante via Fabric_
- FN  COMMAND_INJECTION ligne 5 : rien détecté

### `bb_secret_slack_webhook` (bandit_blind) · Bandit : ❌
_Webhook Slack (secret dans l'URL)_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `bb_secret_google_key` (bandit_blind) · Bandit : ❌
_Clé Google (préfixe AIza)_
- FN  HARDCODED_SECRET ligne 1 : rien détecté

### `bb_secret_client_api_key_kwarg` (bandit_blind) · Bandit : ❌
_api_key= en littéral dans un constructeur_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `bb_secret_tuple_unpack` (bandit_blind) · Bandit : ❌
_Identifiants dans un unpacking de tuple_
- FN  HARDCODED_SECRET ligne 2 : rien détecté

### `bb_secret_sentry_dsn` (bandit_blind) · Bandit : ❌
_DSN Sentry avec clé publique/privée_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `bb_secret_aws_access_key_id` (bandit_blind) · Bandit : ❌
_AWS Access Key ID seul (AKIA...)_
- FN  HARDCODED_SECRET ligne 3 : rien détecté

### `bb_secret_dsn_keyword_string` (bandit_blind) · Bandit : ❌
_Mot de passe dans une chaîne de connexion libpq_
- FN  HARDCODED_SECRET ligne 4 : rien détecté

### `bb_secret_x_api_key_header` (bandit_blind) · Bandit : ❌
_Clé dans un header X-API-Key_
- FN  HARDCODED_SECRET ligne 4 : rien détecté

### `bb_mixed_service` (bandit_blind) · Bandit : ❌
_Script réaliste : 4 vulns que Bandit ne voit pas + code sain_
- FN  HARDCODED_SECRET ligne 7 : rien détecté
- FN  COMMAND_INJECTION ligne 15 : rien détecté
- FP  SQL_INJECTION bloc 28-30 [Fonction `safe_report()`] conf=69.9%

### `bn_sql_fstring_constant_table` (bandit_noise) · Bandit : ❌
_f-string SQL avec constante de module (aucune entrée externe)_
- FP  SQL_INJECTION bloc 3-4 [Fonction `purge()`] conf=95.22%
- FP  SQL_INJECTION bloc 6-8 [Fonction `count()`] conf=92.81%

### `bn_shell_true_literal` (bandit_noise) · Bandit : ❌
_shell=True sur commande 100 % littérale_
- FP  COMMAND_INJECTION bloc 6-7 [Fonction `uptime()`] conf=55.61%

## 9. Comparaison avec Bandit

- Réussis par Bandit mais **pas** par le modèle (19) : `deser_pandas_read_pickle`, `deser_alias_function`, `deser_jsonpickle_dill`, `secret_aws`, `secret_dict_token`, `secret_class_attr`, `secret_default_arg`, `safe_sql_parametrized_percent`, `safe_sql_parametrized_qmark`, `safe_sql_constant`, `safe_pickle_dumps`, `safe_yaml_safe_loader_kw`, `safe_docstring_comment_mentions`, `mixed_flask_app`, `mixed_class_service`, `mixed_two_vulns_same_function`, `mixed_module_level_script`, `mixed_async_nested`, `mixed_safe_after_vuln_neighbour`
- Réussis par le modèle mais **pas** par Bandit (12) : `sqli_multiline_concat`, `cmd_sh_c_list`, `safe_secret_empty_placeholder`, `bb_sqli_split_where`, `bb_sqli_join_conditions`, `bb_sqli_string_template`, `bb_deser_joblib`, `bb_deser_numpy_allow_pickle`, `bb_deser_cloudpickle`, `bb_deser_dynamic_import`, `bb_deser_ruamel_unsafe`, `bn_password_named_constants`

## 10. Complémentarité modèle + Bandit

| Métrique | Valeur |
|---|---|
| Vulnérabilités attendues (total) | 83 |
| Trouvées par Bandit seul | 47 (57 %) |
| Trouvées par le modèle seul | 47 (57 %) |
| Trouvées par l'union | 60 (72 %) |
| **Prises uniques du modèle** (Bandit les rate) | 13 |
| Prises uniques de Bandit (le modèle les rate) | 13 |
| Faux positifs – modèle | 18 |
| Faux positifs – Bandit | 15 |
| Faux positifs ajoutés par le modèle (là où Bandit est muet) | 9 |

_Le modèle est un bon complément s'il a beaucoup de prises uniques ET peu de faux positifs ajoutés._

Prises uniques du modèle : `sqli_multiline_concat`, `cmd_sh_c_list`, `bb_sqli_split_where`, `bb_sqli_join_conditions`, `bb_sqli_string_template`, `bb_sqli_filter_helper`, `bb_deser_joblib`, `bb_deser_numpy_allow_pickle`, `bb_deser_cloudpickle`, `bb_deser_dynamic_import`, `bb_deser_ruamel_unsafe`, `bb_mixed_service`
