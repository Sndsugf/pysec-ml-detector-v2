# 🛡️ PySec ML Hybride — Détecteur de Vulnérabilités Python (Option 1)

Version enrichie intégrant les **données réelles issues de Zenodo** (`data/raw/zenodo_python.csv`), nettoyées (suppression des tests unitaires et doublons, normalisation des espaces) et fusionnées avec des exemples synthétiques pour obtenir un **dataset multiclasse parfaitement équilibré**.

---

## 📊 Composition du Dataset Hybride (`data/python_vuln_hybrid_dataset.csv`)

- **5 classes équilibrées** (180 échantillons par classe = **900 échantillons au total**)
- **Split explicite** : `data/train_split.csv` (80 % — 720 échantillons) et `data/test_split.csv` (20 % — 180 échantillons)
- **Intégration Zenodo** :
  - `SAFE` : **180 vrais correctifs (`patch`)** issus de commits de sécurité Python sur GitHub
  - `SQL_INJECTION` (CWE-89) : **49 vraies failles Zenodo** + 131 compléments équilibrés
  - `COMMAND_INJECTION` (CWE-78) : **23 vraies failles Zenodo** + 157 compléments équilibrés
  - `INSECURE_DESERIALIZATION` (CWE-502) : **23 vraies failles Zenodo** + 157 compléments équilibrés
  - `HARDCODED_SECRET` (CWE-798) : 180 échantillons équilibrés

---

## 🚀 Installation et Lancement

```bash
pip install -r requirements.txt
python -m src.train_model
streamlit run app.py localhost:8501
```
