"""
Application Web Interactive (Streamlit) pour la détection de vulnérabilités Python par Machine Learning Hybride.
Lancement : py -m streamlit run app.py
"""

import json
import os
import pandas as pd
import streamlit as st
from src.analyzer import PythonVulnerabilityScanner
from src.train_model import METRICS_PATH, train_and_evaluate

st.set_page_config(
    page_title="PySec ML Hybride - Détecteur de Vulnérabilités Python",
    page_icon="🛡️",
    layout="wide"
)

@st.cache_resource
def load_scanner():
    return PythonVulnerabilityScanner()

scanner = load_scanner()

st.title("🛡️ PySec ML — Détecteur Hybride de Vulnérabilités Python")
st.markdown(
    "Analyse statique propulsée par un modèle **Machine Learning multiclasse hybride** "
    "(données réelles open-source **Zenodo** nettoyées + échantillons synthétiques équilibrés) "
    "capable de localiser les **lignes dangereuses** et de proposer des **solutions correctives**."
)

with st.sidebar:
    st.header("📊 Performance du Modèle ML")
    if not os.path.exists(METRICS_PATH):
        metrics = train_and_evaluate()
    else:
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            metrics = json.load(f)

    col1, col2 = st.columns(2)
    col1.metric("Accuracy Test", f"{metrics['test_accuracy']*100:.2f}%")
    col2.metric("F1-Macro (CV)", f"{metrics['cv_f1_macro_mean']*100:.2f}%")

    st.caption(f"Split : {metrics['train_size']} Train (80%) / {metrics['test_size']} Test (20%)")

    st.subheader("Provenance du Dataset")
    prov_df = pd.DataFrame(metrics["provenance_by_class"]).T.reset_index()
    prov_df.columns = ["Classe", "Zenodo Réel", "Synthétique", "Total"]
    st.dataframe(prov_df, hide_index=True, use_container_width=True)

tab_analyze, tab_metrics = st.tabs(["🔍 Analyse de Code", "📈 Détails d'Évaluation ML"])

with tab_analyze:
    sample_choice = st.selectbox(
        "Charger un exemple de code :",
        [
            "Exemple complet multi-vulnérabilités (samples/vulnerable_app.py)",
            "Exemple de code sécurisé (samples/safe_app.py)",
            "Saisie libre / Upload de fichier"
        ]
    )

    default_code = ""
    if "vulnerable_app.py" in sample_choice and os.path.exists("samples/vulnerable_app.py"):
        with open("samples/vulnerable_app.py", "r", encoding="utf-8") as f:
            default_code = f.read()
    elif "safe_app.py" in sample_choice and os.path.exists("samples/safe_app.py"):
        with open("samples/safe_app.py", "r", encoding="utf-8") as f:
            default_code = f.read()

    uploaded_file = st.file_uploader("Ou importer un fichier `.py` :", type=["py"])
    if uploaded_file is not None:
        default_code = uploaded_file.getvalue().decode("utf-8", errors="replace")

    widget_key = f"code_area_{sample_choice}_{uploaded_file.name if uploaded_file else 'none'}"
    code_input = st.text_area("Code source Python à analyser :", value=default_code, height=280, key=widget_key)

    if st.button("🚀 Lancer l'analyse de sécurité", type="primary"):
        if not code_input.strip():
            st.warning("Veuillez saisir ou importer du code Python avant de lancer l'analyse.")
        else:
            report = scanner.scan_code(code_input)

            m1, m2, m3 = st.columns(3)
            m1.metric("Blocs analysés", report["total_blocks_analyzed"])
            m2.metric("Vulnérabilités détectées", report["vulnerabilities_found"])
            m3.metric("Statut global", "✅ Sain" if report["is_clean"] else "⚠️ Vulnérable")

            if report["is_clean"]:
                st.success("Aucune vulnérabilité détectée ! Les bonnes pratiques de sécurité sont respectées.")
            else:
                st.error(f"{report['vulnerabilities_found']} vulnérabilité(s) critique(s) détectée(s) :")

                all_bad_lines = set()
                for f_item in report["findings"]:
                    for dl in f_item["dangerous_lines"]:
                        all_bad_lines.add(dl["line_number"])

                st.subheader("📌 Code source annoté (Lignes dangereuses signalées)")
                annotated = []
                for idx, line in enumerate(code_input.splitlines(), start=1):
                    marker = "🚨 >>>" if idx in all_bad_lines else "      "
                    annotated.append(f"{idx:03d} {marker} | {line}")
                st.code("\n".join(annotated), language="python")

                st.subheader("🛠️ Détails des vulnérabilités et solutions correctives")
                for idx, item in enumerate(report["findings"], start=1):
                    with st.expander(
                        f"#{idx} — {item['title']} ({item['cwe']}) | {item['scope']} | Confiance : {item['confidence']}%",
                        expanded=True
                    ):
                        st.markdown(f"**Sévérité :** `{item['severity']}` | **Lignes du bloc :** `{item['start_line']}` à `{item['end_line']}`")
                        if item["dangerous_lines"]:
                            st.markdown("**Lignes dangereuses détectées :**")
                            for dl in item["dangerous_lines"]:
                                st.code(f"Ligne {dl['line_number']}: {dl['code'].strip()}", language="python")

                        st.markdown(f"**Pourquoi est-ce dangereux ?** {item['description']}")
                        st.info(f"**Solution recommandée :** {item['remediation']}")
                        st.markdown("**Exemple de correction sécurisée :**")
                        st.code(item["secure_example"], language="python")

                        with st.expander("Voir les probabilités multiclasses du modèle"):
                            prob_df = pd.DataFrame(
                                list(item["probabilities"].items()),
                                columns=["Classe", "Probabilité (%)"]
                            ).sort_values(by="Probabilité (%)", ascending=False)
                            st.dataframe(prob_df, hide_index=True, use_container_width=True)

with tab_metrics:
    st.subheader("Matrice de confusion sur le jeu de test (20%)")
    cm_df = pd.DataFrame(
        metrics["confusion_matrix"],
        index=[f"Réel: {l}" for l in metrics["labels"]],
        columns=[f"Prédit: {l}" for l in metrics["labels"]]
    )
    st.dataframe(cm_df, use_container_width=True)

    st.subheader("Métriques par classe (Precision, Recall, F1-Score)")
    rep_rows = []
    for label in metrics["labels"]:
        r = metrics["classification_report"][label]
        rep_rows.append({
            "Classe": label,
            "Precision": f"{r['precision']*100:.2f}%",
            "Recall": f"{r['recall']*100:.2f}%",
            "F1-Score": f"{r['f1-score']*100:.2f}%",
            "Support": int(r["support"])
        })
    st.dataframe(pd.DataFrame(rep_rows), hide_index=True, use_container_width=True)