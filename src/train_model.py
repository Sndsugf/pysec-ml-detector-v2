import os
import json
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, accuracy_score, f1_score, confusion_matrix

from src.dataset_builder import build_hybrid_balanced_dataset, OUTPUT_DATASET_PATH

MODEL_PATH = "models/vuln_classifier.joblib"
METRICS_PATH = "models/metrics_report.json"
TRAIN_SPLIT_PATH = "data/train_split.csv"
TEST_SPLIT_PATH = "data/test_split.csv"

def create_ml_pipeline() -> Pipeline:
    features = FeatureUnion([
        ("word_tfidf", TfidfVectorizer(
            token_pattern=r"[a-zA-Z_][a-zA-Z0-9_]*|==|!=|<=|>=|[+%\"'(){}\[\]=.]",
            ngram_range=(1, 3),
            max_features=8000,
            sublinear_tf=True
        )),
        ("char_tfidf", TfidfVectorizer(
            analyzer="char",
            ngram_range=(3, 6),
            max_features=12000,
            sublinear_tf=True
        ))
    ])

    base_svm = LinearSVC(C=1.5, class_weight="balanced", random_state=42, max_iter=3000)
    clf = CalibratedClassifierCV(base_svm, cv=3, method="sigmoid")

    return Pipeline([
        ("features", features),
        ("classifier", clf)
    ])

def train_and_evaluate():
    print("1. Construction du dataset hybride (Zenodo réel + complément équilibré)...")
    df, provenance_stats = build_hybrid_balanced_dataset(target_per_class=200, output_csv=OUTPUT_DATASET_PATH)

    class_counts = df["label"].value_counts().to_dict()
    source_counts = df["source"].value_counts().to_dict()
    print(f"   Total : {len(df)} échantillons | Sources : {source_counts}")

    train_df, test_df = train_test_split(
        df, test_size=0.20, random_state=42, stratify=df["label"]
    )
    train_df.to_csv(TRAIN_SPLIT_PATH, index=False, encoding="utf-8")
    test_df.to_csv(TEST_SPLIT_PATH, index=False, encoding="utf-8")

    X_train = train_df["code"].to_numpy(dtype=str)
    y_train = train_df["label"].to_numpy(dtype=str)
    X_test = test_df["code"].to_numpy(dtype=str)
    y_test = test_df["label"].to_numpy(dtype=str)

    pipeline = create_ml_pipeline()

    print("2. Validation croisée stratifiée (5-Fold sur Train 80%)...")
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=skf, scoring="f1_macro")
    print(f"   F1-Macro moyen (CV 5-fold) : {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

    print("3. Évaluation sur le jeu de test indépendant (Test 20%)...")
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    f1_macro = f1_score(y_test, y_pred, average="macro")
    report_dict = classification_report(y_test, y_pred, output_dict=True)
    report_str = classification_report(y_test, y_pred)
    labels = sorted(list(set(y_test)))
    cm = confusion_matrix(y_test, y_pred, labels=labels).tolist()

    print(f"\n   Accuracy Test : {acc*100:.2f}%")
    print(f"   F1-Macro Test : {f1_macro*100:.2f}%")
    print("\nRapport de classification détaillé :\n")
    print(report_str)

    # Ré-entraînement final sur 100% du dataset hybride
    pipeline.fit(df["code"].to_numpy(dtype=str), df["label"].to_numpy(dtype=str))
    os.makedirs("models", exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH)

    metrics_payload = {
        "dataset_size": len(df),
        "train_size": len(train_df),
        "test_size": len(test_df),
        "source_distribution": source_counts,
        "provenance_by_class": provenance_stats,
        "class_distribution": class_counts,
        "cv_f1_macro_mean": round(float(cv_scores.mean()), 4),
        "cv_f1_macro_std": round(float(cv_scores.std()), 4),
        "test_accuracy": round(float(acc), 4),
        "test_f1_macro": round(float(f1_macro), 4),
        "labels": labels,
        "confusion_matrix": cm,
        "classification_report": report_dict
    }
    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics_payload, f, indent=2, ensure_ascii=False)

    print(f"4. Modèle sauvegardé dans `{MODEL_PATH}` et splits dans `data/train_split.csv` / `data/test_split.csv`.")
    return metrics_payload

if __name__ == "__main__":
    train_and_evaluate()