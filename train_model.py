import os
import time
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")           # non-interactive backend (no GUI needed)
import matplotlib.pyplot as plt

from sklearn.ensemble          import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model      import LogisticRegression
from sklearn.naive_bayes       import MultinomialNB
from sklearn.svm               import LinearSVC
from sklearn.metrics           import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix,
    classification_report, ConfusionMatrixDisplay
)

# ─────────────────────────────────────────────
# 1.  LOAD PREPROCESSED DATA
# ─────────────────────────────────────────────

def load_data(processed_dir: str = "processed/"):
    """Load the .npy arrays saved by preprocess.py."""
    print(f"\n[train] Loading data from '{processed_dir}'...")

    X_train = np.load(os.path.join(processed_dir, "X_train.npy"), allow_pickle=True)
    X_test  = np.load(os.path.join(processed_dir, "X_test.npy"),  allow_pickle=True)
    y_train = np.load(os.path.join(processed_dir, "y_train.npy"))
    y_test  = np.load(os.path.join(processed_dir, "y_test.npy"))

    print(f"[train] X_train: {X_train.shape}  |  X_test: {X_test.shape}")
    print(f"[train] Train positives (phishing): {y_train.sum()} / {len(y_train)}")
    print(f"[train] Test  positives (phishing): {y_test.sum()}  / {len(y_test)}\n")
    return X_train, X_test, y_train, y_test


# ─────────────────────────────────────────────
# 2.  DEFINE CANDIDATE MODELS
# ─────────────────────────────────────────────

def get_models(mode: str = "url") -> dict:
    """
    Return a dictionary of {name: model} to try.

    For URL mode  → tree-based models work best with tabular features.
    For email mode→ Naive Bayes / LogReg work well with sparse TF-IDF.

    Note: MultinomialNB requires non-negative inputs (TF-IDF is fine,
    scaled URL features can be negative → excluded from url mode).
    """
    url_models = {
        "Random Forest": RandomForestClassifier(
            n_estimators  = 200,
            max_depth     = None,
            min_samples_leaf = 2,
            class_weight  = "balanced",   # handle class imbalance
            random_state  = 42,
            n_jobs        = -1
        ),
        "Gradient Boosting": GradientBoostingClassifier(
            n_estimators  = 150,
            learning_rate = 0.1,
            max_depth     = 5,
            random_state  = 42
        ),
        "Logistic Regression": LogisticRegression(
            max_iter      = 1000,
            class_weight  = "balanced",
            solver        = "lbfgs",
            C             = 1.0,
            random_state  = 42
        ),
        "Linear SVM": LinearSVC(
            max_iter      = 2000,
            class_weight  = "balanced",
            C             = 1.0,
            random_state  = 42
        ),
    }

    email_models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression": LogisticRegression(
            max_iter      = 1000,
            class_weight  = "balanced",
            solver        = "lbfgs",
            C             = 1.0,
            random_state  = 42
        ),
        "Linear SVM": LinearSVC(
            max_iter      = 2000,
            class_weight  = "balanced",
            C             = 0.5,
            random_state  = 42
        ),
        "Random Forest": RandomForestClassifier(
            n_estimators  = 100,
            class_weight  = "balanced",
            random_state  = 42,
            n_jobs        = -1
        ),
    }

    return url_models if mode == "url" else email_models


# ─────────────────────────────────────────────
# 3.  TRAIN & EVALUATE ALL MODELS
# ─────────────────────────────────────────────

def evaluate_model(model, X_test, y_test, model_name: str) -> dict:
    """
    Run predictions and return a metrics dictionary.
    LinearSVC doesn't support predict_proba, so ROC-AUC uses
    decision_function scores instead.
    """
    y_pred = model.predict(X_test)

    # ROC-AUC (needs probability or decision score)
    if hasattr(model, "predict_proba"):
        y_score = model.predict_proba(X_test)[:, 1]
    elif hasattr(model, "decision_function"):
        y_score = model.decision_function(X_test)
    else:
        y_score = y_pred   # fallback (poor AUC estimate)

    metrics = {
        "model"     : model_name,
        "accuracy"  : accuracy_score(y_test, y_pred),
        "precision" : precision_score(y_test, y_pred, zero_division=0),
        "recall"    : recall_score(y_test, y_pred, zero_division=0),
        "f1"        : f1_score(y_test, y_pred, zero_division=0),
        "roc_auc"   : roc_auc_score(y_test, y_score),
    }
    return metrics, y_pred


def train_all_models(X_train, X_test, y_train, y_test,
                     mode: str = "url") -> tuple:
    """
    Train every candidate model, evaluate, print a comparison table,
    and return (results_list, best_model_name, best_model).
    """
    models  = get_models(mode)
    results = []
    trained = {}

    print("=" * 62)
    print(f"  Training {len(models)} models — mode: {mode.upper()}")
    print("=" * 62)

    for name, model in models.items():
        print(f"\n[train] ▶  {name}")
        t0 = time.time()
        model.fit(X_train, y_train)
        elapsed = time.time() - t0

        metrics, y_pred = evaluate_model(model, X_test, y_test, name)
        metrics["train_time_s"] = round(elapsed, 2)
        results.append(metrics)
        trained[name] = (model, y_pred)

        print(f"         Accuracy  : {metrics['accuracy']:.4f}")
        print(f"         Precision : {metrics['precision']:.4f}")
        print(f"         Recall    : {metrics['recall']:.4f}")
        print(f"         F1-score  : {metrics['f1']:.4f}")
        print(f"         ROC-AUC   : {metrics['roc_auc']:.4f}")
        print(f"         Train time: {elapsed:.2f}s")

    # ── Comparison table ──────────────────────────────────────────
    results_df = pd.DataFrame(results).set_index("model")
    results_df = results_df.sort_values("f1", ascending=False)

    print("\n" + "=" * 62)
    print("  MODEL COMPARISON (sorted by F1-score)")
    print("=" * 62)
    print(results_df[["accuracy","precision","recall","f1","roc_auc"]].to_string())
    print("=" * 62)

    # ── Pick best by F1 ───────────────────────────────────────────
    best_name  = results_df.index[0]
    best_model = trained[best_name][0]
    best_pred  = trained[best_name][1]

    print(f"\n[train] ★  Best model: {best_name}  (F1 = {results_df.loc[best_name,'f1']:.4f})\n")
    return results_df, best_name, best_model, best_pred


# ─────────────────────────────────────────────
# 4.  DETAILED REPORT ON BEST MODEL
# ─────────────────────────────────────────────

def print_full_report(model, X_test, y_test, y_pred, model_name: str):
    """Print classification report and confusion matrix for best model."""
    print(f"\n{'─'*50}")
    print(f"  Full Classification Report — {model_name}")
    print(f"{'─'*50}")
    print(classification_report(
        y_test, y_pred,
        target_names=["Legitimate (0)", "Phishing (1)"]
    ))

    cm = confusion_matrix(y_test, y_pred)
    print("  Confusion Matrix:")
    print(f"  {'':20s}  Pred Legit  Pred Phish")
    print(f"  {'True Legit':20s}  {cm[0,0]:10d}  {cm[0,1]:10d}")
    print(f"  {'True Phish':20s}  {cm[1,0]:10d}  {cm[1,1]:10d}")
    print()

    # ── False positive / negative analysis ───────────────────────
    fp = cm[0, 1]   # legit classified as phishing (annoying for user)
    fn = cm[1, 0]   # phishing missed (dangerous!)
    print(f"  False Positives (legit flagged as phishing): {fp}")
    print(f"  False Negatives (phishing missed!):          {fn}  ← minimize this!")


# ─────────────────────────────────────────────
# 5.  FEATURE IMPORTANCE (URL mode only)
# ─────────────────────────────────────────────

def plot_feature_importance(model, processed_dir: str = "processed/",
                            output_dir: str = "outputs/"):
    """
    For tree-based models, plot and save a feature importance bar chart.
    Skips gracefully for models that don't support feature_importances_.
    """
    if not hasattr(model, "feature_importances_"):
        print("[train] (Feature importance plot not available for this model type)")
        return

    try:
        feature_names = joblib.load(os.path.join(processed_dir, "feature_names.pkl"))
    except FileNotFoundError:
        print("[train] feature_names.pkl not found — skipping importance plot")
        return

    importances = model.feature_importances_
    indices     = np.argsort(importances)[::-1]
    top_n       = min(15, len(feature_names))

    os.makedirs(output_dir, exist_ok=True)
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(range(top_n),
           importances[indices[:top_n]],
           color="#2a78d6", edgecolor="white")
    ax.set_xticks(range(top_n))
    ax.set_xticklabels(
        [feature_names[i] for i in indices[:top_n]],
        rotation=45, ha="right", fontsize=9
    )
    ax.set_ylabel("Importance Score")
    ax.set_title("Top Feature Importances – Phishing Detection")
    plt.tight_layout()
    path = os.path.join(output_dir, "feature_importance.png")
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"[train] Feature importance chart saved → {path}")


# ─────────────────────────────────────────────
# 6.  SAVE BEST MODEL
# ─────────────────────────────────────────────

def save_model(model, model_name: str, output_dir: str = "outputs/"):
    """Save the trained model to disk using joblib."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "model.pkl")
    joblib.dump(model, path)
    print(f"[train] ✓ Model saved → {path}")
    print(f"[train]   Model type : {model_name}")
    size_kb = os.path.getsize(path) / 1024
    print(f"[train]   File size  : {size_kb:.1f} KB")
    return path


# ─────────────────────────────────────────────
# 7.  SINGLE-SAMPLE PREDICTION DEMO
# ─────────────────────────────────────────────

def demo_predictions(model, mode: str = "url"):
    """
    Run the trained model on a few hard-coded examples so you can
    visually verify it is working correctly before deploying.
    """
    print("\n" + "─" * 50)
    print("  DEMO PREDICTIONS")
    print("─" * 50)

    if mode == "url":
        from preprocess import preprocess_single_url
        test_cases = [
            ("https://www.google.com",                   "Legit"),
            ("http://secure-login-paypal.xyz/verify",    "Phishing"),
            ("https://www.amazon.com/dp/B09XY12345",     "Legit"),
            ("http://192.168.1.1/login/account/confirm", "Phishing"),
            ("https://github.com/login",                 "Legit"),
            ("http://amaz0n-update.tk/account/suspend",  "Phishing"),
        ]
        for url, expected in test_cases:
            try:
                x     = preprocess_single_url(url)
                pred  = model.predict(x)[0]
                label = "⚠ PHISHING" if pred == 1 else "✓ LEGIT"
                match = "✓" if (pred == 1) == (expected == "Phishing") else "✗"
                print(f"  {match} [{label}]  {url[:55]}")
            except Exception as e:
                print(f"  [error] {url[:50]} — {e}")

    elif mode == "email":
        from preprocess import preprocess_single_email
        test_cases = [
            ("Dear customer, your PayPal account has been suspended. "
             "Click here immediately to verify your identity and avoid permanent closure.",
             "Phishing"),
            ("Hi team, please find the meeting notes attached. "
             "Let me know if you have questions. Best regards.",
             "Legit"),
        ]
        for text, expected in test_cases:
            try:
                x     = preprocess_single_email(text)
                pred  = model.predict(x)[0]
                label = "⚠ PHISHING" if pred == 1 else "✓ LEGIT"
                match = "✓" if (pred == 1) == (expected == "Phishing") else "✗"
                print(f"  {match} [{label}]  \"{text[:55]}...\"")
            except Exception as e:
                print(f"  [error] {e}")

    print()


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def run_training(
    processed_dir : str = "processed/",
    output_dir    : str = "outputs/",
    mode          : str = "url",        # must match what preprocess.py used
):
    """
    Master training pipeline:
      1. Load preprocessed data
      2. Train & compare all candidate models
      3. Print full report for the best model
      4. Plot feature importance (URL mode)
      5. Save best model to outputs/model.pkl
      6. Run demo predictions
    """
    # Step 1
    X_train, X_test, y_train, y_test = load_data(processed_dir)

    # Step 2
    results_df, best_name, best_model, best_pred = train_all_models(
        X_train, X_test, y_train, y_test, mode
    )

    # Step 3
    print_full_report(best_model, X_test, y_test, best_pred, best_name)

    # Step 4
    if mode == "url":
        plot_feature_importance(best_model, processed_dir, output_dir)

    # Step 5
    save_model(best_model, best_name, output_dir)

    # Step 6
    #demo_predictions(best_model, mode)

    print("[train] ✓ All done! Next step → run  python app.py")
    return best_model


if __name__ == "__main__":
    # ── CONFIGURE HERE ────────────────────────────────────────────
    # Change mode to "email" if you preprocessed email data.

    run_training(
        processed_dir = "processed/",
        output_dir    = "outputs/",
        mode          = "url",     # change to "email" if needed
    )