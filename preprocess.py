import os
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import re


def clean_email_text(text):
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", " url ", text)
    text = re.sub(r"\S+@\S+", " email ", text)
    text = re.sub(r"\d+", " ", text)
    text = re.sub(r"[^\w\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_email_tfidf(train_texts, test_texts, max_features=3000):
    train_clean = train_texts.apply(clean_email_text)
    test_clean  = test_texts.apply(clean_email_text)
    vectorizer  = TfidfVectorizer(
        max_features=max_features,
        ngram_range=(1, 2),
        sublinear_tf=True,
        min_df=2,
        stop_words="english"
    )
    X_train = vectorizer.fit_transform(train_clean)
    X_test  = vectorizer.transform(test_clean)
    return X_train, X_test, vectorizer


def run_preprocessing(
    input_csv="webpagedataset_phishing.csv",
    output_dir="processed/",
    mode="url",
    url_col="url",
    text_col="email_text",
    label_col="status",
    test_size=0.2,
    random_state=42,
):
    os.makedirs(output_dir, exist_ok=True)

    print(f"\n[preprocess] Loading dataset: {input_csv}")
    df = pd.read_csv(input_csv)
    print(f"[preprocess] Shape: {df.shape}")
    print(f"[preprocess] Label distribution:\n{df[label_col].value_counts()}\n")

    key_col = url_col if mode == "url" else text_col
    df = df.dropna(subset=[key_col, label_col])

    # Convert text labels to numbers
    df[label_col] = df[label_col].map({"legitimate": 0, "phishing": 1})
    df[label_col] = df[label_col].astype(int)

    if mode == "url":
        drop_cols  = [url_col, label_col]
        feature_df = df.drop(columns=drop_cols, errors="ignore")
        X          = feature_df.values.astype(float)
        y          = df[label_col].values

        feature_names = feature_df.columns.tolist()
        joblib.dump(feature_names, os.path.join(output_dir, "feature_names.pkl"))
        print(f"[preprocess] Features used: {len(feature_names)}")

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )

        scaler  = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test  = scaler.transform(X_test)
        joblib.dump(scaler, os.path.join(output_dir, "scaler.pkl"))

    elif mode == "email":
        y         = df[label_col].values
        idx       = np.arange(len(df))
        train_idx, test_idx = train_test_split(
            idx, test_size=test_size, random_state=random_state, stratify=y
        )
        train_texts = df.iloc[train_idx][text_col]
        test_texts  = df.iloc[test_idx][text_col]
        X_train, X_test, vectorizer = build_email_tfidf(train_texts, test_texts)
        y_train = y[train_idx]
        y_test  = y[test_idx]
        joblib.dump(vectorizer, os.path.join(output_dir, "tfidf_vectorizer.pkl"))

    else:
        raise ValueError(f"mode must be 'url' or 'email', got '{mode}'")

    np.save(os.path.join(output_dir, "X_train.npy"), X_train)
    np.save(os.path.join(output_dir, "X_test.npy"),  X_test)
    np.save(os.path.join(output_dir, "y_train.npy"), y_train)
    np.save(os.path.join(output_dir, "y_test.npy"),  y_test)

    print(f"\n[preprocess] Done! Saved to '{output_dir}/'")
    print(f"[preprocess] X_train : {X_train.shape}")
    print(f"[preprocess] X_test  : {X_test.shape}")
    print(f"[preprocess] Phishing in train: {y_train.sum()} / {len(y_train)}")
    print("[preprocess] Now run: python train_model.py\n")

    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    run_preprocessing(
        input_csv    = "webpagedataset_phishing.csv",
        output_dir   = "processed/",
        mode         = "url",
        url_col      = "url",
        text_col     = "email_text",
        label_col    = "status",
        test_size    = 0.2,
        random_state = 42,
    )