import os
import re
import pickle
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
DATASET_PATH = r"D:\Semester5\NLP\CyberLens\datasets\threat\Cybersecurity_Dataset.csv"

MODEL_PATH = r"D:\Semester5\NLP\CyberLens\models\cyberlens_threat_category_model.pkl"
print("=" * 70)
print("CYBERLENS - THREAT CATEGORY MODEL TRAINING")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Dataset loaded successfully.")
print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")

print("\nAvailable columns:")
for column in df.columns:
    print(" -", column)

df.columns = [
    str(column).strip()
    for column in df.columns
]

TARGET_COLUMN = "Threat Category"

if TARGET_COLUMN not in df.columns:
    raise ValueError(
        f"\nERROR: '{TARGET_COLUMN}' column was not found.\n"
        f"Available columns: {list(df.columns)}"
    )
LEAKAGE_COLUMNS = [
    "Predicted Threat Category"
]

for column in LEAKAGE_COLUMNS:
    if column in df.columns:
        df = df.drop(columns=[column])
        print(f"\nRemoved leakage column: {column}")

print("\nPreparing NLP input...")
TEXT_COLUMNS = [
    "Cleaned Threat Description",
    "IOCs (Indicators of Compromise)",
    "Threat Actor",
    "Attack Vector",
    "Geographical Location",
    "Keyword Extraction",
    "Named Entities (NER)",
    "Topic Modeling Labels"
]

available_text_columns = [
    column
    for column in TEXT_COLUMNS
    if column in df.columns
]

print("\nText features used:")

for column in available_text_columns:
    print(" -", column)

if not available_text_columns:
    raise ValueError(
        "No suitable text columns were found in the dataset."
    )

def combine_text(row):

    parts = []

    for column in available_text_columns:

        value = row[column]

        if pd.notna(value):

            value = str(value).strip()

            if value:
                parts.append(value)

    return " ".join(parts)


df["combined_text"] = df.apply(
    combine_text,
    axis=1
)

def clean_text(text):

    text = str(text).lower()
    text = re.sub(r"[\[\]{}()]", " ", text)
    text = text.replace("_", " ")
    text = re.sub(r"\s+", " ", text)

    return text.strip()


df["combined_text"] = df["combined_text"].apply(
    clean_text
)

df = df[
    (df["combined_text"].str.len() > 0)
    &
    (df[TARGET_COLUMN].notna())
].copy()

df[TARGET_COLUMN] = (
    df[TARGET_COLUMN]
    .astype(str)
    .str.strip()
)
df = df[
    df[TARGET_COLUMN] != ""
].copy()

print("\nDataset after cleaning:")
print(f"Rows: {len(df):,}")

print("\nThreat Category Distribution")
print("=" * 40)

class_distribution = (
    df[TARGET_COLUMN]
    .value_counts()
)

print(class_distribution)

print(
    f"\nNumber of threat categories: "
    f"{df[TARGET_COLUMN].nunique()}"
)

X = df["combined_text"]

y = df[TARGET_COLUMN]

print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"Training samples : {len(X_train):,}")
print(f"Testing samples  : {len(X_test):,}")

print("\nBuilding NLP classification pipeline...")

model = Pipeline(
    [
        (
            "tfidf",
            TfidfVectorizer(
                ngram_range=(1, 2),
                min_df=2,
                max_df=0.98,
                sublinear_tf=True,
                max_features=50000
            )
        ),

        (
            "classifier",
            LinearSVC(
                C=1.5,
                class_weight="balanced",
                random_state=42
            )
        )
    ]
)
print("\nStarting NLP model training...")
print("TF-IDF + Linear SVM")

model.fit(
    X_train,
    y_train
)

print("\nTraining completed successfully.")
print("\nGenerating predictions...")

y_pred = model.predict(X_test)
accuracy = accuracy_score(
    y_test,
    y_pred
)

precision = precision_score(
    y_test,
    y_pred,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_test,
    y_pred,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_test,
    y_pred,
    average="weighted",
    zero_division=0
)

print("\n")
print("=" * 70)
print("MODEL EVALUATION")
print("=" * 70)

print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1 Score  : {f1 * 100:.2f}%")
print("\n")
print("=" * 70)
print("CLASSIFICATION REPORT")
print("=" * 70)

print(
    classification_report(
        y_test,
        y_pred,
        zero_division=0
    )
)
print("\n")
print("=" * 70)
print("CONFUSION MATRIX")
print("=" * 70)

labels = sorted(
    y.unique()
)

cm = confusion_matrix(
    y_test,
    y_pred,
    labels=labels
)

cm_df = pd.DataFrame(
    cm,
    index=labels,
    columns=labels
)

print(cm_df)
print("\n")
print("=" * 70)
print("MODEL INFORMATION")
print("=" * 70)

tfidf = model.named_steps["tfidf"]

print(
    f"Vocabulary size : "
    f"{len(tfidf.vocabulary_):,}"
)

print(
    f"Number of classes: "
    f"{len(model.classes_)}"
)

print("\nClasses:")

for category in model.classes_:
    print(" -", category)
print("\n")
print("=" * 70)
print("SAVING MODEL")
print("=" * 70)

with open(
    MODEL_PATH,
    "wb"
) as file:

    pickle.dump(
        model,
        file
    )

print(
    f"\nModel saved successfully to:\n"
    f"{MODEL_PATH}"
)
print("\n")
print("=" * 70)
print("SAMPLE PREDICTIONS")
print("=" * 70)

sample_texts = [
    "phishing email containing malicious login link",
    "ransomware encrypted files and demanded payment",
    "distributed denial of service attack against public website",
    "malware executable delivered through email attachment"
]

sample_predictions = model.predict(
    sample_texts
)

for text, prediction in zip(
    sample_texts,
    sample_predictions
):

    print("\nInput:")
    print(text)

    print("Predicted Threat Category:")
    print(prediction)

print("\n")
print("=" * 70)
print("CYBERLENS THREAT CATEGORY TRAINING COMPLETE")
print("=" * 70)

print(
    f"\nFinal Accuracy : {accuracy * 100:.2f}%"
)

print(
    f"Final F1 Score : {f1 * 100:.2f}%"
)

print(
    f"\nModel location:\n{MODEL_PATH}"
)