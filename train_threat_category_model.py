import os
import json
import pickle

import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# CYBERLENS - THREAT CATEGORY NLP MODEL
# ============================================================

print("=" * 70)
print("CYBERLENS - THREAT CATEGORY NLP MODEL TRAINING")
print("=" * 70)


# ============================================================
# 1. PATHS
# ============================================================

BASE_DIR = r"D:\Semester5\NLP\CyberLens"

DATASET_1 = os.path.join(
    BASE_DIR,
    "datasets",
    "threat_category",
    "train.jsonl"
)

DATASET_2 = os.path.join(
    BASE_DIR,
    "datasets",
    "threat_category",
    "eval.jsonl"
)

MODEL_DIR = os.path.join(
    BASE_DIR,
    "static",
    "model",
    "threat_category"
)

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "threat_category_model.pkl"
)


# ============================================================
# 2. CHECK FILES
# ============================================================

print("\nChecking dataset files...")

for path in [DATASET_1, DATASET_2]:

    if os.path.exists(path):
        print(f"FOUND: {path}")

    else:
        print(f"ERROR: File not found:")
        print(path)
        raise FileNotFoundError(path)


# ============================================================
# 3. LOAD JSONL DATASET
# ============================================================

def load_jsonl_dataset(path):

    records = []

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)

                metadata = record.get(
                    "metadata",
                    {}
                )

                instruction = str(
                    record.get(
                        "instruction",
                        ""
                    )
                )

                input_text = str(
                    record.get(
                        "input",
                        ""
                    )
                )

                category = metadata.get(
                    "category"
                )

                if category:

                    records.append({

                        "instruction": instruction,

                        "input": input_text,

                        "category": category

                    })

            except json.JSONDecodeError:

                continue

    return pd.DataFrame(records)


# ============================================================
# 4. LOAD BOTH DATASETS
# ============================================================

print("\nLoading Dataset 1...")

df1 = load_jsonl_dataset(DATASET_1)

print(
    f"Dataset 1 records: {len(df1):,}"
)


print("\nLoading Dataset 2...")

df2 = load_jsonl_dataset(DATASET_2)

print(
    f"Dataset 2 records: {len(df2):,}"
)


# ============================================================
# 5. COMBINE DATASETS
# ============================================================

df = pd.concat(
    [df1, df2],
    ignore_index=True
)


print("\n" + "=" * 70)
print("COMBINED DATASET")
print("=" * 70)

print(
    f"Total records: {len(df):,}"
)


# ============================================================
# 6. REMOVE MISSING VALUES
# ============================================================

df = df.dropna(
    subset=[
        "instruction",
        "input",
        "category"
    ]
).copy()


# ============================================================
# 7. REMOVE DUPLICATES
# ============================================================

before_duplicates = len(df)

df = df.drop_duplicates(
    subset=[
        "instruction",
        "input",
        "category"
    ]
).reset_index(
    drop=True
)

duplicates_removed = (
    before_duplicates - len(df)
)

print(
    f"Duplicates removed: {duplicates_removed:,}"
)


# ============================================================
# 8. CREATE NLP INPUT
# ============================================================

print("\nCreating NLP text representation...")

df["text"] = (

    "Instruction: "
    + df["instruction"].astype(str)

    + " Input: "
    + df["input"].astype(str)

)


# ============================================================
# 9. CATEGORY ANALYSIS
# ============================================================

category_counts = (
    df["category"]
    .value_counts()
)


print(
    f"\nNumber of threat categories: "
    f"{len(category_counts)}"
)

print("\nThreat Category Distribution:")

print(category_counts.to_string())


# ============================================================
# 10. TRAIN / TEST SPLIT
# ============================================================

X = df["text"]

y = df["category"]


X_train, X_test, y_train, y_test = train_test_split(

    X,
    y,

    test_size=0.20,

    random_state=42,

    stratify=y
)


print("\n" + "=" * 70)
print("DATASET SPLIT")
print("=" * 70)

print(
    f"Training samples : {len(X_train):,}"
)

print(
    f"Testing samples  : {len(X_test):,}"
)


# ============================================================
# 11. NLP FEATURE EXTRACTION
# ============================================================

print("\nBuilding NLP feature pipeline...")

print(
    "Using Word + Character TF-IDF features"
)


features = FeatureUnion([

    (
        "word_tfidf",

        TfidfVectorizer(

            lowercase=True,

            strip_accents="unicode",

            ngram_range=(1, 2),

            min_df=2,

            max_df=0.98,

            sublinear_tf=True,

            max_features=100000
        )
    ),

    (
        "char_tfidf",

        TfidfVectorizer(

            analyzer="char_wb",

            ngram_range=(3, 5),

            min_df=2,

            sublinear_tf=True,

            max_features=100000
        )
    )

])


# ============================================================
# 12. LINEAR SVM NLP CLASSIFIER
# ============================================================

model = Pipeline([

    (
        "features",
        features
    ),

    (
        "classifier",

        LinearSVC(

            C=1.5,

            class_weight="balanced",

            random_state=42,

            max_iter=5000
        )
    )

])


# ============================================================
# 13. TRAIN MODEL
# ============================================================

print("\n" + "=" * 70)
print("STARTING THREAT CATEGORY MODEL TRAINING")
print("=" * 70)

print(
    "\nThis is a TF-IDF + LinearSVC NLP model."
)

print(
    "No BERT / GPU is required."
)

print(
    "Training should be considerably faster than the NER model."
)


model.fit(
    X_train,
    y_train
)


print("\nTraining completed successfully.")


# ============================================================
# 14. PREDICTIONS
# ============================================================

print("\nGenerating predictions...")

predictions = model.predict(
    X_test
)


# ============================================================
# 15. EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

precision = precision_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

recall = recall_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)

f1 = f1_score(
    y_test,
    predictions,
    average="weighted",
    zero_division=0
)


print("\n" + "=" * 70)
print("THREAT CATEGORY MODEL RESULTS")
print("=" * 70)

print(
    f"Accuracy  : {accuracy * 100:.2f}%"
)

print(
    f"Precision : {precision * 100:.2f}%"
)

print(
    f"Recall    : {recall * 100:.2f}%"
)

print(
    f"F1 Score  : {f1 * 100:.2f}%"
)

print("=" * 70)


# ============================================================
# 16. CLASSIFICATION REPORT
# ============================================================

print("\nDetailed Classification Report:\n")

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# ============================================================
# 17. CONFUSION MATRIX
# ============================================================

labels = sorted(
    df["category"].unique()
)

cm = confusion_matrix(
    y_test,
    predictions,
    labels=labels
)

cm_df = pd.DataFrame(
    cm,
    index=labels,
    columns=labels
)


print("\nConfusion Matrix:")

print(cm_df)


# ============================================================
# 18. SAVE MODEL
# ============================================================

print("\nSaving model...")

os.makedirs(
    MODEL_DIR,
    exist_ok=True
)


model_package = {

    "model": model,

    "categories": labels,

    "model_type":
        "TF-IDF Word + Character N-Grams + LinearSVC",

    "training_samples":
        len(X_train),

    "testing_samples":
        len(X_test),

    "accuracy":
        accuracy,

    "precision":
        precision,

    "recall":
        recall,

    "f1":
        f1

}


with open(
    MODEL_PATH,
    "wb"
) as file:

    pickle.dump(
        model_package,
        file
    )


# ============================================================
# 19. FINAL MESSAGE
# ============================================================

print("\n" + "=" * 70)
print("CYBERLENS THREAT CATEGORY TRAINING COMPLETE")
print("=" * 70)

print(
    f"\nModel saved to:\n{MODEL_PATH}"
)

print(
    f"\nCategories: {len(labels)}"
)

print(
    f"Accuracy  : {accuracy * 100:.2f}%"
)

print(
    f"Precision : {precision * 100:.2f}%"
)

print(
    f"Recall    : {recall * 100:.2f}%"
)

print(
    f"F1 Score  : {f1 * 100:.2f}%"
)

print("\nModel is ready for Module 3.")