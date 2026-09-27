import os
import json
import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

# ------------------------------------------------------------
# TRAINED MODELS
# ------------------------------------------------------------

PHISHING_MODEL = r"D:\Semester5\NLP\CyberLens\models\phishing_hybrid_model.pkl"

THREAT_MODEL = Path(
    r"D:\Semester5\NLP\CyberLens\models\cyberlens_threat_category_model.pkl"
)

NER_MODEL = Path(
    r"D:\Semester5\NLP\CyberLens\models\cyberlens_ner"
)


# ------------------------------------------------------------
# DATASETS
# ------------------------------------------------------------

PHISHING_DATASET = Path(
    r"D:\Semester5\NLP\CyberLens\datasets\Phishing_Site.csv"
)

THREAT_DATASET = Path(
    r"D:\Semester5\NLP\CyberLens\datasets\Cybersecurity_Dataset.csv"
)

CYNER_TEST_FILE = Path(
    r"D:\Semester5\NLP\CyberLens\datasets\CyNER\test.txt"
)

DNRTI_TEST_FILE = Path(
    r"D:\Semester5\NLP\CyberLens\datasets\DNRTI\test.txt"
)


# ============================================================
# HELPER
# ============================================================

def print_header(title):

    print("\n")
    print("=" * 70)
    print(title)
    print("=" * 70)


# ============================================================
# 1. PHISHING MODEL
# ============================================================

def evaluate_phishing():

    print_header("1. PHISHING DETECTION EVALUATION")

    if not PHISHING_MODEL.exists():
        print("ERROR: Phishing model not found:")
        print(PHISHING_MODEL)
        return

    if not PHISHING_DATASET.exists():
        print("ERROR: Phishing dataset not found:")
        print(PHISHING_DATASET)
        return

    print("Loading phishing model...")

    model = joblib.load(PHISHING_MODEL)

    print("Model loaded successfully.")

    print("\nLoading phishing dataset...")

    df = pd.read_csv(PHISHING_DATASET)

    print("Dataset shape:", df.shape)

    print("\nDataset columns:")
    print(list(df.columns))

    # --------------------------------------------------------
    # FIND URL COLUMN
    # --------------------------------------------------------

    possible_url_columns = [
        "URL",
        "Url",
        "url",
        "Website",
        "website",
        "Link",
        "link"
    ]

    url_column = None

    for column in possible_url_columns:
        if column in df.columns:
            url_column = column
            break

    if url_column is None:

        print("\nERROR: Could not identify URL column.")

        print(
            "Expected one of:",
            possible_url_columns
        )

        return

    # --------------------------------------------------------
    # FIND LABEL COLUMN
    # --------------------------------------------------------

    possible_label_columns = [
        "Label",
        "label",
        "Class",
        "class",
        "Target",
        "target"
    ]

    label_column = None

    for column in possible_label_columns:
        if column in df.columns:
            label_column = column
            break

    if label_column is None:

        print("\nERROR: Could not identify label column.")

        print(
            "Expected one of:",
            possible_label_columns
        )

        return

    print("\nURL column:", url_column)
    print("Label column:", label_column)

    # --------------------------------------------------------
    # REMOVE MISSING VALUES
    # --------------------------------------------------------

    df = df[
        df[url_column].notna()
        & df[label_column].notna()
    ].copy()

    X = df[url_column].astype(str)

    y = df[label_column]

    # --------------------------------------------------------
    # CONVERT COMMON STRING LABELS
    # --------------------------------------------------------

    if y.dtype == object:

        y = (
            y.astype(str)
            .str.strip()
            .str.lower()
        )

        mapping = {
            "phishing": 1,
            "malicious": 1,
            "bad": 1,
            "1": 1,

            "legitimate": 0,
            "benign": 0,
            "safe": 0,
            "good": 0,
            "0": 0
        }

        y = y.map(mapping)

    y = pd.to_numeric(
        y,
        errors="coerce"
    )

    valid = y.notna()

    X = X[valid]
    y = y[valid].astype(int)

    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    print("\nGenerating predictions...")

    predictions = model.predict(X)

    predictions = np.asarray(
        predictions
    ).astype(int)

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y,
        predictions
    )

    precision = precision_score(
        y,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y,
        predictions,
        zero_division=0
    )

    # --------------------------------------------------------
    # CONFUSION MATRIX
    # --------------------------------------------------------

    cm = confusion_matrix(
        y,
        predictions,
        labels=[0, 1]
    )

    tn, fp, fn, tp = cm.ravel()

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print("\nPHISHING RESULTS")
    print("-" * 40)

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1-score  : {f1:.4f}"
    )

    print("\nCONFUSION MATRIX")
    print("-" * 40)

    print(
        f"True Negatives  (TN): {tn}"
    )

    print(
        f"False Positives (FP): {fp}"
    )

    print(
        f"False Negatives (FN): {fn}"
    )

    print(
        f"True Positives  (TP): {tp}"
    )

    print("\nClassification Report")
    print("-" * 40)

    print(
        classification_report(
            y,
            predictions,
            zero_division=0
        )
    )


# ============================================================
# 2. THREAT CLASSIFICATION
# ============================================================

def evaluate_threat_classification():

    print_header("2. THREAT CLASSIFICATION EVALUATION")

    if not THREAT_MODEL.exists():

        print("ERROR: Threat model not found:")
        print(THREAT_MODEL)

        return

    if not THREAT_DATASET.exists():

        print("ERROR: Threat dataset not found:")
        print(THREAT_DATASET)

        return

    print("Loading threat classification model...")

    model = joblib.load(
        THREAT_MODEL
    )

    print("Model loaded successfully.")

    print("\nLoading threat dataset...")

    df = pd.read_csv(
        THREAT_DATASET
    )

    print(
        "Dataset shape:",
        df.shape
    )

    print("\nDataset columns:")
    print(list(df.columns))

    # --------------------------------------------------------
    # TARGET COLUMN
    # --------------------------------------------------------

    target_column = None

    possible_targets = [
        "Threat Category",
        "Threat_Category",
        "ThreatCategory",
        "threat_category",
        "Label",
        "label"
    ]

    for column in possible_targets:

        if column in df.columns:

            target_column = column
            break

    if target_column is None:

        print(
            "\nERROR: Threat Category column "
            "could not be found."
        )

        return

    print(
        "\nTarget column:",
        target_column
    )

    # --------------------------------------------------------
    # REMOVE DATA LEAKAGE COLUMN
    # --------------------------------------------------------

    leakage_columns = [
        "Predicted Threat Category",
        "Predicted_Threat_Category"
    ]

    for column in leakage_columns:

        if column in df.columns:

            df = df.drop(
                columns=[column]
            )

    # --------------------------------------------------------
    # BUILD TEXT INPUT
    # --------------------------------------------------------

    excluded_columns = {
        target_column,
        "id",
        "ID"
    }

    text_columns = []

    for column in df.columns:

        if column in excluded_columns:
            continue

        if df[column].dtype == object:

            text_columns.append(
                column
            )

    if not text_columns:

        print(
            "\nERROR: No textual input columns found."
        )

        return

    print(
        "\nText columns used:"
    )

    for column in text_columns:

        print(
            " -",
            column
        )

    # Combine textual fields.

    df["combined_text"] = (
        df[text_columns]
        .fillna("")
        .astype(str)
        .agg(" ".join, axis=1)
    )

    df = df[
        df["combined_text"].str.strip() != ""
    ]

    df = df[
        df[target_column].notna()
    ]

    X = df["combined_text"]

    y = df[target_column].astype(str)

    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    print("\nGenerating predictions...")

    predictions = model.predict(X)

    predictions = np.asarray(
        predictions
    ).astype(str)

    # --------------------------------------------------------
    # METRICS
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y,
        predictions
    )

    precision = precision_score(
        y,
        predictions,
        average="weighted",
        zero_division=0
    )

    recall = recall_score(
        y,
        predictions,
        average="weighted",
        zero_division=0
    )

    f1 = f1_score(
        y,
        predictions,
        average="weighted",
        zero_division=0
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print("\nTHREAT CLASSIFICATION RESULTS")
    print("-" * 40)

    print(
        f"Accuracy          : {accuracy:.4f}"
    )

    print(
        f"Weighted Precision : {precision:.4f}"
    )

    print(
        f"Weighted Recall    : {recall:.4f}"
    )

    print(
        f"Weighted F1-score  : {f1:.4f}"
    )

    # --------------------------------------------------------
    # CLASSIFICATION REPORT
    # --------------------------------------------------------

    print("\nClassification Report")
    print("-" * 40)

    print(
        classification_report(
            y,
            predictions,
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # CONFUSION MATRIX
    # --------------------------------------------------------

    labels = sorted(
        list(
            set(y) | set(predictions)
        )
    )

    cm = confusion_matrix(
        y,
        predictions,
        labels=labels
    )

    print("\nConfusion Matrix")
    print("-" * 40)

    print(
        pd.DataFrame(
            cm,
            index=labels,
            columns=labels
        )
    )


# ============================================================
# 3. NER EVALUATION
# ============================================================

def read_bio_file(file_path):

    file_path = Path(file_path)

    if not file_path.exists():

        print(
            "\nERROR: NER test file not found:"
        )

        print(file_path)

        return []

    sentences = []

    tokens = []
    labels = []

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            # Blank line = end of sentence

            if not line:

                if tokens:

                    sentences.append(
                        (
                            tokens,
                            labels
                        )
                    )

                    tokens = []
                    labels = []

                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            token = parts[0]

            label = parts[-1]

            tokens.append(token)
            labels.append(label)

    if tokens:

        sentences.append(
            (
                tokens,
                labels
            )
        )

    return sentences


def evaluate_ner():

    print_header(
        "3. NAMED ENTITY RECOGNITION EVALUATION"
    )

    if not NER_MODEL.exists():

        print(
            "ERROR: NER model folder not found:"
        )

        print(NER_MODEL)

        return

    # --------------------------------------------------------
    # LOAD LABEL INFORMATION
    # --------------------------------------------------------

    label_file = (
        NER_MODEL
        / "label_information.json"
    )

    if not label_file.exists():

        print(
            "ERROR: label_information.json "
            "not found."
        )

        return

    with open(
        label_file,
        "r",
        encoding="utf-8"
    ) as file:

        label_info = json.load(file)

    labels = label_info["labels"]

    print(
        "Number of labels:",
        len(labels)
    )

    # --------------------------------------------------------
    # LOAD TRANSFORMERS
    # --------------------------------------------------------

    try:

        import torch

        from transformers import (
            AutoTokenizer,
            AutoModelForTokenClassification
        )

    except ImportError:

        print(
            "ERROR: Install transformers and torch."
        )

        return

    print("\nLoading NER model...")

    tokenizer = AutoTokenizer.from_pretrained(
        str(NER_MODEL)
    )

    model = AutoModelForTokenClassification.from_pretrained(
        str(NER_MODEL)
    )

    device = torch.device(
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    model.to(device)

    model.eval()

    print(
        "Device:",
        device
    )

    # --------------------------------------------------------
    # LOAD TEST DATA
    # --------------------------------------------------------

    print("\nLoading CyNER test data...")

    cyner_data = read_bio_file(
        CYNER_TEST_FILE
    )

    print(
        "CyNER sentences:",
        len(cyner_data)
    )

    print("\nLoading DNRTI test data...")

    dnrti_data = read_bio_file(
        DNRTI_TEST_FILE
    )

    print(
        "DNRTI sentences:",
        len(dnrti_data)
    )

    test_data = (
        cyner_data
        + dnrti_data
    )

    if not test_data:

        print(
            "\nNo NER test data was found."
        )

        print(
            "Update CYNER_TEST_FILE and "
            "DNRTI_TEST_FILE at the top of "
            "this script."
        )

        return

    print(
        "\nTotal test sentences:",
        len(test_data)
    )

    # --------------------------------------------------------
    # SEQEVAL
    # --------------------------------------------------------

    try:

        from seqeval.metrics import (
            precision_score,
            recall_score,
            f1_score,
            accuracy_score,
            classification_report
        )

    except ImportError:

        print(
            "\nseqeval is not installed."
        )

        print(
            "Run:"
        )

        print(
            "pip install seqeval"
        )

        return

    true_labels = []
    predicted_labels = []

    # --------------------------------------------------------
    # PREDICTION
    # --------------------------------------------------------

    print(
        "\nEvaluating NER model..."
    )

    for index, (words, gold_labels) in enumerate(
        test_data
    ):

        if index % 100 == 0:

            print(
                f"Processing sentence "
                f"{index + 1}/{len(test_data)}"
            )

        encoding = tokenizer(
            words,
            is_split_into_words=True,
            return_tensors="pt",
            truncation=True,
            padding=True
        )

        word_ids = encoding.word_ids(
            batch_index=0
        )

        inputs = {
            key: value.to(device)
            for key, value in encoding.items()
        }

        with torch.no_grad():

            outputs = model(
                **inputs
            )

        predictions = (
            torch.argmax(
                outputs.logits,
                dim=-1
            )
            .cpu()
            .numpy()[0]
        )

        sentence_predictions = []

        previous_word_id = None

        for token_index, word_id in enumerate(
            word_ids
        ):

            if word_id is None:
                continue

            # Only evaluate the first
            # sub-token of each word.

            if word_id == previous_word_id:
                continue

            predicted_id = predictions[
                token_index
            ]

            predicted_label = (
                model.config.id2label[
                    int(predicted_id)
                ]
            )

            sentence_predictions.append(
                predicted_label
            )

            previous_word_id = word_id

        # Make sure the lengths match.

        minimum_length = min(
            len(gold_labels),
            len(sentence_predictions)
        )

        gold_labels = gold_labels[
            :minimum_length
        ]

        sentence_predictions = (
            sentence_predictions[
                :minimum_length
            ]
        )

        true_labels.append(
            gold_labels
        )

        predicted_labels.append(
            sentence_predictions
        )

    # --------------------------------------------------------
    # NER METRICS
    # --------------------------------------------------------

    precision = precision_score(
        true_labels,
        predicted_labels,
        zero_division=0
    )

    recall = recall_score(
        true_labels,
        predicted_labels,
        zero_division=0
    )

    f1 = f1_score(
        true_labels,
        predicted_labels,
        zero_division=0
    )

    accuracy = accuracy_score(
        true_labels,
        predicted_labels
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    print("\nNER RESULTS")
    print("-" * 40)

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1-score  : {f1:.4f}"
    )

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print("\nNER Classification Report")
    print("-" * 40)

    print(
        classification_report(
            true_labels,
            predicted_labels,
            zero_division=0
        )
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print(
        "\n"
        "CYBERLENS MODEL EVALUATION"
    )

    print(
        "=" * 70
    )

    # --------------------------------------------------------
    # PHISHING
    # --------------------------------------------------------

    evaluate_phishing()

    # --------------------------------------------------------
    # THREAT CLASSIFICATION
    # --------------------------------------------------------

    evaluate_threat_classification()

    # --------------------------------------------------------
    # NER
    # --------------------------------------------------------

    evaluate_ner()

    print(
        "\n"
        "=" * 70
    )

    print(
        "MODEL EVALUATION COMPLETED"
    )

    print(
        "=" * 70
    )