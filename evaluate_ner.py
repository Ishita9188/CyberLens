import json
import numpy as np
import torch

from pathlib import Path
from datasets import Dataset
from transformers import (
    AutoTokenizer,
    AutoModelForTokenClassification,
    Trainer
)
from seqeval.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    classification_report
)


# ============================================================
# PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_DIR = BASE_DIR / "models" / "cyberlens_ner"

# CHANGE THESE TWO PATHS TO YOUR ACTUAL TEST FILES
CYNER_TEST = Path(r"D:\Semester5\NLP\CyberLens\datasets\ner\CyNER\test.txt")
DNRTI_TEST = Path(r"D:\Semester5\NLP\CyberLens\datasets\ner\DNRTI\test.txt")


# ============================================================
# CHECK MODEL
# ============================================================

print("\nChecking trained NER model...")

if not MODEL_DIR.exists():
    raise FileNotFoundError(
        f"Model folder not found:\n{MODEL_DIR}"
    )

print("Model folder:")
print(MODEL_DIR)

print("\nModel files:")

for file in MODEL_DIR.iterdir():
    print(" -", file.name)


# ============================================================
# LOAD LABEL INFORMATION
# ============================================================

label_file = MODEL_DIR / "label_information.json"

if not label_file.exists():
    raise FileNotFoundError(
        f"label_information.json not found:\n{label_file}"
    )

with open(
    label_file,
    "r",
    encoding="utf-8"
) as f:

    label_info = json.load(f)


print("\nLabel information loaded.")


# ============================================================
# DISPLAY LABEL INFORMATION
# ============================================================

print("\nLabel information:")

print(json.dumps(
    label_info,
    indent=4
))


# ============================================================
# EXTRACT LABEL MAPPINGS
# ============================================================

if "label2id" in label_info:

    label2id = {
        label: int(idx)
        for label, idx
        in label_info["label2id"].items()
    }

elif "label_to_id" in label_info:

    label2id = {
        label: int(idx)
        for label, idx
        in label_info["label_to_id"].items()
    }

else:

    raise KeyError(
        "Could not find label2id in label_information.json"
    )


if "id2label" in label_info:

    id2label = {
        int(idx): label
        for idx, label
        in label_info["id2label"].items()
    }

elif "id_to_label" in label_info:

    id2label = {
        int(idx): label
        for idx, label
        in label_info["id_to_label"].items()
    }

else:

    # Generate reverse mapping
    id2label = {
        idx: label
        for label, idx in label2id.items()
    }


print("\nNumber of labels:", len(label2id))

print("\nLabels:")

for idx in sorted(id2label):

    print(
        f"{idx} -> {id2label[idx]}"
    )


# ============================================================
# READ BIO DATASET
# ============================================================

def read_bio_file(file_path):

    if not file_path.exists():

        raise FileNotFoundError(
            f"\nTest dataset not found:\n{file_path}\n\n"
            "Update CYNER_TEST or DNRTI_TEST "
            "with the correct location."
        )

    sentences = []

    tokens = []
    tags = []

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            line = line.strip()

            # Sentence boundary
            if not line:

                if tokens:

                    sentences.append({
                        "tokens": tokens,
                        "tags": tags
                    })

                    tokens = []
                    tags = []

                continue

            parts = line.split()

            if len(parts) < 2:
                continue

            tokens.append(parts[0])
            tags.append(parts[-1])

    # Last sentence
    if tokens:

        sentences.append({
            "tokens": tokens,
            "tags": tags
        })

    return sentences


# ============================================================
# LABEL NORMALIZATION
# ============================================================

def normalize_tag(tag):

    if tag == "O":
        return "O"

    if tag.startswith("B-"):

        entity = tag[2:]

        return "B-" + entity

    if tag.startswith("I-"):

        entity = tag[2:]

        return "I-" + entity

    return tag


# ============================================================
# LOAD TEST DATA
# ============================================================

print("\nLoading test datasets...")

cyner_data = read_bio_file(
    CYNER_TEST
)

dnrti_data = read_bio_file(
    DNRTI_TEST
)

test_data = (
    cyner_data +
    dnrti_data
)


# Normalize tags

for sentence in test_data:

    sentence["tags"] = [
        normalize_tag(tag)
        for tag in sentence["tags"]
    ]


print(
    "\nCyNER test sentences:",
    len(cyner_data)
)

print(
    "DNRTI test sentences:",
    len(dnrti_data)
)

print(
    "Total test sentences:",
    len(test_data)
)


# ============================================================
# CREATE DATASET
# ============================================================

dataset = Dataset.from_list(
    test_data
)


# ============================================================
# LOAD TOKENIZER
# ============================================================

print("\nLoading tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    str(MODEL_DIR)
)


# ============================================================
# TOKENIZATION + LABEL ALIGNMENT
# ============================================================

def tokenize_and_align_labels(examples):

    tokenized = tokenizer(
        examples["tokens"],
        truncation=True,
        max_length=256,
        is_split_into_words=True
    )

    all_labels = []

    for batch_index, labels in enumerate(
        examples["tags"]
    ):

        word_ids = tokenized.word_ids(
            batch_index=batch_index
        )

        label_ids = []

        previous_word_id = None

        for word_id in word_ids:

            if word_id is None:

                label_ids.append(-100)

            elif word_id != previous_word_id:

                label = labels[word_id]

                if label in label2id:

                    label_ids.append(
                        label2id[label]
                    )

                else:

                    label_ids.append(-100)

            else:

                # Subword token

                label = labels[word_id]

                if label.startswith("B-"):

                    entity = label[2:]

                    continuation = "I-" + entity

                    if continuation in label2id:

                        label_ids.append(
                            label2id[continuation]
                        )

                    elif label in label2id:

                        label_ids.append(
                            label2id[label]
                        )

                    else:

                        label_ids.append(-100)

                elif label in label2id:

                    label_ids.append(
                        label2id[label]
                    )

                else:

                    label_ids.append(-100)

            previous_word_id = word_id

        all_labels.append(label_ids)

    tokenized["labels"] = all_labels

    return tokenized


print("\nTokenizing test data...")

tokenized_dataset = dataset.map(
    tokenize_and_align_labels,
    batched=True,
    remove_columns=[
        "tokens",
        "tags"
    ]
)


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

print("\nLoading trained model...")

model = AutoModelForTokenClassification.from_pretrained(
    str(MODEL_DIR)
)


# ============================================================
# DEVICE
# ============================================================

device = (
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

model.to(device)

print(
    "Evaluation device:",
    device
)


# ============================================================
# PREDICTION
# ============================================================

trainer = Trainer(
    model=model,
    tokenizer=tokenizer
)


print("\nGenerating predictions...")

prediction_output = trainer.predict(
    tokenized_dataset
)


logits = prediction_output.predictions

true_label_ids = prediction_output.label_ids


predicted_label_ids = np.argmax(
    logits,
    axis=2
)


# ============================================================
# CONVERT IDS TO LABELS
# ============================================================

true_predictions = []

true_labels = []


for predictions, labels in zip(
    predicted_label_ids,
    true_label_ids
):

    sentence_predictions = []

    sentence_labels = []

    for prediction, label in zip(
        predictions,
        labels
    ):

        # Ignore special/subword positions
        if label == -100:
            continue

        sentence_predictions.append(
            id2label[int(prediction)]
        )

        sentence_labels.append(
            id2label[int(label)]
        )

    true_predictions.append(
        sentence_predictions
    )

    true_labels.append(
        sentence_labels
    )


# ============================================================
# CALCULATE METRICS
# ============================================================

precision = precision_score(
    true_labels,
    true_predictions
)

recall = recall_score(
    true_labels,
    true_predictions
)

f1 = f1_score(
    true_labels,
    true_predictions
)

accuracy = accuracy_score(
    true_labels,
    true_predictions
)


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n")
print("=" * 65)

print(
    "CYBERLENS NER MODEL - TEST SET EVALUATION"
)

print("=" * 65)

print(
    f"Precision : {precision:.4f}"
)

print(
    f"Recall    : {recall:.4f}"
)

print(
    f"F1 Score  : {f1:.4f}"
)

print(
    f"Accuracy  : {accuracy:.4f}"
)

print("=" * 65)


# ============================================================
# DETAILED CLASSIFICATION REPORT
# ============================================================

print("\nDetailed Entity-Level Classification Report")
print("-" * 65)

print(
    classification_report(
        true_labels,
        true_predictions,
        digits=4
    )
)


# ============================================================
# SAVE RESULTS
# ============================================================

results = {

    "model": "CyberLens NER",

    "test_sentences": len(test_data),

    "precision": float(precision),

    "recall": float(recall),

    "f1_score": float(f1),

    "accuracy": float(accuracy)
}


output_file = (
    MODEL_DIR /
    "final_test_metrics.json"
)


with open(
    output_file,
    "w",
    encoding="utf-8"
) as f:

    json.dump(
        results,
        f,
        indent=4
    )


print("\nResults saved to:")

print(output_file)