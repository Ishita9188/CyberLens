import os
import json
import random
import numpy as np
import torch

from datasets import Dataset, DatasetDict
from transformers import (
    AutoTokenizer,
    AutoModelForTokenClassification,
    TrainingArguments,
    Trainer,
    DataCollatorForTokenClassification
)
from seqeval.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score
)

# ============================================================
# CONFIGURATION
# ============================================================

CYNER_TRAIN = r"D:\Semester5\NLP\CyberLens\datasets\ner\CyNER\train.txt"
CYNER_VALID = r"D:\Semester5\NLP\CyberLens\datasets\ner\CyNER\valid.txt"
CYNER_TEST = r"D:\Semester5\NLP\CyberLens\datasets\ner\CyNER\test.txt"

DNRTI_TRAIN = r"D:\Semester5\NLP\CyberLens\datasets\ner\DNRTI\train.txt"
DNRTI_VALID = r"D:\Semester5\NLP\CyberLens\datasets\ner\DNRTI\valid.txt"
DNRTI_TEST = r"D:\Semester5\NLP\CyberLens\datasets\ner\DNRTI\test.txt"

MODEL_OUTPUT = r"D:\Semester5\NLP\CyberLens\models\ner_model"

BASE_MODEL = "bert-base-cased"

RANDOM_SEED = 42


# ============================================================
# REPRODUCIBILITY
# ============================================================

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)
torch.manual_seed(RANDOM_SEED)

if torch.cuda.is_available():
    torch.cuda.manual_seed_all(RANDOM_SEED)


# ============================================================
# UNIFIED CYBERLENS LABEL SCHEMA
# ============================================================

LABEL_MAPPING = {

    # --------------------------------------------------------
    # Threat actors / hacker organizations
    # --------------------------------------------------------

    "HackOrg": "ThreatActor",

    # --------------------------------------------------------
    # Organizations
    # --------------------------------------------------------

    "Organization": "Organization",
    "Org": "Organization",

    # --------------------------------------------------------
    # Security teams
    # --------------------------------------------------------

    "SecTeam": "SecurityTeam",

    # --------------------------------------------------------
    # Malware
    # --------------------------------------------------------

    "Malware": "Malware",

    # --------------------------------------------------------
    # Tools / software
    # --------------------------------------------------------

    "Tool": "Tool",

    # --------------------------------------------------------
    # Indicators
    # --------------------------------------------------------

    "Indicator": "Indicator",

    # --------------------------------------------------------
    # Vulnerabilities / exploits
    # --------------------------------------------------------

    "Vulnerability": "Vulnerability",
    "Exp": "Exploit",

    # --------------------------------------------------------
    # Attack / malicious activities
    # --------------------------------------------------------

    "OffAct": "AttackActivity",

    # --------------------------------------------------------
    # Methods / attack delivery
    # --------------------------------------------------------

    "Way": "AttackMethod",

    # --------------------------------------------------------
    # Target industries / target entities
    # --------------------------------------------------------

    "Idus": "TargetIndustry",

    # --------------------------------------------------------
    # Locations
    # --------------------------------------------------------

    "Area": "Location",

    # --------------------------------------------------------
    # Time
    # --------------------------------------------------------

    "Time": "Time",

    # --------------------------------------------------------
    # Files / samples
    # --------------------------------------------------------

    "SamFile": "FileArtifact",

    # --------------------------------------------------------
    # Purpose / motivation
    # --------------------------------------------------------

    "Purp": "Purpose",

    # --------------------------------------------------------
    # Features
    # --------------------------------------------------------

    "Features": "CyberFeature",

    # --------------------------------------------------------
    # CyNER System entity
    # --------------------------------------------------------

    "System": "System"
}


# ============================================================
# BIO DATASET READER
# ============================================================

def read_bio_file(file_path):
    """
    Reads a token/tag BIO file.

    Expected format:

    token    tag
    token    tag
    token    tag

    Blank lines separate sentences.
    """

    sentences = []

    current_tokens = []
    current_tags = []

    with open(file_path, "r", encoding="utf-8") as file:

        for raw_line in file:

            line = raw_line.strip()

            # ------------------------------------------------
            # Sentence boundary
            # ------------------------------------------------

            if not line:

                if current_tokens:

                    sentences.append({
                        "tokens": current_tokens,
                        "tags": current_tags
                    })

                    current_tokens = []
                    current_tags = []

                continue

            # ------------------------------------------------
            # Ignore malformed lines
            # ------------------------------------------------

            parts = line.split()

            if len(parts) < 2:
                continue

            token = parts[0]
            tag = parts[-1]

            current_tokens.append(token)
            current_tags.append(tag)

    # --------------------------------------------------------
    # Last sentence
    # --------------------------------------------------------

    if current_tokens:

        sentences.append({
            "tokens": current_tokens,
            "tags": current_tags
        })

    return sentences


# ============================================================
# NORMALIZE BIO LABELS
# ============================================================

def normalize_tag(tag):

    if tag == "O":
        return "O"

    if tag.startswith("B-"):

        entity = tag[2:]

        normalized_entity = LABEL_MAPPING.get(
            entity,
            entity
        )

        return "B-" + normalized_entity

    if tag.startswith("I-"):

        entity = tag[2:]

        normalized_entity = LABEL_MAPPING.get(
            entity,
            entity
        )

        return "I-" + normalized_entity

    return "O"


# ============================================================
# LOAD DATASET
# ============================================================

def load_dataset_files(train_path, valid_path, test_path):

    print("\nLoading dataset...")
    print("Train:", train_path)
    print("Validation:", valid_path)
    print("Test:", test_path)

    train_data = read_bio_file(train_path)
    valid_data = read_bio_file(valid_path)
    test_data = read_bio_file(test_path)

    # Normalize tags

    for dataset in [
        train_data,
        valid_data,
        test_data
    ]:

        for sentence in dataset:

            sentence["tags"] = [
                normalize_tag(tag)
                for tag in sentence["tags"]
            ]

    return train_data, valid_data, test_data


# ============================================================
# LOAD BOTH DATASETS
# ============================================================

print("=" * 70)
print("CYBERLENS - CYBERSECURITY NER MODEL TRAINING")
print("=" * 70)

print("\nLoading CyNER dataset...")

cyner_train, cyner_valid, cyner_test = load_dataset_files(
    CYNER_TRAIN,
    CYNER_VALID,
    CYNER_TEST
)

print("\nCyNER:")
print("Train:", len(cyner_train))
print("Valid:", len(cyner_valid))
print("Test :", len(cyner_test))


print("\nLoading DNRTI dataset...")

dnrti_train, dnrti_valid, dnrti_test = load_dataset_files(
    DNRTI_TRAIN,
    DNRTI_VALID,
    DNRTI_TEST
)

print("\nDNRTI:")
print("Train:", len(dnrti_train))
print("Valid:", len(dnrti_valid))
print("Test :", len(dnrti_test))


# ============================================================
# COMBINE DATASETS
# ============================================================

combined_train = cyner_train + dnrti_train
combined_valid = cyner_valid + dnrti_valid
combined_test = cyner_test + dnrti_test

print("\n" + "=" * 70)
print("COMBINED DATASET")
print("=" * 70)

print("Training sentences  :", len(combined_train))
print("Validation sentences:", len(combined_valid))
print("Testing sentences   :", len(combined_test))


# ============================================================
# DISCOVER LABELS
# ============================================================

all_tags = set()

for dataset in [
    combined_train,
    combined_valid,
    combined_test
]:

    for sentence in dataset:

        for tag in sentence["tags"]:

            all_tags.add(tag)


# Put O first

all_tags.discard("O")

entity_tags = sorted(all_tags)

label_list = ["O"] + entity_tags

label2id = {
    label: index
    for index, label in enumerate(label_list)
}

id2label = {
    index: label
    for index, label in enumerate(label_list)
}

print("\nNumber of labels:", len(label_list))

print("\nLabels:")

for label in label_list:
    print(label)


# ============================================================
# CONVERT TO HUGGING FACE DATASETS
# ============================================================

train_dataset = Dataset.from_list(combined_train)
valid_dataset = Dataset.from_list(combined_valid)
test_dataset = Dataset.from_list(combined_test)

dataset = DatasetDict({

    "train": train_dataset,
    "validation": valid_dataset,
    "test": test_dataset

})


# ============================================================
# TOKENIZER
# ============================================================

print("\nLoading BERT tokenizer...")

tokenizer = AutoTokenizer.from_pretrained(
    BASE_MODEL
)


# ============================================================
# TOKENIZATION + LABEL ALIGNMENT
# ============================================================

def tokenize_and_align_labels(examples):

    tokenized_inputs = tokenizer(
        examples["tokens"],
        truncation=True,
        max_length=256,
        is_split_into_words=True
    )

    all_labels = []

    for batch_index, labels in enumerate(
        examples["tags"]
    ):

        word_ids = tokenized_inputs.word_ids(
            batch_index=batch_index
        )

        previous_word_id = None
        label_ids = []

        for word_id in word_ids:

            # Special token

            if word_id is None:

                label_ids.append(-100)

            # First token of word

            elif word_id != previous_word_id:

                label_ids.append(
                    label2id[labels[word_id]]
                )

            # Subword token

            else:

                original_label = labels[word_id]

                # Convert B-X to I-X for subword continuation

                if original_label.startswith("B-"):

                    entity = original_label[2:]

                    continuation_label = (
                        "I-" + entity
                    )

                    if continuation_label in label2id:

                        label_ids.append(
                            label2id[
                                continuation_label
                            ]
                        )

                    else:

                        label_ids.append(
                            label2id[
                                original_label
                            ]
                        )

                else:

                    label_ids.append(
                        label2id[original_label]
                    )

            previous_word_id = word_id

        all_labels.append(label_ids)

    tokenized_inputs["labels"] = all_labels

    return tokenized_inputs


print("\nTokenizing datasets...")

tokenized_dataset = dataset.map(
    tokenize_and_align_labels,
    batched=True,
    remove_columns=[
        "tokens",
        "tags"
    ]
)


# ============================================================
# MODEL
# ============================================================

print("\nLoading BERT token classification model...")

model = AutoModelForTokenClassification.from_pretrained(

    BASE_MODEL,

    num_labels=len(label_list),

    id2label=id2label,

    label2id=label2id

)


# ============================================================
# METRICS
# ============================================================

def compute_metrics(eval_prediction):

    predictions, labels = eval_prediction

    predictions = np.argmax(
        predictions,
        axis=2
    )

    true_predictions = []
    true_labels = []

    for prediction, label in zip(
        predictions,
        labels
    ):

        current_predictions = []
        current_labels = []

        for pred, lab in zip(
            prediction,
            label
        ):

            # Ignore special tokens

            if lab == -100:
                continue

            current_predictions.append(
                id2label[pred]
            )

            current_labels.append(
                id2label[lab]
            )

        true_predictions.append(
            current_predictions
        )

        true_labels.append(
            current_labels
        )

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

    return {

        "precision": precision,

        "recall": recall,

        "f1": f1,

        "accuracy": accuracy

    }


# ============================================================
# DATA COLLATOR
# ============================================================

data_collator = DataCollatorForTokenClassification(
    tokenizer=tokenizer
)


# ============================================================
# TRAINING ARGUMENTS
# ============================================================

training_args = TrainingArguments(

    output_dir=MODEL_OUTPUT,

    eval_strategy="epoch",

    save_strategy="epoch",

    logging_strategy="steps",

    logging_steps=100,

    learning_rate=2e-5,

    per_device_train_batch_size=8,

    per_device_eval_batch_size=8,

    num_train_epochs=3,

    weight_decay=0.01,

    warmup_ratio=0.1,

    load_best_model_at_end=True,

    metric_for_best_model="f1",

    greater_is_better=True,

    save_total_limit=2,

    report_to="none",

    fp16=torch.cuda.is_available(),

    seed=RANDOM_SEED

)


# ============================================================
# TRAINER
# ============================================================

trainer = Trainer(

    model=model,

    args=training_args,

    train_dataset=tokenized_dataset["train"],

    eval_dataset=tokenized_dataset["validation"],

    processing_class=tokenizer,

    data_collator=data_collator,

    compute_metrics=compute_metrics

)


# ============================================================
# TRAIN
# ============================================================

print("\n" + "=" * 70)
print("STARTING NER MODEL TRAINING")
print("=" * 70)

trainer.train()


# ============================================================
# VALIDATION RESULTS
# ============================================================

print("\n" + "=" * 70)
print("VALIDATION RESULTS")
print("=" * 70)

validation_results = trainer.evaluate(
    tokenized_dataset["validation"]
)

for key, value in validation_results.items():

    if isinstance(value, float):

        print(
            f"{key}: {value:.4f}"
        )


# ============================================================
# TEST RESULTS
# ============================================================

print("\n" + "=" * 70)
print("FINAL TEST RESULTS")
print("=" * 70)

test_results = trainer.evaluate(
    tokenized_dataset["test"]
)

for key, value in test_results.items():

    if isinstance(value, float):

        print(
            f"{key}: {value:.4f}"
        )


# ============================================================
# SAVE MODEL
# ============================================================

print("\nSaving trained model...")

os.makedirs(
    MODEL_OUTPUT,
    exist_ok=True
)

trainer.save_model(
    MODEL_OUTPUT
)

tokenizer.save_pretrained(
    MODEL_OUTPUT
)


# ============================================================
# SAVE LABEL INFORMATION
# ============================================================

label_information = {

    "label_list": label_list,

    "label2id": label2id,

    "id2label": {
        str(key): value
        for key, value in id2label.items()
    },

    "base_model": BASE_MODEL,

    "datasets": [
        "CyNER",
        "DNRTI"
    ]

}

with open(
    os.path.join(
        MODEL_OUTPUT,
        "labels.json"
    ),
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        label_information,
        file,
        indent=4
    )


# ============================================================
# SAVE TEST RESULTS
# ============================================================

clean_test_results = {}

for key, value in test_results.items():

    if isinstance(value, (float, int)):

        clean_test_results[key] = float(value)

with open(
    os.path.join(
        MODEL_OUTPUT,
        "test_metrics.json"
    ),
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        clean_test_results,
        file,
        indent=4
    )


# ============================================================
# COMPLETION
# ============================================================

print("\n" + "=" * 70)
print("NER MODEL TRAINING COMPLETED")
print("=" * 70)

print("\nModel saved at:")
print(MODEL_OUTPUT)

print("\nFiles created:")

print("  config.json")
print("  model.safetensors")
print("  tokenizer files")
print("  labels.json")
print("  test_metrics.json")

print("\nCyberLens Module 2 model is ready.")