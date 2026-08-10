# ============================================================
# Phishing URL Model Training Script
# ============================================================
import os
import re
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# ------------------------------------------------------------
# 1. CUSTOM TOKENIZER
# ------------------------------------------------------------
def url_tokenizer(url):
    """Splits URL on common structural delimiters preserving sub-words and parameters."""
    return [token for token in re.split(r'[/.\-?=&_:@#]', url) if token]

# ------------------------------------------------------------
# 2. LOAD & PREPARE DATASET
# ------------------------------------------------------------
DATASET_PATH = r"D:\Semester5\NLP\CyberLens\datasets\phishing\Phishing_Site.csv"
MODEL_DESTINATION = r"D:\Semester5\NLP\CyberLens\static\model\phishing_model.pkl"

print("Loading dataset...")
phish_frame = pd.read_csv(DATASET_PATH)

# Clean dataset column names and drop empty entries
phish_frame.columns = [col.strip() for col in phish_frame.columns]
phish_frame = phish_frame.dropna(subset=["URL", "Label"]).copy()

url_series = phish_frame["URL"]
label_series = phish_frame["Label"]

print(f"Dataset loaded: {len(phish_frame):,} rows")

# Split dataset into Train and Test sets
split_urls_train, split_urls_test, split_labels_train, split_labels_test = train_test_split(
    url_series, label_series, test_size=0.3, random_state=42, stratify=label_series
)

print(f"Training samples : {len(split_urls_train):,}")
print(f"Testing samples  : {len(split_urls_test):,}")

# ------------------------------------------------------------
# 3. FEATURE EXTRACTION & PIPELINE DEFINITION
# ------------------------------------------------------------
print("\nBuilding NLP Feature Union (Word + Char N-Grams)...")

combined_features = FeatureUnion([
    ('word_tfidf', TfidfVectorizer(
        tokenizer=url_tokenizer,
        ngram_range=(1, 2),
        min_df=3,
        token_pattern=None
    )),
    ('char_tfidf', TfidfVectorizer(
        analyzer='char_wb',
        ngram_range=(3, 5),
        min_df=5
    ))
])

optimized_pipeline = Pipeline(
    [
        ("features", combined_features),
        (
            "classifier",
            LogisticRegression(
                C=1.0,  # Lower C value prevents overfitting on short benign tokens
                max_iter=1000,
                random_state=42,
            ),
        ),
    ]
)

# ------------------------------------------------------------
# 4. MODEL TRAINING
# ------------------------------------------------------------
print("Training Logistic Regression Model...")
optimized_pipeline.fit(split_urls_train, split_labels_train)

# ------------------------------------------------------------
# 5. EVALUATION
# ------------------------------------------------------------
print("Evaluating predictions...")
predictions = optimized_pipeline.predict(split_urls_test)

pos_class = 'bad' if 'bad' in list(optimized_pipeline.classes_) else 1

accuracy = accuracy_score(split_labels_test, predictions)
precision = precision_score(split_labels_test, predictions, pos_label=pos_class)
recall = recall_score(split_labels_test, predictions, pos_label=pos_class)
f1 = f1_score(split_labels_test, predictions, pos_label=pos_class)

print("\n==========================================")
print("             MODEL EVALUATION             ")
print("==========================================")
print(f"Accuracy  : {accuracy * 100:.2f}%")
print(f"Precision : {precision * 100:.2f}%")
print(f"Recall    : {recall * 100:.2f}%")
print(f"F1 Score  : {f1 * 100:.2f}%")
print("==========================================\n")

# ------------------------------------------------------------
# 6. SAVE MODEL TO PICKLE
# ------------------------------------------------------------
os.makedirs(os.path.dirname(MODEL_DESTINATION), exist_ok=True)
with open(MODEL_DESTINATION, "wb") as pkl_file:
    pickle.dump(optimized_pipeline, pkl_file)

print(f"Model successfully saved to:\n{MODEL_DESTINATION}")