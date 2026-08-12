import streamlit as st
import torch
from transformers import AutoTokenizer, AutoModelForTokenClassification
from database import log_ner_analysis
from database import get_connection
from utils.navigation import analyst_navigation
from utils.theme import load_theme
st.set_page_config(
    page_title="CyberLens - Cyber Threat NER",
    page_icon="🧠",
    layout="wide",
)
load_theme()
if not st.session_state.get("logged_in", False):
    st.warning("Please login to access CyberLens.")
    
    if st.button("Go to Login"):
        st.switch_page("login.py")
    
    st.stop()

analyst_navigation(
    active_page="threat"
)
MODEL_PATH = r"D:\Semester5\NLP\CyberLens\models\cyberlens_ner"
@st.cache_resource
def load_ner_model():

    tokenizer = AutoTokenizer.from_pretrained(
        MODEL_PATH,
        local_files_only=True
    )

    model = AutoModelForTokenClassification.from_pretrained(
        MODEL_PATH,
        local_files_only=True
    )

    device = torch.device(
        "cuda" if torch.cuda.is_available() else "cpu"
    )

    model.to(device)
    model.eval()

    return tokenizer, model, device
try:

    tokenizer, model, device = load_ner_model()

except Exception as e:

    st.error("Unable to load the CyberLens NER model.")

    st.write(
        "Make sure the trained model folder exists at:"
    )

    st.code(MODEL_PATH)

    st.error(str(e))

    st.stop()
st.title("🧠 Cyber Threat Entity Extraction")

st.write(
    "Analyze a cybersecurity threat report and extract "
    "important entities using the CyberLens NER model."
    "The model was trained using the "
    "combined CyNER and DNRTI datasets."
)

st.divider()
st.subheader("Model Information")

col1, col2, col3 = st.columns(3)

with col1:
    st.metric(
        "Model",
        "CyberLens NER"
    )

with col2:
    st.metric(
        "Labels",
        len(model.config.id2label)
    )

with col3:
    st.metric(
        "Device",
        str(device)
    )
st.divider()
st.subheader("Enter Threat Report")

threat_text = st.text_area(
    "Threat Report",
    height=220,
    placeholder=(
        "Example:\n\n"
        "APT28 used PowerShell to download malware from a "
        "malicious server. The attack targeted organizations "
        "in Ukraine and exploited a known vulnerability."
    )
)
def extract_entities(text):

    encoding = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        return_offsets_mapping=True
    )

    offset_mapping = encoding.pop("offset_mapping")

    encoding = {
        key: value.to(device)
        for key, value in encoding.items()
    }

    with torch.no_grad():

        outputs = model(**encoding)

    probabilities = torch.softmax(
        outputs.logits,
        dim=-1
    )

    predictions = torch.argmax(
        probabilities,
        dim=-1
    )[0]

    confidence_scores = torch.max(
        probabilities,
        dim=-1
    ).values[0]

    input_ids = encoding["input_ids"][0]

    tokens = tokenizer.convert_ids_to_tokens(
        input_ids
    )

    entities = []

    current_entity = None

    for index, token in enumerate(tokens):

        label_id = predictions[index].item()

        label = model.config.id2label.get(
            label_id,
            "O"
        )

        confidence = confidence_scores[index].item()

        start, end = offset_mapping[0][index].tolist()

        # Special tokens
        if start == end:
            continue

        word = text[start:end]

        # Ignore outside label
        if label == "O":

            if current_entity is not None:
                entities.append(current_entity)
                current_entity = None

            continue
        if label.startswith("B-"):

            if current_entity is not None:
                entities.append(current_entity)

            entity_type = label[2:]

            current_entity = {
                "text": word,
                "type": entity_type,
                "confidence": confidence,
                "start": start,
                "end": end
            }

        elif label.startswith("I-"):

            entity_type = label[2:]

            if (
                current_entity is not None
                and current_entity["type"] == entity_type
            ):

                previous_end = current_entity["end"]

                separator = text[
                    previous_end:start
                ]

                current_entity["text"] += (
                    separator + word
                )

                current_entity["end"] = end

                current_entity["confidence"] = min(
                    current_entity["confidence"],
                    confidence
                )

            else:

                current_entity = {
                    "text": word,
                    "type": entity_type,
                    "confidence": confidence,
                    "start": start,
                    "end": end
                }

    # Add final entity

    if current_entity is not None:
        entities.append(current_entity)

    return entities
if st.button(
    "🔍 Extract Cyber Threat Entities",
    type="primary",
    use_container_width=True
):

    if not threat_text.strip():

        st.warning(
            "Please enter a cybersecurity threat report."
        )

        st.stop()
    with st.spinner(
        "Analyzing threat report..."
    ):

        entities = extract_entities(
            threat_text
        )
        user_id = st.session_state.get("user_id")

        if user_id:
            success = log_ner_analysis(
        user_id,
        threat_text,
        entities
    )

        if not success:
            st.warning(
            "NER analysis could not be saved to the database."
        )
    st.divider()
    st.subheader("Detection Result")

    if not entities:

        st.info(
            "No cybersecurity entities were detected "
            "in the provided text."
        )
    else:

        st.success(
            f"{len(entities)} cybersecurity entities detected."
        )
        st.subheader("Extracted Entities")

        entity_rows = []

        for entity in entities:

            entity_rows.append({
                "Entity": entity["text"],
                "Type": entity["type"],
                "Confidence": (
                    f"{entity['confidence'] * 100:.2f}%"
                )
            })

        st.dataframe(
            entity_rows,
            use_container_width=True,
            hide_index=True
        )
        st.divider()

        st.subheader(
            "Entities by Cybersecurity Category"
        )

        grouped_entities = {}

        for entity in entities:

            entity_type = entity["type"]

            if entity_type not in grouped_entities:
                grouped_entities[entity_type] = []

            if entity["text"] not in grouped_entities[entity_type]:
                grouped_entities[entity_type].append(
                    entity["text"]
                )
        for entity_type in sorted(
            grouped_entities.keys()
        ):

            st.write(
                f"**{entity_type}**"
            )

            for value in grouped_entities[
                entity_type
            ]:

                st.write(
                    f"- {value}"
                )
    user_id = st.session_state.get("user_id")
    if user_id:
        log_ner_analysis(
        user_id,
        threat_text,
        entities
        )   