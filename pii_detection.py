from faker import Faker
import random
import json

fake = Faker()

PII_LABELS = ["NAME", "EMAIL", "PHONE", "SSN", "ADDRESS", "CREDIT_CARD", "DOB"]

LABEL_LIST = ["O"] + [f"B-{l}" for l in PII_LABELS] + [f"I-{l}" for l in PII_LABELS]
LABEL2ID   = {l: i for i, l in enumerate(LABEL_LIST)}
ID2LABEL   = {i: l for l, i in LABEL2ID.items()}


def generate_sample():
    templates = [
        lambda: (
            f"My name is {fake.name()} and you can reach me at {fake.email()}.",
            ["NAME", "EMAIL"]
        ),
        lambda: (
            f"Call {fake.name()} at {fake.phone_number()} or email {fake.email()}.",
            ["NAME", "PHONE", "EMAIL"]
        ),
        lambda: (
            f"SSN: {fake.ssn()} — DOB: {fake.date_of_birth().strftime('%m/%d/%Y')}",
            ["SSN", "DOB"]
        ),
        lambda: (
            f"{fake.name()} lives at {fake.address().replace(chr(10), ', ')}.",
            ["NAME", "ADDRESS"]
        ),
        lambda: (
            f"Card number {fake.credit_card_number()} belongs to {fake.name()}.",
            ["CREDIT_CARD", "NAME"]
        ),
    ]

    text, _ = random.choice(templates)()

    tokens = text.split()
    labels = ["O"] * len(tokens)

    def tag_span(value, label):
        value_tokens = value.split()
        for i in range(len(tokens) - len(value_tokens) + 1):
            # Strip punctuation for matching
            window = [t.strip(".,!?;:") for t in tokens[i:i + len(value_tokens)]]
            if window == value_tokens:
                labels[i] = f"B-{label}"
                for j in range(1, len(value_tokens)):
                    labels[i + j] = f"I-{label}"

    return {"tokens": tokens, "labels": labels}


def build_dataset(n=500):
    return [generate_sample() for _ in range(n)]


print("Generating synthetic dataset...")
raw_data = build_dataset(n=1000)

# Split into train / validation
split = int(0.8 * len(raw_data))
train_data = raw_data[:split]
val_data   = raw_data[split:]
print(f"  Train: {len(train_data)} samples | Val: {len(val_data)} samples")



from datasets import load_dataset
dataset = load_dataset("ai4privacy/pii-masking-300k")


from transformers import AutoTokenizer
import torch
from torch.utils.data import Dataset

MODEL_CHECKPOINT = "bert-base-cased"
tokenizer = AutoTokenizer.from_pretrained(MODEL_CHECKPOINT)


def tokenize_and_align_labels(example, label_all_tokens=False):
    """
    Tokenize a single example and align BIO labels to subword tokens.

    label_all_tokens=True  → assign the entity label to ALL subword pieces
    label_all_tokens=False → only the first subword piece gets the label;
                             subsequent pieces get -100 (ignored in loss)
    """
    tokenized = tokenizer(
        example["tokens"],
        is_split_into_words=True,   # input is already word-tokenized
        truncation=True,
        padding="max_length",
        max_length=128,
    )

    word_ids     = tokenized.word_ids()   # maps each subword token → original word index
    label_ids    = []
    previous_word_idx = None

    for word_idx in word_ids:
        if word_idx is None:
            # Special tokens ([CLS], [SEP], [PAD]) → ignore in loss
            label_ids.append(-100)
        elif word_idx != previous_word_idx:
            # First subword of a new word → use the word's label
            label_ids.append(LABEL2ID.get(example["labels"][word_idx], 0))
        else:
            # Subsequent subwords of the same word
            if label_all_tokens:
                lbl = example["labels"][word_idx]
                # Convert B-XXX to I-XXX for continuation tokens
                if lbl.startswith("B-"):
                    lbl = "I-" + lbl[2:]
                label_ids.append(LABEL2ID.get(lbl, 0))
            else:
                label_ids.append(-100)

        previous_word_idx = word_idx

    tokenized["labels"] = label_ids
    return tokenized


class PIIDataset(Dataset):
    def __init__(self, data):
        self.encodings = [tokenize_and_align_labels(d) for d in data]

    def __len__(self):
        return len(self.encodings)

    def __getitem__(self, idx):
        item = self.encodings[idx]
        return {
            "input_ids":      torch.tensor(item["input_ids"]),
            "attention_mask": torch.tensor(item["attention_mask"]),
            "labels":         torch.tensor(item["labels"]),
        }


print("Tokenizing and aligning labels...")
train_dataset = PIIDataset(train_data)
val_dataset   = PIIDataset(val_data)


# ──────────────────────────────────────────────────────────────
# STEP 4: Load BERT with a Token Classification Head & Train
# ──────────────────────────────────────────────────────────────
from transformers import (
    AutoModelForTokenClassification,
    TrainingArguments,
    Trainer,
    DataCollatorForTokenClassification,
)
import numpy as np
from seqeval.metrics import classification_report, f1_score

model = AutoModelForTokenClassification.from_pretrained(
    MODEL_CHECKPOINT,
    num_labels=len(LABEL_LIST),
    id2label=ID2LABEL,
    label2id=LABEL2ID,
)

# Data collator handles dynamic padding within a batch
data_collator = DataCollatorForTokenClassification(tokenizer)


def compute_metrics(eval_preds):
    """
    Convert model logits → predicted label strings, then compute
    seqeval metrics (precision, recall, F1) ignoring -100 positions.
    """
    logits, labels = eval_preds
    predictions = np.argmax(logits, axis=-1)

    true_labels = [
        [ID2LABEL[l] for l in label_seq if l != -100]
        for label_seq in labels
    ]
    pred_labels = [
        [ID2LABEL[p] for p, l in zip(pred_seq, label_seq) if l != -100]
        for pred_seq, label_seq in zip(predictions, labels)
    ]

    return {
        "f1":        f1_score(true_labels, pred_labels),
        "report":    classification_report(true_labels, pred_labels),
    }


training_args = TrainingArguments(
    output_dir="./pii_model",
    num_train_epochs=3,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    warmup_steps=100,
    weight_decay=0.01,
    learning_rate=2e-5,
    evaluation_strategy="epoch",
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
    logging_dir="./logs",
    logging_steps=50,
    report_to="none",               # set to "wandb" or "tensorboard" if desired
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_dataset,
    eval_dataset=val_dataset,
    tokenizer=tokenizer,
    data_collator=data_collator,
    compute_metrics=compute_metrics,
)

print("\nStarting training...")
# trainer.train()   ← uncomment to actually run training
# trainer.save_model("./pii_model_final")
print("(Training call is commented out — uncomment to run.)")


# ──────────────────────────────────────────────────────────────
# STEP 5: Inference — Detect PII in New Text
# ──────────────────────────────────────────────────────────────
from transformers import pipeline

def load_pii_detector(model_path="./pii_model_final"):
    """Load the fine-tuned model and return a Hugging Face NER pipeline."""
    return pipeline(
        "ner",
        model=model_path,
        tokenizer=model_path,
        aggregation_strategy="simple",   # merges B/I tokens into single entities
    )


def detect_pii(text: str, detector) -> list[dict]:
    """
    Run PII detection on a string.
    Returns a list of dicts: {entity_group, score, word, start, end}
    """
    results = detector(text)
    return [
        {
            "type":  r["entity_group"],
            "value": r["word"],
            "score": round(r["score"], 3),
            "span":  (r["start"], r["end"]),
        }
        for r in results
    ]


def redact_pii(text: str, detector, replacement="[REDACTED]") -> str:
    """Replace detected PII spans with a placeholder."""
    entities = sorted(detector(text), key=lambda x: x["start"], reverse=True)
    for ent in entities:
        text = text[: ent["start"]] + replacement + text[ent["end"] :]
    return text


# Example usage (requires a trained model saved to ./pii_model_final):
# detector = load_pii_detector()
#
# text = "Hi, I'm Alice Johnson. Email me at alice@example.com or call 555-867-5309."
# print(detect_pii(text, detector))
# # → [{'type': 'NAME', 'value': 'Alice Johnson', ...},
# #    {'type': 'EMAIL', 'value': 'alice@example.com', ...},
# #    {'type': 'PHONE', 'value': '555-867-5309', ...}]
#
# print(redact_pii(text, detector))
# # → "Hi, I'm [REDACTED]. Email me at [REDACTED] or call [REDACTED]."


# ──────────────────────────────────────────────────────────────
# STEP 6: Tips for Production
# ──────────────────────────────────────────────────────────────
PRODUCTION_TIPS = """
Production Checklist
====================
1. DATA QUALITY
   - Use real (de-identified) domain data, not just synthetic
   - Annotate edge cases: nicknames, non-English names, unusual formats
   - Balance your dataset — PII tokens are rare; oversample them

2. MODEL CHOICE
   - bert-base-cased         → good baseline, widely supported
   - roberta-base            → usually slightly better accuracy
   - distilbert-base-cased   → 40% smaller/faster, slight accuracy trade-off
   - domain-specific models  → e.g. Bio_ClinicalBERT for medical PII

3. EVALUATION
   - Prioritize RECALL over precision in privacy contexts
     (missing PII is worse than a false alarm)
   - Evaluate per entity type — SSN detection != NAME detection
   - Test on out-of-domain text (different writing styles)

4. HYBRID APPROACH
   - Combine the ML model with regex rules for structured PII
     (SSNs, credit cards, emails) for near-perfect recall on those types
   - Use Microsoft Presidio as an orchestration layer

5. DEPLOYMENT
   - Quantize the model (INT8) for faster inference: trainer.save_model(),
     then use optimum or torch.quantization
   - For high-throughput, batch inputs and use ONNX Runtime
   - Log false positives/negatives and retrain periodically

6. COMPLIANCE
   - Document which PII types you detect (GDPR Article 30)
   - Keep training data handling compliant (don't train on real PII
     without proper data processing agreements)
"""
print(PRODUCTION_TIPS)