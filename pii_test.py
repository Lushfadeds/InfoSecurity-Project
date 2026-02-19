"""
PII Guard — Test Suite
======================
Tests are organized in 4 layers:
  1. Unit tests       — individual regex patterns
  2. Integration tests — Flask API endpoints
  3. Edge case tests  — tricky inputs that fool naive detectors
  4. Recall/Precision — quantified accuracy scoring

Run:
    pip install pytest requests flask
    pytest test_pii_guard.py -v
"""

import re
import json
import pytest
from pii_guard import app, detect_pii, redact_text, PII_PATTERNS


# ═══════════════════════════════════════════════════════════════
# LAYER 1: Unit Tests — Pattern by Pattern
# ═══════════════════════════════════════════════════════════════

class TestNRIC:
    """Singapore NRIC/FIN: [STFGM] + 7 digits + 1 letter"""

    # ── Should DETECT ──────────────────────────────────────────
    @pytest.mark.parametrize("text", [
        "My NRIC is S1234567D",
        "NRIC: T0123456A",
        "FIN number F1234567N",
        "G1234567X is my FIN",
        "M1234567J",                        # newest prefix (MyPR)
        "nric s1234567d",                   # lowercase prefix
        "S1234567D.",                       # trailing punctuation
        "patient S1234567D was admitted",   # inline in sentence
    ])
    def test_detects_valid_nric(self, text):
        findings = detect_pii(text)
        types = [f["type"] for f in findings]
        assert "NRIC/FIN" in types, f"Should detect NRIC in: '{text}'"

    # ── Should NOT detect (false positive guard) ───────────────
    @pytest.mark.parametrize("text", [
        "Invoice #A1234567",         # wrong format — no valid prefix letter before digits
        "Order B9999999Z extra",     # B is not a valid NRIC prefix
        "Step 1234567 of process",   # pure digits, no letter prefix
        "model S1234 is great",      # too few digits
    ])
    def test_no_false_positive_nric(self, text):
        findings = [f for f in detect_pii(text) if f["type"] == "NRIC/FIN"]
        assert len(findings) == 0, f"Should NOT detect NRIC in: '{text}'"


class TestSingaporePhone:
    """SG mobile: optional +65, starts with 8 or 9, 8 digits total"""

    @pytest.mark.parametrize("text", [
        "Call me at 91234567",
        "Phone: 81234567",
        "+65 91234567",
        "+6591234567",
        "reach me at 9123 4567",        # with space
        "tel: +65-9123-4567",           # with dashes
    ])
    def test_detects_sg_phone(self, text):
        findings = detect_pii(text)
        types = [f["type"] for f in findings]
        assert "PHONE_SG" in types, f"Should detect phone in: '{text}'"

    @pytest.mark.parametrize("text", [
        "Room 6123456",             # starts with 6 (landline format, not mobile)
        "version 9.1.2",            # not a phone number
        "12345678",                 # starts with 1 — not SG mobile
        "PI = 3.14159265",          # digits but not a phone
    ])
    def test_no_false_positive_phone(self, text):
        findings = [f for f in detect_pii(text) if f["type"] == "PHONE_SG"]
        assert len(findings) == 0, f"Should NOT detect phone in: '{text}'"


class TestEmail:
    @pytest.mark.parametrize("text", [
        "email me at john@example.com",
        "JOHN.DOE+tag@hospital.org.sg",
        "Contact: alice_99@mail.co",
    ])
    def test_detects_email(self, text):
        findings = detect_pii(text)
        assert any(f["type"] == "EMAIL" for f in findings)

    @pytest.mark.parametrize("text", [
        "sent @ 3pm",               # not an email
        "user at domain dot com",   # written out, not an email format
    ])
    def test_no_false_positive_email(self, text):
        findings = [f for f in detect_pii(text) if f["type"] == "EMAIL"]
        assert len(findings) == 0


class TestCreditCard:
    @pytest.mark.parametrize("text", [
        "card: 4111 1111 1111 1111",
        "CC 4111-1111-1111-1111",
        "number 4111111111111111",
    ])
    def test_detects_credit_card(self, text):
        findings = detect_pii(text)
        assert any(f["type"] == "CREDIT_CARD" for f in findings)


# ═══════════════════════════════════════════════════════════════
# LAYER 2: Integration Tests — Flask Endpoints
# ═══════════════════════════════════════════════════════════════

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class TestCheckEndpoint:

    def test_clean_message_returns_no_pii(self, client):
        r = client.post("/check", json={"message": "See you at 3pm tomorrow!"})
        data = r.get_json()
        assert r.status_code == 200
        assert data["has_pii"] is False
        assert data["findings"] == []
        assert "warning" not in data

    def test_nric_message_triggers_warning(self, client):
        r = client.post("/check", json={"message": "My NRIC is S9812345A"})
        data = r.get_json()
        assert data["has_pii"] is True
        assert any(f["type"] == "NRIC/FIN" for f in data["findings"])
        assert "warning" in data
        assert "NRIC/FIN" in data["warning"]

    def test_response_includes_redacted_version(self, client):
        r = client.post("/check", json={"message": "email: bob@test.com"})
        data = r.get_json()
        assert "[EMAIL]" in data["redacted"]
        assert "bob@test.com" not in data["redacted"]

    def test_multiple_pii_types_detected(self, client):
        msg = "I'm S1234567D, call 91234567 or email a@b.com"
        r = client.post("/check", json={"message": msg})
        data = r.get_json()
        found_types = {f["type"] for f in data["findings"]}
        assert "NRIC/FIN" in found_types
        assert "PHONE_SG" in found_types
        assert "EMAIL"    in found_types

    def test_high_severity_reflected_in_warning(self, client):
        r = client.post("/check", json={"message": "NRIC: S1234567D"})
        data = r.get_json()
        # High-severity items should mention it explicitly
        assert "highly sensitive" in data["warning"].lower() or "high" in data["warning"].lower()

    def test_missing_message_key(self, client):
        r = client.post("/check", json={})
        # Should not crash — empty string treated as clean
        assert r.status_code == 200


class TestRedactEndpoint:

    def test_redacts_all_pii_by_default(self, client):
        msg = "NRIC S1234567D phone 91234567"
        r = client.post("/redact", json={"message": msg})
        data = r.get_json()
        assert "S1234567D" not in data["redacted_message"]
        assert "91234567"  not in data["redacted_message"]

    def test_selective_redaction(self, client):
        msg = "NRIC S1234567D email a@b.com"
        r = client.post("/redact", json={
            "message": msg,
            "types_to_redact": ["NRIC/FIN"]   # only redact NRIC, keep email
        })
        data = r.get_json()
        assert "S1234567D" not in data["redacted_message"]
        assert "a@b.com"   in data["redacted_message"]   # email preserved


# ═══════════════════════════════════════════════════════════════
# LAYER 3: Edge Cases — Where Naive Detectors Fail
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases:

    def test_pii_at_start_of_string(self):
        findings = detect_pii("S1234567D is the patient")
        assert any(f["type"] == "NRIC/FIN" for f in findings)

    def test_pii_at_end_of_string(self):
        findings = detect_pii("The patient's NRIC is S1234567D")
        assert any(f["type"] == "NRIC/FIN" for f in findings)

    def test_pii_with_surrounding_punctuation(self):
        findings = detect_pii("(S1234567D)")
        assert any(f["type"] == "NRIC/FIN" for f in findings)

    def test_multiple_same_type(self):
        findings = detect_pii("S1234567D and T7654321B are co-applicants")
        nric_hits = [f for f in findings if f["type"] == "NRIC/FIN"]
        assert len(nric_hits) == 2

    def test_pii_in_multiline_text(self):
        text = "Name: John\nNRIC: S1234567D\nPhone: 91234567"
        findings = detect_pii(text)
        types = {f["type"] for f in findings}
        assert "NRIC/FIN"  in types
        assert "PHONE_SG"  in types

    def test_empty_string(self):
        assert detect_pii("") == []

    def test_only_whitespace(self):
        assert detect_pii("     ") == []

    def test_unicode_and_mixed_scripts(self):
        # PII embedded in non-Latin text should still be caught
        findings = detect_pii("我的NRIC是 S1234567D 谢谢")
        assert any(f["type"] == "NRIC/FIN" for f in findings)

    def test_redaction_preserves_surrounding_text(self):
        original = "Hello, my NRIC is S1234567D. Thank you."
        findings = detect_pii(original)
        redacted = redact_text(original, findings)
        assert redacted.startswith("Hello, my NRIC is ")
        assert redacted.endswith(". Thank you.")
        assert "S1234567D" not in redacted

    def test_overlapping_pattern_safety(self):
        # A string that could naively match both PHONE and CREDIT_CARD
        # Should not crash or produce garbled output
        findings = detect_pii("9123456712345678")
        redacted = redact_text("9123456712345678", findings)
        assert isinstance(redacted, str)   # just verify it doesn't crash


# ═══════════════════════════════════════════════════════════════
# LAYER 4: Precision & Recall Scoring
# ═══════════════════════════════════════════════════════════════
# Precision = of everything we flagged, how much was actually PII?
# Recall    = of all real PII in the test set, how much did we catch?
#
# In privacy contexts, RECALL is more important.
# Missing PII (false negative) > wrongly flagging clean text (false positive)

LABELED_TEST_SET = [
    # (text, expected_types_present)
    ("NRIC: S9812345A",                             {"NRIC/FIN"}),
    ("Call 91234567 for appointments",              {"PHONE_SG"}),
    ("reach me at nurse@hospital.sg",               {"EMAIL"}),
    ("card 4111 1111 1111 1111",                    {"CREDIT_CARD"}),
    ("S1234567D, 91234567, a@b.com",                {"NRIC/FIN", "PHONE_SG", "EMAIL"}),
    ("See you at 3pm",                              set()),           # clean
    ("Room 101, ward B",                            set()),           # clean
    ("Version 9.1.2 released",                      set()),           # clean
    ("DOB: 01/01/1990",                             {"DATE_OF_BIRTH"}),
    ("Passport A12345678",                          {"PASSPORT"}),
]


def score_detector():
    tp = fp = fn = 0

    for text, expected in LABELED_TEST_SET:
        findings      = detect_pii(text)
        detected_types = {f["type"] for f in findings}

        # True positives: correctly detected
        tp += len(expected & detected_types)
        # False positives: flagged something that isn't PII
        fp += len(detected_types - expected)
        # False negatives: missed real PII
        fn += len(expected - detected_types)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {"precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3),
            "tp": tp, "fp": fp, "fn": fn}


class TestAccuracyMetrics:

    def test_recall_above_threshold(self):
        """Recall must be >= 0.90 — missing PII is the worst failure mode."""
        scores = score_detector()
        print(f"\nDetector scores: {scores}")
        assert scores["recall"] >= 0.90, (
            f"Recall {scores['recall']} is below 0.90 threshold. "
            f"Missed PII (FN={scores['fn']}) needs investigation."
        )

    def test_precision_above_threshold(self):
        """Precision should be >= 0.80 — too many false alarms cause alert fatigue."""
        scores = score_detector()
        assert scores["precision"] >= 0.80, (
            f"Precision {scores['precision']} is below 0.80. "
            f"False positives (FP={scores['fp']}) need investigation."
        )


# ═══════════════════════════════════════════════════════════════
# Standalone runner (without pytest)
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 50)
    print("Running smoke tests...\n")

    smoke = [
        "My NRIC is S9812345A and my phone is 91234567.",
        "Email: doctor@hospital.sg | Card: 4111 1111 1111 1111",
        "See you at the clinic tomorrow at 2pm.",         # clean
    ]
    for text in smoke:
        findings = detect_pii(text)
        redacted = redact_text(text, findings)
        print(f"  Input:    {text}")
        print(f"  Findings: {[f['type'] for f in findings] or 'None'}")
        print(f"  Redacted: {redacted}\n")

    print("=" * 50)
    print("Accuracy scores on labeled test set:\n")
    scores = score_detector()
    for k, v in scores.items():
        print(f"  {k.upper():<12} {v}")