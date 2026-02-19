"""
Sender-Side PII Detection (Pre-Encryption Hook)
================================================
Run this BEFORE the message is encrypted and sent.
Detects Singapore NRIC, phone numbers, emails, and credit cards.

Flask usage:
    pip install flask presidio-analyzer spacy
    python -m spacy download en_core_web_sm
    python pii_guard.py

Endpoint:
    POST /check   { "message": "Hello, my NRIC is S1234567D" }
    → { "has_pii": true, "findings": [...], "redacted": "Hello, my NRIC is [NRIC]" }
"""

import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# ──────────────────────────────────────────────
# PII Pattern Definitions
# Singapore-specific + universal patterns
# ──────────────────────────────────────────────

PII_PATTERNS = [
    {
        "type": "NRIC/FIN",
        # Singapore NRIC: starts with S/T/F/G/M, 7 digits, 1 letter
        "pattern": r"\b[STFGM]\d{7}[A-Z]\b",
        "severity": "high",
        "message": "Singapore NRIC/FIN detected",
    },
    {
        "type": "PHONE_SG",
        # Singapore mobile (+65 or local): 8 digits starting with 8 or 9
        "pattern": r"(\+65[-\s]?)?[89]\d{3}[-\s]?\d{4}\b",
        "severity": "medium",
        "message": "Singapore phone number detected",
    },
    {
        "type": "EMAIL",
        "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "severity": "medium",
        "message": "Email address detected",
    },
    {
        "type": "CREDIT_CARD",
        # Visa/MC/Amex — basic Luhn-passing patterns
        "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        "severity": "high",
        "message": "Credit card number detected",
    },
    {
        "type": "PASSPORT",
        # Generic passport: letter(s) + 6-9 digits
        "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",
        "severity": "high",
        "message": "Possible passport number detected",
    },
    {
        "type": "DATE_OF_BIRTH",
        # Common date formats: DD/MM/YYYY, YYYY-MM-DD, DD-MM-YYYY
        "pattern": r"\b(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{2}[\/\-]\d{2})\b",
        "severity": "low",
        "message": "Date detected (possible DOB)",
    },
]


# ──────────────────────────────────────────────
# Core Detection Function
# ──────────────────────────────────────────────

def detect_pii(text: str) -> dict:
    """
    Scan text for PII patterns.
    Returns findings with match positions for highlighting in the UI.
    """
    findings = []

    for rule in PII_PATTERNS:
        for match in re.finditer(rule["pattern"], text, re.IGNORECASE):
            findings.append({
                "type":     rule["type"],
                "value":    match.group(),          # the actual matched text
                "start":    match.start(),           # character offset (for UI highlighting)
                "end":      match.end(),
                "severity": rule["severity"],
                "message":  rule["message"],
            })

    # Sort by position so the UI can highlight left-to-right
    findings.sort(key=lambda x: x["start"])
    return findings


def redact_text(text: str, findings: list, replacement_map: dict = None) -> str:
    """
    Replace detected PII spans with [TYPE] placeholders.
    Process in reverse order so offsets stay valid as we modify the string.

    replacement_map: optional override, e.g. {"NRIC/FIN": "****"}
    """
    replacement_map = replacement_map or {}
    for finding in sorted(findings, key=lambda x: x["start"], reverse=True):
        placeholder = replacement_map.get(finding["type"], f"[{finding['type']}]")
        text = text[: finding["start"]] + placeholder + text[finding["end"] :]
    return text


# ──────────────────────────────────────────────
# Flask API Endpoint
# ──────────────────────────────────────────────

@app.route("/check", methods=["POST"])
def check_message():
    """
    Called when the user hits "Send" — before the message is encrypted.

    Request:  { "message": "My NRIC is S1234567D" }
    Response: {
        "has_pii":   true,
        "findings":  [{ "type": "NRIC/FIN", "value": "S1234567D", ... }],
        "redacted":  "My NRIC is [NRIC/FIN]",
        "warning":   "You are about to send sensitive PHI. Redact before sending?"
    }
    """
    data    = request.get_json()
    message = data.get("message", "")

    findings = detect_pii(message)
    has_pii  = len(findings) > 0

    response = {
        "has_pii":  has_pii,
        "findings": findings,
        "redacted": redact_text(message, findings) if has_pii else message,
    }

    if has_pii:
        types   = list({f["type"] for f in findings})
        high    = any(f["severity"] == "high" for f in findings)
        response["warning"] = (
            f"⚠️ Sensitive information detected ({', '.join(types)}). "
            f"{'This includes highly sensitive data. ' if high else ''}"
            "Do you want to redact before sending?"
        )

    return jsonify(response)


@app.route("/redact", methods=["POST"])
def redact_message():
    """
    User confirmed redaction — return the clean version ready for encryption.

    Request:  { "message": "...", "types_to_redact": ["NRIC/FIN", "PHONE_SG"] }
              (omit types_to_redact to redact ALL detected PII)
    Response: { "redacted_message": "..." }
    """
    data             = request.get_json()
    message          = data.get("message", "")
    types_to_redact  = data.get("types_to_redact", None)   # None = redact all

    findings = detect_pii(message)

    if types_to_redact:
        findings = [f for f in findings if f["type"] in types_to_redact]

    return jsonify({ "redacted_message": redact_text(message, findings) })


# ──────────────────────────────────────────────
# Optional: Upgrade with Presidio for Name/Address Detection
# ──────────────────────────────────────────────
# The patterns above cover structured PII perfectly.
# To also catch unstructured PII (names, addresses), add Presidio:
#
#   from presidio_analyzer import AnalyzerEngine
#   analyzer = AnalyzerEngine()
#
#   def detect_names(text):
#       results = analyzer.analyze(text=text, entities=["PERSON", "LOCATION"], language="en")
#       return [{"type": r.entity_type, "start": r.start, "end": r.end,
#                "value": text[r.start:r.end], "severity": "medium"} for r in results]
#
# Then merge with regex findings before returning.


# ──────────────────────────────────────────────
# Frontend Integration (plain JavaScript)
# ──────────────────────────────────────────────
FRONTEND_SNIPPET = """
// Intercept the Send button
document.getElementById("sendBtn").addEventListener("click", async (e) => {
  e.preventDefault();                          // pause — don't encrypt yet

  const message = document.getElementById("messageInput").value;

  const res  = await fetch("/check", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  const data = await res.json();

  if (data.has_pii) {
    // Highlight the flagged text and show the warning modal
    showPIIWarning(data.warning, data.redacted, () => {
      // User chose "Redact & Send" → swap in the clean version
      encryptAndSend(data.redacted);
    }, () => {
      // User chose "Send Anyway" → send the original
      encryptAndSend(message);
    });
  } else {
    encryptAndSend(message);                   // no PII → encrypt normally
  }
});
"""

if __name__ == "__main__":
    # Quick smoke test
    test_cases = [
        "Hi, my NRIC is S9812345A and I'm reaching out about my appointment.",
        "Call me at 91234567 or email john@example.com",
        "Card: 4111 1111 1111 1111, expires 12/26",
        "Everything looks good, see you tomorrow!",
    ]

    print("=== PII Detection Smoke Test ===\n")
    for text in test_cases:
        findings = detect_pii(text)
        print(f"Input:    {text}")
        if findings:
            print(f"Findings: {[f['type'] + ':' + f['value'] for f in findings]}")
            print(f"Redacted: {redact_text(text, findings)}")
        else:
            print("Findings: None ✓")
        print()

    app.run(debug=True, port=5000)