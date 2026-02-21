from flask import Blueprint, render_template, session, redirect, url_for, flash, request, jsonify
from flask_socketio import emit, join_room, leave_room, send
from supabase import create_client, Client
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Create chat blueprint
chat_bp = Blueprint('chat', __name__, url_prefix='/chat')

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ──────────────────────────────────────────────────────────────
# PII Detection
# ──────────────────────────────────────────────────────────────
import re, secrets

PII_PATTERNS = [
    {"type": "NRIC/FIN",    "pattern": r"\b[STFGM]\d{7}[A-Z]\b",                          "severity": "high",   "message": "Singapore NRIC/FIN detected"},
    {"type": "PHONE_SG",    "pattern": r"(\+65[-\s]?)?[89]\d{3}[-\s]?\d{4}\b",           "severity": "medium", "message": "Singapore phone number detected"},
    {"type": "EMAIL",       "pattern": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "severity": "medium", "message": "Email address detected"},
    {"type": "CREDIT_CARD", "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",                   "severity": "high",   "message": "Credit card number detected"},
    {"type": "PASSPORT",    "pattern": r"\b[A-Z]{1,2}\d{6,9}\b",                            "severity": "high",   "message": "Possible passport number detected"},
]

_NRIC_STRICT = re.compile(r'[STFGM]\d{7}[A-Z]', re.IGNORECASE)
_OBFUSCATION = re.compile(r'[\s\-\.\#\_]+')
_SEP_GROUP   = re.compile(r'[\s\-\.\#\_]+')

def _find_fuzzy_nric(text):
    findings, seen = [], set()
    for m in re.finditer(r'\b[STFGM][0-9\s\-\.\#\_]{7,15}[A-Z]\b', text, re.IGNORECASE):
        raw    = m.group()
        middle = raw[1:-1]
        norm1  = _OBFUSCATION.sub('', raw)
        norm2  = raw[0] + _SEP_GROUP.sub('0', middle) + raw[-1]
        if (_NRIC_STRICT.fullmatch(norm1) or _NRIC_STRICT.fullmatch(norm2)) and m.span() not in seen:
            seen.add(m.span())
            findings.append({"type": "NRIC/FIN", "value": raw, "start": m.start(), "end": m.end(), "severity": "high"})
    return findings

def _detect_pii(text):
    findings = []
    for rule in PII_PATTERNS:
        for match in re.finditer(rule["pattern"], text, re.IGNORECASE):
            findings.append({"type": rule["type"], "value": match.group(), "start": match.start(), "end": match.end(), "severity": rule["severity"]})
    for f in _find_fuzzy_nric(text):
        if not any(e["type"] == "NRIC/FIN" and e["start"] == f["start"] for e in findings):
            findings.append(f)
    return sorted(findings, key=lambda x: x["start"])

def _redact_text(text, findings):
    for f in sorted(findings, key=lambda x: x["start"], reverse=True):
        text = text[:f["start"]] + f"[{f['type']}]" + text[f["end"]:]
    return text

@chat_bp.route('/check_pii', methods=['POST'])
def check_pii():
    print('CHECKING FOR PIIIIIIIIII')
    if not session.get('user'):
        return jsonify({"error": "Unauthorized"}), 401

    data     = request.get_json(silent=True) or {}
    message  = data.get("message", "")

    if not message:
        return jsonify({"has_pii": False, "findings": [], "redacted": ""}), 200

    findings = _detect_pii(message)
    has_pii  = len(findings) > 0

    types   = list({f["type"] for f in findings}) if has_pii else []
    warning = f"Your message may contain sensitive information: {', '.join(types)}." if has_pii else ""

    response = {
        "has_pii":   has_pii,
        "findings":  findings,
        "redacted":  _redact_text(message, findings) if has_pii else message,
        "warning":   warning
    }

    return jsonify(response), 200

# ...existing code...

# ──────────────────────────────────────────────────────────────
# Room Key — deterministic per-room AES key for history decryption
# ──────────────────────────────────────────────────────────────

@chat_bp.route('/room_key/<room_id>', methods=['GET'])
def get_room_key(room_id):
    """
    Return (or generate) a stable 256-bit room secret for this chat room.
    This secret is used by both participants to derive the same AES-GCM key,
    enabling decryption of stored message history across sessions.

    Security note: the server holds this secret, so this is NOT perfect forward
    secrecy — it is a deliberate tradeoff to enable chat history.
    """
    user_session = session.get('user')
    if not user_session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = user_session.get("id")

    # Verify the user is actually a participant in this room
    room = supabase.table("chat_rooms") \
        .select("id, patient_id, doctor_id") \
        .eq("id", room_id) \
        .execute()

    if not room.data:
        return jsonify({"error": "Room not found"}), 404

    r = room.data[0]
    if str(user_id) not in (str(r.get("patient_id")), str(r.get("doctor_id"))):
        return jsonify({"error": "Forbidden"}), 403

    # Check if a room secret already exists
    existing = supabase.table("chat_room_keys") \
        .select("room_secret") \
        .eq("room_id", room_id) \
        .execute()

    if existing.data:
        return jsonify({"room_secret": existing.data[0]["room_secret"]})

    # Generate and store a new 256-bit secret (hex-encoded)
    new_secret = secrets.token_hex(32)  # 32 bytes = 256 bits
    supabase.table("chat_room_keys").insert({
        "room_id":     room_id,
        "room_secret": new_secret,
    }).execute()

    return jsonify({"room_secret": new_secret})


def register_socketio_handlers(socketio):

    # ── In-memory room occupancy tracker ──────────────────────────────────────
    # Tracks how many active socket connections are in each room.
    # When the count drops to 0, all messages in that room are deleted.
    # This is reset on server restart — that's acceptable because a restart
    # also kills all sessions, so all users effectively "leave" anyway.
    # Format: { room_id: set(user_id, ...) }
    import threading
    room_occupancy = {}
    occupancy_lock = threading.Lock()

    def user_join_room(room_id, user_id):
        with occupancy_lock:
            if room_id not in room_occupancy:
                room_occupancy[room_id] = set()
            room_occupancy[room_id].add(user_id)

    def user_leave_room(room_id, user_id):
        """Remove user from occupancy. Returns True if room is now empty."""
        with occupancy_lock:
            if room_id in room_occupancy:
                room_occupancy[room_id].discard(user_id)
                if len(room_occupancy[room_id]) == 0:
                    del room_occupancy[room_id]
                    return True  # room is now empty
        return False

    @socketio.on('send_message')
    def handle_send_message(data):

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        text = data.get("text")
        iv = data.get("iv")  # <-- NEW: get IV if present

        if not room_id or not text:
            return

        sender_id = user_session.get("id")
        now_utc = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

        # Store encrypted message and IV (optional: store plaintext only if not using E2EE)
        supabase.table("chat_messages").insert({
            "room_id": room_id,
            "sender_id": sender_id,
            "content": text,
            "iv": iv,  # <-- NEW: store IV
        }).execute()

        profile_resp = supabase.table("profiles").select("full_name").eq("id", sender_id).execute()
        full_name = profile_resp.data[0]["full_name"] if profile_resp.data else "Unknown"

        emit("receive_message", {
            "room_id": room_id,
            "sender_id": sender_id,
            "fullname": full_name,
            "text": text,
            "iv": iv,  # <-- NEW: send IV
            "timestamp": now_utc
        }, room=room_id)


    @socketio.on('join_room')
    def handle_join(data):
        """User joins chat room — track their presence."""
        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        username = user_session.get("full_name")
        user_id  = user_session.get("id")

        if not room_id:
            return

        join_room(room_id)
        user_join_room(room_id, user_id)  # track occupancy

        emit("status", {
            "msg": f"{username} joined the chat"
        }, room=room_id)


    @socketio.on('leave_room')
    def handle_leave(data):
        """
        User leaves chat room.
        If this was the last participant, delete all messages in the room.
        The room itself is preserved — it's only removed when the doctor
        ends the consultation (which cascades message deletion via Supabase).
        """
        user_session = session.get('user')
        if not user_session:
            return

        room_id  = data.get("room_id")
        username = user_session.get("full_name")
        user_id  = user_session.get("id")

        leave_room(room_id)

        room_now_empty = user_leave_room(room_id, user_id)

        if room_now_empty and room_id:
            # Both users have left — delete all messages
            try:
                supabase.table("chat_messages").delete().eq("room_id", room_id).execute()
                print(f"Room {room_id} is empty — messages deleted.")
            except Exception as e:
                print(f"Error deleting messages for room {room_id}: {e}")

        emit("status", {
            "msg": f"{username} left the chat"
        }, room=room_id)

    @socketio.on('exchange_public_key')
    def handle_key_exchange(data):
        """Handle public key exchange for E2EE"""

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        public_key = data.get("public_key")

        if not room_id or not public_key:
            return

        sender_id = user_session.get("id")

        emit("public_key", {
            "sender_id": sender_id,
            "public_key": public_key
        }, room=room_id)

    @socketio.on_error()        # Handles the internal errors
    def error_handler(e):
        print(f"SocketIO Error: {e}")

def get_conversations_for_user(user_id):
    # Fetch all chat rooms where user is a participant
    rooms_resp = (
        supabase
        .table("chat_rooms")
        .select("*")
        .or_(f'patient_id.eq."{user_id}",doctor_id.eq."{user_id}"')
        .execute()
    )
    rooms = rooms_resp.data if rooms_resp.data else []
    conversations = []

    # Collect all room_ids for batch message query
    room_ids = [room["id"] for room in rooms]
    last_messages = {}
    if room_ids:
        # Get last message for each room
        msgs_resp = (
            supabase
            .table("chat_messages")
            .select("room_id, content, created_at")
            .in_("room_id", room_ids)
            .order("created_at", desc=True)
            .execute()
        )
        if msgs_resp.data:
            for msg in msgs_resp.data:
                rid = msg["room_id"]
                if rid not in last_messages:
                    last_messages[rid] = msg

    # Collect all participant ids for name lookup
    participant_ids = set()
    for room in rooms:
        participant_ids.add(room.get("patient_id"))
        participant_ids.add(room.get("doctor_id"))
    participant_ids.discard(user_id)
    name_map = {}
    if participant_ids:
        profiles = supabase.table("profiles").select("id, full_name").in_("id", list(participant_ids)).execute()
        if profiles.data:
            name_map = {row["id"]: row["full_name"] for row in profiles.data}

    for room in rooms:
        # Determine the other participant
        other_id = room["doctor_id"] if room["patient_id"] == user_id else room["patient_id"]
        conversations.append({
            "room_id": room["id"],
            "recipient_name": name_map.get(other_id, "Unknown"),
            "last_message": "🔒 Encrypted message" if last_messages.get(room["id"]) else "No messages yet",
            "timestamp": last_messages.get(room["id"], {}).get("created_at", ""),
        })
    return conversations

@chat_bp.route('/<room_id>')
def chat_room(room_id):

    user_session = session.get('user')
    if not user_session:
        flash("Please log in to access the chat", "error")
        return redirect(url_for('login'))

    # Note: chat history is intentionally NOT loaded here.
    # Messages are E2EE — the server stores only ciphertext and cannot
    # decrypt it. History is session-only by design (Option C / ephemeral).

    conversations = get_conversations_for_user(user_session.get("id"))

    if user_session.get("role") == "patient":
        recipient = supabase.table("chat_rooms").select("doctor_id").eq("id", room_id).execute()
    elif user_session.get("role") == "doctor":
        recipient = supabase.table("chat_rooms").select("patient_id").eq("id", room_id).execute()

    recipient_id = recipient.data[0]["doctor_id"] if user_session.get("role") == "patient" else recipient.data[0]["patient_id"]
    recipient_name = supabase.table("profiles").select("full_name", "role").eq("id", recipient_id).execute()

    return render_template(
        "chat/chat.html",
        room=room_id,
        role=user_session.get("role"),
        user_name=user_session.get("full_name"),
        user_id=user_session.get("id"),
        conversations=conversations,
        recipient_name=recipient_name
    )

@chat_bp.route('/')
def chat_redirect():
    user_session = session.get('user')
    if not user_session:
        flash("Please log in to access the chat", "error")
        return redirect(url_for('login'))

    user_id = user_session.get("id")

    filter_str = f'patient_id.eq."{user_id}",doctor_id.eq."{user_id}"'
    resp = (
        supabase
        .table("chat_rooms")
        .select("id")
        .or_(filter_str)
        .limit(1)
        .execute()
    )

    rooms = resp.data if resp.data else []
    if rooms:
        room_id = rooms[0]["id"]
        # Fetch conversations for sidebar
        conversations = get_conversations_for_user(user_id)
        return redirect(url_for('chat.chat_room', room_id=room_id))
    else:
        flash("No chat rooms found for your account.", "info")
        if user_session.get("role") == "patient":
            return redirect(url_for('patient_dashboard'))
        elif user_session.get("role") == "doctor":
            return redirect(url_for('doctor_dashboard'))
        else:
            return redirect(url_for('index'))

def create_chat_room(patient_id, doctor_id):
    # Check if room already exists (use .execute() not .single() to avoid error on 0 rows)
    room = supabase.table("chat_rooms").select("*").eq("patient_id", patient_id).eq("doctor_id", doctor_id).execute()
    if room.data and len(room.data) > 0:
        print("Chat room already exists between patient_id:", patient_id, "and doctor_id:", doctor_id)
        return room.data[0].get("id")
        
    resp = (
        supabase
        .table("chat_rooms")
        .insert({
            "patient_id": patient_id,
            "doctor_id": doctor_id,
        })
        .execute()
    )
    # Return the new room id if created
    if resp.data and isinstance(resp.data, list):
        return resp.data[0].get("id")
    elif resp.data and isinstance(resp.data, dict):
        return resp.data.get("id")
    return None

def delete_chat_room(room_id):
    """Delete a chat room when consultation ends."""
    supabase.table("chat_rooms").delete().eq("id", room_id).execute()