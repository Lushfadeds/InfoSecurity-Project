from flask import Blueprint, render_template, session, redirect, url_for, flash
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

def register_socketio_handlers(socketio):

    @socketio.on('send_message')
    def handle_send_message(data):

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        text = data.get("text")

        if not room_id or not text:
            return

        sender_id = user_session.get("id")

        # Use UTC ISO format with 'Z' for consistency
        now_utc = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

        supabase.table("chat_messages").insert({
            "room_id": room_id,
            "sender_id": sender_id,
            "content": text,
            "created_at": now_utc
        }).execute()

        profile_resp = supabase.table("profiles").select("full_name").eq("id", sender_id).execute()
        full_name = profile_resp.data[0]["full_name"] if profile_resp.data else "Unknown"

        emit("receive_message", {
            "room_id": room_id,
            "sender_id": sender_id,
            "fullname": full_name,
            "text": text,
            "timestamp": now_utc
        }, room=room_id)


    @socketio.on('join_room')
    def handle_join(data):
        """User joins chat room"""

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        username = user_session.get("full_name")

        if not room_id:
            return

        join_room(room_id)

        emit("status", {
            "msg": f"{username} joined the chat"
        }, room=room_id)


    @socketio.on('leave_room')
    def handle_leave(data):
        """User leaves chat room"""

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        username = user_session.get("full_name")

        leave_room(room_id)

        emit("status", {
            "msg": f"{username} left the chat"
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
            "last_message": last_messages.get(room["id"], {}).get("content", ""),
            "timestamp": last_messages.get(room["id"], {}).get("created_at", ""),
        })
    return conversations

@chat_bp.route('/<room_id>')
def chat_room(room_id):

    user_session = session.get('user')
    if not user_session:
        flash("Please log in to access the chat", "error")
        return redirect(url_for('login'))

    # Load chat history
    resp = (
        supabase
        .table("chat_messages")
        .select("*")
        .eq("room_id", room_id)
        .order("created_at", desc=False)
        .execute()
    )

    messages = resp.data if resp.data else []

    # Fetch all sender_ids in one go for efficiency
    sender_ids = list({msg["sender_id"] for msg in messages if msg.get("sender_id")})
    name_map = {}
    if sender_ids:
        profiles = supabase.table("profiles").select("id, full_name").in_("id", sender_ids).execute()
        if profiles.data:
            name_map = {row["id"]: row["full_name"] for row in profiles.data}

    # Attach fullname and standardize timestamp to each message
    for msg in messages:
        msg["fullname"] = name_map.get(msg.get("sender_id"), "Unknown")
        # Standardize timestamp field for template
        # Prefer 'created_at', fallback to None
        msg["timestamp"] = msg.get("created_at")

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
        messages=messages,
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
