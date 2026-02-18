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

        print('joining ROOOOOM')

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        username = user_session.get("full_name")
        print(room_id)

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

    return render_template(
        "chat/chat.html",
        room=room_id,
        role=user_session.get("role"),
        user_name=user_session.get("full_name"),
        user_id=user_session.get("id"),
        messages=messages
    )
