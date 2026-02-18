from flask import Blueprint, render_template, session, redirect, url_for, flash
from flask_socketio import emit, join_room, leave_room, send
from supabase import create_client, Client
import os
from datetime import datetime

# Create chat blueprint
chat_bp = Blueprint('chat', __name__, url_prefix='/chat')

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def register_socketio_handlers(socketio):

    @socketio.on('send_message')
    def handle_send_message(data):
        """Handle sending a chat message"""

        user_session = session.get('user')
        if not user_session:
            return

        room_id = data.get("room_id")
        text = data.get("text")

        if not room_id or not text:
            return

        sender_id = user_session.get("id")

        # Store message in Supabase
        supabase.table("chat_messages").insert({
            "room_id": room_id,
            "sender_id": sender_id,
            "content": text
        }).execute()

        # Broadcast to room only
        emit("receive_message", {
            "room_id": room_id,
            "sender_id": sender_id,
            "text": text,
            "created_at": datetime.utcnow().isoformat()
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

@chat_bp.route('/<room_id>')
def chat_room(room_id):

    user_session = session.get('user')
    if not user_session:
        flash("Please log in to access the chat", "error")
        return redirect(url_for('login'))

    room_id = 1

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

    return render_template(
        "chat/chat.html",
        room=room_id,
        role=user_session.get("role"),
        user_name=user_session.get("full_name"),
        user_id=user_session.get("id"),
        messages=messages
    )
