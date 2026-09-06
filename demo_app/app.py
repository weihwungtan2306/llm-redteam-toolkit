"""
AcmeCorp Support Bot -- an intentionally vulnerable demo target for the
LLM red-teaming toolkit.

This is a small Flask app that behaves like a typical "wrap an LLM in a
customer-support chat widget" project. It is deliberately built the way a
lot of real first-drafts are: system prompt concatenated with user input,
untrusted document content folded into the same context, and business
rules (refund limits) enforced by asking the model nicely rather than in
code. Every one of those choices is a documented, real-world LLM
application weakness (see OWASP LLM Top 10) -- this app exists so the
toolkit has a safe, reproducible, zero-setup target to demonstrate them
against.

Run it:
    python demo_app/app.py
Then point the red-team runner at it:
    python cli.py run --target http://127.0.0.1:5001
"""

from __future__ import annotations

import os
import sys
import uuid

from flask import Flask, jsonify, request

sys.path.insert(0, os.path.dirname(__file__))
from llm_backend import get_backend  # noqa: E402

app = Flask(__name__)
BACKEND = get_backend()

SYSTEM_PROMPT_PATH = os.path.join(os.path.dirname(__file__), "system_prompt.txt")
with open(SYSTEM_PROMPT_PATH, "r", encoding="utf-8") as f:
    SYSTEM_PROMPT = f.read()

SESSIONS: dict[str, list] = {}


def _history_for(session_id: str) -> list:
    return SESSIONS.setdefault(session_id, [])


@app.get("/health")
def health():
    return jsonify({"status": "ok", "backend": BACKEND.name})


@app.post("/reset")
def reset():
    body = request.get_json(force=True, silent=True) or {}
    session_id = body.get("session_id", "default")
    SESSIONS.pop(session_id, None)
    return jsonify({"status": "reset", "session_id": session_id})


@app.post("/chat")
def chat():
    body = request.get_json(force=True, silent=True) or {}
    session_id = body.get("session_id") or str(uuid.uuid4())
    message = body.get("message", "")
    history = _history_for(session_id)

    result = BACKEND.chat(SYSTEM_PROMPT, history, message)

    history.append({"role": "user", "content": message})
    history.append({"role": "assistant", "content": result.reply})

    return jsonify({"session_id": session_id, "reply": result.reply, "meta": result.meta})


@app.post("/summarize")
def summarize():
    """Simulates a common real feature: summarizing an inbound customer
    document (an email, an order note, a support ticket) into the chat.
    The document is untrusted content -- this endpoint is the app's
    indirect-prompt-injection attack surface."""
    body = request.get_json(force=True, silent=True) or {}
    session_id = body.get("session_id") or str(uuid.uuid4())
    document = body.get("document", "")
    history = _history_for(session_id)

    result = BACKEND.chat(
        SYSTEM_PROMPT,
        history,
        user_message="Please summarize the note below for the support log.",
        injected_document=document,
    )

    history.append({"role": "user", "content": f"[summarize document]\n{document}"})
    history.append({"role": "assistant", "content": result.reply})

    return jsonify({"session_id": session_id, "reply": result.reply, "meta": result.meta})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    print(f"AcmeCorp Support Bot running (backend={BACKEND.name}) on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port)
