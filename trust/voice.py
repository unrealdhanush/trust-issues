"""The escalation call: an ElevenLabs agent phones on-call through its Twilio integration.

Without ElevenLabs settings this runs in console mode: it prints the brief and the decision
is made from the dashboard or `trust decide`.
"""

import httpx

from .config import env

API = "https://api.elevenlabs.io"


def configured():
    return all(env(k) for k in ("ELEVENLABS_API_KEY", "ELEVENLABS_AGENT_ID",
                                "ELEVENLABS_PHONE_NUMBER_ID", "ONCALL_PHONE_NUMBER"))


def _headers():
    return {"xi-api-key": env("ELEVENLABS_API_KEY")}


def call_oncall(brief: dict):
    """Place the call. `brief` becomes the agent's dynamic variables. Returns a conversation id."""
    body = {
        "agent_id": env("ELEVENLABS_AGENT_ID"),
        "agent_phone_number_id": env("ELEVENLABS_PHONE_NUMBER_ID"),
        "to_number": env("ONCALL_PHONE_NUMBER"),
        "conversation_initiation_client_data": {
            "dynamic_variables": {k: str(v) for k, v in brief.items()},
        },
    }
    resp = httpx.post(f"{API}/v1/convai/twilio/outbound-call", json=body, headers=_headers(), timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success", True):
        raise RuntimeError(data.get("message", "outbound call failed"))
    return data.get("conversation_id")


def conversation(conversation_id):
    resp = httpx.get(f"{API}/v1/convai/conversations/{conversation_id}", headers=_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()


def transcript_text(conv):
    lines = []
    for turn in conv.get("transcript") or []:
        if turn.get("message"):
            lines.append(f'{turn.get("role", "?")}: {turn["message"]}')
    return "\n".join(lines)
