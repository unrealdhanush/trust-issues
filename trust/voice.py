"""The escalation call: an ElevenLabs agent phones on-call through its Twilio integration.

Without ElevenLabs settings this runs in console mode: it prints the brief and the decision
is made from the dashboard or `trust decide`.
"""

import re

import httpx

from .config import env

API = "https://api.elevenlabs.io"

PROMPT = """You are Trust Issues, an automated security remediation system. You are calling the
on-call engineer because a security fix could not be proven safe.

What you know at the start of the call:
- Fix id: {{fix_id}}
- Vulnerability: {{vuln_class}} in {{file}}
- Attempts so far: {{attempts}}
- Why proof failed: {{failed_check}}
- Failing tests: {{failing_tests}}

How to behave:
- Speak briefly and plainly, like a calm colleague on a phone call.
- State only facts listed above or returned by the read_ledger tool. If you are asked something
  you don't know, call read_ledger with fix_id {{fix_id}}. If the answer still isn't there, say
  you don't have that information. Never guess.
- You need exactly one decision:
  ship: merge the fix even though it is unproven.
  hold: don't merge, and file a ticket for review.
  retry: try again with a hint from the engineer. Capture the hint in their own words.
- When you hear a decision, repeat it back in one sentence. Then call write_decision with
  fix_id {{fix_id}}, the decision, and the hint for a retry. After the tool confirms, say
  goodbye and end the call.
- Don't offer options other than ship, hold or retry. Don't discuss anything unrelated."""

FIRST_MESSAGE = (
    "Hi, this is Trust Issues. I couldn't prove a fix for a {{vuln_class}} in {{file}}: "
    "{{failed_check}}. Do you want me to ship it, hold it, or retry with a hint?"
)


def first_message(brief: dict):
    """The opening line with the brief's dynamic variables filled in, as the caller will hear it."""
    return re.sub(r"\{\{(\w+)\}\}", lambda m: str(brief.get(m.group(1), m.group(0))), FIRST_MESSAGE)


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
