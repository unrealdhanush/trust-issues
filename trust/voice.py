"""The escalation call: an ElevenLabs agent phones on-call through its Twilio integration.

Without ElevenLabs settings this runs in console mode: it prints the brief and the decision
is made from the dashboard or `trust decide`.
"""

import json
import re
from urllib.parse import urlencode

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

How to speak:
- Brief and plain, like a calm colleague on a phone call. One or two sentences at a time.
- Never read file paths, "::", underscores or ids aloud. Say "the admin sort test", not
  "tests/test_admin.py::test_orders_custom_sort_expression". Say "the admin module", not
  "app/admin.py", after the first mention.
- If the engineer goes quiet, they are probably busy. Wait. Check in at most once, briefly
  ("Take your time, I'm here."), then keep waiting without repeating the question.
- A fragment, a filler or a lone "okay" is not an answer, and the line may be noisy. Don't react
  to it; wait for a full sentence. If you truly can't tell what they said, ask once, briefly:
  "Sorry, I didn't catch that."
- No sympathy filler ("I hear you", "I understand your concern", "I know you wouldn't want").
  Answer the question or ask yours.

How to stay honest:
- State only facts listed above or returned by the read_ledger tool. If you're asked something
  you don't know, call read_ledger with fix_id {{fix_id}}. If the answer still isn't there, say
  you don't have that information. Never guess.

The decision:
- You need exactly one decision:
  ship: merge the fix even though it is unproven.
  hold: don't merge, and file a ticket for review.
  retry: try again with a hint from the engineer.
- When proof failed because an existing test broke while the exploit was blocked, explain the
  trade-off before asking for a hint. The fix closes the hole, but it changes behavior that the
  test still expects, and you are not allowed to edit tests yourself. Then ask the useful
  question directly, for example: "Should I update that test to match the safe behavior?"
  A yes is the hint; you don't need them to word it.
- When you have a decision, repeat it back in one sentence and call write_decision with fix_id
  {{fix_id}}, the decision, and for a retry the hint in plain words (for example "you can update
  the admin sort test"). After the tool confirms, say one short goodbye sentence and then
  call end_call straight away. Don't keep talking after the goodbye.
- Don't offer options other than ship, hold or retry. Don't discuss anything unrelated."""

FIRST_MESSAGE = (
    "Hi, this is Trust Issues. I couldn't prove a fix for a {{vuln_class}} in {{file}}: "
    "{{failed_check}}. Do you want me to ship it, hold it, or retry with a hint?"
)


# Turn-taking for a phone call in a noisy room: wait for a real sentence, ignore voices in the
# background, don't let "okay" or "mm" cut the agent off, and listen hard for the decision words.
LISTENING = {
    "turn": {"turn_eagerness": "patient", "speculative_turn": False,
             "interruption_ignore_terms": ["okay", "ok", "mm", "mhm", "uh", "um", "yeah", "yes",
                                           "right", "hmm", "uh huh"]},
    "vad": {"background_voice_detection": True},
    "asr": {"keywords": ["retry", "ship", "hold", "hint", "admin sort test", "Trust Issues"]},
}

# ElevenLabs' built-in hang-up tool; without it the agent lingers after the decision.
END_CALL_TOOL = {
    "type": "system",
    "name": "end_call",
    "description": "End the call right after your goodbye, once write_decision has confirmed the "
                   "decision, or as soon as the engineer says goodbye or asks to hang up.",
    "params": {"system_tool_type": "end_call"},
}

# Silence before the agent speaks again; the default 7 seconds makes it nag a busy engineer.
TURN_TIMEOUT_SECS = 20


def spoken_test(nodeid):
    """tests/test_admin.py::test_orders_custom_sort_expression -> "the admin test for orders custom sort expression"."""
    path, _, name = nodeid.partition("::")
    module = path.rsplit("/", 1)[-1].removesuffix(".py").removeprefix("test_").replace("_", " ")
    name = name.split("[", 1)[0].removeprefix("test_").replace("_", " ")
    return f"the {module} test for {name}" if name else f"the {module} tests"


def first_message(brief: dict):
    """The opening line with the brief's dynamic variables filled in, as the caller will hear it."""
    return re.sub(r"\{\{(\w+)\}\}", lambda m: str(brief.get(m.group(1), m.group(0))), FIRST_MESSAGE)


def twilio_configured():
    return all(env(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"))


def configured():
    """Can we ring a phone: through ElevenLabs' Twilio integration, or through Twilio directly."""
    base = all(env(k) for k in ("ELEVENLABS_API_KEY", "ELEVENLABS_AGENT_ID", "ONCALL_PHONE_NUMBER"))
    return base and (bool(env("ELEVENLABS_PHONE_NUMBER_ID")) or twilio_configured())


def _headers():
    return {"xi-api-key": env("ELEVENLABS_API_KEY")}


def _call_via_elevenlabs(dynamic):
    body = {
        "agent_id": env("ELEVENLABS_AGENT_ID"),
        "agent_phone_number_id": env("ELEVENLABS_PHONE_NUMBER_ID"),
        "to_number": env("ONCALL_PHONE_NUMBER"),
        "conversation_initiation_client_data": {"dynamic_variables": dynamic},
    }
    resp = httpx.post(f"{API}/v1/convai/twilio/outbound-call", json=body, headers=_headers(), timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if not data.get("success", True):
        raise RuntimeError(data.get("message", "outbound call failed"))
    return data.get("conversation_id")


def register_call(dynamic):
    """TwiML that connects a Twilio call to the agent, with the brief as dynamic variables."""
    resp = httpx.post(f"{API}/v1/convai/twilio/register-call", headers=_headers(), timeout=30, json={
        "agent_id": env("ELEVENLABS_AGENT_ID"),
        "from_number": env("TWILIO_FROM_NUMBER"),
        "to_number": env("ONCALL_PHONE_NUMBER"),
        "direction": "outbound",
        "conversation_initiation_client_data": {"dynamic_variables": {k: str(v) for k, v in dynamic.items()}},
    })
    resp.raise_for_status()
    twiml = resp.text.strip()
    return json.loads(twiml) if twiml.startswith('"') else twiml  # sometimes a JSON-encoded string


def _call_via_twilio(dynamic):
    """Twilio places a plain call; the agent joins through ElevenLabs' TwiML.

    A Twilio trial account refuses the parameters ElevenLabs' own outbound call uses, and
    inline TwiML too, but allows a basic call to a verified number whose instructions come
    from a URL (with its trial notice first). With PUBLIC_BASE_URL set, Twilio fetches them
    from `trust-issues serve` at /twilio/connect; otherwise they're sent inline.
    """
    base = env("PUBLIC_BASE_URL").rstrip("/")
    params = {"To": env("ONCALL_PHONE_NUMBER"), "From": env("TWILIO_FROM_NUMBER")}
    if base:
        query = urlencode({"fix_id": dynamic["fix_id"], "t": env("TRUST_WEBHOOK_TOKEN")})
        params["Url"] = f"{base}/twilio/connect?{query}"
    else:
        params["Twiml"] = register_call(dynamic)
    sid = env("TWILIO_ACCOUNT_SID")
    call = httpx.post(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json",
                      auth=(sid, env("TWILIO_AUTH_TOKEN")), timeout=30, data=params)
    if call.status_code >= 400:
        raise RuntimeError(f"Twilio refused the call: {call.text[:300]}")
    return call.json()["sid"]


def call_oncall(brief: dict):
    """Ring on-call. `brief` becomes the agent's dynamic variables.

    Returns {"via", "conversation_id", "call_sid", "note"}. Tries ElevenLabs' outbound call
    first, then Twilio directly; TRUST_CALL_VIA=twilio skips straight to Twilio.
    """
    dynamic = {k: str(v) for k, v in brief.items()}
    note = ""
    if env("TRUST_CALL_VIA", "elevenlabs") != "twilio" and env("ELEVENLABS_PHONE_NUMBER_ID"):
        try:
            return {"via": "elevenlabs", "conversation_id": _call_via_elevenlabs(dynamic), "call_sid": None, "note": ""}
        except Exception as exc:
            if not twilio_configured():
                raise
            note = f"ElevenLabs' outbound call failed ({str(exc)[:120]})"
    return {"via": "twilio", "conversation_id": None, "call_sid": _call_via_twilio(dynamic), "note": note}


def conversation(conversation_id):
    resp = httpx.get(f"{API}/v1/convai/conversations/{conversation_id}", headers=_headers(), timeout=30)
    resp.raise_for_status()
    return resp.json()


def transcript_text(conv):
    lines = []
    for turn in conv.get("transcript") or []:
        role = turn.get("role", "?")
        if turn.get("message"):
            lines.append(f'{role}: {turn["message"]}')
        for call in turn.get("tool_calls") or []:
            lines.append(f'{role}: [{call.get("tool_name")} {call.get("params_as_json") or ""}]')
    return "\n".join(lines)


def find_conversation(fix_id, since_unix, limit=10):
    """The agent's conversation about `fix_id` (a widget call has no id handed to us)."""
    resp = httpx.get(f"{API}/v1/convai/conversations", headers=_headers(), timeout=30,
                     params={"agent_id": env("ELEVENLABS_AGENT_ID"), "page_size": limit})
    resp.raise_for_status()
    for conv in resp.json().get("conversations", []):
        if conv.get("start_time_unix_secs", 0) < since_unix - 5:
            continue
        detail = conversation(conv["conversation_id"])
        dyn = (detail.get("conversation_initiation_client_data") or {}).get("dynamic_variables") or {}
        if dyn.get("fix_id") == fix_id:
            return conv["conversation_id"]
    return None
