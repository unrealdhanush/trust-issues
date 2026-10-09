"""One-time ElevenLabs setup: two webhook tools, the on-call agent, and the Twilio number.

    PUBLIC_BASE_URL=https://<your-tunnel> uv run python scripts/setup_elevenlabs.py

Needs ELEVENLABS_API_KEY, plus TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER to
import the number. Prints the env lines to add to .env. Re-running creates new copies.
"""

import sys

import httpx

from trust.config import env

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


def headers():
    return {"xi-api-key": env("ELEVENLABS_API_KEY")}


def post(path, body):
    r = httpx.post(f"{API}{path}", json=body, headers=headers(), timeout=30)
    if r.status_code >= 400:
        sys.exit(f"{path} failed: {r.status_code} {r.text}")
    return r.json()


def webhook_tool(name, description, url, properties, required):
    api_schema = {
        "url": url,
        "method": "POST",
        "request_body_schema": {
            "type": "object",
            "description": description,
            "properties": properties,
            "required": required,
        },
    }
    if env("TRUST_WEBHOOK_TOKEN"):
        api_schema["request_headers"] = {"x-trust-token": env("TRUST_WEBHOOK_TOKEN")}
    return post("/v1/convai/tools", {"tool_config": {
        "type": "webhook", "name": name, "description": description, "api_schema": api_schema,
    }})["id"]


def main():
    base = env("PUBLIC_BASE_URL").rstrip("/")
    if not env("ELEVENLABS_API_KEY") or not base:
        sys.exit("set ELEVENLABS_API_KEY and PUBLIC_BASE_URL (your tunnel to `trust serve`)")

    fix_id = {"type": "string", "description": "The fix id, exactly as given at the start of the call."}
    read_id = webhook_tool(
        "read_ledger",
        "Look up this fix's proof attempts: which checks failed, which tests broke, what the patch changed.",
        f"{base}/tools/read_ledger", {"fix_id": fix_id}, ["fix_id"],
    )
    write_id = webhook_tool(
        "write_decision",
        "Record the engineer's decision once they have confirmed it.",
        f"{base}/tools/write_decision",
        {
            "fix_id": fix_id,
            "decision": {"type": "string", "enum": ["ship", "hold", "retry"],
                         "description": "ship, hold or retry"},
            "hint": {"type": "string",
                     "description": "For retry: the engineer's hint in their own words. Empty otherwise."},
        },
        ["fix_id", "decision"],
    )
    agent = post("/v1/convai/agents/create", {
        "name": "Trust Issues on-call",
        "conversation_config": {
            "agent": {
                "first_message": FIRST_MESSAGE,
                "language": "en",
                "prompt": {"prompt": PROMPT, "tool_ids": [read_id, write_id]},
            },
        },
    })
    print(f"ELEVENLABS_AGENT_ID={agent['agent_id']}")

    if all(env(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER")):
        number = post("/v1/convai/phone-numbers", {
            "provider": "twilio",
            "label": "Trust Issues on-call",
            "phone_number": env("TWILIO_FROM_NUMBER"),
            "sid": env("TWILIO_ACCOUNT_SID"),
            "token": env("TWILIO_AUTH_TOKEN"),
        })
        print(f"ELEVENLABS_PHONE_NUMBER_ID={number['phone_number_id']}")
    else:
        print("# Twilio settings missing: import the number in the ElevenLabs dashboard instead")


if __name__ == "__main__":
    main()
