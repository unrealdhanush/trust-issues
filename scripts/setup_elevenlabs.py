"""One-time ElevenLabs setup: two webhook tools, the on-call agent, and the Twilio number.

    PUBLIC_BASE_URL=https://<your-tunnel> uv run python scripts/setup_elevenlabs.py
    uv run python scripts/setup_elevenlabs.py --number-only   # import the Twilio number later
    uv run python scripts/setup_elevenlabs.py --update        # push prompt/settings to the existing
                                                              # agent, repoint tools at PUBLIC_BASE_URL

Needs ELEVENLABS_API_KEY, plus TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER to
import the number. Prints the env lines to add to .env. Re-running creates new copies.
"""

import sys

import httpx

from trust.config import env
from trust.voice import END_CALL_TOOL, FIRST_MESSAGE, LISTENING, PROMPT, TURN_TIMEOUT_SECS

API = "https://api.elevenlabs.io"


def headers():
    return {"xi-api-key": env("ELEVENLABS_API_KEY")}


def call(method, path, body=None):
    r = httpx.request(method, f"{API}{path}", json=body, headers=headers(), timeout=30)
    if r.status_code >= 400:
        sys.exit(f"{method} {path} failed: {r.status_code} {r.text}")
    return r.json()


def post(path, body):
    return call("POST", path, body)


def agent_config(tool_ids):
    return {
        "agent": {
            "first_message": FIRST_MESSAGE,
            "language": "en",
            "prompt": {"prompt": PROMPT, "tool_ids": tool_ids,
                       "built_in_tools": {"end_call": END_CALL_TOOL}},
        },
        "turn": {"turn_timeout": TURN_TIMEOUT_SECS, **LISTENING["turn"]},
        "vad": LISTENING["vad"],
        "asr": LISTENING["asr"],
    }


def update():
    """Change the existing agent in place: same agent id, same tools, new prompt and settings."""
    agent_id = env("ELEVENLABS_AGENT_ID")
    if not agent_id:
        sys.exit("set ELEVENLABS_AGENT_ID")
    base = env("PUBLIC_BASE_URL").rstrip("/")
    current = call("GET", f"/v1/convai/agents/{agent_id}")
    tool_ids = current["conversation_config"]["agent"]["prompt"].get("tool_ids") or []
    for tid in tool_ids:
        cfg = call("GET", f"/v1/convai/tools/{tid}")["tool_config"]
        schema = cfg["api_schema"]
        path = "/tools/" + schema["url"].rstrip("/").rsplit("/tools/", 1)[-1]
        wanted_headers = {"x-trust-token": env("TRUST_WEBHOOK_TOKEN")} if env("TRUST_WEBHOOK_TOKEN") else {}
        if base and (schema["url"] != base + path or (schema.get("request_headers") or {}) != wanted_headers):
            schema["url"] = base + path
            schema["request_headers"] = wanted_headers
            call("PATCH", f"/v1/convai/tools/{tid}", {"tool_config": cfg})
            print(f"repointed {cfg['name']} -> {schema['url']}")
        else:
            print(f"{cfg['name']} already points at {schema['url']}")
    call("PATCH", f"/v1/convai/agents/{agent_id}", {"conversation_config": agent_config(tool_ids)})
    print(f"updated agent {agent_id}: prompt, opening line, end_call, listening settings, "
          f"turn_timeout={TURN_TIMEOUT_SECS}s")


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


def import_number():
    if not all(env(k) for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER")):
        print("# Twilio settings missing: add them to .env, then run with --number-only")
        return
    number = post("/v1/convai/phone-numbers", {
        "provider": "twilio",
        "label": "Trust Issues on-call",
        "phone_number": env("TWILIO_FROM_NUMBER"),
        "sid": env("TWILIO_ACCOUNT_SID"),
        "token": env("TWILIO_AUTH_TOKEN"),
    })
    print(f"ELEVENLABS_PHONE_NUMBER_ID={number['phone_number_id']}")


def main():
    if "--update" in sys.argv:
        if not env("ELEVENLABS_API_KEY"):
            sys.exit("set ELEVENLABS_API_KEY")
        update()
        return
    if "--number-only" in sys.argv:
        if not env("ELEVENLABS_API_KEY"):
            sys.exit("set ELEVENLABS_API_KEY")
        import_number()
        return
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
        "conversation_config": agent_config([read_id, write_id]),
    })
    print(f"ELEVENLABS_AGENT_ID={agent['agent_id']}")
    import_number()


if __name__ == "__main__":
    main()
