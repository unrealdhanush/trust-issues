Scripted agent output, used when `TRUST_AGENT=scripted` (the default without `OPENAI_API_KEY`).
It replays the demo deterministically so the prove harness, ledger and escalation can be built
and rehearsed without an LLM.

- `<file stem>/exploit.py` is the exploit test for that finding.
- `<file stem>/attempt-N/` holds the files the agent writes on its Nth attempt.
- `<file stem>/hint-N/` holds the files it writes on its Nth attempt after a human hint.
