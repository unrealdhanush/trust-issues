import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")


def env(name, default=""):
    return os.environ.get(name, default).strip()


RUNS_DIR = Path(env("TRUST_RUNS_DIR", str(ROOT / "runs")))
MAX_PROOFS = int(env("TRUST_MAX_PROOFS", "2"))
MAX_ESCALATIONS = int(env("TRUST_MAX_ESCALATIONS", "2"))
DECISION_TIMEOUT = int(env("TRUST_DECISION_TIMEOUT", "600"))
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-6.1-sol")
