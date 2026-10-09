import hashlib
from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    rule_id: str
    path: str  # relative to the target root
    line: int
    message: str
    vuln_class: str = "sqli"
    related_rules: list[str] = field(default_factory=list)
    function: str = ""  # qualname of the vulnerable function, "<module>" at top level

    @property
    def fix_id(self):
        # One finding per function, so file + function is the identity. The rule id differs
        # between the MCP server and the CLI (different rule namespaces), so it stays out.
        digest = hashlib.sha1(f"{self.vuln_class}:{self.path}:{self.function}".encode()).hexdigest()[:6]
        stem = self.path.rsplit("/", 1)[-1].removesuffix(".py")
        return f"{self.vuln_class}-{stem}-{digest}"

    @property
    def rule_short(self):
        return self.rule_id.rsplit(".", 1)[-1]


@dataclass
class FileEdit:
    path: str
    content: str


@dataclass
class Patch:
    edits: list[FileEdit]
    explanation: str = ""


@dataclass
class Proof:
    """The evidence for one attempt. A fix is proven only when every check holds."""

    exploit_pre: bool  # exploit landed on the original code
    exploit_post: bool  # exploit landed on the patched code
    semgrep_clear: bool
    suite_pass: bool
    tamper: list[str] = field(default_factory=list)
    slop: list[str] = field(default_factory=list)  # scope violations, see scope.py
    failing_tests: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    diff: str = ""
    details: dict = field(default_factory=dict)

    @property
    def scope_clean(self):
        return not self.slop

    @property
    def proven(self):
        return (
            self.exploit_pre
            and not self.exploit_post
            and self.semgrep_clear
            and self.suite_pass
            and not self.tamper
            and not self.slop
        )

    @property
    def verdict(self):
        return "proven" if self.proven else "failed"

    def to_dict(self):
        d = asdict(self)
        d["verdict"] = self.verdict
        d["scope_clean"] = self.scope_clean
        return d
