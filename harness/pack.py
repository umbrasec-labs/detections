"""Read-only access to the upstream sigma-pack and its writeups.

Nothing here writes under the upstream checkout.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

import yaml

PACK_PATH = "tools/sigma-pack"
PACK_GLOBS = ("*.yml", "*.yaml", "*.kql")
WRITEUP_RE = re.compile(r"https://umbrasec\.dev/(research/[a-z0-9][a-z0-9-]*\.html)")
SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[\"'A-Z0-9(])")


def normalize(text: str) -> str:
    """Collapse every whitespace run to one space and strip."""
    return re.sub(r"\s+", " ", text).strip()


@dataclass
class RuleFile:
    id: str  # file stem; also the BlueTeamMapper rule id
    rel: str  # path relative to tools/sigma-pack, posix style
    path: Path
    sha256: str
    engine: str  # sigma | kusto
    text: str
    docs: list = field(default_factory=list)  # parsed YAML documents (sigma only)

    @property
    def upstream_rel(self) -> str:
        return f"{PACK_PATH}/{self.rel}"


def discover(upstream: Path) -> list[RuleFile]:
    pack = Path(upstream) / PACK_PATH
    paths = sorted({p for g in PACK_GLOBS for p in pack.rglob(g) if p.is_file()})
    out = []
    for p in paths:
        raw = p.read_bytes()
        text = raw.decode("utf-8")
        engine = "kusto" if p.suffix == ".kql" else "sigma"
        docs = []
        if engine == "sigma":
            try:
                docs = [d for d in yaml.safe_load_all(text) if d is not None]
            except yaml.YAMLError:
                docs = []
        out.append(
            RuleFile(
                id=p.stem,
                rel=p.relative_to(pack).as_posix(),
                path=p,
                sha256=hashlib.sha256(raw).hexdigest(),
                engine=engine,
                text=text,
                docs=docs,
            )
        )
    return out


def commit(upstream: Path) -> str | None:
    try:
        res = subprocess.run(
            ["git", "-C", str(upstream), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    sha = res.stdout.strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _string_scalars(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                yield k
            yield from _string_scalars(v)
    elif isinstance(node, list):
        for v in node:
            yield from _string_scalars(v)


def kql_comments(text: str) -> str:
    lines = [ln.strip() for ln in text.splitlines()]
    return normalize(" ".join(ln[2:] for ln in lines if ln.startswith("//")))


def rule_haystacks(rf: RuleFile) -> list[str]:
    """Normalized texts a `source: rule` quote may be a substring of."""
    if rf.engine == "kusto":
        return [kql_comments(rf.text)]
    hay = [normalize(rf.text)]
    hay += [normalize(s) for s in _string_scalars(rf.docs)]
    return hay


def titled_doc(rf: RuleFile) -> dict | None:
    for d in rf.docs:
        if isinstance(d, dict) and "title" in d:
            return d
    return None


def falsepositive_bullets(rf: RuleFile) -> list[str]:
    bullets = []
    for d in rf.docs:
        if isinstance(d, dict):
            for b in d.get("falsepositives") or []:
                bullets.append(normalize(str(b)))
    return bullets


def writeup_refs(rf: RuleFile) -> set[str]:
    return set(WRITEUP_RE.findall(rf.text))


_BLOCK_TAGS = {
    "address", "article", "aside", "blockquote", "br", "dd", "div", "dl", "dt", "figcaption",
    "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav",
    "ol", "p", "pre", "section", "table", "tbody", "td", "th", "thead", "tr", "ul",
}
_SKIP_TAGS = {"script", "style", "template", "noscript"}
_HEADINGS = {"h2", "h3", "h4"}


class _TextParser(HTMLParser):
    """Collects visible text, plus the text of one named section.

    convert_charrefs=True unescapes entities exactly once.
    """

    def __init__(self, section: str | None):
        super().__init__(convert_charrefs=True)
        self.section = section
        self.parts: list[str] = []
        self.sec_parts: list[str] = []
        self.skip = 0
        self.pre = 0
        self.heading: list[str] | None = None
        self.state = "before"  # before | in | after
        self.found = False

    def handle_starttag(self, tag, attrs):
        if tag in _SKIP_TAGS:
            self.skip += 1
            return
        if tag == "pre":
            self.pre += 1
        if tag in _HEADINGS:
            self.heading = []
            if self.state == "in":
                self.state = "after"
        if tag in _BLOCK_TAGS:
            self._emit(" ")

    def handle_endtag(self, tag):
        if tag in _SKIP_TAGS:
            self.skip = max(0, self.skip - 1)
            return
        if tag in _BLOCK_TAGS:
            self._emit(" ")
        if tag == "pre":
            self.pre = max(0, self.pre - 1)
        if tag in _HEADINGS and self.heading is not None:
            text = normalize("".join(self.heading))
            self.heading = None
            if self.section and self.state == "before" and text == self.section:
                self.state = "in"
                self.found = True

    def handle_data(self, data):
        if self.skip:
            return
        if self.heading is not None:
            self.heading.append(data)
        self._emit(data)

    def _emit(self, s):
        if self.skip:
            return
        self.parts.append(s)
        if self.state == "in" and self.heading is None and not self.pre:
            self.sec_parts.append(s)


def _parse(path: Path, section: str | None) -> _TextParser:
    p = _TextParser(section)
    p.feed(Path(path).read_text(encoding="utf-8"))
    p.close()
    return p


def writeup_text(path: Path) -> str:
    """Normalized visible text of a writeup (tags stripped, entities unescaped)."""
    return normalize("".join(_parse(path, None).parts))


def writeup_section(path: Path, heading: str = "Honest limitations") -> str | None:
    """Normalized text between the h2-h4 titled `heading` and the next h2-h4, skipping <pre>."""
    p = _parse(path, heading)
    if not p.found:
        return None
    return normalize("".join(p.sec_parts))


def split_sentences(text: str) -> list[str]:
    return [s for s in (normalize(x) for x in SENTENCE_RE.split(text)) if s]
