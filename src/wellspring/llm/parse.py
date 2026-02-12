from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from pydantic import ValidationError

from ..schemas import Triple

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|```$", re.IGNORECASE | re.MULTILINE)
_TRAILING_COMMA_RE = re.compile(r",\s*([}\]])")

# Security identifiers that look like junk but are actually valuable entities.
# Checked BEFORE the junk regex so they are never dropped.
_SECURITY_ID_RE = re.compile(
    r"^T\d{4}"  # MITRE ATT&CK technique IDs — T1059, T1059.001
    r"|^TA\d{4}"  # MITRE ATT&CK tactic IDs — TA0001
    r"|^S\d{4}"  # MITRE ATT&CK software IDs — S0154
    r"|^G\d{4}"  # MITRE ATT&CK group IDs — G0007
    r"|^M\d{4}"  # MITRE ATT&CK mitigation IDs — M1036
    r"|^CVE-"  # CVE identifiers — CVE-2021-44228
    r"|^CWE-"  # CWE identifiers — CWE-79
    r"|^CAPEC-"  # CAPEC identifiers
    r"|^APT\d"  # APT group names — APT28, APT29
    r"|^FIN\d"  # FIN groups — FIN7
    r"|^UNC\d",  # UNC groups — UNC2452
    re.IGNORECASE,
)

# Patterns that indicate junk entities (page refs, IDs, bare numbers, etc.)
_JUNK_ENTITY_RE = re.compile(
    r"^[\d\s.,;:/#\-]+$"  # bare numbers / punctuation
    r"|^\d{3,}"  # long digit strings (ISBN, control numbers)
    r"|^page\s*\d+"  # page references
    r"|^figure\s*\d+"  # figure references
    r"|^table\s*\d+"  # table references
    r"|^chapter\s*\d+"  # chapter references
    r"|^section\s*\d+"  # section references
    r"|^https?://"  # URLs
    r"|^\d{1,2}$"  # single/double digit numbers
    r"|^isbn"  # ISBN
    r"|^doi:",  # DOI
    re.IGNORECASE,
)

# Predicates that are too vague to be useful
_JUNK_PREDICATES = frozenset(
    [
        "is",
        "has",
        "are",
        "was",
        "were",
        "be",
        "is_found_on_page_number",
        "is_on_page",
        "found_on_page",
        "is_in_section",
        "contains_page",
        "page_number",
        "has_isbn",
        "has_number",
        "has_id",
    ]
)


def _strip_code_fences(text: str) -> str:
    return _CODE_FENCE_RE.sub("", text).strip()


def _extract_json_block(text: str) -> str:
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return ""
    return text[start : end + 1]


def _repair_json(text: str) -> str:
    return _TRAILING_COMMA_RE.sub(r"\1", text)


def parse_json_safe(raw: str) -> Dict[str, Any]:
    if not raw:
        return {}
    text = _strip_code_fences(raw)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        extracted = _extract_json_block(text)
        if not extracted:
            return {}
        repaired = _repair_json(extracted)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError:
            return {}


def _is_junk_entity(name: str) -> bool:
    """Return True if *name* looks like noise rather than a real entity."""
    stripped = name.strip()
    if len(stripped) <= 2:
        return True
    # Whitelist security identifiers even if they look numeric
    if _SECURITY_ID_RE.match(stripped):
        return False
    return bool(_JUNK_ENTITY_RE.match(stripped))


def _is_junk_predicate(pred: str) -> bool:
    """Return True if *pred* is too vague or structural to be useful."""
    return pred.strip().lower() in _JUNK_PREDICATES


def extract_triples(raw: str) -> List[Triple]:
    data = parse_json_safe(raw)
    triples: List[Triple] = []
    if not data or "triples" not in data:
        return triples
    items = data.get("triples")
    if not isinstance(items, list):
        return triples
    for item in items:
        if not isinstance(item, dict):
            continue
        try:
            triple = Triple(**item)
        except ValidationError:
            continue
        if not triple.subject or not triple.predicate or not triple.object:
            continue
        # --- quality gate ---
        if _is_junk_entity(triple.subject) or _is_junk_entity(triple.object):
            continue
        if _is_junk_predicate(triple.predicate):
            continue
        if triple.confidence < 0.4:
            continue
        triples.append(triple)
    return triples
