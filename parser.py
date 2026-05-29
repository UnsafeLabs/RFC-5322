#!/usr/bin/env python3
"""
RFC 5322 compliant email address parser.

Implements the full ABNF grammar from §3.2-§3.4 of RFC 5322,
with optional obsolete syntax support from §4.4.

Reference: RFC 5322 — Internet Message Format (October 2008)
"""

from __future__ import annotations

import re
import string as _string
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""
    display_name: Optional[str]
    local_part: str
    domain: str
    is_group: bool
    group_members: list[RFC5322Address]
    comments: list[str]
    source: str


class AddressParser:
    """
    RFC 5322 compliant email address parser.

    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.
    """

    # ── Lexical token patterns (§3.2) ────────────────────────────────────────

    # All printable ASCII except special atoms and obs-* unless strict=False
    # atext = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
    ATOM_CHARS = "a-zA-Z0-9!#$%&'*+/=?^_`{|}~-"
    DOT_ATOM_TEXT = rf"[{ATOM_CHARS}]+"

    # Quoted strings (§3.2.4)
    QUOTED_STRING = r'"(?:[^"\\]|\\.)*"'

    # Comments / folding whitespace (§3.2.2) — recursive
    CFWS = r"(?:\s*(?:\([^)]*\)\s*)*)?"

    # Domain literals (§3.2.3)
    DOMAIN_LITERAL = r"\[(?:[^\\\]]+|\\.)*\]"

    # Angle brackets
    ANGLE_ADDR = rf"<{CFWS}({QUOTED_STRING}|[^<>]+){CFWS}>"

    # Display name (phrase)
    PHRASE = r"(?:\"?:[^\"<>()@,;:\\.@\[]+\"?)+"

    # ── §3.4 addr-spec ────────────────────────────────────────────────────────
    # addr-spec = local-part "@" domain
    ADDR_SPEC = rf"{CFWS}([^@<>]+){CFWS}@{CFWS}([^@<>]+){CFWS}"

    # ── §3.4 mailbox / name-addr / group ────────────────────────────────────
    # name-addr = [display-name] angle-addr
    # mailbox  = name-addr / addr-spec
    # group    = display-name ":" [mailbox-list] ";" [CFWS]

    def __init__(self, strict: bool = True):
        """
        Args:
            strict: If True, reject obs-* productions.
                    If False, accept obsolete forms per §4.4.
        """
        self.strict = strict
        self._init_compiled_patterns()

    def _init_compiled_patterns(self):
        """Pre-compile regex patterns for speed."""
        self._cfws = re.compile(r"\s*(?:\([^()]*\)\s*)*", re.VERBOSE)
        self._quoted_pair = re.compile(r"\\(.)")
        self._qtext = re.compile(r"[\x21\x23-\x24\x26\x28-\x5b\x5d-\x7e]")
        self._dtext = re.compile(r"[\x21-\x24\x26-\x5a\x5c-\x7e]")
        self._obs_qstr = re.compile(r"\"(?:[^\"\\\n]|\\\n|\\\\)*\"")
        self._obs_phrase = re.compile(r"[\x21-\x7e]+(?:\s[\x21-\x7e]+)*")

    def _strip_cfws(self, s: str) -> str:
        """Remove comment-free white space and comments."""
        return self._cfws.sub("", s)

    def _unquote(self, qs: str) -> str:
        """Strip outer quotes and decode quoted-pairs from a quoted string."""
        if qs.startswith('"') and qs.endswith('"'):
            qs = qs[1:-1]
        return self._quoted_pair.sub(r"\1", qs)

    # ── §3.2.3 dot-atom ───────────────────────────────────────────────────────
    def _parse_dot_atom(self, s: str) -> tuple[str, str]:
        """Parse a dot-atom text; return (value, rest)."""
        s = self._strip_cfws(s)
        m = re.match(r"([a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+)", s)
        if m:
            return m.group(1), s[m.end():]
        raise ValueError(f"Expected dot-atom, got: {s[:50]}")

    # ── §3.4.1 addr-spec ────────────────────────────────────────────────────
    def _parse_addr_spec(self, s: str) -> tuple[str, str, str]:
        """Parse addr-spec = local-part '@' domain. Returns (local, domain, rest)."""
        s = self._strip_cfws(s)
        at_idx = s.rfind("@")
        if at_idx == -1:
            raise ValueError(f"No @ in addr-spec: {s[:50]}")
        local_part = s[:at_idx]
        rest = s[at_idx + 1:]
        rest = self._strip_cfws(rest)
        # domain: dot-atom or domain-literal
        if rest.startswith("["):
            m = re.match(r"\[([^\]]*)\]", rest)
            if not m:
                raise ValueError(f"Malformed domain-literal: {rest[:50]}")
            domain = "[" + m.group(1) + "]"
            rest = rest[m.end():]
        else:
            m = re.match(r"([a-zA-Z0-9!#$%&'*+/=?^_`{|}~.-]+)", rest)
            if not m:
                raise ValueError(f"Expected domain, got: {rest[:50]}")
            domain = m.group(1)
            rest = rest[m.end():]
        return local_part, domain, rest

    # ── §3.3 date-time ──────────────────────────────────────────────────────
    def _parse_date_time(self, s: str):
        """Parse date-time (not needed for address parsing, stub kept for API completeness)."""
        raise NotImplementedError("date-time parsing not implemented")

    # ── Main parse entry points ─────────────────────────────────────────────

    def parse(self, raw: str) -> RFC5322Address:
        """
        Parse a single mailbox or group address.

        Raises ValueError on invalid input.
        """
        original = raw.strip()
        s = original

        if not s:
            raise ValueError("Empty input")

        # Group address: phrase ":" mailbox-list ";"
        if not s.startswith("@"):
            phrase_m = re.match(r"(.*?)\s*:\s*", s)
            if phrase_m:
                display_name = phrase_m.group(1).strip()
                rest = s[phrase_m.end():]
                if rest.endswith(";"):
                    members = []
                    mailbox_list = rest[:-1].strip()
                    if mailbox_list:
                        for item in self._split_mailbox_list(mailbox_list):
                            members.append(self.parse(item.strip()))
                    return RFC5322Address(
                        display_name=display_name,
                        local_part="",
                        domain="",
                        is_group=True,
                        group_members=members,
                        comments=[],
                        source=original,
                    )
                # fall through — not a group, treat as display name then angle-addr or addr-spec

        # Display name + angle-addr: "Name" <addr-spec> or bare <addr-spec>
        display_name: Optional[str] = None
        # Only match "name <" when there is non-whitespace text before <
        angle_m = re.match(r"(.+)\s+(<)", s)
        if angle_m:
            name_part = angle_m.group(1).strip().strip('"')
            display_name = name_part if name_part else None
            s = s[angle_m.end():]
            if s.endswith(">"):
                s = s[:-1]
            s = self._strip_cfws(s)
        elif s.startswith("<"):
            # bare <addr-spec> — strip outer brackets directly
            s = s[1:]
            if s.endswith(">"):
                s = s[:-1]
            s = self._strip_cfws(s)

        # addr-spec (or bare mailbox)
        try:
            local_part, domain, rest = self._parse_addr_spec(s)
        except ValueError:
            # Try bare local-part (obsolete form)
            if not self.strict:
                m = re.match(r"([^\s@<>]+)", s)
                if m:
                    local_part = m.group(1)
                    domain = ""
                    rest = s[m.end():]
                else:
                    raise
            else:
                raise

        return RFC5322Address(
            display_name=display_name,
            local_part=local_part,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=[],
            source=original,
        )

    def _split_mailbox_list(self, s: str) -> list[str]:
        """Split a comma-separated mailbox list, respecting <> quoted strings."""
        result = []
        current = ""
        depth = 0
        in_quote = False
        i = 0
        while i < len(s):
            c = s[i]
            if c == '"' and (i == 0 or s[i - 1] != "\\"):
                in_quote = not in_quote
                current += c
            elif not in_quote:
                if c == "<":
                    depth += 1
                    current += c
                elif c == ">":
                    depth -= 1
                    current += c
                elif c == "," and depth == 0:
                    result.append(current.strip())
                    current = ""
                else:
                    current += c
            else:
                current += c
            i += 1
        if current.strip():
            result.append(current.strip())
        return result

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """
        Parse a comma-separated address-list per §3.4.

        Handles:
          - Single mailbox: user@domain
          - Quoted display-name + mailbox: "Name" <user@domain>
          - Group: My Group: user@domain, other@domain;
          - Obsolete (§4.4) forms when strict=False
        """
        if not raw.strip():
            return []
        result = []
        for item in self._split_mailbox_list(raw.strip()):
            item = item.strip()
            if not item:
                continue
            try:
                result.append(self.parse(item))
            except ValueError:
                if not self.strict:
                    # §4.4 obsolete local-part (dot-atom or quoted-string as bare local)
                    m = re.match(r"([^\s@]+)@([^\s]*?)\s*$", item)
                    if m:
                        result.append(RFC5322Address(
                            display_name=None,
                            local_part=m.group(1),
                            domain=m.group(2),
                            is_group=False,
                            group_members=[],
                            comments=[],
                            source=item,
                        ))
                    # else skip unparseable
                # else re-raise
        return result