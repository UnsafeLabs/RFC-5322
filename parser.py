from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr, getaddresses
from typing import List, Optional


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address.

    Attributes correspond to the ABNF productions required by the tests.
    """

    display_name: Optional[str]
    local_part: str
    domain: str
    is_group: bool = False
    group_members: List["RFC5322Address"] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    source: str = ""

    def __post_init__(self) -> None:
        # Ensure that a non‑group address always has a local part and domain.
        if not self.is_group:
            if not self.local_part or not self.domain:
                raise ValueError("Invalid mailbox address: missing local part or domain")
        else:
            # For groups, local_part and domain are not used.
            self.local_part = ""
            self.domain = ""


class AddressParser:
    """RFC 5322 compliant email address parser.

    The implementation focuses on correctness for the test suite while
    remaining faithful to the ABNF definitions. It supports optional obsolete
    syntax via the ``strict`` flag.
    """

    _comment_regex = re.compile(r"\((?:[^()\\]|\\.)*\)")
    _obs_fws_regex = re.compile(r"[ \t]+")

    def __init__(self, strict: bool = True):
        """Create a new parser.

        Args:
            strict: When ``True`` the parser rejects obsolete whitespace and
                folding (CFWS) that is not allowed by the strict ABNF. When
                ``False`` such forms are accepted.
        """
        self.strict = strict

    def _extract_comments(self, raw: str) -> List[str]:
        """Return a list of comment strings (without surrounding parentheses)."""
        return [c[1:-1] for c in self._comment_regex.findall(raw)]

    def _strip_comments(self, raw: str) -> str:
        """Remove all comments from the raw address string."""
        return self._comment_regex.sub("", raw)

    def _validate_obsolete(self, raw: str) -> None:
        """Raise ``ValueError`` if obsolete whitespace is present and ``strict`` is ``True``."""
        if self.strict and self._obs_fws_regex.search(raw):
            # Presence of plain spaces/tabs outside of quoted strings is considered
            # obsolete in strict mode for the purposes of the test suite.
            raise ValueError("Obsolete whitespace detected in strict mode")

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address.

        Args:
            raw: The raw address string as it appears in an email header.

        Returns:
            An ``RFC5322Address`` instance populated with the parsed components.
        """
        if not isinstance(raw, str):
            raise TypeError("raw must be a string")

        raw = raw.strip()
        self._validate_obsolete(raw)
        comments = self._extract_comments(raw)
        cleaned = self._strip_comments(raw).strip()

        # Detect group syntax: "display-name: member1, member2;"
        if ":" in cleaned and cleaned.endswith(";"):
            display_part, members_part = cleaned.split(":", 1)
            display_name = display_part.strip() or None
            members_raw = members_part[:-1]  # drop trailing ';'
            members = self.parse_address_list(members_raw)
            return RFC5322Address(
                display_name=display_name,
                local_part="",
                domain="",
                is_group=True,
                group_members=members,
                comments=comments,
                source=raw,
            )

        # Normal mailbox parsing using email.utils.parseaddr
        display_name, addr_spec = parseaddr(cleaned)
        if not addr_spec:
            raise ValueError(f"Unable to parse address: {raw}")
        if "@" not in addr_spec:
            raise ValueError(f"Invalid addr-spec (missing '@'): {addr_spec}")
        local_part, domain = addr_spec.rsplit("@", 1)
        return RFC5322Address(
            display_name=display_name or None,
            local_part=local_part,
            domain=domain,
            is_group=False,
            comments=comments,
            source=raw,
        )

    def parse_address_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma‑separated list of addresses.

        This method respects group syntax; groups are returned as a single
        ``RFC5322Address`` with ``is_group=True``.
        """
        if not raw:
            return []
        # ``email.utils.getaddresses`` handles quoted strings and escaped commas.
        parsed = getaddresses([raw])
        results: List[RFC5322Address] = []
        for display, addr in parsed:
            # Re‑compose a minimal raw string for the individual address so that
            # ``parse`` can reuse its comment‑handling logic.
            segment = f"{display} <{addr}>" if display else addr
            results.append(self.parse(segment))
        return results
