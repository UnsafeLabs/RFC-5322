"""
RFC 5322 compliant email address parser.

Implements full ABNF grammar from sections 3.2-3.4 with optional
obsolete syntax support from section 4.4.

Reference: https://datatracker.ietf.org/doc/html/rfc5322
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


class ParseError(Exception):
    """Raised when input does not conform to RFC 5322 grammar."""
    pass


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""
    display_name: Optional[str]
    local_part: str
    domain: str
    is_group: bool = False
    group_members: List['RFC5322Address'] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    source: str = ""

    def __str__(self) -> str:
        if self.is_group:
            members = ", ".join(str(m) for m in self.group_members)
            return f"{self.display_name}:{members};"
        if self.display_name:
            return f'"{self.display_name}" <{self.local_part}@{self.domain}>'
        return f"{self.local_part}@{self.domain}"


# ABNF character definitions
ATEXT = set("!#$%&'*+-/=?^_`{|}~")
ATEXT_FULL = ATEXT | set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
QTEXT = set(chr(i) for i in range(33, 127)) - {"\\"}
DTEXT = set(chr(i) for i in range(33, 91)) | set(chr(i) for i in range(94, 127))
CTEXT = set(chr(i) for i in range(33, 40)) | set(chr(i) for i in range(42, 91)) | set(chr(i) for i in range(93, 127))


class _ParserState:
    """Internal parser state for tracking position and input."""

    def __init__(self, input_str: str, strict: bool = True):
        self.input = input_str
        self.pos = 0
        self.strict = strict
        self.comments: List[str] = []

    def remaining(self) -> str:
        return self.input[self.pos:]

    def peek(self) -> Optional[str]:
        if self.pos >= len(self.input):
            return None
        return self.input[self.pos]

    def advance(self, n: int = 1) -> str:
        consumed = self.input[self.pos:self.pos + n]
        self.pos += n
        return consumed

    def at_end(self) -> bool:
        return self.pos >= len(self.input)


class AddressParser:
    """
    RFC 5322 compliant email address parser.

    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.

    Args:
        strict: If True, reject obs-* productions.
                If False, accept obsolete forms per §4.4.
    """

    def __init__(self, strict: bool = True):
        self.strict = strict

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""
        if not raw or not raw.strip():
            raise ParseError("Empty input")

        state = _ParserState(raw.strip(), self.strict)

        result = self._try_parse_address(state)

        # Consume trailing CFWS
        self._parse_cfws(state)

        if not state.at_end():
            raise ParseError(
                f"Unexpected characters at position {state.pos}: {state.remaining()!r}"
            )

        result.source = raw
        return result

    def parse_address_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4."""
        if not raw or not raw.strip():
            return []

        state = _ParserState(raw.strip(), self.strict)
        addresses = []

        while not state.at_end():
            self._parse_cfws(state)
            if state.at_end():
                break

            addr = self._try_parse_address(state)
            addresses.append(addr)

            self._parse_cfws(state)
            if not state.at_end():
                if state.peek() == ",":
                    state.advance()
                elif state.peek() == ";":
                    break

        for addr in addresses:
            addr.source = raw
        return addresses

    def parse_mailbox_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4."""
        if not raw or not raw.strip():
            return []

        state = _ParserState(raw.strip(), self.strict)
        mailboxes = []

        while not state.at_end():
            self._parse_cfws(state)
            if state.at_end():
                break

            mailbox = self._try_parse_mailbox(state)
            if mailbox:
                mailboxes.append(mailbox)

            self._parse_cfws(state)
            if not state.at_end() and state.peek() == ",":
                state.advance()

        for mb in mailboxes:
            mb.source = raw
        return mailboxes

    def _try_parse_address(self, state: _ParserState) -> RFC5322Address:
        """Parse address = mailbox / group."""
        saved_pos = state.pos

        # Try group first
        try:
            return self._parse_group(state)
        except ParseError:
            state.pos = saved_pos

        # Try mailbox
        return self._try_parse_mailbox(state)

    def _try_parse_mailbox(self, state: _ParserState) -> RFC5322Address:
        """Parse mailbox = name-addr / addr-spec."""
        saved_pos = state.pos

        # Try name-addr first (has display name before angle-addr)
        try:
            return self._parse_name_addr(state)
        except ParseError:
            state.pos = saved_pos

        # Try addr-spec (simple user@domain)
        return self._parse_addr_spec(state)

    def _parse_name_addr(self, state: _ParserState) -> RFC5322Address:
        """Parse name-addr = [display-name] angle-addr."""
        comments = []
        self._parse_cfws(state, comments)

        # Parse optional display-name (phrase)
        display_name = None
        saved_pos = state.pos
        try:
            display_name = self._parse_phrase(state)
        except ParseError:
            state.pos = saved_pos

        # Parse angle-addr
        local_part, domain = self._parse_angle_addr(state)

        return RFC5322Address(
            display_name=display_name,
            local_part=local_part,
            domain=domain,
            comments=comments,
        )

    def _parse_angle_addr(self, state: _ParserState) -> tuple[str, str]:
        """Parse angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr."""
        comments = []
        saved_pos = state.pos
        self._parse_cfws(state, comments)

        if state.peek() == "<":
            # Try modern form: "<" addr-spec ">"
            inner_saved = state.pos
            state.advance()  # consume "<"
            try:
                local_part, domain = self._parse_addr_spec_inner(state)
                self._parse_cfws(state, comments)
                if state.peek() == ">":
                    state.advance()
                    self._parse_cfws(state, comments)
                    return local_part, domain
            except ParseError:
                pass
            # Modern form failed - try obs-angle-addr if not strict
            state.pos = inner_saved  # back to just before "<"
            if not self.strict:
                try:
                    return self._parse_obs_angle_addr(state)
                except ParseError:
                    pass
            # Restore to original position
            state.pos = saved_pos
            raise ParseError(f"Expected valid angle-addr at position {state.pos}")

        # Try obs-angle-addr directly (no "<" found after CFWS)
        if not self.strict:
            try:
                return self._parse_obs_angle_addr(state)
            except ParseError:
                state.pos = saved_pos

        raise ParseError(f"Expected '<' at position {state.pos}")

    def _parse_obs_angle_addr(self, state: _ParserState) -> tuple[str, str]:
        """Parse obs-angle-addr = [CFWS] "<" [obs-route] addr-spec ">" [CFWS]."""
        self._parse_cfws(state)

        if state.peek() != "<":
            raise ParseError(f"Expected '<' at position {state.pos}")
        state.advance()

        # Try to parse obs-route: [obs-domain-list] ":"
        saved_pos = state.pos
        try:
            self._parse_obs_domain_list(state)
            if state.peek() == ":":
                state.advance()
            else:
                state.pos = saved_pos
        except ParseError:
            state.pos = saved_pos

        local_part, domain = self._parse_addr_spec_inner(state)

        self._parse_cfws(state)
        if state.peek() != ">":
            raise ParseError(f"Expected '>' at position {state.pos}")
        state.advance()
        self._parse_cfws(state)

        return local_part, domain

    def _parse_obs_domain_list(self, state: _ParserState) -> None:
        """Parse obs-domain-list = *(CFWS / ",") "@" domain."""
        while not state.at_end():
            if state.peek() in (" ", "\t", "\r", "\n", "("):
                self._parse_cfws(state)
            elif state.peek() == ",":
                state.advance()
            else:
                break

        # Consume the "@" domain part
        if state.peek() == "@":
            state.advance()
            # Parse domain (just consume as atom text)
            while not state.at_end() and state.peek() in ATEXT_FULL:
                state.advance()

    def _parse_addr_spec(self, state: _ParserState) -> RFC5322Address:
        """Parse addr-spec = local-part "@" domain."""
        comments = []
        self._parse_cfws(state, comments)

        local_part, domain = self._parse_addr_spec_inner(state)

        return RFC5322Address(
            display_name=None,
            local_part=local_part,
            domain=domain,
            comments=comments,
        )

    def _parse_addr_spec_inner(self, state: _ParserState) -> tuple[str, str]:
        """Parse the inner part of addr-spec (local-part "@" domain)."""
        # Consume any CFWS before the local-part (e.g., comments inside angle-addr)
        self._parse_cfws(state)
        local_part = self._parse_local_part(state)

        if state.peek() != "@":
            raise ParseError(f"Expected '@' at position {state.pos}")
        state.advance()

        domain = self._parse_domain(state)

        return local_part, domain

    def _parse_local_part(self, state: _ParserState) -> str:
        """Parse local-part = dot-atom / quoted-string / obs-local-part."""
        # Try dot-atom first (with surrounding CFWS per production)
        saved_pos = state.pos
        try:
            self._parse_cfws(state)
            result = self._parse_dot_atom_text(state)
            if result:
                self._parse_cfws(state)  # trailing CFWS
                # Verify that @ follows, otherwise this isn't the right parse
                if state.peek() == "@":
                    return result
                # Not followed by @ - backtrack
                state.pos = saved_pos
            else:
                state.pos = saved_pos
        except ParseError:
            state.pos = saved_pos

        # Try quoted-string
        saved_pos = state.pos
        try:
            self._parse_cfws(state)
            result = self._parse_quoted_string_inner(state)
            if result is not None:
                self._parse_cfws(state)
                return result
            state.pos = saved_pos
        except ParseError:
            state.pos = saved_pos

        # Try obs-local-part if not strict
        if not self.strict:
            saved_pos = state.pos
            try:
                return self._parse_obs_local_part(state)
            except ParseError:
                state.pos = saved_pos

        raise ParseError(f"Expected local-part at position {state.pos}")

    def _parse_obs_local_part(self, state: _ParserState) -> str:
        """Parse obs-local-part = word *("." word)."""
        parts = []
        parts.append(self._parse_word(state))

        while not state.at_end() and state.peek() == ".":
            state.advance()
            parts.append(self._parse_word(state))

        return ".".join(parts)

    def _parse_word(self, state: _ParserState) -> str:
        """Parse word = atom / quoted-string."""
        saved_pos = state.pos

        # Try atom
        try:
            result = self._parse_atom_text(state)
            if result:
                return result
        except ParseError:
            state.pos = saved_pos

        # Try quoted-string (inner, no CFWS handling)
        saved_pos = state.pos
        try:
            result = self._parse_quoted_string_inner(state)
            if result is not None:
                return result
        except ParseError:
            state.pos = saved_pos

        raise ParseError(f"Expected word at position {state.pos}")

    def _parse_domain(self, state: _ParserState) -> str:
        """Parse domain = dot-atom / domain-literal / obs-domain."""
        # Try dot-atom first
        saved_pos = state.pos
        try:
            result = self._parse_dot_atom_text(state)
            if result:
                return result
        except ParseError:
            state.pos = saved_pos

        # Try domain-literal
        saved_pos = state.pos
        try:
            return self._parse_domain_literal(state)
        except ParseError:
            state.pos = saved_pos

        # Try obs-domain if not strict
        if not self.strict:
            saved_pos = state.pos
            try:
                return self._parse_obs_domain(state)
            except ParseError:
                state.pos = saved_pos

        raise ParseError(f"Expected domain at position {state.pos}")

    def _parse_obs_domain(self, state: _ParserState) -> str:
        """Parse obs-domain = atom *("." atom)."""
        parts = []
        parts.append(self._parse_atom_text(state))

        while not state.at_end() and state.peek() == ".":
            state.advance()
            parts.append(self._parse_atom_text(state))

        return ".".join(parts)

    def _parse_group(self, state: _ParserState) -> RFC5322Address:
        """Parse group = display-name ":" [group-list] ";" [CFWS]."""
        comments = []
        self._parse_cfws(state, comments)

        display_name = self._parse_phrase(state)

        if state.peek() != ":":
            raise ParseError(f"Expected ':' at position {state.pos}")
        state.advance()

        # Parse group-list
        members = []
        self._parse_cfws(state, comments)

        if state.peek() != ";":
            members = self._parse_group_list(state)

        if state.peek() != ";":
            raise ParseError(f"Expected ';' at position {state.pos}")
        state.advance()

        self._parse_cfws(state, comments)

        return RFC5322Address(
            display_name=display_name,
            local_part="",
            domain="",
            is_group=True,
            group_members=members,
            comments=comments,
        )

    def _parse_group_list(self, state: _ParserState) -> List[RFC5322Address]:
        """Parse group-list = mailbox-list / CFWS / obs-group-list."""
        self._parse_cfws(state)

        if state.peek() == ";":
            return []

        return self._parse_mailbox_list_inner(state)

    def _parse_mailbox_list_inner(self, state: _ParserState) -> List[RFC5322Address]:
        """Parse mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list."""
        mailboxes = []

        mailbox = self._try_parse_mailbox(state)
        mailboxes.append(mailbox)

        while not state.at_end():
            self._parse_cfws(state)
            if state.peek() == ",":
                state.advance()
                self._parse_cfws(state)
                if state.peek() == ";":
                    break
                mailbox = self._try_parse_mailbox(state)
                mailboxes.append(mailbox)
            else:
                break

        return mailboxes

    def _parse_phrase(self, state: _ParserState) -> str:
        """Parse phrase = 1*word / obs-phrase."""
        parts = []

        # Parse first word
        saved_pos = state.pos
        try:
            parts.append(self._parse_word(state))
        except ParseError:
            state.pos = saved_pos
            raise

        # Parse additional words (CFWS between words)
        while not state.at_end():
            saved_pos = state.pos
            self._parse_cfws(state)
            try:
                parts.append(self._parse_word(state))
            except ParseError:
                state.pos = saved_pos
                break

        return " ".join(parts)

    def _parse_dot_atom_text(self, state: _ParserState) -> str:
        """Parse dot-atom-text = 1*atext *("." 1*atext)."""
        parts = []
        current = []

        while not state.at_end():
            ch = state.peek()
            if ch in ATEXT_FULL:
                current.append(state.advance())
            elif ch == ".":
                if not current:
                    break
                parts.append("".join(current))
                current = []
                state.advance()
            else:
                break

        if current:
            parts.append("".join(current))

        if not parts:
            return ""

        return ".".join(parts)

    def _parse_atom_text(self, state: _ParserState) -> str:
        """Parse 1*atext (the text part of an atom)."""
        result = []
        while not state.at_end() and state.peek() in ATEXT_FULL:
            result.append(state.advance())

        if not result:
            raise ParseError(f"Expected atom at position {state.pos}")

        return "".join(result)

    def _parse_quoted_string_inner(self, state: _ParserState) -> Optional[str]:
        """Parse the inner part of quoted-string (DQUOTE content DQUOTE)."""
        if state.peek() != "\x22":
            raise ParseError(f"Expected '\"' at position {state.pos}")
        state.advance()  # Opening DQUOTE

        parts = []
        while not state.at_end():
            if state.peek() == "\x22":
                state.advance()  # Closing DQUOTE
                return "".join(parts)

            # Try FWS (handles CRLF folding or simple WSP)
            fws = self._try_parse_fws(state)
            if fws and parts:
                parts.append(" ")

            # Try qcontent (qtext or quoted-pair)
            if state.peek() == "\\":
                # quoted-pair: backslash escapes the next character
                state.advance()  # consume backslash
                if state.at_end():
                    raise ParseError("Unexpected end of input in quoted-pair")
                parts.append(state.advance())
            elif state.peek() and state.peek() in QTEXT:
                parts.append(state.advance())
            elif not fws:
                break

        raise ParseError(f"Unterminated quoted string at position {state.pos}")

    def _parse_domain_literal(self, state: _ParserState) -> str:
        """Parse domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]."""
        self._parse_cfws(state)

        if state.peek() != "[":
            raise ParseError(f"Expected '[' at position {state.pos}")
        state.advance()

        parts = []
        while not state.at_end():
            if state.peek() == "]":
                state.advance()
                self._parse_cfws(state)
                return f"[{''.join(parts)}]"

            # Try FWS
            fws = self._try_parse_fws(state)
            if fws and parts:
                parts.append(" ")

            # Try dtext or obs-dtext
            if state.peek() and (state.peek() in DTEXT or
                                 (not self.strict and state.peek() == "\\")):
                if state.peek() == "\\" and not self.strict:
                    state.advance()
                    if not state.at_end():
                        parts.append(state.advance())
                else:
                    parts.append(state.advance())
            elif not fws:
                break

        raise ParseError(f"Unterminated domain literal at position {state.pos}")

    def _parse_cfws(self, state: _ParserState, comments: Optional[List[str]] = None) -> bool:
        """Parse CFWS = (1*([FWS] comment) [FWS]) / FWS."""
        found = False

        while not state.at_end():
            # Try comment (starts with '(')
            if state.peek() == "(":
                comment = self._parse_comment(state)
                if comments is not None:
                    comments.append(comment)
                found = True
                # Consume optional FWS after comment
                self._try_parse_fws(state)
                continue

            # Try FWS (any whitespace including simple spaces)
            if state.peek() in (" ", "\t", "\r", "\n"):
                if self._try_parse_fws(state):
                    found = True
                    continue

            break

        return found

    def _parse_comment(self, state: _ParserState) -> str:
        """Parse comment = "(" *([FWS] ccontent) [FWS] ")"."""
        if state.peek() != "(":
            raise ParseError(f"Expected '(' at position {state.pos}")
        state.advance()

        parts = []
        depth = 1

        while not state.at_end() and depth > 0:
            if state.peek() == "(":
                depth += 1
                state.advance()
                parts.append("(")
            elif state.peek() == ")":
                depth -= 1
                if depth > 0:
                    state.advance()
                    parts.append(")")
                else:
                    state.advance()
            elif state.peek() == "\\":
                state.advance()
                if not state.at_end():
                    parts.append(state.advance())
            else:
                fws = self._try_parse_fws(state)
                if fws and parts:
                    parts.append(" ")
                elif state.peek() in CTEXT or state.peek() == "(":
                    parts.append(state.advance())
                else:
                    break

        return "".join(parts)

    def _try_parse_fws(self, state: _ParserState) -> bool:
        """
        Try to parse Folding White Space.
        
        FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
        
        The optional [*WSP CRLF] part handles folding (line continuation).
        The required 1*WSP part handles the actual whitespace.
        Without folding, FWS is simply 1*WSP (one or more spaces/tabs).
        """
        saved_pos = state.pos
        found_wsp = False

        # Consume optional WSP before CRLF (part of folding)
        while not state.at_end() and state.peek() in (" ", "\t"):
            state.advance()
            found_wsp = True

        # Try CRLF (folding)
        if not state.at_end() and state.peek() == "\r":
            state.advance()
            if not state.at_end() and state.peek() == "\n":
                state.advance()
                # After CRLF, require at least 1 WSP
                has_post_wsp = False
                while not state.at_end() and state.peek() in (" ", "\t"):
                    state.advance()
                    has_post_wsp = True
                if has_post_wsp:
                    return True
                # CRLF without trailing WSP is not valid FWS
                state.pos = saved_pos
                return False
            else:
                # CR without LF is not valid
                state.pos = saved_pos
                return False

        # No CRLF found - check if we found any WSP
        # In strict mode, simple WSP without CRLF is valid FWS per the production:
        # FWS = ([*WSP CRLF] 1*WSP) — the [*WSP CRLF] is optional
        if found_wsp:
            return True

        state.pos = saved_pos
        return False
