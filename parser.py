"""RFC 5322 conformant email address parser.

Implements the complete ABNF grammar from RFC 5322 section 3.2 through
3.4 (lexical tokens, addresses, mailboxes, groups, addr-spec, and domain
literals) plus the obsolete addressing syntax from section 4.4 (and its
supporting obsolete tokens from 4.1 and 4.2).

The parser is a hand-written recursive-descent parser over the raw input.
Strict mode (default) implements only the "generation" grammar of section
3 and rejects every obs-* production.  Permissive mode additionally
accepts the obsolete forms a conformant *receiver* MUST interpret per
section 4.

No third-party dependencies; pure Python standard library only.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Character classes (RFC 5322 core rules, section 3.2.x)
# ---------------------------------------------------------------------------

#: atext = ALPHA / DIGIT / "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" /
#:         "-" / "/" / "=" / "?" / "^" / "_" / "`" / "{" / "|" / "}" / "~"
_ATEXT = frozenset(string.ascii_letters + string.digits + "!#$%&'*+-/=?^_`{|}~")

_WSP = frozenset(" \t")  # SP (32) and HTAB (9)


def _is_vchar(ch: str) -> bool:
    """VCHAR = %d33-126 (printable US-ASCII)."""
    return 0x21 <= ord(ch) <= 0x7E


def _is_no_ws_ctl(ch: str) -> bool:
    """obs-NO-WS-CTL = %d1-8 / %d11 / %d12 / %d14-31 / %d127 (section 4.1)."""
    o = ord(ch)
    return (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127


def _is_dtext(ch: str) -> bool:
    """dtext = %d33-90 / %d94-126, excluding "[", "]", and "\"."""
    o = ord(ch)
    return 0x21 <= o <= 0x5A or 0x5E <= o <= 0x7E


def _is_qtext(ch: str) -> bool:
    """qtext = %d33 / %d35-91 / %d93-126, excluding "\" and DQUOTE."""
    o = ord(ch)
    return 0x21 <= o <= 0x7E and o not in (0x22, 0x5C)


def _is_ctext(ch: str) -> bool:
    """ctext = %d33-39 / %d42-91 / %d93-126, excluding "(", ")", and "\"."""
    o = ord(ch)
    return 0x21 <= o <= 0x7E and o not in (0x28, 0x29, 0x5C)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""

    display_name: str | None = None
    local_part: str = ""
    domain: str = ""
    is_group: bool = False
    group_members: list["RFC5322Address"] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    source: str = ""


class AddressParseError(ValueError):
    """Raised when the input does not conform to the RFC 5322 grammar."""

    def __init__(self, message: str, position: int = 0, source: str = "") -> None:
        self.position = position
        self.source = source
        snippet = source[max(0, position - 20): position + 20]
        super().__init__(f"{message} (at position {position}: {snippet!r})")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class AddressParser:
    """
    RFC 5322 compliant email address parser.

    Implements full ABNF grammar from §3.2-§3.4 with optional obsolete
    syntax support from §4.4.
    """

    _MAX_LINE_LENGTH = 998  # RFC 5322 section 2.1.1 line length limit

    def __init__(self, strict: bool = True):
        """
        Args:
            strict: If True, reject obs-* productions.
                    If False, accept obsolete forms per §4.4.
        """
        self.strict = bool(strict)
        self._source = ""
        self._pos = 0
        self._comments: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""
        self._reset(raw)
        addr = self._parse_address()
        if addr is None:
            raise AddressParseError(
                "not a valid RFC 5322 address (mailbox or group)", self._pos, raw
            )
        self._consume_cfws()
        if not self._at_end():
            raise AddressParseError(
                "unexpected trailing characters after address", self._pos, raw
            )
        return addr

    def parse_address_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4."""
        self._reset(raw)
        addrs = self._parse_address_list()
        if addrs is None:
            raise AddressParseError(
                "not a valid RFC 5322 address-list", self._pos, raw
            )
        self._consume_cfws()
        if not self._at_end():
            raise AddressParseError(
                "unexpected trailing characters after address-list", self._pos, raw
            )
        return addrs

    def parse_mailbox_list(self, raw: str) -> list[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4."""
        self._reset(raw)
        mailboxes = self._parse_mailbox_list()
        if mailboxes is None:
            raise AddressParseError(
                "not a valid RFC 5322 mailbox-list", self._pos, raw
            )
        self._consume_cfws()
        if not self._at_end():
            raise AddressParseError(
                "unexpected trailing characters after mailbox-list", self._pos, raw
            )
        return mailboxes

    # ------------------------------------------------------------------
    # Low-level scanning helpers
    # ------------------------------------------------------------------

    def _reset(self, raw: str) -> None:
        if self.strict and len(raw) > self._MAX_LINE_LENGTH:
            raise AddressParseError(
                f"input exceeds RFC 5322 {self._MAX_LINE_LENGTH}-character line limit",
                0,
                raw,
            )
        self._source = raw
        self._pos = 0
        self._comments = []

    def _save(self) -> tuple[int, int]:
        """Checkpoint for backtracking: (position, comment count)."""
        return (self._pos, len(self._comments))

    def _restore(self, state: tuple[int, int]) -> None:
        self._pos, keep = state
        del self._comments[keep:]

    def _peek(self) -> str:
        return self._source[self._pos] if self._pos < len(self._source) else ""

    def _peek_at(self, offset: int) -> str:
        idx = self._pos + offset
        return self._source[idx] if 0 <= idx < len(self._source) else ""

    def _at_end(self) -> bool:
        return self._pos >= len(self._source)

    def _advance(self, count: int = 1) -> None:
        self._pos += count

    # ------------------------------------------------------------------
    # §3.2.1 quoted-pair
    # ------------------------------------------------------------------

    def _consume_quoted_pair(self) -> str | None:
        """Consume ``quoted-pair`` and return the unescaped character.

        quoted-pair = ("\" (VCHAR / WSP)) / obs-qp

        The backslash is semantically invisible: returns the character
        alone.  obs-qp (permissive only) additionally allows "\" followed
        by NUL, bare CR/LF, and obsolete control characters.
        """
        if self._peek() != "\\":
            return None
        if self._pos + 1 >= len(self._source):
            return None
        nxt = self._source[self._pos + 1]
        if self.strict:
            if not (_is_vchar(nxt) or nxt in _WSP):
                return None
        self._advance(2)
        return nxt

    # ------------------------------------------------------------------
    # §3.2.2 FWS, comments, CFWS
    # ------------------------------------------------------------------

    def _consume_fws(self) -> bool:
        """Consume one ``FWS`` production if present.

        FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
        obs-FWS = 1*WSP *(CRLF 1*WSP)      (permissive, section 4.2)
        """
        state = self._save()
        while not self._at_end() and self._peek() in _WSP:
            self._advance()
        # [*WSP CRLF] followed by 1*WSP
        if self._peek_at(0) == "\r" and self._peek_at(1) == "\n":
            self._advance(2)
            if not self._at_end() and self._peek() in _WSP:
                while not self._at_end() and self._peek() in _WSP:
                    self._advance()
                if not self.strict:
                    while True:
                        if self._peek_at(0) == "\r" and self._peek_at(1) == "\n":
                            if self._peek_at(2) in _WSP:
                                self._advance(2)
                                while not self._at_end() and self._peek() in _WSP:
                                    self._advance()
                                continue
                        break
                return True
            self._restore(state)
            return False
        # plain 1*WSP with no fold
        if self._pos > state[0]:
            return True
        self._restore(state)
        return False

    def _consume_comment(self) -> str | None:
        """Consume one ``comment`` production, returning its inner text.

        comment = "(" *([FWS] ccontent) [FWS] ")"
        ccontent = ctext / quoted-pair / comment

        The enclosing parentheses are not part of the comment.  Quoted-
        pairs are unescaped, FWS runs collapse to a single space, and
        nested comments are kept verbatim in the parent while also being
        collected individually.  Returns None (restoring position and
        comments) if the text is not a well-formed comment.
        """
        state = self._save()
        if self._peek() != "(":
            return None
        self._advance()
        parts: list[str] = []
        while True:
            if self._consume_fws():
                parts.append(" ")
                continue
            ch = self._peek()
            if ch == ")":
                self._advance()
                text = "".join(parts)
                self._comments.append(text)
                return text
            if ch == "\\":
                qp = self._consume_quoted_pair()
                if qp is None:
                    self._restore(state)
                    return None
                parts.append(qp)
                continue
            if ch == "(":
                inner = self._consume_comment()
                if inner is None:
                    self._restore(state)
                    return None
                parts.append("(")
                parts.append(inner)
                parts.append(")")
                continue
            if ch and (self._is_ctext_char(ch)):
                self._advance()
                parts.append(ch)
                continue
            self._restore(state)
            return None

    def _is_ctext_char(self, ch: str) -> bool:
        """ctext / obs-ctext (permissive)."""
        if _is_ctext(ch):
            return True
        return not self.strict and _is_no_ws_ctl(ch)

    def _consume_cfws(self) -> bool:
        """Consume ``CFWS`` if present.

        CFWS = (1*([FWS] comment) [FWS]) / FWS

        Each ``[FWS]`` is tied to the comment that follows it; when no
        comment is present only a single trailing ``FWS`` may be consumed
        (so two consecutive folds require obs-FWS, permissive mode only).
        """
        state = self._save()
        n_comments = 0
        while True:
            fws_before = self._pos
            self._consume_fws()
            if self._peek() == "(":
                if self._consume_comment() is None:
                    self._restore(state)
                    return False
                n_comments += 1
            else:
                # no comment follows this [FWS] — undo it and consume at
                # most one trailing FWS below
                self._pos = fws_before
                break
        self._consume_fws()
        if n_comments > 0 or self._pos > state[0]:
            return True
        self._restore(state)
        return False

    # ------------------------------------------------------------------
    # §3.2.3 atoms
    # ------------------------------------------------------------------

    def _parse_atom(self) -> str | None:
        """Parse ``atom = [CFWS] 1*atext [CFWS]``, returning atext only."""
        state = self._save()
        self._consume_cfws()
        start = self._pos
        while not self._at_end() and self._source[self._pos] in _ATEXT:
            self._advance()
        if self._pos == start:
            self._restore(state)
            return None
        content = self._source[start:self._pos]
        self._consume_cfws()
        return content

    def _parse_dot_atom(self) -> str | None:
        """Parse ``dot-atom = [CFWS] dot-atom-text [CFWS]``.

        dot-atom-text = 1*atext *("." 1*atext)
        """
        state = self._save()
        self._consume_cfws()
        start = self._pos
        if self._at_end() or self._source[self._pos] not in _ATEXT:
            self._restore(state)
            return None
        self._advance()
        while not self._at_end() and self._source[self._pos] in _ATEXT:
            self._advance()
        while self._peek() == ".":
            if self._peek_at(1) in _ATEXT:
                self._advance(2)
                while not self._at_end() and self._source[self._pos] in _ATEXT:
                    self._advance()
            else:
                break
        content = self._source[start:self._pos]
        self._consume_cfws()
        return content

    # ------------------------------------------------------------------
    # §3.2.4 quoted-string
    # ------------------------------------------------------------------

    def _parse_quoted_string(self) -> str | None:
        """Parse ``quoted-string``, returning the content between the quotes.

        quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]

        FWS inside the quoted-string collapses to a single space and
        quoted-pairs are unescaped.  Both are semantically invisible
        (section 3.2.4).
        """
        state = self._save()
        self._consume_cfws()
        if self._peek() != '"':
            self._restore(state)
            return None
        self._advance()
        parts: list[str] = []
        while True:
            if self._consume_fws():
                # runs of FWS inside a quoted-string collapse to a single
                # space (section 3.2.2); the CRLF of a fold is invisible
                parts.append(" ")
                continue
            ch = self._peek()
            if ch == '"':
                self._advance()
                self._consume_cfws()
                return "".join(parts)
            if ch == "\\":
                qp = self._consume_quoted_pair()
                if qp is None:
                    self._restore(state)
                    return None
                parts.append(qp)
                continue
            if ch and self._is_qtext_char(ch):
                self._advance()
                parts.append(ch)
                continue
            self._restore(state)
            return None

    def _is_qtext_char(self, ch: str) -> bool:
        """qtext / obs-qtext (permissive)."""
        if _is_qtext(ch):
            return True
        return not self.strict and _is_no_ws_ctl(ch)

    # ------------------------------------------------------------------
    # §3.2.5 words and phrases
    # ------------------------------------------------------------------

    def _parse_word(self) -> str | None:
        """Parse ``word = atom / quoted-string``."""
        state = self._save()
        atom = self._parse_atom()
        if atom is not None:
            return atom
        self._restore(state)
        qs = self._parse_quoted_string()
        if qs is not None:
            return qs
        self._restore(state)
        return None

    def _parse_display_name(self) -> str | None:
        """Parse ``display-name = phrase``.

        phrase = 1*word / obs-phrase
        obs-phrase = word *(word / "." / CFWS)   (permissive, section 4.1)
        """
        state = self._save()
        first = self._parse_word()
        if first is None:
            self._restore(state)
            return None
        parts: list[str] = [first]
        while True:
            before = self._pos
            if self._peek() == "." and not self.strict:
                self._advance()
                parts.append(".")
                continue
            word = self._parse_word()
            if word is not None:
                parts.append(" ")
                parts.append(word)
                continue
            self._pos = before
            break
        return "".join(parts)

    # ------------------------------------------------------------------
    # §3.4.1 addr-spec, local-part, domain
    # ------------------------------------------------------------------

    def _parse_local_part(self) -> str | None:
        """Parse ``local-part = dot-atom / quoted-string / obs-local-part``."""
        state = self._save()
        if not self.strict:
            lp = self._parse_obs_local_part()
            if lp is not None:
                return lp
            self._restore(state)
            return None
        da = self._parse_dot_atom()
        if da is not None:
            return da
        self._restore(state)
        qs = self._parse_quoted_string()
        if qs is not None:
            return qs
        self._restore(state)
        return None

    def _parse_obs_local_part(self) -> str | None:
        """Parse ``obs-local-part = word *("." word)`` (section 4.4).

        Allows mixing dot-atoms and quoted-strings.  A trailing dot is
        tolerated for robustness (the parser is liberal here).
        """
        state = self._save()
        first = self._parse_word()
        if first is None:
            self._restore(state)
            return None
        parts: list[str] = [first]
        while self._peek() == ".":
            self._advance()
            word = self._parse_word()
            if word is not None:
                parts.append(".")
                parts.append(word)
            else:
                parts.append(".")
                break
        return "".join(parts)

    def _parse_domain_literal(self) -> str | None:
        """Parse ``domain-literal``, returning the literal content.

        domain-literal = [CFWS] "[" *([FWS] dtext) [FWS] "]" [CFWS]
        dtext = %d33-90 / %d94-126 / obs-dtext
        obs-dtext = obs-NO-WS-CTL / quoted-pair   (permissive, section 4.4)
        """
        state = self._save()
        self._consume_cfws()
        if self._peek() != "[":
            self._restore(state)
            return None
        self._advance()
        parts: list[str] = []
        while True:
            if self._peek() == "]":
                self._advance()
                self._consume_cfws()
                return "".join(parts)
            if self._consume_fws():
                if self._peek() == "]":
                    continue  # trailing [FWS] before closing bracket
                parts.append(" ")
                continue
            ch = self._peek()
            if ch == "\\":
                if self.strict:
                    self._restore(state)
                    return None
                qp = self._consume_quoted_pair()
                if qp is None:
                    self._restore(state)
                    return None
                parts.append(qp)
                continue
            if ch and self._is_dtext_char(ch):
                self._advance()
                parts.append(ch)
                continue
            self._restore(state)
            return None

    def _is_dtext_char(self, ch: str) -> bool:
        """dtext / obs-dtext (permissive)."""
        if _is_dtext(ch):
            return True
        return not self.strict and _is_no_ws_ctl(ch)

    def _parse_obs_domain(self) -> str | None:
        """Parse ``obs-domain = atom *("." atom)`` (section 4.4).

        CFWS is permitted around the period-separated atoms.  A leading
        dot is tolerated for robustness; this is more liberal than the
        strict ABNF but accepts real-world mail per section 4's mandate
        that receivers must not crash on unusual forms.
        """
        state = self._save()
        parts: list[str] = []
        if self._peek() == ".":
            self._advance()
            parts.append(".")
        while True:
            atom = self._parse_atom()
            if atom is None:
                break
            parts.append(atom)
            if self._peek() == ".":
                self._advance()
                parts.append(".")
            else:
                break
        result = "".join(parts)
        if not any(c in _ATEXT for c in result):
            self._restore(state)
            return None
        return result

    def _parse_domain(self) -> str | None:
        """Parse ``domain = dot-atom / domain-literal / obs-domain``."""
        state = self._save()
        if not self.strict:
            # obs-domain is a superset of dot-atom (it permits CFWS around
            # the dots), so try it first so that "test  .  example" is
            # consumed as a single domain rather than "test" + trailing junk.
            od = self._parse_obs_domain()
            if od is not None:
                return od
            self._restore(state)
        da = self._parse_dot_atom()
        if da is not None:
            return da
        self._restore(state)
        dl = self._parse_domain_literal()
        if dl is not None:
            return dl
        self._restore(state)
        return None

    def _parse_addr_spec(self) -> tuple[str, str] | None:
        """Parse ``addr-spec = local-part "@" domain``."""
        state = self._save()
        lp = self._parse_local_part()
        if lp is None:
            self._restore(state)
            return None
        if self._peek() != "@":
            self._restore(state)
            return None
        self._advance()
        dom = self._parse_domain()
        if dom is None:
            self._restore(state)
            return None
        return (lp, dom)

    # ------------------------------------------------------------------
    # §3.4 address, mailbox, group
    # ------------------------------------------------------------------

    def _parse_address(self) -> RFC5322Address | None:
        """Parse ``address = mailbox / group``."""
        state = self._save()
        group = self._parse_group()
        if group is not None:
            return group
        self._restore(state)
        mailbox = self._parse_mailbox()
        if mailbox is not None:
            return mailbox
        self._restore(state)
        return None

    def _parse_mailbox(self) -> RFC5322Address | None:
        """Parse ``mailbox = name-addr / addr-spec``."""
        state = self._save()
        # name-addr = [display-name] angle-addr
        display_name = self._parse_display_name()
        if display_name is not None:
            angle = self._parse_angle_addr()
            if angle is not None:
                local_part, domain = angle
                return self._build_address(
                    state, display_name=display_name, local_part=local_part, domain=domain
                )
            self._restore(state)
        angle = self._parse_angle_addr()
        if angle is not None:
            local_part, domain = angle
            return self._build_address(state, local_part=local_part, domain=domain)
        self._restore(state)
        spec = self._parse_addr_spec()
        if spec is not None:
            local_part, domain = spec
            return self._build_address(state, local_part=local_part, domain=domain)
        self._restore(state)
        return None

    def _parse_angle_addr(self) -> tuple[str, str] | None:
        """Parse ``angle-addr`` and return (local-part, domain).

        angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr
        obs-angle-addr = [CFWS] "<" obs-route addr-spec ">" [CFWS]
        """
        state = self._save()
        self._consume_cfws()
        if self._peek() != "<":
            self._restore(state)
            return None
        self._advance()
        if not self.strict and self._peek() == "@":
            if self._parse_obs_route() is None:
                self._restore(state)
                return None
        spec = self._parse_addr_spec()
        if spec is None:
            self._restore(state)
            return None
        if self._peek() != ">":
            self._restore(state)
            return None
        self._advance()
        self._consume_cfws()
        return spec

    def _parse_obs_route(self) -> bool:
        """Parse ``obs-route = obs-domain-list ":"`` (section 4.4).

        obs-domain-list = *(CFWS / ",") "@" domain
                          *("," [CFWS] ["@" domain])

        The route portion is semantically ignored (RFC 5322 section 4.4).
        """
        state = self._save()
        while True:
            self._consume_cfws()
            if self._peek() == ",":
                self._advance()
                continue
            break
        if self._peek() != "@":
            self._restore(state)
            return False
        self._advance()
        if self._parse_domain() is None:
            self._restore(state)
            return False
        while self._peek() == ",":
            self._advance()
            self._consume_cfws()
            if self._peek() == "@":
                self._advance()
                if self._parse_domain() is None:
                    self._restore(state)
                    return False
        if self._peek() != ":":
            self._restore(state)
            return False
        self._advance()
        return True

    def _parse_group(self) -> RFC5322Address | None:
        """Parse ``group = display-name ":" [group-list] ";" [CFWS]``."""
        state = self._save()
        display_name = self._parse_display_name()
        if display_name is None:
            self._restore(state)
            return None
        if self._peek() != ":":
            self._restore(state)
            return None
        self._advance()
        members: list[RFC5322Address] = []
        mailboxes = self._parse_mailbox_list()
        if mailboxes is not None:
            members = mailboxes
        else:
            self._consume_cfws()  # group-list = CFWS (empty group)
            if not self.strict:
                # obs-group-list = 1*([CFWS] ",") [CFWS]
                consumed_commas = False
                while True:
                    self._consume_cfws()
                    if self._peek() == ",":
                        self._advance()
                        consumed_commas = True
                    else:
                        break
                if consumed_commas:
                    self._consume_cfws()
        if self._peek() != ";":
            self._restore(state)
            return None
        self._advance()
        self._consume_cfws()
        return self._build_address(
            state, display_name=display_name, is_group=True, group_members=members
        )

    # ------------------------------------------------------------------
    # §3.4 lists
    # ------------------------------------------------------------------

    def _parse_mailbox_list(self) -> list[RFC5322Address] | None:
        """Parse ``mailbox-list = (mailbox *("," mailbox)) / obs-mbox-list``.

        obs-mbox-list = *([CFWS] ",") mailbox *("," [mailbox / CFWS])
        (permissive — leading, doubled, and trailing commas are allowed)
        """
        state = self._save()
        out: list[RFC5322Address] = []
        if not self.strict:
            while True:
                self._consume_cfws()
                if self._peek() == ",":
                    self._advance()
                    continue
                break
        mailbox = self._parse_mailbox()
        if mailbox is None:
            self._restore(state)
            return None
        out.append(mailbox)
        while True:
            self._consume_cfws()
            if self._peek() != ",":
                break
            self._advance()
            self._consume_cfws()
            nxt = self._parse_mailbox()
            if nxt is not None:
                out.append(nxt)
            elif not self.strict:
                continue  # null member: ",," or trailing ","
            else:
                self._restore(state)
                return None
        return out

    def _parse_address_list(self) -> list[RFC5322Address] | None:
        """Parse ``address-list = (address *("," address)) / obs-addr-list``."""
        state = self._save()
        out: list[RFC5322Address] = []
        if not self.strict:
            while True:
                self._consume_cfws()
                if self._peek() == ",":
                    self._advance()
                    continue
                break
        address = self._parse_address()
        if address is None:
            self._restore(state)
            return None
        out.append(address)
        while True:
            self._consume_cfws()
            if self._peek() != ",":
                break
            self._advance()
            self._consume_cfws()
            nxt = self._parse_address()
            if nxt is not None:
                out.append(nxt)
            elif not self.strict:
                continue  # null member: ",," or trailing ","
            else:
                self._restore(state)
                return None
        return out

    # ------------------------------------------------------------------
    # Result construction
    # ------------------------------------------------------------------

    def _build_address(
        self,
        state: tuple[int, int],
        display_name: str | None = None,
        local_part: str = "",
        domain: str = "",
        is_group: bool = False,
        group_members: list[RFC5322Address] | None = None,
    ) -> RFC5322Address:
        return RFC5322Address(
            display_name=display_name,
            local_part=local_part,
            domain=domain,
            is_group=is_group,
            group_members=group_members or [],
            comments=self._comments[state[1]:],
            source=self._source[state[0]:self._pos],
        )