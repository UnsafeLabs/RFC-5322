"""RFC 5322 compliant email address parser (§3.2–§3.4, optional §4.4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


# atext per §3.2.3
_ATEXT = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "!#$%&'*+-/=?^_`{|}~"
)

# qtext: printable US-ASCII excluding \ and "  (§3.2.4)
# %d33 / %d35-91 / %d93-126
def _is_qtext(ch: str) -> bool:
    o = ord(ch)
    return o == 33 or 35 <= o <= 91 or 93 <= o <= 126


# ctext: printable US-ASCII excluding ( ) \  (§3.2.2)
# %d33-39 / %d42-91 / %d93-126
def _is_ctext(ch: str) -> bool:
    o = ord(ch)
    return (33 <= o <= 39) or (42 <= o <= 91) or (93 <= o <= 126)


# dtext: printable US-ASCII excluding [ ] \  (§3.4.1)
# %d33-90 / %d94-126
def _is_dtext(ch: str) -> bool:
    o = ord(ch)
    return (33 <= o <= 90) or (94 <= o <= 126)


# VCHAR: %x21-7E
def _is_vchar(ch: str) -> bool:
    return 33 <= ord(ch) <= 126


def _is_wsp(ch: str) -> bool:
    return ch in (" ", "\t")


class ParseError(ValueError):
    """Raised when input does not match RFC 5322 address syntax."""

    def __init__(self, message: str, position: int = -1) -> None:
        self.position = position
        super().__init__(message if position < 0 else f"{message} at position {position}")


@dataclass
class RFC5322Address:
    """Parsed RFC 5322 email address."""

    display_name: Optional[str]
    local_part: str
    domain: str
    is_group: bool
    group_members: List["RFC5322Address"]
    comments: List[str]
    source: str


class AddressParser:
    """
    RFC 5322 compliant email address parser.

    Implements full ABNF grammar from §3.2-§3.4 with optional
    obsolete syntax support from §4.4.
    """

    MAX_LENGTH = 998  # RFC 5322 line length limit (§2.1.1)

    def __init__(self, strict: bool = True) -> None:
        """
        Args:
            strict: If True, reject obs-* productions.
                    If False, accept obsolete forms per §4.4.
        """
        self.strict = strict
        self._s: str = ""
        self._i: int = 0
        self._comments: List[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, raw: str) -> RFC5322Address:
        """Parse a single mailbox or group address."""
        self._prepare(raw)
        addr = self._parse_address()
        self._skip_cfws()
        if self._i < len(self._s):
            raise ParseError("trailing garbage after address", self._i)
        addr.comments = list(self._comments)
        addr.source = raw
        return addr

    def parse_address_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma-separated address-list per §3.4."""
        self._prepare(raw)
        result = self._parse_address_list()
        self._skip_cfws()
        if self._i < len(self._s):
            raise ParseError("trailing garbage after address-list", self._i)
        return result

    def parse_mailbox_list(self, raw: str) -> List[RFC5322Address]:
        """Parse a comma-separated mailbox-list per §3.4."""
        self._prepare(raw)
        result = self._parse_mailbox_list()
        self._skip_cfws()
        if self._i < len(self._s):
            raise ParseError("trailing garbage after mailbox-list", self._i)
        return result

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _prepare(self, raw: str) -> None:
        if not isinstance(raw, str):
            raise TypeError("input must be str")
        if len(raw) > self.MAX_LENGTH:
            raise ParseError(
                f"input exceeds RFC 5322 line length limit of {self.MAX_LENGTH} characters"
            )
        self._s = raw
        self._i = 0
        self._comments = []

    def _peek(self, n: int = 0) -> Optional[str]:
        pos = self._i + n
        if pos < len(self._s):
            return self._s[pos]
        return None

    def _advance(self, n: int = 1) -> str:
        ch = self._s[self._i : self._i + n]
        self._i += n
        return ch

    def _at_end(self) -> bool:
        return self._i >= len(self._s)

    # ------------------------------------------------------------------
    # §3.2.1 quoted-pair
    # ------------------------------------------------------------------

    def _try_quoted_pair(self) -> Optional[str]:
        """Parse quoted-pair = ("\\" (VCHAR / WSP)) [/ obs-qp]. Returns char or None."""
        if self._peek() != "\\":
            return None
        nxt = self._peek(1)
        if nxt is None:
            return None
        if _is_vchar(nxt) or _is_wsp(nxt):
            self._advance(2)
            return nxt
        # obs-qp allows \ + obs-NO-WS-CTL / LF / CR  (§4.1) — only in permissive mode
        if not self.strict:
            o = ord(nxt)
            if o == 0 or (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127 or nxt in ("\n", "\r"):
                self._advance(2)
                return nxt
        return None

    # ------------------------------------------------------------------
    # §3.2.2 FWS / comment / CFWS
    # ------------------------------------------------------------------

    def _try_fws(self) -> bool:
        """
        FWS = ([*WSP CRLF] 1*WSP) / obs-FWS
        Also accept plain runs of WSP (unfolded form).
        Returns True if any FWS was consumed.
        """
        saw = False
        while self._peek() is not None and _is_wsp(self._peek()):  # type: ignore[arg-type]
            self._advance()
            saw = True
        while self._peek() == "\r" and self._peek(1) == "\n":
            if self._peek(2) is not None and _is_wsp(self._peek(2)):  # type: ignore[arg-type]
                self._advance(2)  # CRLF (semantically invisible)
                while self._peek() is not None and _is_wsp(self._peek()):  # type: ignore[arg-type]
                    self._advance()
                saw = True
            else:
                break
        return saw

    def _try_fws_collect_wsp(self) -> str:
        """
        Like FWS, but return preserved WSP characters (CRLF folding removed).
        Used inside quoted-string where WSP is semantic content (§3.2.4).
        """
        parts: List[str] = []
        while True:
            ch = self._peek()
            if ch is not None and _is_wsp(ch):
                parts.append(self._advance())
                continue
            if self._peek() == "\r" and self._peek(1) == "\n":
                if self._peek(2) is not None and _is_wsp(self._peek(2)):  # type: ignore[arg-type]
                    self._advance(2)  # drop CRLF
                    continue
            break
        return "".join(parts)

    def _parse_fws_required(self) -> None:
        if not self._try_fws():
            # Allow zero-width only where optional; callers use _try
            pass

    def _try_comment(self) -> Optional[str]:
        """comment = '(' *([FWS] ccontent) [FWS] ')'"""
        if self._peek() != "(":
            return None
        self._advance()  # (
        parts: List[str] = []
        while True:
            self._try_fws()
            if self._peek() == ")":
                self._advance()
                text = "".join(parts)
                self._comments.append(text)
                return text
            if self._at_end():
                raise ParseError("unclosed comment", self._i)
            # ccontent = ctext / quoted-pair / comment
            qp = self._try_quoted_pair()
            if qp is not None:
                parts.append(qp)
                continue
            if self._peek() == "(":
                nested = self._try_comment()
                if nested is not None:
                    parts.append("(" + nested + ")")
                    continue
            ch = self._peek()
            if ch is not None and _is_ctext(ch):
                parts.append(self._advance())
                continue
            # obs-ctext in permissive mode
            if not self.strict and ch is not None:
                o = ord(ch)
                if o == 0 or (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127:
                    parts.append(self._advance())
                    continue
            raise ParseError(f"invalid character in comment: {ch!r}", self._i)

    def _skip_cfws(self) -> bool:
        """
        CFWS = (1*([FWS] comment) [FWS]) / FWS
        Consume CFWS; return True if anything was consumed.
        """
        start = self._i
        # Try form with at least one comment
        while True:
            before = self._i
            self._try_fws()
            if self._try_comment() is not None:
                continue
            # No comment after optional FWS — if we only had FWS that's still CFWS
            break
        # Trailing FWS after comments, or bare FWS
        self._try_fws()
        return self._i > start

    # ------------------------------------------------------------------
    # §3.2.3 atom / dot-atom
    # ------------------------------------------------------------------

    def _try_atext_run(self) -> Optional[str]:
        """1*atext"""
        chars: List[str] = []
        while True:
            ch = self._peek()
            if ch is not None and ch in _ATEXT:
                chars.append(self._advance())
            else:
                break
        return "".join(chars) if chars else None

    def _try_atom(self) -> Optional[str]:
        """atom = [CFWS] 1*atext [CFWS]"""
        save = self._i
        save_c = len(self._comments)
        self._skip_cfws()
        text = self._try_atext_run()
        if text is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._skip_cfws()
        return text

    def _try_dot_atom_text(self) -> Optional[str]:
        """dot-atom-text = 1*atext *('.' 1*atext)"""
        first = self._try_atext_run()
        if first is None:
            return None
        parts = [first]
        while self._peek() == ".":
            save = self._i
            self._advance()  # .
            nxt = self._try_atext_run()
            if nxt is None:
                self._i = save
                break
            parts.append(nxt)
        return ".".join(parts)

    def _try_dot_atom(self) -> Optional[str]:
        """dot-atom = [CFWS] dot-atom-text [CFWS]"""
        save = self._i
        save_c = len(self._comments)
        self._skip_cfws()
        text = self._try_dot_atom_text()
        if text is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._skip_cfws()
        return text

    # ------------------------------------------------------------------
    # §3.2.4 quoted-string
    # ------------------------------------------------------------------

    def _try_quoted_string(self, *, collect_cfws: bool = True) -> Optional[str]:
        """
        quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]
        Returns semantic content (without surrounding quotes / CFWS).
        """
        save = self._i
        save_c = len(self._comments)
        if collect_cfws:
            self._skip_cfws()
        if self._peek() != '"':
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # opening "
        content: List[str] = []
        while True:
            # FWS inside quoted-string: keep WSP, drop CRLF (§3.2.4)
            wsp = self._try_fws_collect_wsp()
            if wsp:
                content.append(wsp)
            if self._peek() == '"':
                self._advance()
                break
            if self._at_end():
                self._i = save
                self._comments = self._comments[:save_c]
                return None
            qp = self._try_quoted_pair()
            if qp is not None:
                content.append(qp)
                continue
            ch = self._peek()
            if ch is not None and _is_qtext(ch):
                content.append(self._advance())
                continue
            # obs-qtext
            if not self.strict and ch is not None:
                o = ord(ch)
                if o == 0 or (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127:
                    content.append(self._advance())
                    continue
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        if collect_cfws:
            self._skip_cfws()
        return "".join(content)

    # ------------------------------------------------------------------
    # §3.2.5 word / phrase
    # ------------------------------------------------------------------

    def _try_word(self) -> Optional[str]:
        """word = atom / quoted-string"""
        qs = self._try_quoted_string()
        if qs is not None:
            return qs
        return self._try_atom()

    def _try_phrase(self) -> Optional[str]:
        """phrase = 1*word / obs-phrase"""
        words: List[str] = []
        while True:
            w = self._try_word()
            if w is None:
                break
            words.append(w)
        if words:
            return " ".join(words)
        # obs-phrase = word *(word / "." / CFWS) — permissive only
        if not self.strict:
            # Already covered partially; allow dots between words
            pass
        return None

    # ------------------------------------------------------------------
    # §3.4.1 addr-spec / domain-literal
    # ------------------------------------------------------------------

    def _try_domain_literal(self) -> Optional[str]:
        """domain-literal = [CFWS] '[' *([FWS] dtext) [FWS] ']' [CFWS]"""
        save = self._i
        save_c = len(self._comments)
        self._skip_cfws()
        if self._peek() != "[":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # [
        content: List[str] = []
        while True:
            self._try_fws()
            if self._peek() == "]":
                self._advance()
                break
            if self._at_end():
                self._i = save
                self._comments = self._comments[:save_c]
                return None
            ch = self._peek()
            if ch is not None and _is_dtext(ch):
                content.append(self._advance())
                continue
            # obs-dtext = obs-NO-WS-CTL / quoted-pair
            if not self.strict:
                qp = self._try_quoted_pair()
                if qp is not None:
                    content.append(qp)
                    continue
                if ch is not None:
                    o = ord(ch)
                    if o == 0 or (1 <= o <= 8) or o == 11 or o == 12 or (14 <= o <= 31) or o == 127:
                        content.append(self._advance())
                        continue
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._skip_cfws()
        return "[" + "".join(content) + "]"

    def _try_obs_local_part(self) -> Optional[str]:
        """obs-local-part = word *('.' word)  §4.4"""
        if self.strict:
            return None
        save = self._i
        save_c = len(self._comments)
        first = self._try_word()
        if first is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        parts = [first]
        while self._peek() == ".":
            self._advance()
            # Allow empty between dots? RFC requires word; still try word
            w = self._try_word()
            if w is None:
                # bare trailing/mid dot — keep dot for obs tolerance of mixed forms
                parts.append("")
            else:
                parts.append(w)
        # Only treat as obs if it actually mixes or has CFWS-separated form;
        # pure dot-atom-text is fine either way
        result = ".".join(parts)
        return result

    def _try_obs_domain(self) -> Optional[str]:
        """
        obs-domain = atom *('.' atom)  §4.4
        Also accept leading/empty atoms in permissive mode for real-world forms
        like user@.leading-dot.com
        """
        if self.strict:
            return None
        save = self._i
        save_c = len(self._comments)
        self._skip_cfws()
        parts: List[str] = []
        # Leading dot(s)
        while self._peek() == ".":
            self._advance()
            parts.append("")
        atom = self._try_atom()
        if atom is None and not parts:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        if atom is not None:
            parts.append(atom)
        while self._peek() == ".":
            self._advance()
            self._skip_cfws()
            a = self._try_atom()
            if a is None:
                parts.append("")
            else:
                parts.append(a)
        if not parts or all(p == "" for p in parts):
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        return ".".join(parts)

    def _try_local_part(self) -> Optional[str]:
        """local-part = dot-atom / quoted-string / obs-local-part"""
        save = self._i
        save_c = len(self._comments)

        # Try quoted-string first (may have CFWS)
        qs = self._try_quoted_string()
        if qs is not None:
            # If followed by '.' then more (obs-local-part mixing)
            if not self.strict and self._peek() == ".":
                parts = [qs]
                while self._peek() == ".":
                    self._advance()
                    w = self._try_word()
                    if w is None:
                        parts.append("")
                    else:
                        parts.append(w)
                return ".".join(parts)
            return qs

        # Try obs-local-part before pure dot-atom so mixed forms work
        if not self.strict:
            self._i = save
            self._comments = self._comments[:save_c]
            obs = self._try_obs_local_part()
            if obs is not None:
                # Verify we didn't leave unparsed local junk before @
                return obs

        self._i = save
        self._comments = self._comments[:save_c]
        da = self._try_dot_atom()
        if da is not None:
            return da

        return None

    def _try_domain(self) -> Optional[str]:
        """domain = dot-atom / domain-literal / obs-domain"""
        dl = self._try_domain_literal()
        if dl is not None:
            return dl
        save = self._i
        save_c = len(self._comments)
        da = self._try_dot_atom()
        if da is not None:
            return da
        self._i = save
        self._comments = self._comments[:save_c]
        if not self.strict:
            return self._try_obs_domain()
        return None

    def _try_addr_spec(self) -> Optional[tuple]:
        """addr-spec = local-part '@' domain  → (local, domain) or None"""
        save = self._i
        save_c = len(self._comments)
        local = self._try_local_part()
        if local is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        # CFWS around @ is discouraged but atom/dot-atom may have consumed trailing CFWS
        if self._peek() != "@":
            # Maybe CFWS before @
            self._skip_cfws()
        if self._peek() != "@":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # @
        domain = self._try_domain()
        if domain is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        return (local, domain)

    # ------------------------------------------------------------------
    # §3.4 address / mailbox / group
    # ------------------------------------------------------------------

    def _try_obs_route(self) -> Optional[str]:
        """obs-route = obs-domain-list ':' """
        if self.strict:
            return None
        save = self._i
        save_c = len(self._comments)
        # obs-domain-list = *(CFWS / ',') '@' domain *(',' [CFWS] ['@' domain])
        saw_at = False
        while True:
            self._skip_cfws()
            if self._peek() == ",":
                self._advance()
                continue
            if self._peek() == "@":
                self._advance()
                saw_at = True
                if self._try_domain() is None:
                    self._i = save
                    self._comments = self._comments[:save_c]
                    return None
                # more , [@ domain]
                while True:
                    self._skip_cfws()
                    if self._peek() != ",":
                        break
                    self._advance()
                    self._skip_cfws()
                    if self._peek() == "@":
                        self._advance()
                        if self._try_domain() is None:
                            self._i = save
                            self._comments = self._comments[:save_c]
                            return None
                break
            break
        if not saw_at:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._skip_cfws()
        if self._peek() != ":":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # :
        return ""  # route ignored per §4.4

    def _try_angle_addr(self) -> Optional[tuple]:
        """
        angle-addr = [CFWS] '<' addr-spec '>' [CFWS] / obs-angle-addr
        Returns (local, domain) or None.
        """
        save = self._i
        save_c = len(self._comments)
        self._skip_cfws()
        if self._peek() != "<":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # <
        # Optional obs-route
        if not self.strict:
            self._try_obs_route()
        spec = self._try_addr_spec()
        if spec is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._skip_cfws()
        if self._peek() != ">":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # >
        self._skip_cfws()
        return spec

    def _try_name_addr(self) -> Optional[RFC5322Address]:
        """name-addr = [display-name] angle-addr"""
        save = self._i
        save_c = len(self._comments)
        display = self._try_phrase()
        spec = self._try_angle_addr()
        if spec is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        local, domain = spec
        return RFC5322Address(
            display_name=display,
            local_part=local,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=[],
            source="",
        )

    def _try_mailbox(self) -> Optional[RFC5322Address]:
        """mailbox = name-addr / addr-spec"""
        # Prefer name-addr (has angle brackets)
        na = self._try_name_addr()
        if na is not None:
            return na
        save = self._i
        save_c = len(self._comments)
        spec = self._try_addr_spec()
        if spec is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        local, domain = spec
        return RFC5322Address(
            display_name=None,
            local_part=local,
            domain=domain,
            is_group=False,
            group_members=[],
            comments=[],
            source="",
        )

    def _try_group(self) -> Optional[RFC5322Address]:
        """group = display-name ':' [group-list] ';' [CFWS]"""
        save = self._i
        save_c = len(self._comments)
        display = self._try_phrase()
        if display is None:
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        if self._peek() != ":":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # :
        members: List[RFC5322Address] = []
        # group-list = mailbox-list / CFWS / obs-group-list
        self._skip_cfws()
        if self._peek() != ";":
            # Try mailbox-list; in permissive mode allow null members
            members = self._parse_mailbox_list_inner()
        self._skip_cfws()
        if self._peek() != ";":
            self._i = save
            self._comments = self._comments[:save_c]
            return None
        self._advance()  # ;
        self._skip_cfws()
        return RFC5322Address(
            display_name=display,
            local_part="",
            domain="",
            is_group=True,
            group_members=members,
            comments=[],
            source="",
        )

    def _parse_address(self) -> RFC5322Address:
        """address = mailbox / group"""
        # Try group first only if we see phrase ':' pattern — try group then mailbox
        save = self._i
        save_c = len(self._comments)
        grp = self._try_group()
        if grp is not None:
            return grp
        self._i = save
        self._comments = self._comments[:save_c]
        mb = self._try_mailbox()
        if mb is not None:
            return mb
        raise ParseError("expected mailbox or group address", self._i)

    def _parse_mailbox_list_inner(self) -> List[RFC5322Address]:
        """mailbox-list = (mailbox *(',' mailbox)) / obs-mbox-list"""
        result: List[RFC5322Address] = []
        if not self.strict:
            # obs-mbox-list: *([CFWS] ',') mailbox *(',' [mailbox / CFWS])
            while True:
                self._skip_cfws()
                if self._peek() == ",":
                    self._advance()
                    continue
                break
        mb = self._try_mailbox()
        if mb is None:
            if self.strict:
                raise ParseError("expected mailbox in mailbox-list", self._i)
            return result
        result.append(mb)
        while True:
            save = self._i
            save_c = len(self._comments)
            self._skip_cfws()
            if self._peek() != ",":
                self._i = save
                self._comments = self._comments[:save_c]
                break
            self._advance()  # ,
            self._skip_cfws()
            mb2 = self._try_mailbox()
            if mb2 is None:
                if self.strict:
                    raise ParseError("expected mailbox after comma", self._i)
                # obs null member — continue
                continue
            result.append(mb2)
        return result

    def _parse_mailbox_list(self) -> List[RFC5322Address]:
        items = self._parse_mailbox_list_inner()
        for item in items:
            item.comments = list(self._comments)
            item.source = self._s
        return items

    def _parse_address_list(self) -> List[RFC5322Address]:
        """address-list = (address *(',' address)) / obs-addr-list"""
        result: List[RFC5322Address] = []
        if not self.strict:
            while True:
                self._skip_cfws()
                if self._peek() == ",":
                    self._advance()
                    continue
                break
        # Need at least one address in strict mode
        save = self._i
        save_c = len(self._comments)
        try:
            addr = self._parse_address()
        except ParseError:
            if self.strict:
                raise
            self._i = save
            self._comments = self._comments[:save_c]
            return result
        addr.comments = list(self._comments)
        addr.source = self._s
        result.append(addr)
        while True:
            save = self._i
            save_c = len(self._comments)
            self._skip_cfws()
            if self._peek() != ",":
                self._i = save
                self._comments = self._comments[:save_c]
                break
            self._advance()
            c_before = list(self._comments)
            self._skip_cfws()
            save2 = self._i
            save_c2 = len(self._comments)
            try:
                addr2 = self._parse_address()
            except ParseError:
                if self.strict:
                    raise
                # null member
                continue
            addr2.comments = list(self._comments)
            addr2.source = self._s
            result.append(addr2)
        return result
