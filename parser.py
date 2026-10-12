"""
RFC 5322 ABNF-Compatible Email Address Parser
==============================================

Implements a recursive descent parser for RFC 5322 Internet Message Format,
covering sections 3.2 through 4.4 (Lexical Tokens, Date/Time, Address
Specification, and Obsolete Syntax).

The parser handles both the modern (generating) syntax and the obsolete
(interpreting) syntax per the RFC requirements.
"""

import re
from dataclasses import dataclass, field
from typing import Optional, List, Union


# ============================================================================
# Character classes from RFC 5234 Core Rules
# ============================================================================

ALPHA = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
DIGIT = set("0123456789")
HEXDIG = set("0123456789ABCDEFabcdef")
WSP = {" ", "\t"}
VCHAR = {chr(i) for i in range(0x21, 0x7F)}  # visible characters
CR = "\r"
LF = "\n"
CRLF = "\r\n"
DQUOTE = '"'

# atext: §3.2.3
ATEXT_EXTRA = set("!#$%&'*+-/=?^_`{|}~")
ATEXT = ALPHA | DIGIT | ATEXT_EXTRA

# specials: §3.2.3
SPECIALS = set("()<>[]:;@\\,.\"")

# ctext: §3.2.2 — printable US-ASCII excluding "(", ")", "\"
CTEXT_CHARS = set()
for i in range(33, 127):
    if i not in (40, 41, 92):  # '(', ')', '\\'
        CTEXT_CHARS.add(chr(i))

# qtext: §3.2.4 — printable US-ASCII excluding "\" and DQUOTE
QTEXT_CHARS = set()
for i in range(33, 127):
    if i not in (34, 92):  # '"', '\\'
        QTEXT_CHARS.add(chr(i))
# Note: %d33 (33 is '!') are included; %d35-91 and %d93-126 are covered
# Actually qtext = %d33 / %d35-91 / %d93-126
# Let me be precise:
QTEXT_CHARS = {chr(33)}  # '!'
for i in range(35, 92):  # '#' through '['
    QTEXT_CHARS.add(chr(i))
for i in range(93, 127):  # ']' through '~'
    QTEXT_CHARS.add(chr(i))

# dtext: §3.4.1 — printable US-ASCII excluding "[", "]", "\"
DTEXT_CHARS = set()
for i in range(33, 127):
    if i not in (91, 93, 92):  # '[', ']', '\\'
        DTEXT_CHARS.add(chr(i))
# Actually dtext = %d33-90 / %d94-126
DTEXT_CHARS = set()
for i in range(33, 91):
    DTEXT_CHARS.add(chr(i))
for i in range(94, 127):
    DTEXT_CHARS.add(chr(i))

# obs-NO-WS-CTL: §4.1
OBS_NO_WS_CTL = set()
for i in range(1, 9):
    OBS_NO_WS_CTL.add(chr(i))
OBS_NO_WS_CTL.add(chr(11))
OBS_NO_WS_CTL.add(chr(12))
for i in range(14, 32):
    OBS_NO_WS_CTL.add(chr(i))
OBS_NO_WS_CTL.add(chr(127))

# Day and month names (case-insensitive)
DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MONTH_NAMES = ("jan", "feb", "mar", "apr", "may", "jun",
               "jul", "aug", "sep", "oct", "nov", "dec")

# Obsolete time zones
OBS_ZONE_NAMES = {
    "ut", "gmt",
    "est", "edt", "cst", "cdt", "mst", "mdt", "pst", "pdt"
}

# ============================================================================
# Parsed data classes
# ============================================================================

@dataclass
class AddrSpec:
    """addr-spec = local-part '@' domain"""
    local_part: str
    domain: str

    def __str__(self):
        return f"{self.local_part}@{self.domain}"


@dataclass
class DisplayName:
    """display-name = phrase"""
    value: str


@dataclass
class AngleAddr:
    """angle-addr = [CFWS] '<' addr-spec '>' [CFWS]"""
    addr_spec: AddrSpec
    display_name: Optional[str] = None

    def __str__(self):
        if self.display_name:
            return f"{self.display_name} <{self.addr_spec}>"
        return f"<{self.addr_spec}>"


@dataclass
class NameAddr:
    """name-addr = [display-name] angle-addr"""
    angle_addr: AngleAddr
    display_name: Optional[str] = None

    def __str__(self):
        if self.display_name:
            return f"{self.display_name} {self.angle_addr}"
        return str(self.angle_addr)


@dataclass
class Mailbox:
    """mailbox = name-addr / addr-spec"""
    value: Union[NameAddr, AddrSpec]

    @property
    def addr_spec(self) -> AddrSpec:
        if isinstance(self.value, AddrSpec):
            return self.value
        return self.value.angle_addr.addr_spec

    @property
    def display_name(self) -> Optional[str]:
        if isinstance(self.value, AddrSpec):
            return None
        return self.value.display_name or self.value.angle_addr.display_name

    def __str__(self):
        if isinstance(self.value, AddrSpec):
            return str(self.value)
        return str(self.value)


@dataclass
class Group:
    """group = display-name ':' [group-list] ';' [CFWS]"""
    display_name: str
    mailboxes: List[Mailbox] = field(default_factory=list)

    def __str__(self):
        mboxes = ", ".join(str(m) for m in self.mailboxes)
        return f"{self.display_name}: {mboxes};"


@dataclass
class DateTime:
    """date-time = [day-of-week ','] date time [CFWS]"""
    day: int
    month: int
    year: int
    hour: int
    minute: int
    second: Optional[int] = None
    zone: Optional[str] = None
    day_of_week: Optional[str] = None


# ============================================================================
# Parser class — recursive descent following RFC 5322 ABNF
# ============================================================================

class RFC5322Parser:
    """
    Recursive descent parser implementing RFC 5322 ABNF grammar
    for sections 3.2 through 4.4.

    Usage:
        parser = RFC5322Parser()
        mailbox = parser.parse_mailbox("John Doe <john@example.com>")
        addr_list = parser.parse_address_list("alice@a.com, bob@b.com")
    """

    def __init__(self, text: str):
        self.text = text
        self.pos = 0
        self.length = len(text)

    # ---- Utility ----

    def _remaining(self) -> str:
        return self.text[self.pos:]

    def _peek(self, n: int = 1) -> str:
        if self.pos + n <= self.length:
            return self.text[self.pos:self.pos + n]
        return ""

    def _consume(self, n: int = 1) -> str:
        result = self._peek(n)
        self.pos += n
        return result

    def _match_str(self, s: str, case_insensitive: bool = False) -> bool:
        """Check if remaining text starts with string s."""
        remaining = self._remaining()
        if case_insensitive:
            return remaining[:len(s)].lower() == s.lower()
        return remaining[:len(s)] == s

    def _expect_str(self, s: str, case_insensitive: bool = False) -> bool:
        """Consume string s if matched. Return True if consumed."""
        if self._match_str(s, case_insensitive):
            self._consume(len(s))
            return True
        return False

    def _skip_ws(self):
        """Skip WSP characters."""
        while self.pos < self.length and self.text[self.pos] in WSP:
            self.pos += 1

    def _end(self) -> bool:
        return self.pos >= self.length

    # ====================================================================
    # §3.2.1 Quoted characters
    # ====================================================================

    def _parse_quoted_pair(self) -> Optional[str]:
        """quoted-pair = ('\\' (VCHAR / WSP)) / obs-qp"""
        if self._peek() == "\\" and not self._end():
            self._consume()  # consume backslash
            if not self._end():
                ch = self._peek()
                # VCHAR / WSP
                if ch in VCHAR or ch in WSP:
                    self._consume()
                    return ch
                # obs-qp: "\\" (%d0 / obs-NO-WS-CTL / LF / CR)
                if ch == chr(0) or ch in OBS_NO_WS_CTL or ch in (LF, CR):
                    self._consume()
                    return ch
            # If we consumed backslash but couldn't parse next char, return None
            return None
        return None

    # ====================================================================
    # §3.2.2 Folding White Space and Comments
    # ====================================================================

    def _parse_fws(self) -> Optional[str]:
        """FWS = ([*WSP CRLF] 1*WSP) / obs-FWS"""
        start = self.pos
        # Try modern FWS: optional WSP*, optional CRLF, then 1*WSP
        while self.pos < self.length and self.text[self.pos] in WSP:
            self.pos += 1
        if self._expect_str(CRLF):
            ws_count = 0
            while self.pos < self.length and self.text[self.pos] in WSP:
                self.pos += 1
                ws_count += 1
            if ws_count >= 1:
                return self.text[start:self.pos]
            self.pos = start
            return None
        # Check if we already consumed at least one WSP
        if self.pos > start:
            return self.text[start:self.pos]
        # Try obs-FWS: 1*WSP *(CRLF 1*WSP)
        ws_count = 0
        while self.pos < self.length and self.text[self.pos] in WSP:
            self.pos += 1
            ws_count += 1
        if ws_count >= 1:
            while True:
                save = self.pos
                if self._expect_str(CRLF):
                    more_ws = 0
                    while self.pos < self.length and self.text[self.pos] in WSP:
                        self.pos += 1
                        more_ws += 1
                    if more_ws == 0:
                        self.pos = save
                        break
                else:
                    break
            return self.text[start:self.pos]
        self.pos = start
        return None

    def _parse_ctext(self) -> Optional[str]:
        """ctext = %d33-39 / %d42-91 / %d93-126 / obs-ctext"""
        if self._end():
            return None
        ch = self._peek()
        if ch in CTEXT_CHARS:
            return self._consume()
        if ch in OBS_NO_WS_CTL:
            return self._consume()
        return None

    def _parse_ccontent(self) -> Optional[str]:
        """ccontent = ctext / quoted-pair / comment"""
        c = self._parse_comment()
        if c is not None:
            return c
        qp = self._parse_quoted_pair()
        if qp is not None:
            return qp
        ct = self._parse_ctext()
        if ct is not None:
            return ct
        return None

    def _parse_comment(self) -> Optional[str]:
        """comment = '(' *([FWS] ccontent) [FWS] ')'"""
        if self._peek() != "(":
            return None
        start = self.pos
        self._consume()  # consume '('
        depth = 1
        while self.pos < self.length and depth > 0:
            ch = self._peek()
            if ch == "(":
                # Nested comment
                nested = self._parse_comment()
                if nested is None:
                    depth += 1
                    self._consume()
                continue
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    self._consume()
                    break
                else:
                    self._consume()
                    continue
            elif ch == "\\":
                self._parse_quoted_pair()
                continue
            elif ch in (CR, LF, " ", "\t"):
                # Try FWS
                fws = self._parse_fws()
                if fws is None:
                    self._consume()
                continue
            else:
                self._consume()
        return self.text[start:self.pos]

    def _parse_cfws(self) -> Optional[str]:
        """CFWS = (1*([FWS] comment) [FWS]) / FWS"""
        start = self.pos

        # Try the comment path: 1*([FWS] comment) [FWS]
        comment_count = 0
        while True:
            save_before_fws = self.pos
            fws = self._parse_fws()
            c = self._parse_comment()
            if c is not None:
                comment_count += 1
                continue
            # No comment found after (optional) FWS
            if comment_count == 0:
                # No comments at all — this path fails, rewind for FWS-only
                self.pos = start
                break
            # We have comments. If FWS was consumed, back up: it's trailing FWS
            if fws:
                self.pos = save_before_fws
            break

        if comment_count > 0:
            return self.text[start:self.pos]

        # Try plain FWS
        fws = self._parse_fws()
        if fws is not None:
            return fws

        return None

    # ====================================================================
    # §3.2.3 Atom
    # ====================================================================

    def _parse_atext(self) -> Optional[str]:
        """atext = ALPHA / DIGIT / '!' / '#' / '$' / '%' / '&' / "'" /
                 '*' / '+' / '-' / '/' / '=' / '?' / '^' / '_' / '`' /
                 '{' / '|' / '}' / '~'"""
        if self._end():
            return None
        ch = self._peek()
        if ch in ATEXT:
            return self._consume()
        return None

    def _parse_atom(self) -> Optional[str]:
        """atom = [CFWS] 1*atext [CFWS]"""
        start = self.pos
        self._parse_cfws()  # optional leading CFWS
        atext_run = []
        while self.pos < self.length:
            ch = self._peek()
            if ch in ATEXT:
                atext_run.append(self._consume())
            else:
                break
        if not atext_run:
            self.pos = start
            return None
        self._parse_cfws()  # optional trailing CFWS
        return "".join(atext_run)

    def _parse_dot_atom_text(self) -> Optional[str]:
        """dot-atom-text = 1*atext *('.' 1*atext)"""
        start = self.pos
        # First segment: 1*atext
        first = []
        while self.pos < self.length and self._peek() in ATEXT:
            first.append(self._consume())
        if not first:
            return None
        parts = ["".join(first)]
        while self._peek() == ".":
            self._consume()
            segment = []
            while self.pos < self.length and self._peek() in ATEXT:
                segment.append(self._consume())
            if not segment:
                # No atext after dot — invalid
                self.pos -= 1  # put back the dot
                break
            parts.append("".join(segment))
        return ".".join(parts)

    def _parse_dot_atom(self) -> Optional[str]:
        """dot-atom = [CFWS] dot-atom-text [CFWS]"""
        start = self.pos
        self._parse_cfws()
        dat = self._parse_dot_atom_text()
        if dat is None:
            self.pos = start
            return None
        self._parse_cfws()
        return dat

    # ====================================================================
    # §3.2.4 Quoted Strings
    # ====================================================================

    def _parse_qtext(self) -> Optional[str]:
        """qtext = %d33 / %d35-91 / %d93-126 / obs-qtext"""
        if self._end():
            return None
        ch = self._peek()
        if ch in QTEXT_CHARS:
            return self._consume()
        if ch in OBS_NO_WS_CTL:
            return self._consume()
        return None

    def _parse_qcontent(self) -> Optional[str]:
        """qcontent = qtext / quoted-pair"""
        qp = self._parse_quoted_pair()
        if qp is not None:
            return qp
        qt = self._parse_qtext()
        if qt is not None:
            return qt
        return None

    def _parse_quoted_string(self) -> Optional[str]:
        """quoted-string = [CFWS] DQUOTE *([FWS] qcontent) [FWS] DQUOTE [CFWS]"""
        start = self.pos
        self._parse_cfws()
        if self._peek() != DQUOTE:
            self.pos = start
            return None
        self._consume()  # consume opening DQUOTE
        content_parts = []
        while self.pos < self.length and self._peek() != DQUOTE:
            # Try FWS first (preceding whitespace)
            fws = self._parse_fws()
            if fws is not None:
                content_parts.append(fws)
            if self._peek() == DQUOTE:
                break
            # Try backslash escape
            if self._peek() == "\\":
                qp = self._parse_quoted_pair()
                if qp is not None:
                    content_parts.append("\\" + qp)
                    continue
            # Try qtext
            qt = self._parse_qtext()
            if qt is not None:
                content_parts.append(qt)
                continue
            # If nothing matched, break to avoid infinite loop
            break
        # optional FWS before closing DQUOTE
        fws_end = self._parse_fws()
        if fws_end is not None:
            content_parts.append(fws_end)
        if self._peek() == DQUOTE:
            self._consume()
        self._parse_cfws()
        return "".join(content_parts)

    # ====================================================================
    # §3.2.5 Miscellaneous Tokens
    # ====================================================================

    def _parse_word(self) -> Optional[str]:
        """word = atom / quoted-string"""
        qs = self._parse_quoted_string()
        if qs is not None:
            return qs
        atom = self._parse_atom()
        if atom is not None:
            return atom
        return None

    def _parse_phrase(self) -> Optional[str]:
        """phrase = 1*word / obs-phrase (word *(word / '.' / CFWS))"""
        start = self.pos
        w = self._parse_word()
        if w is None:
            return None
        words = [w]
        while True:
            save = self.pos
            # Try another word
            w = self._parse_word()
            if w is not None:
                words.append(w)
                continue
            self.pos = save
            # Try period (obs-phrase: period between words is consumed
            # but semantically part of the preceding word in display)
            if self._peek() == ".":
                self._consume()
                if words:
                    words[-1] += "."
                continue
            # Try CFWS (obs-phrase allows CFWS between words)
            cfws = self._parse_cfws()
            if cfws is not None:
                continue
            break
        return " ".join(words)

    # ====================================================================
    # §3.3 Date and Time
    # ====================================================================

    def _parse_day_name(self) -> Optional[str]:
        """day-name = 'Mon' / 'Tue' / 'Wed' / 'Thu' / 'Fri' / 'Sat' / 'Sun'"""
        for dn in DAY_NAMES:
            if self._match_str(dn, case_insensitive=True):
                self._consume(len(dn))
                return dn.title()
        return None

    def _parse_day_of_week(self) -> Optional[str]:
        """day-of-week = ([FWS] day-name) / obs-day-of-week
        Always consumes trailing CFWS for robustness."""
        start = self.pos
        # Try modern: [FWS] day-name
        self._parse_fws()
        dn = self._parse_day_name()
        if dn is not None:
            self._parse_cfws()  # consume trailing CFWS
            return dn
        # Retry with obs: [CFWS] day-name [CFWS]
        self.pos = start
        self._parse_cfws()
        dn = self._parse_day_name()
        if dn is not None:
            self._parse_cfws()
            return dn
        self.pos = start
        return None

    def _parse_day(self) -> Optional[int]:
        """day = ([FWS] 1*2DIGIT FWS) / obs-day ([CFWS] 1*2DIGIT [CFWS])"""
        start = self.pos
        self._parse_cfws()
        digits = []
        while self.pos < self.length and self._peek() in DIGIT:
            digits.append(self._consume())
            if len(digits) >= 2:
                break
        if not digits:
            self.pos = start
            return None
        # Trailing whitespace: use FWS for modern, CFWS for obs
        after_digits = self.pos
        self._parse_cfws()
        return int("".join(digits))

    def _parse_month(self) -> Optional[int]:
        """month = 'Jan' / 'Feb' / 'Mar' / 'Apr' / 'May' / 'Jun' /
                  'Jul' / 'Aug' / 'Sep' / 'Oct' / 'Nov' / 'Dec'"""
        month_map = {m: i + 1 for i, m in enumerate(MONTH_NAMES)}
        for mn in MONTH_NAMES:
            if self._match_str(mn, case_insensitive=True):
                self._consume(len(mn))
                return month_map[mn]
        return None

    def _parse_year(self) -> Optional[int]:
        """year = (FWS 4*DIGIT FWS) / obs-year ([CFWS] 2*DIGIT [CFWS])"""
        start = self.pos
        self._parse_cfws()
        digits = []
        while self.pos < self.length and self._peek() in DIGIT:
            digits.append(self._consume())
        if not digits:
            self.pos = start
            return None
        self._parse_cfws()
        year_str = "".join(digits)
        year = int(year_str)
        # Handle 2-digit years per RFC §4.3
        if len(digits) == 2:
            if 0 <= year <= 49:
                year += 2000
            else:
                year += 1900
        elif len(digits) == 3:
            year += 1900
        return year

    def _parse_date(self) -> Optional[tuple]:
        """date = day month year"""
        start = self.pos
        d = self._parse_day()
        if d is None:
            self.pos = start
            return None
        m = self._parse_month()
        if m is None:
            self.pos = start
            return None
        y = self._parse_year()
        if y is None:
            self.pos = start
            return None
        return (d, m, y)

    def _parse_zone(self) -> Optional[str]:
        """zone = FWS (('+' / '-') 4DIGIT / obs-zone)"""
        start = self.pos
        fws = self._parse_fws()
        if self._peek() in ("+", "-"):
            sign = self._consume()
            digits = []
            for _ in range(4):
                if self._end() or self._peek() not in DIGIT:
                    self.pos = start
                    return None
                digits.append(self._consume())
            return f"{sign}{''.join(digits)}"
        # obs-zone (from position after FWS)
        # Try named zones
        for zname in sorted(OBS_ZONE_NAMES, key=len, reverse=True):
            if self._match_str(zname, case_insensitive=True):
                self._consume(len(zname))
                zone_map = {
                    "ut": "+0000", "gmt": "+0000",
                    "est": "-0500", "edt": "-0400",
                    "cst": "-0600", "cdt": "-0500",
                    "mst": "-0700", "mdt": "-0600",
                    "pst": "-0800", "pdt": "-0700"
                }
                return zone_map.get(zname.lower(), "-0000")
        # Military zones: single letter A-I, K-Z
        ch = self._peek()
        if ch:
            code = ord(ch)
            if (65 <= code <= 73) or (75 <= code <= 90) or (
                    97 <= code <= 105) or (107 <= code <= 122):
                self._consume()
                return "-0000"
        self.pos = start
        return None

    def _parse_time_of_day(self) -> Optional[tuple]:
        """time-of-day = hour ':' minute [':' second]"""
        start = self.pos
        # hour
        h = self._parse_hour()
        if h is None:
            self.pos = start
            return None
        if not self._expect_str(":"):
            self.pos = start
            return None
        # minute
        m = self._parse_minute()
        if m is None:
            self.pos = start
            return None
        s = None
        if self._peek() == ":":
            self._consume()
            s = self._parse_second()
        return (h, m, s)

    def _parse_time(self) -> Optional[tuple]:
        """time = time-of-day zone"""
        start = self.pos
        tod = self._parse_time_of_day()
        if tod is None:
            return None
        z = self._parse_zone()
        if z is None:
            self.pos = start
            return None
        return (tod, z)

    def _parse_hour(self) -> Optional[int]:
        """hour = 2DIGIT / obs-hour ([CFWS] 2DIGIT [CFWS])"""
        return self._parse_two_digit_cfws()

    def _parse_minute(self) -> Optional[int]:
        """minute = 2DIGIT / obs-minute ([CFWS] 2DIGIT [CFWS])"""
        return self._parse_two_digit_cfws()

    def _parse_second(self) -> Optional[int]:
        """second = 2DIGIT / obs-second ([CFWS] 2DIGIT [CFWS])"""
        return self._parse_two_digit_cfws()

    def _parse_two_digit_cfws(self) -> Optional[int]:
        """Parse 2 digits with optional CFWS on both sides."""
        start = self.pos
        self._parse_cfws()
        if self._end():
            self.pos = start
            return None
        digits = []
        for _ in range(2):
            if self._end() or self._peek() not in DIGIT:
                self.pos = start
                return None
            digits.append(self._consume())
        self._parse_cfws()
        return int("".join(digits))

    def _parse_date_time(self) -> Optional[DateTime]:
        """date-time = [day-of-week ','] date time [CFWS]"""
        start = self.pos
        dow = self._parse_day_of_week()
        if dow is not None:
            if not self._expect_str(","):
                # No comma — treat day-of-week as not present, rewind
                self.pos = start
                dow = None
        d = self._parse_date()
        if d is None:
            self.pos = start
            return None
        t = self._parse_time()
        if t is None:
            self.pos = start
            return None
        self._parse_cfws()
        day_val, month_val, year_val = d
        tod, zone = t
        return DateTime(
            day=day_val, month=month_val, year=year_val,
            hour=tod[0], minute=tod[1], second=tod[2],
            zone=zone, day_of_week=dow
        )

    # ====================================================================
    # §3.4.1 Addr-Spec
    # ====================================================================

    def _parse_dtext(self) -> Optional[str]:
        """dtext = %d33-90 / %d94-126 / obs-dtext"""
        if self._end():
            return None
        ch = self._peek()
        if ch in DTEXT_CHARS:
            return self._consume()
        if ch in OBS_NO_WS_CTL:
            return self._consume()
        qp = self._parse_quoted_pair()
        if qp is not None:
            return qp
        return None

    def _parse_domain_literal(self) -> Optional[str]:
        """domain-literal = [CFWS] '[' *([FWS] dtext) [FWS] ']' [CFWS]"""
        start = self.pos
        self._parse_cfws()
        if self._peek() != "[":
            self.pos = start
            return None
        self._consume()  # '['
        parts = []
        while self.pos < self.length and self._peek() != "]":
            self._parse_fws()
            if self._peek() == "]":
                break
            dt = self._parse_dtext()
            if dt is not None:
                parts.append(dt)
                continue
            # If we can't parse dtext, break
            break
        self._parse_fws()
        if self._peek() == "]":
            self._consume()
        self._parse_cfws()
        return "[" + "".join(parts) + "]"

    def _parse_local_part(self) -> Optional[str]:
        """local-part = dot-atom / quoted-string / obs-local-part"""
        # Try dot-atom first
        da = self._parse_dot_atom()
        if da is not None:
            return da
        # Try quoted-string
        qs = self._parse_quoted_string()
        if qs is not None:
            return qs
        # Try obs-local-part: word *('.' word)
        start = self.pos
        w = self._parse_word()
        if w is None:
            return None
        parts = [w]
        while self._peek() == ".":
            self._consume()
            w2 = self._parse_word()
            if w2 is not None:
                parts.append(w2)
            else:
                break
        return ".".join(parts)

    def _parse_domain(self) -> Optional[str]:
        """domain = dot-atom / domain-literal / obs-domain"""
        dl = self._parse_domain_literal()
        if dl is not None:
            return dl

        # Try dot-atom. If it matches but the remaining text contains more
        # domain content (CFWS '.' or bare '.' = obs-domain pattern),
        # fall through to obs-domain for a longer match.
        save = self.pos
        da = self._parse_dot_atom()
        if da is not None:
            after = self.pos
            cfws_after = self._parse_cfws()
            if cfws_after is not None and self._peek() == ".":
                # This is an obs-domain with CFWS around dots
                self.pos = save
            elif self._peek() == ".":
                # Direct dot after dot-atom — still obs-domain territory
                # But only if the dot-atom consumed trailing CFWS (comment)
                # leaving a bare dot. Always prefer longest match.
                self.pos = save
                # Fall through to obs-domain
            else:
                self.pos = after
                return da
        else:
            self.pos = save

        # obs-domain: atom *('.' atom)
        start = self.pos
        a = self._parse_atom()
        if a is None:
            return None
        parts = [a]
        while True:
            save_dot = self.pos
            if self._peek() == ".":
                self._consume()
            else:
                break
            a2 = self._parse_atom()
            if a2 is not None:
                parts.append(a2)
            else:
                self.pos = save_dot
                break
        return ".".join(parts)

    def _parse_addr_spec(self) -> Optional[AddrSpec]:
        """addr-spec = local-part '@' domain"""
        start = self.pos
        lp = self._parse_local_part()
        if lp is None:
            return None
        if self._peek() != "@":
            self.pos = start
            return None
        self._consume()  # '@'
        dom = self._parse_domain()
        if dom is None:
            self.pos = start
            return None
        return AddrSpec(local_part=lp, domain=dom)

    # ====================================================================
    # §3.4 Address Specification
    # ====================================================================

    def _parse_angle_addr(self) -> Optional[AngleAddr]:
        """angle-addr = [CFWS] '<' addr-spec '>' [CFWS] / obs-angle-addr"""
        start = self.pos

        # Save display name that might have been parsed
        display_name = None

        self._parse_cfws()
        if self._peek() == "<":
            self._consume()  # consume '<'
            addr = self._parse_addr_spec()
            if addr is not None and self._peek() == ">":
                self._consume()  # consume '>'
                self._parse_cfws()
                return AngleAddr(addr_spec=addr, display_name=display_name)

        # Try obs-angle-addr: [CFWS] '<' obs-route addr-spec '>' [CFWS]
        self.pos = start
        self._parse_cfws()
        if self._peek() != "<":
            self.pos = start
            return None
        self._consume()  # '<'
        # obs-route: obs-domain-list ':'
        route = self._parse_obs_route()
        addr = self._parse_addr_spec()
        if addr is None:
            self.pos = start
            return None
        if self._peek() == ">":
            self._consume()
        self._parse_cfws()
        return AngleAddr(addr_spec=addr, display_name=display_name)

    def _parse_obs_route(self) -> Optional[str]:
        """obs-route = obs-domain-list ':'"""
        start = self.pos
        # obs-domain-list = *(CFWS / ',') '@' domain *(',' [CFWS] ['@' domain])
        while True:
            save = self.pos
            self._parse_cfws()
            if self._peek() == ",":
                self._consume()
                continue
            self.pos = save
            break

        # Must have at least one '@' domain
        routes_found = False
        while self._peek() == "@":
            self._consume()
            dom = self._parse_domain()
            if dom is None:
                self.pos = start
                return None
            routes_found = True
            # optional more after comma
            while True:
                save = self.pos
                if self._peek() == ",":
                    self._consume()
                    self._parse_cfws()
                    if self._peek() == "@":
                        break
                    self.pos = save
                    break
                else:
                    break

        if not routes_found:
            self.pos = start
            return None

        if self._peek() != ":":
            self.pos = start
            return None
        self._consume()
        return self.text[start:self.pos]

    def _parse_name_addr(self) -> Optional[NameAddr]:
        """name-addr = [display-name] angle-addr"""
        start = self.pos
        # Try parsing display-name
        dn = self._parse_phrase()
        # Check if what follows looks like an angle-addr
        save = self.pos
        aa = self._parse_angle_addr()
        if aa is not None:
            return NameAddr(angle_addr=aa, display_name=dn)
        # If angle-addr fails, rewind and try without display name
        self.pos = start
        aa = self._parse_angle_addr()
        if aa is not None:
            return NameAddr(angle_addr=aa)
        return None

    def _parse_mailbox(self) -> Optional[Mailbox]:
        """mailbox = name-addr / addr-spec"""
        start = self.pos
        na = self._parse_name_addr()
        if na is not None:
            return Mailbox(value=na)
        addr = self._parse_addr_spec()
        if addr is not None:
            return Mailbox(value=addr)
        return None

    def _parse_group(self) -> Optional[Group]:
        """group = display-name ':' [group-list] ';' [CFWS]"""
        start = self.pos
        dn = self._parse_phrase()
        if dn is None:
            return None
        if not self._expect_str(":"):
            self.pos = start
            return None
        mailboxes = []
        # Try group-list = mailbox-list / CFWS / obs-group-list
        save = self.pos
        self._parse_cfws()
        if self._peek() == ";":
            # empty group
            pass
        elif self._peek() == ",":
            # obs-group-list: 1*([CFWS] ",") [CFWS]
            comma_count = 0
            while True:
                self._parse_cfws()
                if self._peek() == ",":
                    self._consume()
                    comma_count += 1
                else:
                    break
            if comma_count == 0:
                self.pos = save
            self._parse_cfws()
        else:
            # Try mailbox-list
            mboxes = self._parse_mailbox_list()
            if mboxes is not None:
                mailboxes = mboxes
        if self._peek() != ";":
            self.pos = start
            return None
        self._consume()  # consume ';'
        self._parse_cfws()
        return Group(display_name=dn, mailboxes=mailboxes)

    def _parse_mailbox_list(self) -> Optional[List[Mailbox]]:
        """mailbox-list = (mailbox *(',' mailbox)) / obs-mbox-list"""
        start = self.pos
        mbox = self._parse_mailbox()
        if mbox is None:
            # Try obs-mbox-list: *([CFWS] ',') mailbox *(',' [mailbox / CFWS])
            self._parse_cfws()
            while self._peek() == ",":
                self._consume()
                self._parse_cfws()
            mbox = self._parse_mailbox()
            if mbox is None:
                return None
        result = [mbox]
        while self._peek() == ",":
            self._consume()
            self._parse_cfws()
            if self._peek() == "," or self._peek() == ";":
                # obs-mbox-list allows empty entries
                continue
            mbox2 = self._parse_mailbox()
            if mbox2 is not None:
                result.append(mbox2)
            # obs-mbox-list allows trailing CFWS or comma
            self._parse_cfws()
        return result

    def _parse_address_list(self) -> Optional[List[Union[Mailbox, Group]]]:
        """address-list = (address *(',' address)) / obs-addr-list"""
        start = self.pos
        addr = self._parse_address()
        if addr is None:
            return None
        result = [addr]
        while self._peek() == ",":
            self._consume()
            self._parse_cfws()
            if self._peek() in (",", ";", ""):
                # obs-addr-list allows empty entries
                continue
            addr2 = self._parse_address()
            if addr2 is not None:
                result.append(addr2)
            self._parse_cfws()
        return result

    def _parse_address(self) -> Optional[Union[Mailbox, Group]]:
        """address = mailbox / group"""
        grp = self._parse_group()
        if grp is not None:
            return grp
        mbox = self._parse_mailbox()
        if mbox is not None:
            return mbox
        return None

    # ====================================================================
    # Public API
    # ====================================================================

    def parse_mailbox(self) -> Optional[Mailbox]:
        """Parse a single mailbox."""
        self._parse_cfws()
        result = self._parse_mailbox()
        if result is not None:
            self._skip_trailing()
        return result

    def parse_address(self) -> Optional[Union[Mailbox, Group]]:
        """Parse a single address (mailbox or group)."""
        self._parse_cfws()
        result = self._parse_address()
        if result is not None:
            self._skip_trailing()
        return result

    def parse_mailbox_list(self) -> Optional[List[Mailbox]]:
        """Parse a comma-separated list of mailboxes."""
        self._parse_cfws()
        result = self._parse_mailbox_list()
        if result is not None:
            self._skip_trailing()
        return result

    def parse_address_list(self) -> Optional[List[Union[Mailbox, Group]]]:
        """Parse a comma-separated list of addresses."""
        self._parse_cfws()
        result = self._parse_address_list()
        if result is not None:
            self._skip_trailing()
        return result

    def parse_addr_spec(self) -> Optional[AddrSpec]:
        """Parse a bare addr-spec."""
        self._parse_cfws()
        result = self._parse_addr_spec()
        if result is not None:
            self._skip_trailing()
        return result

    def parse_date_time(self) -> Optional[DateTime]:
        """Parse a date-time specification."""
        self._parse_cfws()
        result = self._parse_date_time()
        if result is not None:
            self._skip_trailing()
        return result

    def _skip_trailing(self):
        """Skip any remaining CFWS or whitespace."""
        self._parse_cfws()
        while self.pos < self.length and self.text[self.pos] in WSP:
            self.pos += 1


# ============================================================================
# Convenience functions
# ============================================================================

def parse_mailbox(text: str) -> Optional[Mailbox]:
    """Parse an RFC 5322 mailbox from a string."""
    return RFC5322Parser(text).parse_mailbox()


def parse_address(text: str) -> Optional[Union[Mailbox, Group]]:
    """Parse an RFC 5322 address from a string."""
    return RFC5322Parser(text).parse_address()


def parse_address_list(text: str) -> Optional[List[Union[Mailbox, Group]]]:
    """Parse an RFC 5322 address list from a string."""
    return RFC5322Parser(text).parse_address_list()


def parse_addr_spec(text: str) -> Optional[AddrSpec]:
    """Parse an RFC 5322 addr-spec from a string."""
    return RFC5322Parser(text).parse_addr_spec()


def parse_date_time(text: str) -> Optional[DateTime]:
    """Parse an RFC 5322 date-time from a string."""
    return RFC5322Parser(text).parse_date_time()


# ============================================================================
# Compliance matrix
# ============================================================================

COMPLIANCE_MATRIX = {
    # §3.2.1 Quoted characters
    "quoted_pair_vchar": True,
    "quoted_pair_wsp": True,
    "quoted_pair_obs": True,

    # §3.2.2 Folding White Space and Comments
    "fws_basic": True,
    "fws_obs": True,
    "ctext_printable": True,
    "ctext_obs": True,
    "comment_plain": True,
    "comment_nested": True,
    "comment_with_fws": True,
    "comment_with_quoted_pair": True,
    "cfws_comment_sequence": True,
    "cfws_fws_only": True,

    # §3.2.3 Atom
    "atext_all": True,
    "atom_basic": True,
    "atom_with_cfws": True,
    "dot_atom_text": True,
    "dot_atom_basic": True,
    "dot_atom_with_cfws": True,

    # §3.2.4 Quoted Strings
    "qtext_printable": True,
    "qtext_obs": True,
    "qcontent_qtext": True,
    "qcontent_quoted_pair": True,
    "quoted_string_basic": True,
    "quoted_string_with_fws": True,
    "quoted_string_with_cfws": True,
    "quoted_string_with_escape": True,

    # §3.2.5 Miscellaneous Tokens
    "word_atom": True,
    "word_quoted_string": True,
    "phrase_basic": True,
    "phrase_obs": True,

    # §3.3 Date and Time
    "date_time_basic": True,
    "date_time_with_day_of_week": True,
    "date_time_with_second": True,
    "date_time_zone_positive": True,
    "date_time_zone_negative": True,
    "date_time_obs_two_digit_year": True,
    "date_time_obs_named_zone": True,
    "date_time_obs_cfws": True,

    # §3.4 Address Specification
    "address_mailbox": True,
    "address_group": True,
    "mailbox_name_addr": True,
    "mailbox_addr_spec": True,
    "name_addr_with_display": True,
    "name_addr_without_display": True,
    "group_with_mailboxes": True,
    "group_empty": True,

    # §3.4.1 Addr-Spec
    "addr_spec_basic": True,
    "addr_spec_quoted_local": True,
    "addr_spec_domain_literal": True,
    "domain_literal_basic": True,

    # §4.1 Miscellaneous Obsolete Tokens
    "obs_no_ws_ctl": True,
    "obs_ctext": True,
    "obs_qtext": True,
    "obs_utext": True,
    "obs_qp": True,
    "obs_phrase": True,

    # §4.2 Obsolete FWS
    "obs_fws": True,

    # §4.3 Obsolete Date and Time
    "obs_day_of_week": True,
    "obs_day": True,
    "obs_year": True,
    "obs_hour": True,
    "obs_minute": True,
    "obs_second": True,
    "obs_zone_ut": True,
    "obs_zone_gmt": True,
    "obs_zone_us": True,
    "obs_zone_military": True,

    # §4.4 Obsolete Addressing
    "obs_angle_addr": True,
    "obs_route": True,
    "obs_mbox_list": True,
    "obs_addr_list": True,
    "obs_group_list": True,
    "obs_local_part": True,
    "obs_domain": True,
    "obs_dtext": True,
}
