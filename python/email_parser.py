import re
from typing import Optional, List, Tuple

class EmailAddress:
    def __init__(self, local_part: str, domain: str):
        self.local_part = local_part
        self.domain = domain
    
    def __str__(self) -> str:
        return f"{self.local_part}@{self.domain}"
    
    def __repr__(self) -> str:
        return f"EmailAddress({self.local_part!r}, {self.domain!r})"

class ParseError(ValueError):
    pass

ATExt = r'[a-zA-Z0-9!#$%&\'*+\-/=?^_`{|}~]'
DotAtom = rf'({ATExt}+(\.{ATExt}+)*)'
QuotedString = r'"(?:[^"\\]|\\.)*"'
LocalPart = rf'({DotAtom}|{QuotedString})'
DomainLabel = r'[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
Domain = rf'({DomainLabel}(\.{DomainLabel})*)'
Address = rf'^{LocalPart}@{Domain}$'

_EMAIL_RE = re.compile(Address)

def parse_address(raw: str) -> EmailAddress:
    raw = raw.strip()
    m = _EMAIL_RE.match(raw)
    if not m:
        raise ParseError(f"Invalid email address: {raw!r}")
    local_raw = m.group(1)
    domain_raw = m.group(7)
    if local_raw.startswith('"') and local_raw.endswith('"'):
        local = _unescape_quoted(local_raw[1:-1])
    else:
        local = local_raw
    return EmailAddress(local, domain_raw.lower())

def _unescape_quoted(s: str) -> str:
    return re.sub(r'\\(.)', r'\1', s)

def validate_address(raw: str) -> bool:
    try:
        parse_address(raw)
        return True
    except ParseError:
        return False
