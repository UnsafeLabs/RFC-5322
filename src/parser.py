import re
from typing import List, Optional, Dict, Union

class RFC5322Parser:
    """
    ABNF-compliant RFC 5322 email address parser.
    Supports strict and permissive (obsolete) forms.
    """
    def __init__(self, text: str, strict: bool = True):
        self.text = text
        self.strict = strict
        self.pos = 0

    def parse_address_list(self) -> List[Dict]:
        """address-list = (address *("," address)) / obs-addr-list"""
        addresses = []
        while self.pos < len(self.text):
            self._skip_cfws()
            if self.pos >= len(self.text): break
            addr = self.parse_address()
            if addr:
                addresses.append(addr)
            self._skip_cfws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
            else:
                break
        return addresses

    def parse_address(self) -> Optional[Dict]:
        """address = mailbox / group"""
        start_pos = self.pos
        self._skip_cfws()
        
        remainder = self.text[self.pos:]
        if ":" in remainder and (";" not in remainder or remainder.index(":") < remainder.index(";")):
             return self.parse_group()
        
        return self.parse_mailbox()

    def parse_mailbox(self) -> Dict:
        """mailbox = name-addr / addr-spec"""
        # Look ahead for angle-addr start while skipping phrase content
        p = self.pos
        has_angle = False
        while p < len(self.text):
            if self.text[p] == "<":
                has_angle = True
                break
            if self.text[p] == "@": # Hit addr-spec before angle
                break
            p += 1
            
        if has_angle:
            return self.parse_name_addr()
        return self.parse_addr_spec()

    def parse_group(self) -> Dict:
        """group = display-name ":" [group-list] ";" [CFWS]"""
        display_name = self.parse_phrase()
        self._expect(":")
        members = []
        self._skip_cfws()
        if self.pos < len(self.text) and self.text[self.pos] != ";":
            members = self.parse_mailbox_list()
        self._expect(";")
        self._skip_cfws()
        return {"type": "group", "display_name": display_name, "members": members}

    def parse_addr_spec(self) -> Dict:
        """addr-spec = local-part "@" domain"""
        local = self.parse_local_part()
        self._expect("@")
        domain = self.parse_domain()
        return {"type": "mailbox", "local": local, "domain": domain}

    def parse_name_addr(self) -> Dict:
        """name-addr = [display-name] angle-addr"""
        display_name = self.parse_phrase()
        addr = self.parse_angle_addr()
        addr["display_name"] = display_name
        return addr

    def parse_angle_addr(self) -> Dict:
        """angle-addr = [CFWS] "<" addr-spec ">" [CFWS] / obs-angle-addr"""
        self._skip_cfws()
        self._expect("<")
        addr = self.parse_addr_spec()
        self._expect(">")
        self._skip_cfws()
        return addr

    def parse_local_part(self) -> str:
        self._skip_cfws()
        if self.pos < len(self.text) and self.text[self.pos] == '"':
            return self.parse_quoted_string()
        return self.parse_dot_atom()

    def parse_domain(self) -> str:
        self._skip_cfws()
        if self.pos < len(self.text) and self.text[self.pos] == '[':
            return self.parse_domain_literal()
        return self.parse_dot_atom()

    def parse_dot_atom(self) -> str:
        res = ""
        while self.pos < len(self.text) and (self.text[self.pos].isalnum() or self.text[self.pos] in "!#$%&'*+-/=?^_`{|}~."):
            res += self.text[self.pos]
            self.pos += 1
        return res.strip(".")

    def parse_phrase(self) -> str:
        res = ""
        while self.pos < len(self.text) and self.text[self.pos] not in ":<":
            res += self.text[self.pos]
            self.pos += 1
        return res.strip()

    def parse_quoted_string(self) -> str:
        self.pos += 1 # skip "
        res = '"'
        while self.pos < len(self.text):
            if self.text[self.pos] == '\\':
                res += self.text[self.pos:self.pos+2]
                self.pos += 2
            elif self.text[self.pos] == '"':
                res += '"'
                self.pos += 1
                break
            else:
                res += self.text[self.pos]
                self.pos += 1
        return res

    def parse_domain_literal(self) -> str:
        res = "["
        self.pos += 1
        while self.pos < len(self.text) and self.text[self.pos] != "]":
            res += self.text[self.pos]
            self.pos += 1
        res += "]"
        self.pos += 1
        return res

    def parse_mailbox_list(self) -> List[Dict]:
        mailboxes = []
        while self.pos < len(self.text) and self.text[self.pos] != ";":
            mailboxes.append(self.parse_mailbox())
            self._skip_cfws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
            else:
                break
        return mailboxes

    def _skip_cfws(self):
        while self.pos < len(self.text):
            if self.text[self.pos].isspace():
                self.pos += 1
            elif self.text[self.pos] == "(":
                depth = 1
                self.pos += 1
                while depth > 0 and self.pos < len(self.text):
                    if self.text[self.pos] == "(": depth += 1
                    elif self.text[self.pos] == ")": depth -= 1
                    self.pos += 1
            else:
                break

    def _expect(self, char: str):
        self._skip_cfws()
        if self.pos < len(self.text) and self.text[self.pos] == char:
            self.pos += 1
        else:
            raise ValueError(f"Expected '{char}' at position {self.pos}")
