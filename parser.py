import string

class RFC5322Address:
    def __init__(self, display_name, address, is_group=False, group_list=None):
        self.display_name = display_name
        self.address = address
        self.is_group = is_group
        self.group_list = group_list or []
    def __repr__(self):
        return f"RFC5322Address(display_name={self.display_name!r}, address={self.address!r}, is_group={self.is_group}, group_list={self.group_list!r})"

class ParseError(ValueError):
    pass

class AddressParser:
    def __init__(self, strict=True):
        self.strict = strict
    def parse(self, text):
        self.text = text
        self.pos = 0
        addresses = self._parse_address_list()
        self._skip_cfws()
        if self.pos < len(self.text):
            raise ParseError(f"Unexpected trailing characters at {self.pos}")
        return addresses
    def _peek(self):
        return self.text[self.pos] if self.pos < len(self.text) else ""
    def _skip_cfws(self):
        while True:
            c = self._peek()
            if c and c in ' \t\r\n':
                self.pos += 1
            elif c == '(':
                self._parse_comment()
            else:
                break
    def _parse_comment(self):
        self.pos += 1
        depth = 1
        while depth > 0 and self.pos < len(self.text):
            c = self.text[self.pos]
            if c == '(':
                depth += 1
                self.pos += 1
            elif c == ')':
                depth -= 1
                self.pos += 1
            elif c == '\\':
                self.pos += 2
            else:
                self.pos += 1
        if depth > 0:
            raise ParseError("Unclosed comment")
    def _parse_address_list(self):
        addrs = []
        while self.pos < len(self.text):
            self._skip_cfws()
            if not self._peek(): break
            if self._peek() == ',':
                if self.strict: raise ParseError("Empty address")
                self.pos += 1
                continue
            addr = self._parse_address()
            if addr: addrs.append(addr)
            self._skip_cfws()
            if self._peek() == ',':
                self.pos += 1
            elif self._peek():
                raise ParseError(f"Expected comma, got {self._peek()}")
        return addrs
    def _parse_address(self):
        saved_pos = self.pos
        phrase = self._parse_phrase()
        self._skip_cfws()
        c = self._peek()
        if c == ':':
            self.pos += 1
            group_list = self._parse_group_list()
            self._skip_cfws()
            if self._peek() != ';': raise ParseError("Expected ';'")
            self.pos += 1
            return RFC5322Address(display_name=phrase, address=None, is_group=True, group_list=group_list)
        elif c == '<':
            self.pos += 1
            self._skip_cfws()
            addr_spec = self._parse_addr_spec()
            self._skip_cfws()
            if self._peek() != '>': raise ParseError("Expected '>'")
            self.pos += 1
            return RFC5322Address(display_name=phrase if phrase else None, address=addr_spec)
        else:
            self.pos = saved_pos
            addr_spec = self._parse_addr_spec()
            return RFC5322Address(display_name=None, address=addr_spec)
    def _parse_group_list(self):
        self._skip_cfws()
        if self._peek() == ';': return []
        addrs = []
        while self.pos < len(self.text):
            self._skip_cfws()
            if self._peek() == ';': break
            if self._peek() == ',':
                if self.strict: raise ParseError("Empty address in group")
                self.pos += 1
                continue
            addr = self._parse_address()
            if addr: addrs.append(addr)
            self._skip_cfws()
            if self._peek() == ',':
                self.pos += 1
            elif self._peek() != ';':
                raise ParseError(f"Expected ',' or ';', got {self._peek()}")
        return addrs
    def _parse_phrase(self):
        words = []
        while self.pos < len(self.text):
            self._skip_cfws()
            w = self._parse_word()
            if w: words.append(w)
            else: break
        return " ".join(words) if words else None
    def _parse_word(self):
        c = self._peek()
        if c == '"':
            return self._parse_quoted_string()
        elif c and c not in ' \t\r\n()<>[];:@,."\\':
            return self._parse_atom()
        elif c == '\\':
            self.pos += 1
            char = self._peek()
            self.pos += 1
            return char
        return None
    def _parse_atom(self):
        res = []
        while self.pos < len(self.text):
            c = self.text[self.pos]
            if c == '\\':
                self.pos += 1
                res.append(self.text[self.pos])
                self.pos += 1
            elif c and c in ' \t\r\n()<>[];:@,."\\': break
            else:
                res.append(c)
                self.pos += 1
        return "".join(res)
    def _parse_quoted_string(self):
        self.pos += 1
        res = []
        while self.pos < len(self.text):
            c = self.text[self.pos]
            if c == '"':
                self.pos += 1
                break
            elif c == '\\':
                self.pos += 1
                if self.pos < len(self.text):
                    res.append(self.text[self.pos])
                    self.pos += 1
            else:
                res.append(c)
                self.pos += 1
        return "".join(res)
    def _parse_addr_spec(self):
        local = self._parse_local_part()
        self._skip_cfws()
        if self._peek() != '@': raise ParseError("Expected '@'")
        self.pos += 1
        domain = self._parse_domain()
        return f"{local}@{domain}"
    def _parse_local_part(self):
        self._skip_cfws()
        if self._peek() == '"':
            return f'"{self._parse_quoted_string()}"'
        else:
            res = []
            while self.pos < len(self.text):
                c = self.text[self.pos]
                if c == '\\':
                    self.pos += 1
                    res.append(self.text[self.pos])
                    self.pos += 1
                elif c and c in ' \t\r\n()<>[];:@,"\\': break
                else:
                    res.append(c)
                    self.pos += 1
            return "".join(res)
    def _parse_domain(self):
        self._skip_cfws()
        if self._peek() == '[':
            return self._parse_domain_literal()
        else:
            res = []
            while self.pos < len(self.text):
                c = self.text[self.pos]
                if c == '\\':
                    self.pos += 1
                    res.append(self.text[self.pos])
                    self.pos += 1
                elif c and c in ' \t\r\n()<>[];:@,"\\': break
                else:
                    res.append(c)
                    self.pos += 1
            return "".join(res)
    def _parse_domain_literal(self):
        self.pos += 1
        res = ['[']
        while self.pos < len(self.text):
            c = self.text[self.pos]
            if c == ']':
                res.append(']')
                self.pos += 1
                break
            elif c == '\\':
                self.pos += 1
                if self.pos < len(self.text):
                    res.append(self.text[self.pos])
                    self.pos += 1
            else:
                res.append(c)
                self.pos += 1
        return "".join(res)
