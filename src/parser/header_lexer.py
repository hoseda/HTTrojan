class Header:
    def __init__(self, design_name=None , device_name=None , build_date=None , build_time=None , meta=None):
        self.design_name = design_name
        self.device_name = device_name
        self.build_date = build_date
        self.build_time = build_time
        self.meta = meta

    def __repr__(self):
        return f"""
        Header(
            DesignName:[{self.design_name}] ,
            DeviceName:[{self.device_name}] ,
            BuildDate:[{self.build_date}] ,
            BuildTime:[{self.build_time}] ,
            Meta:[{self.meta}] ,
        )
        """


class HeaderToken:
    def __init__(self, prefix:bytes , tag:bytes , length:bytes , value):
        self.prefix = prefix
        self.tag = tag
        self.length = length
        self.value = value

    def __repr__(self):
        return f"HeaderToken(Prefix:[{self.prefix} , TAG:[{chr(self.tag)}] , LEN:[{self.length}] , Value:[{self.value}])"
    



class HeaderLexer:
    def __init__(self, header):
        self.header = header
        self.toks = []
        self.start = 0
        self.pos = 0

    def peek(self):
        if self.pos < len(self.header):
            c = self.header[self.pos]
            return c

    def advance(self):
        if self.pos < len(self.header):
            c =  self.header[self.pos]
            self.pos += 1
            return c

    def do_lexing(self):
        c = self.advance()
        if c in (0x00 , 0x01):
            prefix = c
        if self.peek() in [0x61 , 0x62 , 0x63 , 0x64 , 0x65]:
            tag = self.advance()
            if self.peek() == 0x00:
                self.pos +=1
                length = self.advance()
                value = self.header[self.pos:(self.pos + length-1)]
                return HeaderToken(prefix , tag , length , value)
    
    def lexer(self):
        while self.pos < len(self.header):
            tok = self.do_lexing()
            if tok:
                self.toks.append(tok)
        return self.toks
