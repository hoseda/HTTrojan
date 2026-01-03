# here is the code of bitstream loder file (.bit)

from typing import Tuple , Optional
from src.parser.header_lexer import Header , HeaderLexer
from src.parser.payload_lexer import FrameLexer

class BitStreamObj:
    def __init__(self, header , config_data , cheksum):
        self.header = header
        self.config_data = config_data
        self.cheksum = cheksum

    def __repr__(self):
        return f"BitStream [Header:[{self.header} , Config:[{self.config_data}]]"

class Parser:
    def __init__(self, src):
        self.src = src
        self.head = None
        self.config :list = []

    def readBinaryFile(self,filepath:str) -> bytes:
        with open(filepath , 'rb') as f:
            return f.read()

    def print_hexdump(self,data,width=16):
        for off in range(0,len(data),width):
            chunk = data[off:off+width]
            hex_byte = " ".join(f"{b:02X}" for b in chunk)
            pad = (width - len(data)) * 3
            ascii_repr = "".join((chr(b)if 32 <= b < 127 else ".") for b in chunk)
            print(f"{off:08X} {hex_byte}{' '* pad} |{ascii_repr}|")

    def split_on_marker(
            self,
            filepath:str , 
            marker:bytes = b"\xAA\x99\x55\x66", 
            which:str ="first" , 
            keep_marker:bool = False , 
            decode_header_as:str = 'ascii'
            ) -> Tuple[bytes,bytes,Optional[int]]:
        
        if which not in ("first","last"):
            raise ValueError("which most be 'first' or 'last'")

        data = self.readBinaryFile(filepath)
        idx = data.find(marker) if which == "first" else data.rfind(marker)
        if idx == -1:
            payload = data
            return (b"" , payload , None)

        head = data[:idx]
        payload = data[idx:] if keep_marker else data[idx + len(marker) :]

        return (head , payload , idx)

    def parse_header(self , header):
        """
        Header Pattern : (0x00 | 0x01) TAG 0x00 LEN
        """

        header_tokens = HeaderLexer(header).lexer()
        self.head = Header()
        for tok in header_tokens:
            match chr(tok.tag):
                case 'a':
                    self.head.design_name = tok
                case 'b':
                    self.head.device_name = tok
                case 'c':
                    self.head.build_date = tok
                case 'd':
                    self.head.build_time = tok
                case 'e':
                    self.head.meta = tok
        

    def parse_payload(self , payload):
        a = FrameLexer(payload)
        res = a.lexer()
        self.config = res

    def parse(self):
        header , payload , idx = self.split_on_marker(self.src)
        
        # header
        self.parse_header(header)

        # payload
        self.parse_payload(payload)
        
        return [self.head,self.config]

# p = Parser("/home/hoseda/Documents/Work/Python/HTTrojan/verilog/test1/xor3.bit")
# p.parse()
