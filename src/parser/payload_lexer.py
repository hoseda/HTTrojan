# # payload lexer code here
import struct
import sys
import time
import itertools
import os


opcode = {
    '00' : 'NOP',
    '01' : 'READ',
    '10' : 'WRITE',
    '11' : 'SYNC',
}

MajorMinors = {
    # column : max minors per column
    0 : 36,
    1 : 36,
    2 : 36,
    3 : 30,
    4 : 36,
    5 : 28,
    6 : 36,
    7 : 54,
    8 : 36,
    9 : 30,
    10 : 36,
    11 : 28,
    12 : 36,
    13 : 54,
    14 : 36,
}

Blocks = {
    0 : 'CLB',
    1 : 'BRAM',
    3 : 'DSP',
    4 : 'IO',
}

Blocks_Majors = {
    'CLB'   : [0,1,2,4,6,8,10,12,14],
    'BRAM'  : [3,9],
    'DSP'   : [5,11],
    'IO'    : [7,13],
}


class Packet:
    pass

class FAR(Packet):
    """
    --> Type 1 Packet
    """
    def __init__(self , opcode , reg_address , word_count , value):
        self.opcode = opcode
        self.reg_address = reg_address
        self.word_count = word_count
        self.value = value
    
    def __repr__(self):
        return f"FAR(OpCode:[{self.opcode}] , REG_ADDR:[{self.reg_address}] , WC:[{self.word_count}] , Value:[0x{''.join(format(b,'02X') for b in self.value)}])"


class FDRI(Packet):
    """
    --> Type 2 Packet
    """
    def __init__(self , opcode , word_count , payload):
        self.opcode = opcode
        self.word_count = word_count
        self.payload = payload
    
    def __repr__(self):
        return f"FDRI(OpCode:[{self.opcode}] , WC:[{self.word_count}] , Frames:[{len(self.payload)}])"

class FrameObj:
    def __init__(self, far_raw , block_type , top_bottom , column , major, minor ,data_words , idx):
        self.far_raw = far_raw
        self.block_type = block_type
        self.top_bottom = top_bottom
        self.column = column
        self.major = major
        self.minor = minor
        self.data_words = data_words
        self.idx = idx

    def __repr__(self):
        return f"FrameObj(FAR:[{self.far_raw}] , Block:[{self.block_type}], TopBottom:[{self.top_bottom}] , Column:[{self.column}] , Minor:[{self.minor}] FrameIdx:[{self.idx}])"


class FrameLexer:
    def __init__(self, payload):
        self.payload = memoryview(payload)
        self.toks = []
        self.frames = {}
        self.result = []
        self.pos = 0
        self.last_far = None
        self.enable_progress = os.environ.get("LEXER_PROGRESS", "").lower() in {"1", "true", "yes"}

    
    def _eof(self):
        return self.pos >= len(self.payload)

    def peek(self,width=4):
        if self.pos+width <= len(self.payload):
            return self.payload[self.pos:self.pos+width]
        return None

    def advance(self,width=4):
        if self.pos+width <= len(self.payload):
            res = self.payload[self.pos:self.pos+width]
            self.pos += width
            return res
        return None
    
    def nextPacket(self, width=4):
        return self.advance(width)
    
    def max_minor(self , column):
        return MajorMinors.get(column,-1)
    
    def last_major_block(self , block_code):
        block_name = Blocks.get(block_code)
        if block_name:
            return Blocks_Majors[block_name][-1]
        return float('-inf')
    
    def first_major_block(self , block_code):
        block_name = Blocks.get(block_code)
        if block_name:
            return Blocks_Majors[block_name][0]
        return float('-inf')
    
    def pack_far(self,block:int,top_bottom:int,column:int,minor:int) -> int:
        # major(6bits) = (top_bottom << 5) | column(5bits)
        major = ((top_bottom & 0x1) << 5) | (column & 0x1F)
        far_int = ((block & 0x7) << 29 | (major & 0x3F) << 23 | (minor & 0x3F) << 17)
        return far_int
    
    def interpret_far(self,far:bytes):
        if far is None:
            raise ValueError("interpreter_far received None as FAR Value.")
        
        if isinstance(far , memoryview):
            far = far.tobytes()
        elif not isinstance(far,bytes):
            raise TypeError(f"interpreter_far expects bytes-like, got {type(far)}")
        
        far_hex = int.from_bytes(far,'big')
        block = (far_hex >> 29) & 0b111 # 31-29 block type
        major= (far_hex >> 23) & 0b11_1111 # 28-23 major
        top_bottom = (major >> 5) & 0b1 # 0 top , 1 bottom
        column = major & 0b11111 # 5 lover bits of major
        minor = (far_hex >> 17) & 0b11_1111 # 6 bits
        # 16-0 are reserved always 0

        return [block ,top_bottom , column , major , minor]
    

    def do_lexing(self , packet , width):
        if packet is None or len(packet) < width:
            return None
        
        if isinstance(packet , memoryview):
            packet = packet.tobytes()
        
        hdr =  struct.unpack(">I",packet)[0]
        _type = (hdr >> 29) & 0x7
        _op = (hdr >> 27) & 0x3
        op = opcode.get(f"{_op:02b}")
        if _type == 0b001:
            reg_address = (hdr >> 13) & 0xFFFF
            word_count = hdr & 0x1FFF         
            if op == "WRITE" and word_count == 1:
                value = self.nextPacket(width)
                return FAR(op , f"{reg_address:014b}" , f"{word_count:013b}",value)
            
        elif _type == 0b010:
            word_count = hdr & 0x1FFFFFF
            n = int(word_count)
            frame_size = 41
            _payload = []              
            
            for _ in range(n):
                word = self.nextPacket(width)
                if word is None:
                    break
                _payload.append(word)

            temp = []
            for i in range(0,len(_payload) , frame_size):
                temp.append(_payload[i:i+frame_size])
            
            return FDRI(op,f"{word_count:b}" , temp)
        
        return None
    
    def _render_progress(self, current: int, total: int, force: bool = False, finalize_only: bool = False) -> None:
        if not self.enable_progress:
            return
        if not hasattr(self, '_progress_state'):
            self._progress_state = {
                'spinner': itertools.cycle('|/-\\'),
                'last_time': 0.0,
                'enabled': sys.stdout.isatty(),
                'active': False,
                'total': 0,
            }
        state = self._progress_state
        if finalize_only:
            if state.get('active'):
                sys.stdout.write('\n')
                sys.stdout.flush()
                state['active'] = False
            return
        state['total'] = total
        if not state['enabled'] or total <= 0:
            return
        now = time.time()
        if not state['active']:
            state['active'] = True
            state['last_time'] = 0.0
        if not force and current < total and (now - state['last_time']) < 0.05:
            return
        percent = current / total if total else 1.0
        bar_length = 30
        filled = min(bar_length, int(bar_length * percent))
        bar = '█' * filled + '░' * (bar_length - filled)
        spinner = next(state['spinner'])
        sys.stdout.write(f"\r[{bar}] {percent*100:6.2f}% {spinner}")
        sys.stdout.flush()
        state['last_time'] = now
        if current >= total:
            sys.stdout.write('\n')
            sys.stdout.flush()
            state['active'] = False
    
    def generate_frames(self , start_fields , payload_frames , start_idx=0):
        block , top_bottom , column , major , minor = start_fields
        block = int(block)
        top_bottom = int(top_bottom)
        column = int(column)
        minor = int(minor)
        total_needed = len(payload_frames)
        created = 0

        def block_name_for(code):
            return Blocks.get(code,None)
        
        def next_block_code(code):
            condidate = code + 1
            for _ in range(10):
                if Blocks.get(  condidate) is not None:
                    return condidate
                condidate += 1
            return None
        
        def major_list_for_block(code):
            name = block_name_for(code)
            if name is None:
                return None
            return Blocks_Majors[name]
        
        major_list = major_list_for_block(block)
        if major_list is None:
            raise ValueError(f"Unknows starting block code {block}")
        
        try:
            maj_idx = major_list.index(column)
        except ValueError:
            maj_idx = 0
            column = major_list[0]
        
        max_iter = total_needed * 4 + 1000

        while created < total_needed and max_iter > 0:
            max_iter -= 1

            far_int = self.pack_far(block,top_bottom,column,minor)
            far_hex = f"{far_int:08X}"
            chunk = payload_frames[created]
            major = ((top_bottom << 5) | (column & 0x1F))
            frame = FrameObj(far_hex,block,top_bottom,column,major,minor,chunk,start_idx+created)
            self.result.append(frame)
            created += 1
            self._render_progress(created, total_needed)

            next_minor = minor + 1
            max_m = self.max_minor(column)

            if max_m == -1:
                raise ValueError(f"Unknows max minor for column {column} (block {block})")
            
            if next_minor < max_m:
                minor = next_minor
                continue

            minor = 0

            maj_idx += 1
            if maj_idx < len(major_list): # pyright: ignore[reportArgumentType]
                column = major_list[maj_idx] # pyright: ignore[reportOptionalSubscript]
                major = column

                continue

            next_block = next_block_code(block)
            if next_block is None:
                top_bottom ^= 1
                min_block_code = min(Blocks.keys())
                block = min_block_code
                major_list = major_list_for_block(block)
                maj_idx = 0
                column = major_list[maj_idx] # pyright: ignore[reportOptionalSubscript]
                major = column
                minor = 0
                continue

            block = next_block
            major_list = major_list_for_block(block)
            if major_list is None:
                raise ValueError(f"No major list for block {block}")
            
            maj_idx = 0
            column = major_list[maj_idx]
            minor = 0


        if created != total_needed:
            raise RuntimeError(f"Could not generate requied frames: created {created}, expected {total_needed}")

        self._render_progress(total_needed, total_needed, force=True)
        return created 


    def lexer(self ,width=4) -> list[Packet]:
        while self.pos + width <= len(self.payload):
            packet = self.advance(width)
            res = self.do_lexing(packet,width)

            if res:
                self.toks.append(res)
                if isinstance(res,FAR):
                    far_bytes = res.value
                    far_tuple = self.interpret_far(far_bytes) # type: ignore
                    self.last_far = far_tuple

                if isinstance(res,FDRI):
                    if self.last_far is None:
                        raise ValueError("FDRI encountered before any FAR (Bitstream malformed.)")
                    
                    start_fields = self.last_far
                    payload_frames = res.payload
                    start_idx = len(self.result)
                    created = self.generate_frames(start_fields,payload_frames,start_idx)
                    expected = len(payload_frames)

                    if created != expected:
                        print(f"Warning: created {created} frames but expected {expected} frames for this FDRI (start FAR={start_fields})")
        self._render_progress(0, 0, finalize_only=True)
        return self.result