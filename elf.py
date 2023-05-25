#!/bin/python3

def print_byte_section(b: bytes, pos: int = 0) -> ():
    def print_char(b: int) -> ():
        c = chr(b)
        if c.isprintable() and c != " ":
            print(c, end="")
        else:
            print(".", end="")
    def print_line_text(b: bytes) -> ():
        for i in range(min(16, len(b))):
            print_char(b[i])
    def print_line(b: bytes, pos: int) -> (bytes, int):
        print(f" {pos:06x} ", end="")
        for i in range(16):
            if i < len(b):
                print(f"{b[i]:02x}", end="")
            else:
                print("  ", end="")
            if i%4 == 3:
                print(" ", end="")
        print("  ", end="")
        print_line_text(b)
        print()
        if len(b) < 16:
            return b'', pos
        return b[16:], pos + 16
    while len(b):
        b, pos = print_line(b, pos)

class FileIdent:
    def __init__(self, b: bytes):
        magic = b[0:4]
        if magic != b'\x7fELF':
            print("Error magic numbers")
            sys.exit(1)
        class_ = b[4]
        if class_ not in (1, 2):
            print("Wrong file class")
            sys.exit(1)
        else:
            self.class_ = [32, 64][class_-1]
        data = b[5]
        if data not in (1, 2):
            print("Wrong data encoding")
            sys.exit(1)
        else:
            self.data = ["lsb", "msb"][data-1]
        if b[6] != 1:
            print("Wrong file version")
            sys.exit(1)
        self.osabi = (["unspecified"]+["some"]*255)[b[7]]
        self.abiversion = b[8]

def readBytes(b: bytes, size: int, pos: int, typ: FileIdent):
    if size == 8 and typ.class_ == 32:
        size = 4
    if pos < 0 or pos > len(b) - size:
        print(f"invalid read of size {size} at offset {pos}")
        sys.exit(1)
    bs = b[pos:pos+size]
    if typ.data == "lsb":
        bs = bs[::-1]
    n = 0
    for bt in bs:
        n *= 256
        n += bt
    return n, pos + size

class Header:
    def __init__(self, b: bytes):
        t = self.e_ident = FileIdent(b)
        off = 16
        self.e_type, off = readBytes(b, 2, off, t)
        self.e_machine, off = readBytes(b, 2, off, t)
        self.e_version, off = readBytes(b, 4, off, t)
        self.e_entry, off = readBytes(b, 8, off, t)
        self.e_phoff, off = readBytes(b, 8, off, t)
        self.e_shoff, off = readBytes(b, 8, off, t)
        self.e_flags, off = readBytes(b, 4, off, t)
        self.e_ehsize, off = readBytes(b, 2, off, t)
        self.e_phentsize, off = readBytes(b, 2, off, t)
        self.e_phnum, off = readBytes(b, 2, off, t)
        self.e_shentsize, off = readBytes(b, 2, off, t)
        self.e_shnum, off = readBytes(b, 2, off, t)
        self.e_shstrndx, off = readBytes(b, 2, off, t)
        if off != self.e_ehsize:
            print("invalid header size")
            sys.exit(1)

SHNAMESECTION = b''
SHSYMNAMESECTION = b''

def get_sh_name(i: int) -> str:
    if SHNAMESECTION == b'':
        return f"name@{i}"
    n = SHNAMESECTION[i:]
    name = ""
    while n[0]:
        name += chr(n[0])
        n=n[1:]
    return name

def get_sym_name(i: int) -> str:
    if SHSYMNAMESECTION == b'':
        return f"name@{i}"
    n = SHSYMNAMESECTION[i:]
    name = ""
    while n[0]:
        name += chr(n[0])
        n=n[1:]
    return name

class PhTable:
    def __init__(self, b: bytes, entsize: int, num: int):
        pass

class SectionHeader:
    def __init__(self, b: bytes, _: int, t: FileIdent):
        off = 0
        self.name, off = readBytes(b, 4, off, t)
        self.typ, off = readBytes(b, 4, off, t)
        self.flags, off = readBytes(b, 8, off, t)
        self.addr, off = readBytes(b, 8, off, t)
        self.offset, off = readBytes(b, 8, off, t)
        self.size, off = readBytes(b, 8, off, t)
        self.link, off = readBytes(b, 4, off, t)
        self.info, off = readBytes(b, 4, off, t)
        self.addralign, off = readBytes(b, 8, off, t)
        self.entsize, off = readBytes(b, 8, off, t)

    def __str__(self) -> str:
        return f"{get_sh_name(self.name)}: {self.typ}, {self.offset} :: {self.size}"

    def empty(self) -> bool:
        return not (self.name or self.typ or self.flags or self.addr or\
            self.offset or self.size or self.link or self.info or self.addralign\
            or self.entsize)

def shtable(b: bytes, entsize: int, num: int, t: FileIdent):
    arr = []
    for i in range(0,entsize*num,entsize):
        arr.append(SectionHeader(b[i:], entsize, t))
    return arr

def disassm(b: bytes, s: int, t: FileIdent, symboles = None):
    def reg(p: int, s: int = 8) -> str:
        pref = ""
        end = ""
        if s == 4:
            pref = "e"
        if s == 8:
            pref = "r"
        if p == 0:
            end = "ax"
        if p == 1:
            end = "cx"
        if p == 2:
            end = "dx"
        if p == 3:
            end = "bx"
        if p == 4:
            end = "sp"
        if p == 5:
            end = "bp"
        if p == 6:
            end = "si"
        if p == 7:
            end = "di"
        return f"%{pref}{end}"

    def disasmStep(b: bytes, pos: int):
        for s in symboles:
            if s.value == pos:
                print("\n"+get_sym_name(s.name)+":")
        if len(b) == 0:
            return

        mode = 4
        if b[0] == 0x66:
            mode = 2
            b = b[1:]
            pos+=1
        elif b[0] == 0x48:
            mode = 8
            b = b[1:]
            pos+=1

        if b[0] == 0xc3:
            print("  ret")
            disasmStep(b[1:], pos+1)
        elif b[0] >> 4 == 5:
            param = b[0] & 0xf
            if param < 8:
                print(f"  push {reg(param,8)}")
            else:
                print(f"  pop {reg(param-8,8)}")
            disasmStep(b[1:], pos+1)
        elif b[0] == 0x89:
            params = b[1]
            p1 = params&7
            p2 = (params>>3)&7
            print(f"  mov {reg(p2, mode)}, {reg(p1, mode)}")
            disasmStep(b[2:], pos+2)
        elif b[0] >> 3 == 0b10111:
            param = b[0]&3
            val, end = readBytes(b, mode, 1, t)
            print(f"  mov 0x{val:x}, {reg(param, mode)}")
            disasmStep(b[end:], pos+end)
        else:
            print(f"  {b[0]:02X}", end="")
            disasmStep(b[1:], pos+1)

    b = b[:s]
    disasmStep(b, shByName(".text").offset)
    print()

sht = []

class Symbol:
    def __init__(self, name, info, other, shndx, value, size):
        self.name = name
        self.value = value
        self.size = size
        self.info = info
        self.other = other
        self.shndx = shndx
    def infostr(self):
        typ = self.info & 0xf
        typ = (["notype","object","func","section","file","common","tls"] +
            [""]*3+["os"]*3+["proc"]*3)[typ]
        bin_ = self.info >> 4
        bin_ = (["local","global","weak"] + [""] * 7 + ["os"] * 3 + ["proc"] * 3)[bin_]
        return f"{bin_} {typ}"
    def __str__(self):
        shndx = [self.shndx, 0][self.shndx >= len(sht)]
        shnam = get_sh_name(sht[shndx].name)
        shstr = [f"in {shnam}",""][shnam == ""]
        return f"{self.infostr()} {get_sym_name(self.name)}: {self.value} :: {self.size} {shstr}"
    def empty(self):
        return not(self.name or self.value or self.size or self.info or self.other or self.shndx)


def symbolTable(sh: SectionHeader, b: bytes, t: FileIdent):
    b = b[sh.offset:]
    symboles = []
    for i in range(0, sh.size, sh.entsize):
        off = i
        name = value = size = info = other = shndx = 0
        if t.class_ == 64:
            name, off = readBytes(b, 4, off, t)
            info, off = readBytes(b, 1, off, t)
            other, off = readBytes(b, 1, off, t)
            shndx, off = readBytes(b, 2, off, t)
            value, off = readBytes(b, 8, off, t)
            size, off = readBytes(b, 8, off, t)
        if t.class_ == 32:
            name, off = readBytes(b, 4, off, t)
            value, off = readBytes(b, 4, off, t)
            size, off = readBytes(b, 4, off, t)
            info, off = readBytes(b, 1, off, t)
            other, off = readBytes(b, 1, off, t)
            shndx, off = readBytes(b, 2, off, t)
        symboles.append(Symbol(name, info, other, shndx, value, size))
    return symboles

def shByName(name: str) -> SectionHeader:
    for sh in sht:
        if get_sh_name(sh.name) == name:
            return sh 
    return None

def print_section(b: bytes, sh: SectionHeader):
    if sh.empty(): return
    print(f"section {get_sh_name(sh.name)}:")
    print_byte_section(b[sh.offset:sh.offset+sh.size], sh.offset)

def read(filename: str):
    global SHNAMESECTION, sht, SHSYMNAMESECTION
    b = b''
    with open(filename, "rb") as f:
        b = f.read() 
    h = Header(b)
    pht = None
    sht = None
    if h.e_phoff: pht = PhTable(b[h.e_phoff:], h.e_phentsize, h.e_phnum)
    if h.e_shoff: sht = shtable(b[h.e_shoff:], h.e_shentsize, h.e_shnum, h.e_ident)
    if h.e_shstrndx: SHNAMESECTION = b[sht[h.e_shstrndx].offset:]
    symboles = []
    for sh in sht:
        if sh.typ == 0: continue
        if get_sh_name(sh.name) == ".strtab":
            SHSYMNAMESECTION = b[sh.offset:]
        if sh.typ == 2:
            symboles = symbolTable(sh, b, h.e_ident)
    for s in sht:
        print_section(b, s)
    

import sys
read(sys.argv[1])
