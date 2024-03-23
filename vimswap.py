import struct
from vimdecrypt import hashpw, makecfb, makeblowfish, zip_decrypt


class DataReader:
    def __init__(self, data:bytes):
        self.data = data
        self.pos = 0

    def readstr(self, n, encoding='utf-8', strip=False):
        data = self.read(n)
        if data is None:
            return
        data = data.rstrip(b"\x00")
        txt = data.decode(encoding)
        if strip:
            txt = txt.rstrip()
        return txt

    def read16le(self):
        return struct.unpack("<H", self.read(2))[0]
    def read32le(self):
        return struct.unpack("<L", self.read(4))[0]
    def read64le(self):
        return struct.unpack("<Q", self.read(8))[0]

    def tell(self):
        return self.pos

    def seek(self, pos):
        self.pos = pos

    def eof(self):
        return self.pos == len(self.data)

    def readbyte(self):
        if self.pos >= len(self.data):
            return
        self.pos += 1
        return self.data[self.pos-1]

    def read(self, n=-1):
        if n == -1:
            n = len(self.data) - self.pos
        if self.pos+n > len(self.data):
            return
        self.pos += n
        return self.data[self.pos-n:self.pos]



class Header:
    def __init__(self, rd):
        self.baseofs = rd.tell()

        self.magic = rd.readstr(2)      # b0: plain,  bc: zip, bC: bf, bd: bf2
        if self.magic not in ('b0', 'bC', 'bd', 'bc'):
            raise Exception("not a vim swap file")

        self.version = rd.readstr(10)   # 0x02   char_u      b0_version[10]; // Vim version string
        self.pagesize = rd.read32le()   # 0x0c   char_u      b0_page_size[4];// number of bytes per page
        self.mtime = rd.read32le()      # 0x10   char_u      b0_mtime[4];    // last modification time of file
        self.ino = rd.read32le()        # 0x14   char_u      b0_ino[4];      // inode of b0_fname
        self.pid = rd.read32le()        # 0x18   char_u      b0_pid[4];      // process id of creator (or 0)
        self.username = rd.readstr(40)  # 0x1c   char_u      b0_uname[B0_UNAME_SIZE]; // name of user (uid if no name)
        self.hostname = rd.readstr(40)  # 0x44   char_u      b0_hname[B0_HNAME_SIZE]; // host name (if it has a name)
        seedlen = 0 if self.magic == 'b0' else 8
        nine00 = rd.read(900-2-seedlen)   # 0x6c   char_u      b0_fname[B0_FNAME_SIZE_ORG]; // name of file being edited
        self.filename = nine00.lstrip(b"\x00")
        k = len(nine00) - len(self.filename) # start of filename
        i = self.filename.find(b"\x00")      # end of filename
        if i>=0:
            self.filename = self.filename[:i].decode()
        j = nine00.rfind(b"\x00")            # start of encoding

        self.encoding = nine00[j+1:].decode()
        if nine00[i+k:j] != b"\x00" *(j-i-k):
            print("NOTE: data between filename and encoding: ", nine00[i+k:j].hex())

        self.seed = rd.read(seedlen)
        self.flags = rd.readbyte()   # 0x3ee == 'U'   b0_flags - since vim7.0
        self.dirty = rd.readbyte()   # 0x3ef == 'U'   b0_dirty
        self.magic_long = rd.read32le()
        self.magic_int = rd.read32le()
        self.long64 = False
        if self.magic_int == 0:
            self.long64 = True # note: long is 64-bit
            self.magic_int = rd.read32le()
        self.magic_short = rd.read16le()
        self.magic_char = rd.readbyte()

    def __repr__(self):
        return f"HDR   {self.baseofs:08x}: m:{self.magic} p:0x{self.pagesize:x} t:{self.mtime} ino:{self.ino} pid:{self.pid} {self.username}@{self.hostname} - {self.filename} / {self.encoding}"+(f" ; seed:{self.seed.hex()}" if self.seed else "")


class Index:
    class Entry:
        def __init__(self, rd):
            self.pagenr = rd.readlong()       # blocknr_T   pe_bnum;        // block number                          
            self.nrlines = rd.readlong()      # linenr_T    pe_line_count;  // number of lines in this branch
            self.firstline = rd.readlong()    # linenr_T    pe_old_lnum;    // lnum for this block (for recovery)
            self.one = rd.readlong()          # int         pe_page_count;  // number of pages in block pe_bnum
        def empty(self):
            return self.pagenr == self.nrlines == self.firstline == self.one == 0
        def __repr__(self):
            return f"#{self.pagenr:08x} nrlines={self.nrlines} firstline={self.firstline} one={self.one}"

    def __init__(self, rd):
        self.baseofs = rd.tell()
        self.magic = rd.readstr(2)    # short_u     pb_id;          // ID for pointer block: PTR_ID   --  'tp'
        self.nrpages = rd.read16le()  # short_u     pb_count;       // number of pointers in this block
        self.maxnr = rd.read32le()    # short_u     pb_count_max;   // maximum value for pb_count
        self.entries = []             # PTR_EN      pb_pointer[1];  // list of pointers to blocks (actually longer)
                                      #                             // followed by empty space until end of page
        for _ in range(self.maxnr):
            e = Index.Entry(rd)
            if e.empty():
                break
            self.entries.append(e)

    def __repr__(self):
        return f"INDEX {self.baseofs:08x}: m:{self.magic} n={self.nrpages} max={self.maxnr} {self.entries}"


class Page:
    def __init__(self, rd, decoder):
        self.baseofs = rd.tell()
        self.magic = rd.readstr(4)   # short_u     db_id;          // ID for data block: DATA_ID       -- 'ad'
        self.free = rd.read32le()    # unsigned    db_free;        // free space available
        self.strofs = rd.read32le()  # unsigned    db_txt_start;   // byte where text starts
        self.endofs = rd.read32le()  # unsigned    db_txt_end;     // byte just after data block
        self.nrlines = rd.readlong() # linenr_T    db_line_count;  // number of lines in this block
                                     # unsigned    db_index[1];    // index for start of line (actually bigger)

        self.lineofs = struct.unpack(f"<{self.nrlines}L", rd.read(4*self.nrlines))
        if rd.tell()%self.endofs < self.strofs:
            x = self.strofs - rd.tell()%self.endofs
            data = rd.read(x)
            if data != b"\x00"*len(data):
                print("NOTE: more data: ", data.hex())

        rd.seek(self.baseofs + self.strofs)
        data = rd.read(self.endofs-self.strofs)

        data = decoder(self.baseofs, data)

        self.lines = []
        prevo = self.endofs
        for o in self.lineofs:
            line = data[o-self.strofs : prevo-self.strofs]
            self.lines.append(line)
            prevo = o
        if len(self.lineofs) != len(self.lines):
            print("NOTE: line/lines mismatch")

    def __repr__(self):
        return f"PAGE  {self.baseofs:08x}: m:{self.magic} free:{self.free:x} str:{self.strofs:x}-{self.endofs:x} #={self.nrlines}"

    def dump(self):
        for o, txt in zip(self.lineofs, self.lines):
            print(f"{o:8x} {txt}")

"""
bc  : decimal byte offset to the block appended to the key
bC,bd : salt = decimal byte offset
"""

def zipdecoder(args):
    # note: the iv is not used for zip encryption.
    def decode(ofs, data):
        return zip_decrypt(data, (args.password+str(ofs)).encode('utf-8'), args)
    return decode

def bfdecoder(args, iv, ver):
    def decode(ofs, data):
        salt = str(ofs).encode()
        key = hashpw(args.password.encode("utf-8"), salt)
        cfb = makecfb(ver, makeblowfish(args, key), iv)
        return cfb.decrypt(bytearray(data))
    return decode

def main():
    import argparse
    parser = argparse.ArgumentParser(description='vimswap dumper')
    parser.add_argument('--debug', action='store_true', help='raise exceptions.')
    parser.add_argument('--verbose', '-v', action='store_true', help='print details about keys etc.')
    parser.add_argument('--password', '-p', type=str, help='Decrypt using password')
    parser.add_argument('files', nargs='*', type=str)
    args = parser.parse_args()

    for fn in args.files:
        print("==>", fn, "<==")
        try:
            with open(fn, "rb") as fh:
                data = fh.read()
                rd = DataReader(data)
                hdr = Header(rd)
                print(hdr)
                decoder = None
                match hdr.magic:
                    case 'b0': decoder = None
                    case 'bc': decoder = zipdecoder(args)
                    case 'bC': decoder = bfdecoder(args, hdr.seed, 'bf1')
                    case 'bd': decoder = bfdecoder(args, hdr.seed, 'bf2')

                if not decoder or args.password is None:
                    if decoder:
                        print("WARNING: no password specified for encrypted swapfile")
                    decoder = lambda o,data:data

                if hdr.long64:
                    rd.readlong = rd.read64le
                else:
                    rd.readlong = rd.read32le
                    print("skipping 32 bit swapfile")
                    continue

                o = 0x1000
                while not rd.eof():
                    rd.seek(o)
                    m = rd.readstr(2)
                    rd.seek(o)
                    if m == 'tp':
                        idx = Index(rd)
                        print(idx)
                        o += 0x1000
                    elif m == 'ad':
                        p = Page(rd, decoder)
                        print("--", p)
                        p.dump()

                        o += p.endofs
                    else:
                        print("unknown magic: ", m)
                        break

        except Exception as e:
            print("ERROR", type(e), e)
            if args.debug:
                raise

if __name__=='__main__':
    main()

