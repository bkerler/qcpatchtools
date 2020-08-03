#!/usr/bin/env python3
from Library.utility import elf
from Library.utility import patchtools
import binascii
import struct
import argparse
bDebug=False
import binaryninja


def getpatchcode(pt,elfheader,ceml_kdf_virt_addr,printf_virt_addr,codecave_virt_addr):
    #86578218
    baseaddr=elfheader.getbaseaddr(codecave_virt_addr)
    ceml=codecave_virt_addr-ceml_kdf_virt_addr
    printf = codecave_virt_addr-printf_virt_addr
    printf2 = codecave_virt_addr-printf_virt_addr
    offs=codecave_virt_addr&0xFFF
    linesofcode=39
    code="" \
    "STP X28, X27, [SP,#-0x60]!\n" \
    "STP X26, X25, [SP,#0x10]\n" \
    "STP X24, X23, [SP,#0x20]\n" \
    "STP X22, X21, [SP,#0x30]\n" \
    "STP X20, X19, [SP,#0x40]\n" \
    "STP X29, X30, [SP,#0x50]\n" \
    "MOV X29, SP\n" \
    "MOV X21, 0\n" \
    "MOV X22, X6\n" \
    "MOV X23, X7\n" \
    "MOV X24, X2\n" \
    "MOV X25, X3\n" \
    f"BL -{hex(ceml)}\n" \
    "MOV X20, X0\n" \
    "loop:\n" \
    "MOV X0, #0x3\n" \
    "LDR X2, [X22, X21]\n" \
    "ADRP  X1, #0x0\n" \
    f"add x1, x1, #{hex(offs+(linesofcode*4))}\n" \
    f"BL -{hex(printf)}\n" \
    "ADD X21, X21, #8\n" \
    "CMP X21, X23\n" \
    "BLT loop\n" \
    "MOV X21, #0\n" \
    "loop2:\n" \
    "MOV X0, #0x3\n" \
    "LDR X2, [X24, X21]\n" \
    "ADRP  X1, #0x0\n" \
    f"add x1, x1, #{hex(offs+(linesofcode*4)+8)}\n" \
    f"BL -{hex(printf2)}\n" \
    "ADD X21, X21, #8\n" \
    "CMP X21, X25\n" \
    "BLT loop2\n" \
    "exit:\n" \
    "mov X0, x20\n" \
    "LDP X29, X30, [SP,#0x50]\n" \
    "LDP X20, X19, [SP,#0x40]\n" \
    "LDP X22, X21, [SP,#0x30]\n" \
    "LDP X24, X23, [SP,#0x20]\n" \
    "LDP X26, X25, [SP,#0x10]\n" \
    "LDP X28, X27, [SP],#0x60\n" \
    "RET\n"
    return pt.assembler(code)+binascii.hexlify(b"K%08X\x00\x00\x00L%08X\x00\x00\x00").decode('utf-8')

def find_code_cave(data, elfheader, pt):
    # Find code cave
    idx = pt.find_binary(data, b"\x00\x00\x00\x00\x0D\x02\x00\x02\x04\x00\x00\x00\x00\x00")  # mov w16, #0
    offset = None
    if (idx != None):
        # 0x865fc830
        addr = struct.unpack("<Q", data[idx + 0x10:idx + 0x18])[0]
        offset = elfheader.getfileoffset(addr)
        # addr=elfheader.getvirtaddr(offset)
        print(f"Found code cave at {hex(addr)}, file offset: {hex(offset)}, svc code: 0x0200020D")
    if offset == None:
        print("Couldn't find code cave offset !!!")
        exit(0)
    return addr

def find_ceml_kdf(data, elfheader, pt):
    idx = pt.find_binary(data, b"\x48\x01\xA0\x52\x08\x10\x84\x72\xE0\x03\x00\x32\x08\x01\x40\xB9")
    offset = None
    if (idx != None):
        for i in range(idx,idx-0xB0,-4):
            disasm=pt.disasm(data[i-4:i],4)
            if "ret" in disasm[0]:
                offset=i
                break
    if (idx!=None and offset!=None):
        addr = elfheader.getvirtaddr(offset)
        print(f"Found ceml_kdf at {hex(addr)}, file offset: {hex(offset)}")
    else:
        print("Couldn't find ceml_kdf offset !!!")
        exit(0)
    return addr

def find_printf(data, elfheader, pt):
    idx = pt.find_binary(data, b"\xE6\x9F\x02\xA9\xE4\x97\x01\xA9\xA9\x43\x00\x91")
    offset = None
    if (idx != None):
        for i in range(idx,idx-0xB0,-4):
            disasm=pt.disasm(data[i-4:i],4)
            if "ret" in disasm[0]:
                offset=i
                break
    if (idx!=None and offset!=None):
        addr = elfheader.getvirtaddr(offset)
        print(f"Found printf at {hex(addr)}, file offset: {hex(offset)}")
    else:
        print("Couldn't find printf offset !!!")
        exit(0)
    return addr

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='TZ Key Patcher Tool (c) B. Kerler 2018')

    parser.add_argument(
        '--infile', '-in',
        help='Input File',
        default='')
    parser.add_argument(
        '--outfile', '-out',
        help='Output File',
        default='')

    args = parser.parse_args()

    if (args.infile == ''):
        print("[tzhack] I must have an infile to work on (-in)")
        exit(0)

    if (args.outfile==''):
        args.outfile=args.infile+".hacked"

    pt=patchtools()
    filename=args.infile
    patched=args.outfile
    with open(filename, "rb") as rf:
        data = bytearray(rf.read())
        elfheader=elf(data)

        codecave_virt_addr=find_code_cave(data, elfheader, pt)
        ceml_kdf_virt_addr=find_ceml_kdf(data,elfheader,pt)
        printf_virt_addr=find_printf(data,elfheader,pt)
        patchcode=getpatchcode(pt,elfheader,ceml_kdf_virt_addr,printf_virt_addr,codecave_virt_addr)
        print(f"Code to patch:{patchcode}")
        fileoffset=elfheader.getfileoffset(codecave_virt_addr)
        pd=binascii.unhexlify(patchcode)
        for i in range(0,len(pd)):
            data[fileoffset+i]=pd[i]
        
        bv = binaryninja.BinaryViewType["ELF"].open(args.infile)
        bv.update_analysis_and_wait()
        xrefs=bv.get_code_refs(ceml_kdf_virt_addr)
        for xref in xrefs:
            offs=xref.address
            foffs=elfheader.getfileoffset(offs)
            code="BL +"+hex(codecave_virt_addr-offs)
            patch=pt.assembler(code)
            print(f"Found ceml_kdf reference at:{hex(offs)}, file offset: {hex(foffs)}, patch:{patch}")
            pa=binascii.unhexlify(patch)
            for i in range(0,4):
                data[foffs+i]=pa[i]
        with open(patched,"wb") as wf:
            wf.write(data)
        print(f"Patching done, saved as {patched}")
main()
