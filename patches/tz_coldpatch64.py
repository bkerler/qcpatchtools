#!/usr/bin/env python3
from Library.utility import elf
from Library.utility import patchtools
import binascii
import struct
import argparse
from keystone import *
bDebug=False

def getpatchcode(pt,elfheader,codecave_virt_addr,patchcode):
    #86578218
    baseaddr=elfheader.getbaseaddr(codecave_virt_addr)
    return pt.assembler(patchcode,KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

def find_code_cave(data, elfheader, pt):
    # Find code cave
    idx = pt.find_binary(data, b"\x00\x00\x00\x00\x0D\x02\x00\x02\x04\x00\x00\x00\x00\x00")  # mov w16, #0
    offset = None
    if (idx != None):
        # 0x865fc830
        addr = struct.unpack("<Q", data[idx + 0x10:idx + 0x18])[0]
        offset = elfheader.getfileoffset(addr)
        # addr=elfheader.getvirtaddr(offset)
        print(f"Found svc_entry_offset: {hex(elfheader.getvirtaddr(idx))}.\nPossible code cave at {hex(addr)}, file offset: {hex(offset)}\nsvc code: 0x0200020D")
    if offset == None:
        print("Couldn't find code cave offset !!!")
        exit(0)
    return addr

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='TZ Hotpatch Tool (c) B. Kerler 2018')

    parser.add_argument(
        '--infile', '-in',
        help='Input File',
        default='')
    parser.add_argument(
        '--shellcode', '-sc',
        help='Shellcode',
        default='')
    parser.add_argument(
        '--outfile', '-out',
        help='Output File',
        default='')

    args = parser.parse_args()

    if (args.infile == ''):
        print("[tzhack] I must have an infile to work on (-in)")
        exit(0)

    if (args.shellcode == ''):
        print("[tzhack] I must have a shellcode to work on (-sc)")
        exit(0)

    if (args.outfile==''):
        args.outfile=args.infile+".patched"

    pt=patchtools()
    filename=args.infile
    patched=args.outfile
    shellcode=args.shellcode
    with open(filename, "rb") as rf:
        data = bytearray(rf.read())
        elfheader=elf(data)
        codecave_virt_addr=find_code_cave(data, elfheader, pt)
        with open(shellcode,"rb") as rf:
            patchcode=rf.read()
            patchcode=getpatchcode(pt,elfheader,codecave_virt_addr,patchcode)
        print(f"Code to patch:{patchcode}")
        fileoffset=elfheader.getfileoffset(codecave_virt_addr)
        pd=binascii.unhexlify(patchcode)
        for i in range(0,len(pd)):
            data[fileoffset+i]=pd[i]
        with open(patched,"wb") as wf:
            wf.write(data)
        print(f"Patching done, saved as {patched}")
main()
