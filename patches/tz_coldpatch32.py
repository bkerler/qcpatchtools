#!/usr/bin/env python3
from Library.utility import elf
from Library.utility import patchtools
from binascii import hexlify, unhexlify
import struct
import argparse
import hashlib
from keystone import *
bDebug=False

def sha256_calc(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()

def getpatchcode(pt,patchcode):
    return pt.assembler(patchcode,KS_ARCH_ARM, KS_MODE_THUMB | KS_MODE_LITTLE_ENDIAN)

def find_code_cave(data, elfheader, pt):
    # Find code cave
    idx = pt.find_binary(data, b"\x06\x0C\x00\x00")  # mov w16, #0
    offset = None
    if (idx != None):
        # 0x865fc830
        addr = struct.unpack("<I", data[idx + 0xC:idx + 0x10])[0]
        offset = elfheader.getfileoffset(addr)-1
        # addr=elfheader.getvirtaddr(offset)
        print(f"Found svc_entry_offset: {hex(elfheader.getvirtaddr(idx))}.\nPossible code cave at {hex(addr)}, file offset: {hex(offset)}\nsvc code: 0x0C06 (svc 0x03 cmd 0x06)")
    if offset == None:
        print("Couldn't find code cave offset !!!")
        exit(0)
    return addr

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='TZ Hotpatch Tool (c) B. Kerler 2019')

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

        # We need to find secure hash table
        header,pentry=elfheader.parse()
        subdata=data[pentry[2].from_file:pentry[2].from_file + pentry[2].seg_file_len]
        digest = sha256_calc(subdata[0:0x1000])
        idx = pt.find_binary(data, digest)
        if idx==None:
            print("Error: Couldn't find secure hash table")
            exit(0)
        with open(shellcode,"rb") as rf:
            patchcode=rf.read()
            patchcode=getpatchcode(pt,patchcode)
        print(f"Code to patch:{patchcode}")
        fileoffset=elfheader.getfileoffset(codecave_virt_addr)-1
        pd=unhexlify(patchcode)
        for i in range(0,len(pd)):
            data[fileoffset+i]=pd[i]

        subdata=data[pentry[2].from_file:pentry[2].from_file + pentry[2].seg_file_len]
        if len(subdata)%0x1000!=0:
            lentopatch=0x1000-(len(subdata)%0x1000)
            subdata.extend(b'\x00'*lentopatch)
        for pos in range(0,len(subdata),0x1000):
            digest=sha256_calc(subdata[pos:pos+0x1000])
            for i in range(0,len(digest)):
                data[idx+((pos//0x1000)*0x20)+i]=digest[i]

        with open(patched,"wb") as wf:
            wf.write(data)
        print(f"Patching done, saved as {patched}")
main()
