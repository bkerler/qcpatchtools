#!/usr/bin/env python3
import os
import struct
import argparse

'''
(c) B.Kerler 2018, tested with MSM8976/53, patches away Root-Of-Trust-Checks
'''

def find_binary(data,strf,pos=0):
    t=strf.split(b".")
    pre=0
    offsets=[]
    while (pre!=-1):
        pre = data[pos:].find(t[0],pre)
        if (pre==-1):
            if len(offsets)>0:
                for offset in offsets:
                    error = 0
                    rt = offset + len(t[0])
                    for i in range(1, len(t)):
                        if (t[i] == b''):
                            rt += 1
                            continue
                        rt += 1
                        prep = data[rt:].find(t[i])
                        if (prep != 0):
                            error = 1
                            break
                        rt += len(t[i])
                    if error == 0:
                        return offset
            else:
                return None
        else:
            offsets.append(pre)
            pre+=1
    return None

def main():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='QC Signer (c) B. Kerler 2018-2019')

    parser.add_argument(
        '--infile', '-in',
        help='Filename to sign',
        default='')
    parser.add_argument(
        '--outfile', '-out',
        help='Filename to sign',
        default='')
    args = parser.parse_args()

    with open(args.infile,"rb") as rf:
        data=bytearray(rf.read())
        patches=0
        idx=find_binary(data,b"\x1F\xBF\xE6\x01\x00.\xE1.\x00\x00\x0A")
        #                \x1F\xBF\xE6\x01\x00\x58\xE1\x08\x00\x00\x0A
        if (idx!=None):
            if data[idx+0xA]==0xA:
                data[idx+0xA]=0xEA
                patches+=1
        if (patches!=1):
            print("Error on patching image length check")
            return

        idx=find_binary(data,b"\x00\x30\xA0\x13\x00\x70\xA0\x11\x00\x30.\x15.\xFF\xFF\x1A")
        if (idx!=None):
            data[idx-4]=0x00
            data[idx-3]=0x00
            data[idx-2]=0xA0
            data[idx-1]=0xE1
            data[idx+3]=0xE3
            data[idx+0x7]=0xE1
            data[idx+0xB]=0xE5
            data[idx+0xF]=0xEA
            patches += 1
        else:
            idx=find_binary(data,b"\x00\x30\xA0\x13\x00\x30.\x15.\xFF\xFF\x1A")
            if (idx!=None):
                data[idx-4] = 0x0
                data[idx-3] = 0x0
                data[idx-2] = 0xA0
                data[idx-1] = 0xE1
                data[idx + 3] = 0xE3
                data[idx + 0x7] = 0xE5
                data[idx + 0xB] = 0xEA
                patches+=1
        if (patches!=2):
            print("Error on patching signature hash check")
            return

        with open(args.outfile,"wb") as wf:
            wf.write(data)

        print("Successfully patched data to "+args.outfile)

main()