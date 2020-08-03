#!/usr/bin/env python3
import os
import struct

'''
(c) B.Kerler 2018, tested with MSM8976/53, patches away Fail-Counter in SSD, Ram-Fail-Counter, Key-Wipe and Forced-Timeouts
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
    with open("tz.bin","rb") as rf:
        data=bytearray(rf.read())
        patches=0
        
        idx=find_binary(data,b"\x80\x5E\xF8.\x04\x40\xB9.\x80\x5F\xF8") #mov w16, #0
        if (idx!=None):
              data[idx+0x3]=0x10
              data[idx+0x4]=0x00
              data[idx+0x5]=0x80
              data[idx+0x6]=0x52
              patches+=1
        else:
            idx=find_binary(data,b"\x80\x5E\xF8\x54\x80\x5F\xF8\x51\x04\x40\xB9") #mov w17, #0
            if (idx!=None):
                  data[idx+0x7]=0x11
                  data[idx+0x8]=0x00
                  data[idx+0x9]=0x80
                  data[idx+0xA]=0x52
                  patches+=1
        
        if (patches!=1):
            print("Error on patching error counter")
            return

        idx=find_binary(data,b"\xF9\x03\x18\xAA\x24\x1C\xFF\x97\xE3\x23\x40\xB9\x63\x04\x00\x11")
        if (idx!=None):
            data[idx+0xC]=0x03
            data[idx+0xD]=0x00
            data[idx+0xE]=0x80
            data[idx+0xF]=0x52
            patches += 1
        else:
            idx=find_binary(data,b"\xAA\x26\xF8\xFE\x97\x39\x07\x00\x11") #mov w25, #0
            if (idx!=None):
                data[idx+0x5] = 0x19
                data[idx+0x6] = 0x00
                data[idx+0x7] = 0x80
                data[idx+0x8] = 0x52
                patches+=1
            else:
                idx=find_binary(data,b"\x97\xF4\x03\x18\x2A\x94\x06\x00\x11") #mov w20, #0
                if (idx!=None):
                    data[idx+0x5] = 0x14
                    data[idx+0x6] = 0x00
                    data[idx+0x7] = 0x80
                    data[idx+0x8] = 0x52
                    patches+=1
        if (patches!=2):
            print("Error on patching boot error increase")
            return

        idx=find_binary(data,b"\xF4\x03\x01\x2A\xF5\x03\x00\x2A..\xFF\x97\xF3\x03\x00\x2A")
        if (idx!=None):
                data[idx+0x8] = 0x00
                data[idx+0x9] = 0x00
                data[idx+0xA] = 0x80
                data[idx+0xB] = 0x52
                data[idx+0xC] = 0x0C
                data[idx+0xD] = 0x00
                data[idx+0xE] = 0x00
                data[idx+0xF] = 0x14
                patches+=1


        if (patches!=3):
            print("Error on patching wait timeout")
            return
                
        with open("tz.patched","wb") as wf:
            wf.write(data)

        print("Successfully patched data to tz.patched")

main()