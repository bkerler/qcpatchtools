#!/usr/bin/env python3
import lzma
import sys
from struct import pack,unpack,calcsize
from binascii import hexlify,unhexlify
import os

def u28tou32(val):
    return unpack("<I", val + b"\x00")[0]

def read_object(data, definition):
    '''
    Unpacks a structure using the given data and definition.
    '''
    obj = {}
    object_size = 0
    pos = 0
    for (name, stype) in definition:
        object_size += calcsize(stype)
        obj[name] = unpack(stype, data[pos:pos + calcsize(stype)])[0]
        pos += calcsize(stype)
    obj['object_size'] = object_size
    obj['raw_data'] = data
    return obj

def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),

    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()

def main(argv):
    if len(argv)<3:
        print("Usage: abl_decomp [infile] [outfile]")
        exit(0)

    EFI_FIRMWARE_VOLUME_HEADER = [
        ('ZeroVector', '16s'),
        ('FileSystemGuid', '16s'),
        ('FvLength', 'Q'),
        ('Signature', 'I'),
        ('Attributes', 'I'),
        ('HeaderLength', 'H'),
        ('Checksum', 'H'),
        ('ExtHeaderOffset', 'H'),
        ('Reserved', 'B'),
        ('Revision', 'B')
    ]

    EFI_FV_BLOCK_MAP_ENTRY = [
        ('NumBlocks', 'I'),
        ('Length', 'I'),
        ('Padding','Q')
    ]

    EFI_FFS_INTEGRITY_CHECKSUM = [
        ('Header', 'B'),
        ('File', 'B')
    ]

    EFI_FFS_FILE_HEADER=[
        ('Name', '16s'),
        ('ChksumHeader', 'B'),  #  EFI_FFS_INTEGRITY_CHECKSUM
        ('ChksumFile', 'B'),    #  EFI_FFS_INTEGRITY_CHECKSUM
        ('Type', 'B'),
        ('Attributes', 'B'),
        ('Size', '3s'),
        ('State', 'B')
    ]

    EFI_GUID_DEFINED_SECTION=[
        ('Size', '3s'),
        ('Type', 'B'),
        ('SectionDefinitionGuid', '16s'),
        ('DataOffset', 'H'),
        ('Attributes', 'H')
    ]

    EFI_COMMON_SECTION_HEADER = [
        ('Size', '3s'),
        ('Type', 'B')
    ]

    EFI_FIRMWARE_VOLUME_EXT_HEADER = [
        ('FvName', '16s'),
        ('ExtHeaderSize', 'I')
    ]

    filename=sys.argv[1]
    outfilename=sys.argv[2]
    with open(filename,"rb") as rf:
        rf.seek(0x3000)
        header={}
        volh=rf.read(0x38)
        header["EFIVOLUME"]=read_object(volh,EFI_FIRMWARE_VOLUME_HEADER)
        blockmap=rf.read(16)
        header["FV_BLOCK_MAP"]=read_object(blockmap,EFI_FV_BLOCK_MAP_ENTRY)
        fileh=rf.read(0x18)
        header["FFS_FILE"]=read_object(fileh,EFI_FFS_FILE_HEADER)
        defined=rf.read(0x18)
        header["GUID_DEFINED"]=read_object(defined,EFI_GUID_DEFINED_SECTION)
        compressedsize=u28tou32(header["GUID_DEFINED"]["Size"])
        data=rf.read(compressedsize)
        f = lzma.LZMADecompressor()
        subdata = f.decompress(data)

        pos=0
        sheader={}
        sheader["SECTION_RAW"]=read_object(subdata[pos:pos+4],EFI_COMMON_SECTION_HEADER)
        pos+=4
        if sheader["SECTION_RAW"]["Type"]==0x19:
            sheader["SECTION_FirmwareVolumeImage"] = read_object(subdata[pos:pos+4], EFI_COMMON_SECTION_HEADER)
            pos+=4
            if sheader["SECTION_FirmwareVolumeImage"]["Type"]==0x17:
                volh = subdata[pos:pos+0x38]
                sheader["EFIVOLUME"] = read_object(volh, EFI_FIRMWARE_VOLUME_HEADER)
                pos+=0x38
                blockmap = subdata[pos:pos+0x10]
                sheader["FV_BLOCK_MAP"] = read_object(blockmap, EFI_FV_BLOCK_MAP_ENTRY)
                pos+=0x10

                fileh = subdata[pos:pos+0x18]
                sheader["FFS_FILE"] = read_object(fileh, EFI_FFS_FILE_HEADER)
                pos+=0x18
                volexthdr=subdata[pos:pos+0x18]
                sheader["FW_VOL_EXT_HDR"]=read_object(volexthdr,EFI_FIRMWARE_VOLUME_EXT_HEADER)
                pos+=0x14

                pos+=0x4 # Alignment

                fileh = subdata[pos:pos + 0x18]
                sheader["FFS_FILE2"] = read_object(fileh, EFI_FFS_FILE_HEADER)
                pos += 0x18
                if sheader["FFS_FILE2"]["Type"]==0x09: #EFI_FV_FILETYPE_APPLICATION
                    sheader["FFS_FILE3"] = read_object(subdata[pos:pos + 4], EFI_COMMON_SECTION_HEADER)
                    pos += 4
                    if sheader["FFS_FILE3"]["Type"]==0x15: #EFI_SECTION_USER_INTERFACE
                        textsize=u28tou32(sheader["FFS_FILE3"]["Size"])
                        sheader["Text"]=subdata[pos:pos+textsize-0x4]
                        pos+=textsize-0x4

                        sheader["FFS_FILE4"] = read_object(subdata[pos:pos + 4],EFI_COMMON_SECTION_HEADER)
                        pos += 4
                        if sheader["FFS_FILE4"]["Type"]==0x10: #EFI_SECTION_PE32
                            fsize = u28tou32(sheader["FFS_FILE4"]["Size"])-4
                            fdata=subdata[pos:pos+fsize]
                            with open(outfilename,"wb") as wf:
                                wf.write(fdata)
    print("Done.")
main(sys.argv)
