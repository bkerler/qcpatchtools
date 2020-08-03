#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import struct
from subprocess import Popen, PIPE
import sys
import binascii
import os
import shutil
import argparse
import platform

if platform.system()=="Windows":
    ssl=os.path.join('Tools','openssl')
else:
    ssl='openssl'

class programentry:
    p_type=0
    from_file=0
    virt_addr=0
    phy_addr=0
    seg_file_len=0
    seg_mem_len=0
    p_flags=0
    p_align=0

targets=[
    # name,filename,sw_id,app_id
    ["sbl1","sbl1.mbn",0x0,0x0],
    ["efs_tar","fs_image.tar.gz.mb",0x0,0x0],
    ["mba","mba.mbn",0x1,0x0],
    ["modem","qdsp6sw.mbn",0x2,0x0],
    ["vip","DigestsToSign.bin.mbn",0x3,0x0],
    ["adsp","dsp2.mbn",0x4,0x0],
    ["qsee","tz.mbn", 0x7,0x0],
    ["appsbl","emmc_appsboot.mbn, aboot", 0x9,0x0],
    ["uefi","uefi_sign_ready.mbn, aboot", 0x9,0x0],
    ["rpm","rpm.mbn",0xA,0x0],
    ["winsecapp","winsecapp.mbn",0xC,0x111],
    ["sampleapp","sampleapp.mbn",0xC,0x111],
    ["uefisecapp","uefi_sec.mbn",0xC,0x222],
    ["isdbtmm","isdbtmm.mbn",0xC,0x222],
    ["widevine","widevine.mbn",0xC,0x333],
    ["dxhdcp2","dxhdcp2.mbn",0xC,0x333],
    ["playready","playready.mbn",0xC,0x444],
    ["sdksecapp","sdksecap.mbn",0xC,0x444],
    ["cmnlib","cmnlib.mbn",0xC,0x555],
    ["keymaster","keymaster.mbn",0xC,0x666],
    ["macchiato_sample","macchiato_sample.mbn",0xC,0x777],
    ["wcnss","wcnss.mbn",0xD],
    ["venus","venus.mbn",0xE],
    ["qhee","hyp.mbn", 0x15],
    ]

class elf:
    def __init__(self,indata):
        self.data=indata

    def parse_programentry(self,dat):
        pe = programentry()
        if self.elfclass==1:
            (pe.p_type,pe.from_file,pe.virt_addr,pe.phy_addr,pe.seg_file_len,pe.seg_mem_len,pe.p_flags,pe.p_align) = struct.unpack("<IIIIIIII",dat)
        elif self.elfclass==2:
            (pe.p_type, pe.p_flags, pe.from_file, pe.virt_addr, pe.phy_addr, pe.seg_file_len, pe.seg_mem_len,pe.p_align) = struct.unpack("<IIQQQQQQ", dat)
        return pe

    def parse(self):
        self.elfclass=self.data[4]
        if self.elfclass==1: #32Bit
            start=0x28
        elif self.elfclass==2: #64Bit
            start=0x34
        elfheadersize, programheaderentrysize, programheaderentrycount = struct.unpack("<HHH", self.data[start:start + 3 * 2])
        programheadersize = programheaderentrysize * programheaderentrycount
        header = self.data[0:elfheadersize+programheadersize]
        pentry=[]
        for i in range(0,programheaderentrycount):
            start=elfheadersize+(i*programheaderentrysize)
            end=start+programheaderentrysize
            pentry.append(self.parse_programentry(self.data[start:end]))

        return [header,pentry]

def sha256_calc(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()

def generatedebugid(serialnr):
    padding=8 #serialnr=((serialnr&0xFF)<<24)+((serialnr&0xFF00)<<8)+((serialnr&0xFF0000)>>8)+((serialnr&0xFF000000)>>24)
    serstring=f"{serialnr:0{padding}X}"+"00000003"
    return serstring

def generate_hash(args,data):
    # subject="\"/CN=DRAGONBOARD TEST PKI – NOT SECURE/O=S/OU=01 0000000000000009 SW_ID/OU=02 0000000000000000 HW_ID\""
    # subject="\"/C=US/CN=SecTools Test User/L=San Diego/O=SecTools/ST=California/OU=01 0000000000000007 SW_ID/OU=02 0000000000000000 HW_ID/OU=04 0000 OEM_ID/OU=05 000001C8 SW_SIZE/OU=06 0000 MODEL_ID/OU=07 0001 SHA256/OU=03 0000000000000002 DEBUG\""

    found=False
    for entry in targets:
        if args.type==entry[0]:
            sw_id=entry[2]
            app_id=entry[3]
            found=True
            break

    if not found:
        print("Supported types are: \n---------------------")
        for entry in targets:
            print("\"%s\", Filename: %s" % (entry[0],entry[1]))
        exit(0)
    if args.hwid!="":
        hw_id=struct.unpack(">Q",binascii.unhexlify(args.hwid))[0]
    else:
        hw_id=0

    SW_ID="/OU=01 %0.16X SW_ID" % sw_id #Signature important
    HW_ID="/OU=02 %0.16X HW_ID" % hw_id #Signature important
    DEBUG = "/OU=03 0000000000000002 DEBUG"
    if args.debugenable!="":
        DEBUG = "/OU=03 "+generatedebugid(int(args.debugenable,16))+" DEBUG"
    OEM_ID="/OU=04 0000 OEM_ID"
    SW_SIZE="/OU=05 %0.8X SW_SIZE" % len(data) #Signature important, Size of data to sign
    MODEL_ID="/OU=06 0000 MODEL_ID"
    HASH="/OU=07 0001 SHA256" #Signature important, Size of data to sign

    if (app_id!=0):
        APP_ID="/OU=08 %0.8X APP_ID" % app_id
    else:
        APP_ID=""

    # Here only for reference
    CRASH_DUMP = "/OU=09 %0.4X CRASH_DUMP"
    ROT_EN = "/OU=10 %0.4X ROT_EN"
    SOC_HW_VERSION = "/OU=11 %0.4X SOC_HW_VERSION"
    MASK_SOC_HW_VERSION = "/OU=12 %0.8X MASK_SOC_HW_VERSION"
    IN_USE_SOC_HW_VERSION = "/OU=13 %0.8X IN_USE_SOC_HW_VERSION"
    USE_SERIAL_NUMBER_IN_SIGNING = "/OU=14 %0.8X USE_SERIAL_NUMBER_IN_SIGNING"
    # End of reference

    subject = "\"/CN="+args.certname+"/O=S"+SW_ID+HW_ID+OEM_ID+SW_SIZE+MODEL_ID+HASH+DEBUG+APP_ID+"\""
    #subject = "\"/C=US/CN=SecTools Test User/L=San Diego/O=SecTools/ST=California/OU=01 0000000000000007 SW_ID/OU=02 0000000000000000 HW_ID/OU=04 0000 OEM_ID/OU=05 000001C8 SW_SIZE/OU=06 0000 MODEL_ID/OU=07 0001 SHA256/OU=03 0000000000000002 DEBUG\""
    SW_ID = binascii.unhexlify("%0.16X" % sw_id)
    HW_ID = binascii.unhexlify("%0.16X" % hw_id)
    opad = b"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C"
    So = b""
    for i in range(0, len(opad)):
        v = int(opad[i]) ^ int(HW_ID[i])
        So += struct.pack("<B", v)

    ipad = b"\x36\x36\x36\x36\x36\x36\x36\x36"
    Si = b""
    for i in range(0, len(ipad)):
        v = int(ipad[i]) ^ int(SW_ID[i])
        Si += struct.pack("<B", v)

    stp0 = sha256_calc(data)
    tmpDigest0=Si+stp0
    stp1 = sha256_calc(tmpDigest0)
    tmpDigest1=So+stp1
    dataToSign = sha256_calc(tmpDigest1)
    return [subject,dataToSign]

    
def run_command(cmd, indata):
    '''
    proc = Popen(cmd.split(" "), stdin=PIPE, stdout=PIPE)
    if (indata!=b""):
        proc.stdin.write(indata)
    p_status=proc.wait()
    proc.stdin.close()
    return proc.stdout.read()
    '''
    print(cmd)
    os.system(cmd)

keyfolder=os.path.join("keys","rootkey")
def generate_root_keys(args):
    import shutil
    if not (os.path.exists("keys")):
        os.mkdir("keys")
    if not os.path.exists(keyfolder):
        os.mkdir(keyfolder)

        if args.sdm660==True:
            res = run_command(ssl+" genrsa -out "+os.path.join(keyfolder,"cakey")+" -f4 2048",b"")
            res = run_command(ssl+" req -new -sha256 -key "+os.path.join(keyfolder,"cakey")+" -x509 -out "+os.path.join(keyfolder,"cacrt")+" -subj /C=\"US\"/ST=\"California\"/L=\"San Diego\"/OU=\"General Use Test key (for testing 13 only)\"/OU=\"CDMA Technologies\"/O=QUALCOMM/CN=\"QCT Root CA 1\" -days 7300 -set_serial 1 -config "+os.path.join("Tools","openssl.cfg")+" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha256",b"")
            res = run_command(ssl+" x509 -in "+os.path.join(keyfolder,"cacrt")+" -inform PEM -out "+os.path.join(keyfolder,"cacer")+" -outform DER ",b"")
            res = run_command(ssl+" genrsa -out "+os.path.join(keyfolder,"attestkey")+" -f4 2048",b"")
            res = run_command(ssl+" req -new -key "+os.path.join(keyfolder,"attestkey")+" -out "+os.path.join(keyfolder,"attestcsr")+" -subj /C=\"US\"/ST=\"CA\"/L=\"San Diego\"/OU=\"CDMA Technologies\"/O=QUALCOMM/CN=\"QUALCOMM attestation CA\" -config "+os.path.join("Tools","openssl.cfg"),b"") #-days 7300
            res = run_command(ssl+" x509 -req -in "+os.path.join(keyfolder,"attestcsr")+" -CA "+os.path.join(keyfolder,"cacrt")+" -CAkey "+os.path.join(keyfolder,"cakey")+" -out "+os.path.join(keyfolder,"attestcrt")+" -set_serial 5 -days 7300 -extfile "+os.path.join("Tools","v3.ext")+" -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha256",b"")
            res = run_command(ssl+" x509 -in "+os.path.join(keyfolder,"attestcrt")+" -inform PEM -out "+os.path.join(keyfolder,"attestcer")+" -outform DER",b"")
            res = run_command(ssl+" dgst -sha256 "+os.path.join(keyfolder,"cacer")+" > "+os.path.join(keyfolder,"sha256rootcert.txt"),b"")
        else:
            res = run_command(ssl+" genrsa -out "+os.path.join(keyfolder,"cakey")+" -f4 2048",b"")
            res = run_command(ssl+" req -new -key "+os.path.join(keyfolder,"cakey")+" -x509 -out "+os.path.join(keyfolder,"cacrt")+" -subj /C=\"US\"/ST=\"CA\"/L=\"SANDIEGO\"/O=\"OEM\"/OU=\"General OEM rootca\"/CN=\"OEM ROOT CA\" -set_serial 1 -config "+os.path.join("Tools","openssl.cfg")+" -sha256",b"") #-days 7300
            res = run_command(ssl+" x509 -in "+os.path.join(keyfolder,"cacrt")+" -inform PEM -out "+os.path.join(keyfolder,"cacer")+" -outform DER ",b"")
            res = run_command(ssl+" genrsa -out "+os.path.join(keyfolder,"attestkey")+" -f4 2048",b"")
            res = run_command(ssl+" req -new -key "+os.path.join(keyfolder,"attestkey")+" -out "+os.path.join(keyfolder,"attestcsr")+" -subj /C=\"US\"/ST=\"CA\"/L=\"SANDIEGO\"/O=\"OEM\"/OU=\"General OEM attestation CA\"/CN=\"OEM attestation CA\" -config "+os.path.join("Tools","openssl.cfg"),b"") #-days 7300
            res = run_command(ssl+" x509 -req -in "+os.path.join(keyfolder,"attestcsr")+" -CA "+os.path.join(keyfolder,"cacrt")+" -CAkey "+os.path.join(keyfolder,"cakey")+" -out "+os.path.join(keyfolder,"attestcrt")+" -set_serial 5 -days 7300 -extfile "+os.path.join("Tools","v3.ext")+" -sha256",b"")
            res = run_command(ssl+" x509 -in "+os.path.join(keyfolder,"attestcrt")+" -inform PEM -out "+os.path.join(keyfolder,"attestcer")+" -outform DER",b"")
            res = run_command(ssl+" dgst -sha256 "+os.path.join(keyfolder,"cacer")+" > "+os.path.join(keyfolder,"sha256rootcert.txt"),b"")

def generate_keys(args,subject):
    import shutil
    if not (os.path.exists("keys")):
        os.mkdir("keys")
    folder=os.path.join("keys",args.type)
    generatekeys=args.generatekeys
    if (generatekeys):
        if (os.path.exists(folder)):
            shutil.rmtree(folder)
    if not (os.path.exists(folder)):
        os.mkdir(folder)
        res = run_command(ssl+" x509 -in "+os.path.join(keyfolder,"cacer")+" -inform DER -outform PEM -out "+os.path.join(folder,"root_certificate.PEM"),b"")
        res = run_command(ssl+" x509 -in "+os.path.join(keyfolder,"attestcer")+" -inform DER -outform PEM -out "+os.path.join(folder,"attest_cert"),b"")
        res = run_command(ssl+" x509 -in " + os.path.join(folder,"attest_cert")+" -inform PEM -outform DER -out " + os.path.join(folder,"attestca_cert.DER"),b"")
        res = run_command(ssl+" x509 -in " + os.path.join(folder,"root_certificate.PEM")+" -inform PEM -outform DER -out " + os.path.join(folder,"root_cert.DER"),b"")
    with open(os.path.join(folder,"ea.ext"),"w") as wf:
        wf.write("crlDistributionPoints=URI:http://crl.qdst.com/crls/qctdevattest.crl\n")
        wf.write("authorityKeyIdentifier=keyid,issuer\n")
        wf.write("basicConstraints=CA:FALSE,pathlen:0\n")
        wf.write("keyUsage=digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment \n")

    if args.sdm660 == True:
        res=run_command(ssl+" genrsa -f4 2048 > "+os.path.join(folder,"attest_ca.PEM"),b"");
        res =run_command(ssl+" req -new -key "+os.path.join(folder,"attest_ca.PEM")+" -subj "+subject+" -out "+os.path.join(folder,"atte_csr.PEM")+" -config "+os.path.join('Tools','openssl.cfg')+" -sha256 -set_serial 1 -days 7300",b"")
        res =run_command(ssl+" x509 -req -in "+os.path.join(folder,"atte_csr.PEM")+" -CAkey "+os.path.join(keyfolder,"attestkey")+" -CA "+os.path.join(folder,"attest_cert")+"-set_serial 1 -sha256  -days 7300 -extfile "+os.path.join(folder,"ea.ext")+" -out "+os.path.join(folder,"atte_cert.PEM")+" -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sigopt digest:sha256",b"")
        res =run_command(ssl+" x509 -in "+os.path.join(folder,"atte_cert.PEM")+" -inform PEM -outform DER -out "+os.path.join(folder,"attest_certificate.der"),b"")
    else:
        res=run_command(ssl+" genrsa -f4 2048 > "+os.path.join(folder,"attest_ca.PEM"),b"");
        res =run_command(ssl+" req -new -key "+os.path.join(folder,"attest_ca.PEM")+" -subj "+subject+" -out "+os.path.join(folder,"atte_csr.PEM")+" -config "+os.path.join('Tools','openssl.cfg'),b"") #-days 7300
        res =run_command(ssl+" x509 -req -in "+os.path.join(folder,"atte_csr.PEM")+" -CAkey "+os.path.join(keyfolder,"attestkey")+" -CA "+os.path.join(folder,"attest_cert")+" -days 7300 -set_serial 1 -extfile "+os.path.join(folder,"ea.ext")+" -sha256 -out "+os.path.join(folder,"atte_cert.PEM"),b"")
        res =run_command(ssl+" x509 -in "+os.path.join(folder,"atte_cert.PEM")+" -inform PEM -outform DER -out "+os.path.join(folder,"attest_certificate.der"),b"")

def rsa_sign(digest, keyfile, args):
    #proc = Popen(['openssl', 'pkeyutl', '-sign', '-inkey', keyfile], stdin=PIPE, stdout=PIPE)
    if args.sdm660 == False:
        proc = Popen([ssl, 'rsautl', '-sign','-pkcs','-inkey', keyfile], stdin=PIPE, stdout=PIPE)
    else:
        proc = Popen([ssl, 'pkeyutl', '-sign', '-inkey', keyfile, '-pkeyopt', 'rsa_padding_mode:pss', '-pkeyopt', 'rsa_pss_saltlen:-1', '-pkeyopt', 'digest:sha256'], stdin=PIPE, stdout=PIPE)

    proc.stdin.write(digest)
    proc.stdin.close()
    sig = proc.stdout.read()
    return sig

def printtype():
    print("Option -t needed\n\nSupported types are: \n---------------------")
    for entry in targets:
        print("\"%s\", Filename: %s" % (entry[0],entry[1]))
    exit(0)


def main(args):
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='QC Signer (c) B. Kerler 2018-2019')

    parser.add_argument(
        '--infile', '-in',
        help='Filename to sign',
        default='')
    parser.add_argument(
        '--outfile', '-out',
        help='Signed Filename',
        default='')
    parser.add_argument(
        '--type', '-t',
        help=printtype,
        default='')
    parser.add_argument(
        '--swid','-swid',
        help='SW_ID: 0000000000000000',
        default='')
    parser.add_argument(
        '--hwid', '-hwid',
        help='HW_ID: 0000000000000000',
        default='')
    parser.add_argument(
        '--generatekeys', '-generatekeys',
        help='Generate new keys',
        action="store_true")
    parser.add_argument(
        '--sdm660', '-sdm660',
        help='Generate sdm660 keys',
        action="store_true")
    parser.add_argument(
        '--certname', '-certname',
        help='Certificate name',
        default='B.KERLER ROOT PKI')
    
    parser.add_argument('--debugenable','-debugenable',help="Enable Debug mode using serialnr",default="")
    
    args = parser.parse_args()

    if args.infile == '':
        print("[qc_signer] I must have an inputfile to work on (-in)")
        exit(0)

    if args.outfile == '':
        print("[qc_signer] I must have an outputfile to work on (-out)")
        exit(0)

    if args.type == '':
        printtype()
        exit(0)

    with open(args.infile,"rb") as rf:
        rdata=rf.read()
        elfheader=elf(rdata)
        header,pentry=elfheader.parse()

        fill = b"\x00"*0x20
        data = b''

        subdata=rdata[pentry[1].from_file:pentry[1].from_file + pentry[1].seg_file_len]
        data += subdata[0:0x28]

        data += sha256_calc(header)
        data += fill

        for seg in range(2,len(pentry)):
            if (pentry[seg].p_flags==0 or pentry[seg].seg_file_len==0):
                data+=fill
            else:
                tohash=rdata[pentry[seg].from_file:pentry[seg].from_file + pentry[seg].seg_file_len]
                hash=sha256_calc(tohash)
                data += hash

        subject,dataToSign=generate_hash(args,data)
        generate_root_keys(args)
        generate_keys(args, subject)

        sig=rsa_sign(dataToSign,os.path.join("keys",args.type,"attest_ca.PEM"),args)

        atte_der=b""
        with open(os.path.join("keys",args.type,"attest_certificate.der"),"rb") as rf:
            atte_der=rf.read()

        atte_ca_der=b""
        with open(os.path.join("keys",args.type,"attestca_cert.DER"),"rb") as rf:
            atte_ca_der=rf.read()

        root_der = b""
        with open(os.path.join("keys",args.type,"root_cert.DER"), "rb") as rf:
            root_der = rf.read()

        signatureblock=data+sig+atte_der+atte_ca_der+root_der
        offset=pentry[1].from_file
        print("Offs:"+hex(offset))
        length=pentry[1].seg_file_len
        print("Len:"+hex(length))

        with open(args.outfile,"wb") as wf:
            wf.write(rdata[0:offset])
            wf.write(signatureblock)
            wf.write(b"\xFF"*(length-len(signatureblock)))
            if pentry[2].from_file<pentry[3].from_file:
                wf.seek(pentry[2].from_file)
                wf.write(rdata[pentry[2].from_file:])
            else:
                wf.seek(pentry[3].from_file)
                wf.write(rdata[pentry[3].from_file:])
        print("Done")

if __name__ == "__main__":
   main(sys.argv[1:])