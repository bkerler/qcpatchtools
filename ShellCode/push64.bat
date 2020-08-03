set PATH="C:\Android\sdk\platform-tools";%PATH%
adb push busybox src\libs\arm64-v8a\qcxploit /data/local/tmp
adb shell chmod 755 /data/local/tmp/*
