#!/bin/sh
adb push busybox src/libs/armeabi-v7a/qcxploit /data/local/tmp
adb shell chmod 755 /data/local/tmp/*
