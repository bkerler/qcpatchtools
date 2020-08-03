#!/bin/sh
rm -rf libs obj
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_PLATFORM=android-21 
