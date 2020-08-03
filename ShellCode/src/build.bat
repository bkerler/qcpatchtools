@echo off
set PATH=%PATH%;%ANDROID_SDK_HOME%\ndk-bundle
rmdir /s /q libs obj
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_PLATFORM=android-21 

