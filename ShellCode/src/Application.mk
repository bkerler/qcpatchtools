LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

APP_PLATFORM := android-21
APP_ABI := armeabi,arm64-v8a
#NDK_TOOLCHAIN_VERSION := clang-obfuscated

include $(BUILD_EXECUTABLE)
