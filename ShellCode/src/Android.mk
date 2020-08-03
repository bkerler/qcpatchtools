LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

#LOCAL_CFLAGS := -mllvm -xse -mllvm -sub -mllvm -fla -mllvm -bcf
LOCAL_CFLAGS += -fPIE
LOCAL_LDFLAGS += -fPIE -pie 
LOCAL_LDFLAGS += -fuse-ld=gold

LOCAL_MODULE := qcxploit
LOCAL_CFLAGS += -std=c99
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := main.c
include $(BUILD_EXECUTABLE)
