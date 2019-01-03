LOCAL_PATH := $(call my-dir)

ifneq ($(TARGET_PROVIDES_KEYMASTER),true)
ifeq ($(TARGET_BOARD_SOC),pxa1908)


include $(CLEAR_VARS)

LOCAL_MODULE := keystore.$(TARGET_BOARD_PLATFORM)
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_SRC_FILES := keymaster_mrvl.cpp

LOCAL_C_INCLUDES := $(TARGET_OUT_HEADERS)/common/inc \
                    $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr/include \
                    external/openssl/include/

LOCAL_CFLAGS := -fvisibility=hidden -Wall

LOCAL_SHARED_LIBRARIES := \
        libtee_client \
        libkeystore_binder \
        libcrypto \
        liblog \
        libstdc++ \
        libc

LOCAL_ADDITIONAL_DEPENDENCIES := \
    $(TARGET_OUT_INTERMEDIATES)/KERNEL_OBJ/usr \
    $(LOCAL_PATH)/Android.mk

LOCAL_MODULE_TAGS := optional

include $(BUILD_SHARED_LIBRARY)

endif # TARGET_BOARD_SOC
endif # TARGET_PROVIDES_KEYMASTER
