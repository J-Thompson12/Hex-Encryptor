LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := active_secret_static
LOCAL_MODULE_FILENAME := libactive_secret
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/src

LOCAL_CPPFLAGS += -std=c++14 -fexceptions -Wall -pedantic

define all-cpp-files-under
$(patsubst ./%, %, \
  $(shell cd $(LOCAL_PATH) ; \
          find $(1) -name "*.cpp" -and -not -name ".*") \
 )
endef

LOCAL_SRC_FILES := \
	$(call all-cpp-files-under, src)

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/src \
	$(LOCAL_PATH)/../clibs/include/android \
	$(LOCAL_PATH)/../mmx-common/src

include $(BUILD_STATIC_LIBRARY)
