ifeq ($(TARGET_BOARD_SOC),pxa1908)
    #This is for 1908 based platforms
    include $(call all-named-subdir-makefiles,pxa1908)
endif
