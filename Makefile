#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

ifeq ($(STANDALONE),)
PROJECT_NAME := hephaistos-aha

include $(IDF_PATH)/make/project.mk
else

CPPFLAGS := -Imain/include \
            -Icomponents/expat-dom/include \
            -Icomponents/expat-dom/src \
            -Ibuild/include

LDFLAGS := -lmbedtls \
           -lmbedx509 \
           -lmbedcrypto \
           -lexpat \
           -lbsd

SRCFILES := main/hephaistos_aha_main.c \
            components/expat-dom/src/escape.c \
            components/expat-dom/src/expat-dom.c

ifneq ($(TESTDATA),)
CPPFLAGS += -DTESTDATA_FILE='"$(TESTDATA)"'
endif

all: hephaistos
hephaistos:
	gcc $(CPPFLAGS) $(LDFLAGS) $(SRCFILES) -o $@

clean:
	rm -f hephaistos

.PHONY: hephaistos

endif
