# -*- Mode: makefile -*-
#
# This Makefile example is fairly independent from the main makefile
# so users can take and adapt it for their build. We only really
# include config-host.mak so we don't have to repeat probing for
# cflags that the main configure has already done for us.
#

SRC_PATH := $(CURDIR)/../qemu/
BUILD_DIR := $(SRC_PATH)/build

include $(BUILD_DIR)/config-host.mak

VPATH += $(SRC_PATH)/contrib/plugins

NAMES :=
NAMES += trace

SONAMES := $(addsuffix .so,$(addprefix lib,$(NAMES)))

# The main QEMU uses Glib extensively so it's perfectly fine to use it
# in plugins (which many example do).
CFLAGS = $(GLIB_CFLAGS)
CFLAGS += -fPIC -Wall $(filter -W%, $(QEMU_CFLAGS))
CFLAGS += $(if $(findstring no-psabi,$(QEMU_CFLAGS)),-Wpsabi)
CFLAGS += -I$(SRC_PATH)/include/qemu

CFLAGS += $(shell pkg-config --cflags capnp)
LDLIBS += $(shell pkg-config --libs capnp)

all: $(SONAMES)

trace.o: trace.cpp trace.capnp.c++
	$(CXX) $(CFLAGS) -c -o $@ $<

lib%.so: %.o
	$(CXX) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

%.capnp.h, %.capnp.c++: %.capnp
	capnp compile -oc++ $<

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
