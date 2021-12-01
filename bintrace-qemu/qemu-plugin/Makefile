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

all: $(SONAMES)

LDLIBS += -lflatbuffers
trace.o: trace.cpp trace_generated.h
	$(CXX) $(CFLAGS) -c -o $@ $<

BINTRACE_DIR = $(shell python -c "import os.path as o, importlib.util as i; print(o.dirname(i.find_spec('bintrace').origin))")
BINTRACE_PROTO = $(BINTRACE_DIR)/trace.fbs

lib%.so: %.o
	$(CXX) -shared -Wl,-soname,$@ -o $@ $^ $(LDLIBS)

trace_generated.h: $(BINTRACE_PROTO)
	flatc --cpp $<

clean:
	rm -f *.o *.so *.d
	rm -Rf .libs

.PHONY: all clean
