V:=1
OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ./libbpf/src)
BPFTOOL_SRC := $(abspath ./bpftool/src)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
VMLINUX := ./vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I./libbpf/include/uapi -I$(dir $(VMLINUX))
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')
APPS = kyanos
CFLAGS := -O2
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
ROOT		:= $(abspath .)

include $(ROOT)/makefiles/arch.mk

HEADERS		:= $(if $(KERNEL),$(KERNEL),/lib/modules/$(shell uname -r)/build/)
NOSTDINC_FLAGS	+= -nostdinc -isystem $(shell $(CC) -print-file-name=include)
USERINCLUDE	:= \
		-I$(HEADERS)/arch/$(SRCARCH)/include/uapi \
		-I$(HEADERS)/arch/$(SRCARCH)/include/generated/uapi \
		-I$(HEADERS)/include/uapi \
		-I$(HEADERS)/include/generated/uapi \
		-include $(HEADERS)/include/linux/kconfig.h \
		-I/usr/include/

LINUXINCLUDE	:= \
		-I$(HEADERS)/arch/$(SRCARCH)/include \
		-I$(HEADERS)/arch/$(SRCARCH)/include/generated \
		-I$(HEADERS)/include \
		$(USERINCLUDE)

KERNEL_CFLAGS	+= $(NOSTDINC_FLAGS) $(LINUXINCLUDE) \
		-D__KERNEL__ -DKBUILD_MODNAME='\"bpftrace\"' -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option -Wno-frame-address

ifdef COMPAT 
ifeq ($(wildcard $(HEADERS)),)
$(error kernel headers not exist in COMPAT mode, please install it)
endif
	kheaders_cmd	:= rm -f bpf/kheaders.h && cd bpf && ln -s ../vmlinux_header.h kheaders.h && cd ..
	CFLAGS		+= -DCOMPAT
	CFLAGS += $(KERNEL_CFLAGS)
	CFLAGS += -I./
	VMLINUX := -I./
	VMLINUX += $(LINUXINCLUDE)
	
else
	kheaders_cmd	:= rm -f bpf/kheaders.h && cd bpf && ln -s ../vmlinux/x86/vmlinux.h kheaders.h && cd ..
	VMLINUX := ""
endif

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)


clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS) kyanos kyanos.log bpf/kheaders.h

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

GO_FILES := $(shell find $(SRC_DIR) -type f -name '*.go' | sort)  
bpf/kheaders.h: FORCE
	$(call kheaders_cmd)

FORCE:

kyanos: $(LIBBPF_OBJ) $(GO_FILES) $(wildcard bpf/*.[ch]) | $(OUTPUT)
	$(call msg,BINARY,$@)
	./build.sh "$(CFLAGS)" "$(VMLINUX)"
	rm -f bpf/kheaders.h
# delete failed targets
.DELETE_ON_ERROR: bpf/kheaders.h

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY: