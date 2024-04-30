# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

pound := \#

CFLAGS_BACKUP := $(CFLAGS)
CFLAGS := $(EXTRA_CFLAGS)
ifneq ($(LLVM),)
  CFLAGS += -Wno-unused-command-line-argument
endif

ifeq ($(V),1)
  LOG=$(warning $(1))
  LOG_RES = (echo $(1) && >&2 echo result: $(1))
  define detect
    $(warning $(1) && $(call LOG_RES,1) || $(call LOG_RES,0))
    $(shell $(1) && $(call LOG_RES,1) || $(call LOG_RES,0))
  endef
else
  LOG=
  LOG_RES = (echo $(1))
  define detect
    $(shell $(1) 2>&1 && $(call LOG_RES,1) || $(call LOG_RES,0))
  endef
  QUIET_STDERR := 2>/dev/null
endif

### feature-clang-bpf-co-re

CLANG_BPF_CO_RE_PROBE_CMD = \
  printf '%s\n' 'struct s { int i; } __attribute__((preserve_access_index)); struct s foo;' | \
    $(CLANG) -g -target bpf -S -o - -x c - $(QUIET_STDERR) | grep -q BTF_KIND_VAR

ifneq ($(findstring clang-bpf-co-re,$(FEATURE_TESTS)),)
$(call LOG,Probing: feature-clang-bpf-co-re)
feature-clang-bpf-co-re := \
  $(findstring 1,$(call detect,$(CLANG_BPF_CO_RE_PROBE_CMD)))
endif # clang-bpf-co-re

### feature-libbfd

ifneq ($(findstring libbfd,$(FEATURE_TESTS)),)
LIBBFD_PROBE := '$(pound)include <bfd.h>\n'
LIBBFD_PROBE += 'int main(void) {'
LIBBFD_PROBE += '	bfd_demangle(0, 0, 0);'
LIBBFD_PROBE += '	return 0;'
LIBBFD_PROBE += '}'
LIBBFD_PROBE_CMD = printf '%b\n' $(LIBBFD_PROBE) | \
  $(CC) $(CFLAGS) -Wall -Werror -x c - $(1) -o /dev/null >/dev/null

define libbfd_build
  $(call detect,$(LIBBFD_PROBE_CMD))
endef

$(call LOG,Probing: feature-libbfd)
feature-libbfd := \
  $(findstring 1,$(call libbfd_build,-lbfd -ldl))
ifneq ($(feature-libbfd),1)
  $(call LOG,Probing: feature-libbfd-liberty)
  feature-libbfd-liberty := \
    $(findstring 1,$(call libbfd_build,-lbfd -ldl -liberty))
  ifneq ($(feature-libbfd-liberty),1)
    $(call LOG,Probing: feature-libbfd-liberty-z)
    feature-libbfd-liberty-z := \
      $(findstring 1,$(call libbfd_build,-lbfd -ldl -liberty -lz))
  endif
endif
HAS_LIBBFD := $(findstring 1, \
  $(feature-libbfd)$(feature-libbfd-liberty)$(feature-libbfd-liberty-z))
endif # libbfd

### feature-disassembler-four-args

ifneq ($(findstring disassembler-four-args,$(FEATURE_TESTS)),)
DISASSEMBLER_PROBE := '$(pound)include <dis-asm.h>\n'
DISASSEMBLER_PROBE += 'int main(void) {'
DISASSEMBLER_PROBE += '	disassembler((enum bfd_architecture)0, 0, 0, NULL);'
DISASSEMBLER_PROBE += '	return 0;'
DISASSEMBLER_PROBE += '}'

DISASSEMBLER_PROBE_CMD = printf '%b\n' $(1) | \
  $(CC) $(CFLAGS) -Wall -Werror -x c - -lbfd -lopcodes -S -o - >/dev/null
define disassembler_build
  $(call detect,$(DISASSEMBLER_PROBE_CMD))
endef

$(call LOG,Probing: feature-disassembler-four-args)
feature-disassembler-four-args := \
    $(findstring 1, $(call disassembler_build,$(DISASSEMBLER_PROBE)))
endif # disassembler-four-args

### feature-disassembler-init-styled

ifneq ($(findstring disassembler-init-styled,$(FEATURE_TESTS)),)
DISASSEMBLER_STYLED_PROBE := '$(pound)include <dis-asm.h>\n'
DISASSEMBLER_STYLED_PROBE += 'int main(void) {'
DISASSEMBLER_STYLED_PROBE += '	init_disassemble_info(NULL, 0, NULL, NULL);'
DISASSEMBLER_STYLED_PROBE += '	return 0;'
DISASSEMBLER_STYLED_PROBE += '}'

$(call LOG,Probing: feature-disassembler-styled)
feature-disassembler-init-styled := \
    $(findstring 1, $(call disassembler_build,$(DISASSEMBLER_STYLED_PROBE)))
endif # disassembler-init-styled

### feature-libcap

ifneq ($(findstring libcap,$(FEATURE_TESTS)),)
LIBCAP_PROBE := '$(pound)include <sys/capability.h>\n'
LIBCAP_PROBE += 'int main(void) {'
LIBCAP_PROBE += '	cap_free(0);'
LIBCAP_PROBE += '	return 0;'
LIBCAP_PROBE += '}'
LIBCAP_PROBE_CMD = printf '%b\n' $(LIBCAP_PROBE) | \
  $(CC) $(CFLAGS) -Wall -Werror -x c - -lcap -S -o - >/dev/null

define libcap_build
  $(call detect,$(LIBCAP_PROBE_CMD))
endef

$(call LOG,Probing: feature-libcap)
feature-libcap := $(findstring 1, $(call libcap_build))
endif # libcap

### feature-llvm

ifneq ($(findstring llvm,$(FEATURE_TESTS)),)
LLVM_PROBE := '$(pound)include <llvm-c/Core.h>\n'
LLVM_PROBE += '$(pound)include <llvm-c/TargetMachine.h>\n'
LLVM_PROBE += 'int main(void) {'
LLVM_PROBE += '	char *triple = LLVMNormalizeTargetTriple("");'
LLVM_PROBE += '	LLVMDisposeMessage(triple);'
LLVM_PROBE += '	return 0;'
LLVM_PROBE += '}'

# We need some adjustments for the flags.
# - $(CFLAGS) was set to parent $(EXTRA_CFLAGS) at the beginning of this file.
# - $(EXTRA_LDFLAGS) from parent Makefile should be kept as well.
# - Libraries to use depend on whether we have a static or shared version of
#   LLVM, pass the llvm-config flag and adjust the list of libraries
#   accordingly.
FEATURE_LLVM_CFLAGS := $(CFLAGS) $(shell $(LLVM_CONFIG) --cflags 2>/dev/null)
FEATURE_LLVM_LIBS := $(shell $(LLVM_CONFIG) --libs target 2>/dev/null)
ifeq ($(shell $(LLVM_CONFIG) --shared-mode 2>/dev/null),static)
  FEATURE_LLVM_LIBS += $(shell $(LLVM_CONFIG) --system-libs target 2>/dev/null)
  FEATURE_LLVM_LIBS += -lstdc++
endif
FEATURE_LDFLAGS := $(EXTRA_LDFLAGS) $(shell $(LLVM_CONFIG) --ldflags 2>/dev/null)

LLVM_PROBE_CMD = printf '%b\n' $(LLVM_PROBE) | \
  $(CC) $(FEATURE_LLVM_CFLAGS) $(FEATURE_LDFLAGS) \
    -Wall -Werror -x c - $(FEATURE_LLVM_LIBS) \
    -o /dev/null >/dev/null

define llvm_build
  $(call detect,$(LLVM_PROBE_CMD))
endef

$(call LOG,Probing: feature-llvm)
feature-llvm := $(findstring 1, $(call llvm_build))
endif # llvm

### Print detection results

define print_status
  ifeq ($(1), 1)
    MSG = $(shell printf '...%30s: [ \033[32mon\033[m  ]' $(2))
  else
    MSG = $(shell printf '...%30s: [ \033[31mOFF\033[m ]' $(2))
  endif
endef
feature_print_status = $(eval $(print_status)) $(info $(MSG))

$(call feature_print_status,$(HAS_LIBBFD),libbfd)

$(foreach feature,$(filter-out libbfd%,$(FEATURE_DISPLAY)), \
  $(call feature_print_status,$(feature-$(feature)),$(feature)))

CFLAGS := $(CFLAGS_BACKUP)
undefine LOG LOG_RES
