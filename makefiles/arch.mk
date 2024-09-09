ARCH ?= $(shell uname -m)
SRCARCH := $(ARCH)

# Additional ARCH settings for x86
ifeq ($(ARCH),i386)
        SRCARCH := x86
endif
ifeq ($(ARCH),x86_64)
        SRCARCH := x86
endif

# Additional ARCH settings for arm64
ifeq ($(ARCH),aarch64)
        SRCARCH := arm64
endif

# Additional ARCH settings for loongarch64
ifeq ($(ARCH),loongarch64)
        SRCARCH := loongarch
endif

# Additional ARCH settings for sparc
ifeq ($(ARCH),sparc32)
       SRCARCH := sparc
endif
ifeq ($(ARCH),sparc64)
       SRCARCH := sparc
endif

# Additional ARCH settings for sh
ifeq ($(ARCH),sh64)
       SRCARCH := sh
endif

# Additional ARCH settings for tile
ifeq ($(ARCH),tilepro)
       SRCARCH := tile
endif
ifeq ($(ARCH),tilegx)
       SRCARCH := tile
endif
