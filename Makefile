# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

PROJECT_ROOT := $(CURDIR)
BUILD := $(PROJECT_ROOT)/build

API ?= 35
HOST_CC ?= clang
HOST_OS := $(shell uname -s)
NDK_HOST_TAG ?= $(if $(filter Darwin,$(HOST_OS)),darwin-x86_64,linux-x86_64)
DEFAULT_NDK_ROOTS := \
  /opt/homebrew/share/android-ndk \
  $(HOME)/android-ndk-cache/android-ndk-r29 \
  $(wildcard /opt/homebrew/Caskroom/android-ndk/*/AndroidNDK*.app/Contents/NDK)
NDK_ROOT ?= $(or $(ANDROID_NDK_HOME),$(ANDROID_NDK_ROOT),$(firstword $(wildcard $(DEFAULT_NDK_ROOTS))))
NDK_BIN := $(NDK_ROOT)/toolchains/llvm/prebuilt/$(NDK_HOST_TAG)/bin
TARGET64_CC := $(NDK_BIN)/aarch64-linux-android$(API)-clang
TARGET32_CC := $(NDK_BIN)/armv7a-linux-androideabi$(API)-clang

HOST_BIN := $(BUILD)/xpad2-ionstack-reroot
WINDOWS_HOST_BIN := $(BUILD)/xpad2-ionstack-reroot.exe
DEVICE_BIN := $(BUILD)/ionstack_reroot_device
TARGET_BIN := $(BUILD)/ionstack_perf_target
PROBE_BIN := $(BUILD)/cve_2026_43499_chainwalk_probe_arm32
SU_BIN := $(BUILD)/su_daemon_aarch64_pie
PRELOAD_BIN := $(BUILD)/ionstack_preload.so

EXPLOIT_SRCS := \
  src/exploit/main.c \
  src/exploit/util.c \
  src/exploit/slide.c \
  src/exploit/fops.c \
  src/exploit/pipe.c \
  src/exploit/root.c \
  src/exploit/preload.c \
  src/exploit/su_blob.S

COMMON_WARN := -Wall -Wextra -Werror
HOST_CFLAGS := -O2 -std=c11 $(COMMON_WARN)
WINDOWS_CC ?= x86_64-w64-mingw32-clang
WINDOWS_HOST_CFLAGS := -O2 -std=c11 $(COMMON_WARN)
TARGET_CFLAGS := -O2 -fPIE -pie $(COMMON_WARN)
EXPLOIT_CFLAGS := -O2 -g0 -fPIC -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
UNSAFE_CONFIGFS_READ ?= 0
EXPLOIT_CFLAGS += -DIONSTACK_ENABLE_UNSAFE_CONFIGFS_READ=$(UNSAFE_CONFIGFS_READ)

.DEFAULT_GOAL := all
.PHONY: all clean info check-tools host host-windows

all: check-tools $(HOST_BIN) $(DEVICE_BIN) $(TARGET_BIN) $(PROBE_BIN) $(PRELOAD_BIN)

host: $(HOST_BIN)

host-windows: $(WINDOWS_HOST_BIN)

check-tools:
	@test -x "$(TARGET64_CC)" || { echo "Android NDK compiler not found: $(TARGET64_CC)" >&2; exit 1; }
	@test -x "$(TARGET32_CC)" || { echo "Android NDK compiler not found: $(TARGET32_CC)" >&2; exit 1; }

$(BUILD):
	mkdir -p $@

$(HOST_BIN): src/host/ionstack_reroot.c | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@

$(WINDOWS_HOST_BIN): src/host/ionstack_reroot.c | $(BUILD)
	$(WINDOWS_CC) $(WINDOWS_HOST_CFLAGS) $< -o $@

$(DEVICE_BIN): src/device/ionstack_reroot_device.c | $(BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(TARGET_BIN): src/device/ionstack_perf_target.c | $(BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(PROBE_BIN): src/trigger/cve_2026_43499_chainwalk_probe.c | $(BUILD)
	$(TARGET32_CC) -O2 -Wall -Wextra -pthread $< -o $@

$(SU_BIN): tools/su_daemon.c | $(BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(PRELOAD_BIN): $(EXPLOIT_SRCS) $(SU_BIN) src/exploit/common.h \
                src/exploit/offset.h src/exploit/kernelsnitch/*.h | $(BUILD)
	$(TARGET64_CC) $(EXPLOIT_CFLAGS) $(EXPLOIT_SRCS) -shared -pthread -o $@

info:
	@echo PROJECT_ROOT=$(PROJECT_ROOT)
	@echo NDK_ROOT=$(NDK_ROOT)
	@echo HOST_BIN=$(HOST_BIN)
	@echo WINDOWS_HOST_BIN=$(WINDOWS_HOST_BIN)
	@echo DEVICE_BIN=$(DEVICE_BIN)
	@echo TARGET_BIN=$(TARGET_BIN)
	@echo PROBE_BIN=$(PROBE_BIN)
	@echo PRELOAD_BIN=$(PRELOAD_BIN)

clean:
	rm -rf $(BUILD)
