# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

PROJECT_ROOT := $(CURDIR)
BUILD := $(PROJECT_ROOT)/build

PROFILE ?= xpad2-v19-b
SUPPORTED_PROFILES := xpad2-v260 xpad2-v19-a xpad2-v19-b

ifeq ($(filter $(PROFILE),$(SUPPORTED_PROFILES)),)
$(error Unsupported PROFILE '$(PROFILE)'; choose one of: $(SUPPORTED_PROFILES))
endif

ifeq ($(PROFILE),xpad2-v260)
PROFILE_DEFINE := IONSTACK_PROFILE_XPAD2_V260
else ifeq ($(PROFILE),xpad2-v19-a)
PROFILE_DEFINE := IONSTACK_PROFILE_XPAD2_V19_A
else ifeq ($(PROFILE),xpad2-v19-b)
PROFILE_DEFINE := IONSTACK_PROFILE_XPAD2_V19_B
endif

PROFILE_CFLAGS := -D$(PROFILE_DEFINE)=1

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
FINGERPRINT_TEST_BIN := $(BUILD)/fingerprint_test
STATE_MACHINE_TEST_BIN := $(BUILD)/state_machine_test

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
.PHONY: all clean info check-tools host host-windows test force-profile \
        release-bundle

all: check-tools $(HOST_BIN) $(DEVICE_BIN) $(TARGET_BIN) $(PROBE_BIN) $(PRELOAD_BIN)

host: $(HOST_BIN)

host-windows: $(WINDOWS_HOST_BIN)

release-bundle:
	tools/build_release_bundle.sh

test: $(FINGERPRINT_TEST_BIN) $(STATE_MACHINE_TEST_BIN)
	$(FINGERPRINT_TEST_BIN)
	$(STATE_MACHINE_TEST_BIN)
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests -p '*_test.py'

check-tools:
	@test -x "$(TARGET64_CC)" || { echo "Android NDK compiler not found: $(TARGET64_CC)" >&2; exit 1; }
	@test -x "$(TARGET32_CC)" || { echo "Android NDK compiler not found: $(TARGET32_CC)" >&2; exit 1; }

$(BUILD):
	mkdir -p $@

# Make does not track command-line flag changes. Rebuild binaries that embed
# profile constants so switching PROFILE can never reuse stale offsets.
force-profile:

$(HOST_BIN): src/host/ionstack_reroot.c | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@

$(WINDOWS_HOST_BIN): src/host/ionstack_reroot.c | $(BUILD)
	$(WINDOWS_CC) $(WINDOWS_HOST_CFLAGS) $< -o $@

$(FINGERPRINT_TEST_BIN): tests/fingerprint_test.c src/fingerprint.h \
                         src/profile.h force-profile | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(PROFILE_CFLAGS) $< -o $@

$(STATE_MACHINE_TEST_BIN): tests/state_machine_test.c src/state_machine.h | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $< -o $@

$(DEVICE_BIN): src/device/ionstack_reroot_device.c src/fingerprint.h \
               src/profile.h src/state_machine.h force-profile | $(BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $(PROFILE_CFLAGS) $< -o $@

$(TARGET_BIN): src/device/ionstack_perf_target.c | $(BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(PROBE_BIN): src/trigger/cve_2026_43499_chainwalk_probe.c | $(BUILD)
	$(TARGET32_CC) -O2 -Wall -Wextra -pthread $< -o $@

$(SU_BIN): tools/su_daemon.c | $(BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(PRELOAD_BIN): $(EXPLOIT_SRCS) $(SU_BIN) src/exploit/common.h \
                src/exploit/offset.h src/exploit/kernelsnitch/*.h \
                src/profile.h force-profile | $(BUILD)
	$(TARGET64_CC) $(EXPLOIT_CFLAGS) $(PROFILE_CFLAGS) $(EXPLOIT_SRCS) \
		-shared -pthread -o $@

info:
	@echo PROJECT_ROOT=$(PROJECT_ROOT)
	@echo PROFILE=$(PROFILE)
	@echo SUPPORTED_PROFILES=$(SUPPORTED_PROFILES)
	@echo NDK_ROOT=$(NDK_ROOT)
	@echo HOST_BIN=$(HOST_BIN)
	@echo WINDOWS_HOST_BIN=$(WINDOWS_HOST_BIN)
	@echo DEVICE_BIN=$(DEVICE_BIN)
	@echo TARGET_BIN=$(TARGET_BIN)
	@echo PROBE_BIN=$(PROBE_BIN)
	@echo PRELOAD_BIN=$(PRELOAD_BIN)
	@echo PROFILE_DIAG=$(PROJECT_ROOT)/tools/ionstack_profile_diag.py
	@echo CRASH_HARVEST=$(PROJECT_ROOT)/tools/ionstack_crash_harvest.py
	@echo AUTO_POC=$(PROJECT_ROOT)/tools/ionstack_auto_poc.py
	@echo RELEASE_BUNDLE=$(PROJECT_ROOT)/dist/xpad2-19-260

clean:
	rm -rf $(BUILD)
