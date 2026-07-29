# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 yoyicue

PROJECT_ROOT := $(CURDIR)
BUILD := $(PROJECT_ROOT)/build

API ?= 35
PROFILE ?= xpad2
# PD2 and PD2P are independent deliverables. Keep their device payloads in
# profile-owned directories so a stale host-controller filename can never
# pick up artifacts from the most recently built sibling profile.
PROFILE_BUILD := $(if $(filter $(PROFILE),xpad2 xpad2p),$(BUILD)/$(PROFILE),$(BUILD))
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

ANDROID_SDK_ROOT ?= /opt/homebrew/share/android-commandlinetools
ANDROID_BUILD_TOOLS ?= $(ANDROID_SDK_ROOT)/build-tools/34.0.0
ANDROID_JAR ?= $(ANDROID_SDK_ROOT)/platforms/android-34/android.jar
AAPT := $(ANDROID_BUILD_TOOLS)/aapt
D8 := $(ANDROID_BUILD_TOOLS)/d8
ZIPALIGN := $(ANDROID_BUILD_TOOLS)/zipalign
APKSIGNER := $(ANDROID_BUILD_TOOLS)/apksigner

HOST_BIN := $(BUILD)/$(PROFILE)-ionstack-reroot
WINDOWS_HOST_BIN := $(BUILD)/$(PROFILE)-ionstack-reroot.exe
DEVICE_BIN := $(PROFILE_BUILD)/ionstack_reroot_device
TARGET_BIN := $(PROFILE_BUILD)/ionstack_perf_target
PROBE_BIN := $(PROFILE_BUILD)/cve_2026_43499_chainwalk_probe_arm32
XPAD3S_AUDIT_BIN := $(PROFILE_BUILD)/xpad3s_profile_audit
XPAD3S_TRACE_PROBE_BIN := $(PROFILE_BUILD)/xpad3s_tracepoint_probe
SU_BIN := $(PROFILE_BUILD)/su_daemon_aarch64_pie
PRELOAD_BIN := $(PROFILE_BUILD)/ionstack_preload.so
TRIGGER_APK := $(PROFILE_BUILD)/ionstack_trigger_app.apk
TRIGGER_APP_BUILD := $(PROFILE_BUILD)/trigger-app
TRIGGER_APP_KEYSTORE ?= $(PROJECT_ROOT)/.signing/ionstack-trigger.keystore
PROFILE_STAMP := $(PROFILE_BUILD)/.profile

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
HOST_PROFILE_CFLAGS := -DIONSTACK_ARTIFACT_DIR=\"build/$(PROFILE)\"
WINDOWS_CC ?= x86_64-w64-mingw32-clang
WINDOWS_HOST_CFLAGS := -O2 -std=c11 $(COMMON_WARN)
WINDOWS_HOST_PROFILE_CFLAGS := $(HOST_PROFILE_CFLAGS)
TARGET_CFLAGS := -O2 -fPIE -pie $(COMMON_WARN)
ifeq ($(PROFILE),xpad3s)
HOST_PROFILE_CFLAGS := -DIONSTACK_ARTIFACT_DIR=\"build\"
WINDOWS_HOST_PROFILE_CFLAGS := $(HOST_PROFILE_CFLAGS)
TARGET_CFLAGS += -DIONSTACK_PROFILE_XPAD3S=1
EXPLOIT_PROFILE_CFLAGS := -DIONSTACK_PROFILE_XPAD3S=1
EXPLOIT_PROFILE_HEADERS := \
  src/exploit/profiles/xpad3s_offset.h \
  src/exploit/profiles/xpad3s_layout.h \
  src/exploit/profiles/xpad3s_symbols.h
PROFILE_ARTIFACTS := $(HOST_BIN) $(DEVICE_BIN) $(TARGET_BIN) $(PROBE_BIN) \
  $(XPAD3S_AUDIT_BIN) $(XPAD3S_TRACE_PROBE_BIN) $(PRELOAD_BIN) $(TRIGGER_APK)
else ifeq ($(PROFILE),xpad2p)
TARGET_CFLAGS += -DIONSTACK_PROFILE_XPAD2P=1
EXPLOIT_PROFILE_CFLAGS := -DIONSTACK_PROFILE_XPAD2P=1
EXPLOIT_PROFILE_HEADERS := src/exploit/profiles/xpad2p_offset.h
PROFILE_ARTIFACTS := $(HOST_BIN) $(DEVICE_BIN) $(TARGET_BIN) $(PROBE_BIN) \
  $(PRELOAD_BIN)
else ifeq ($(PROFILE),xpad2)
PROFILE_ARTIFACTS := $(HOST_BIN) $(DEVICE_BIN) $(TARGET_BIN) $(PROBE_BIN) $(PRELOAD_BIN)
else
$(error Unsupported PROFILE=$(PROFILE); expected xpad2, xpad2p, or xpad3s)
endif
EXPLOIT_CFLAGS := -O2 -g0 -fPIC -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function
UNSAFE_CONFIGFS_READ ?= 0
EXPLOIT_CFLAGS += -DIONSTACK_ENABLE_UNSAFE_CONFIGFS_READ=$(UNSAFE_CONFIGFS_READ)

.DEFAULT_GOAL := all
.PHONY: all clean info check-tools host host-windows release-xpad2 release-xpad2p release-xpad3s \
        test test-profiles test-python

all: check-tools $(PROFILE_ARTIFACTS)

host: $(HOST_BIN)

host-windows: $(WINDOWS_HOST_BIN)

release-xpad2:
	tools/build_xpad2_release.sh

release-xpad2p:
	tools/build_xpad2p_release.sh

release-xpad3s:
	tools/build_xpad3s_release.sh

test: test-profiles test-python

test-profiles: | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) tests/device_profile_test.c \
	  -o $(BUILD)/device_profile_test_xpad2
	$(HOST_CC) $(HOST_CFLAGS) -DIONSTACK_PROFILE_XPAD2P=1 \
	  tests/device_profile_test.c -o $(BUILD)/device_profile_test_xpad2p
	$(HOST_CC) $(HOST_CFLAGS) -DIONSTACK_PROFILE_XPAD3S=1 \
	  tests/device_profile_test.c -o $(BUILD)/device_profile_test_xpad3s
	$(BUILD)/device_profile_test_xpad2
	$(BUILD)/device_profile_test_xpad2p
	$(BUILD)/device_profile_test_xpad3s

test-python:
	PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
	  -s tests -p '*_test.py'

check-tools:
	@test -x "$(TARGET64_CC)" || { echo "Android NDK compiler not found: $(TARGET64_CC)" >&2; exit 1; }
	@test -x "$(TARGET32_CC)" || { echo "Android NDK compiler not found: $(TARGET32_CC)" >&2; exit 1; }

$(BUILD):
	mkdir -p $@

ifneq ($(PROFILE_BUILD),$(BUILD))
$(PROFILE_BUILD): | $(BUILD)
	mkdir -p $@
endif

$(PROFILE_STAMP): | $(PROFILE_BUILD)
	@echo "$(PROFILE)" > "$(PROFILE_STAMP)"

$(HOST_BIN): src/host/ionstack_reroot.c | $(BUILD)
	$(HOST_CC) $(HOST_CFLAGS) $(HOST_PROFILE_CFLAGS) $< -o $@

$(WINDOWS_HOST_BIN): src/host/ionstack_reroot.c | $(BUILD)
	$(WINDOWS_CC) $(WINDOWS_HOST_CFLAGS) $(WINDOWS_HOST_PROFILE_CFLAGS) $< -o $@

$(DEVICE_BIN): src/device/ionstack_reroot_device.c src/device/profile.h \
               src/device/profile_match.h src/device/fingerprint.h \
               $(PROFILE_STAMP) | $(PROFILE_BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(TARGET_BIN): src/device/ionstack_perf_target.c src/device/perf_profile.h \
               $(PROFILE_STAMP) | $(PROFILE_BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(PROBE_BIN): src/trigger/cve_2026_43499_chainwalk_probe.c | $(PROFILE_BUILD)
	$(TARGET32_CC) -O2 -Wall -Wextra -pthread $< -o $@

$(TRIGGER_APK): src/trigger/cve_2026_43499_chainwalk_probe.c \
                src/trigger/app/native_bridge.c \
                src/trigger/app/AndroidManifest.xml \
                src/trigger/app/com/ionstack/trigger/MainActivity.java \
                src/trigger/app/com/ionstack/trigger/TriggerService.java | $(PROFILE_BUILD)
	rm -rf $(TRIGGER_APP_BUILD)
	mkdir -p $(TRIGGER_APP_BUILD)/classes $(TRIGGER_APP_BUILD)/dex \
	  $(TRIGGER_APP_BUILD)/stage/lib/armeabi-v7a
	$(TARGET32_CC) -O2 -Wall -Wextra -pthread -fPIC \
	  -Dmain=ionstack_probe_main -c $< \
	  -o $(TRIGGER_APP_BUILD)/probe.o
	$(TARGET32_CC) -O2 -Wall -Wextra -fPIC -c \
	  src/trigger/app/native_bridge.c \
	  -o $(TRIGGER_APP_BUILD)/native_bridge.o
	$(TARGET32_CC) -shared -pthread $(TRIGGER_APP_BUILD)/probe.o \
	  $(TRIGGER_APP_BUILD)/native_bridge.o \
	  -o $(TRIGGER_APP_BUILD)/stage/lib/armeabi-v7a/libionstack_trigger.so
	$(JAVA_HOME)/bin/javac -source 8 -target 8 -bootclasspath $(ANDROID_JAR) \
	  -d $(TRIGGER_APP_BUILD)/classes \
	  src/trigger/app/com/ionstack/trigger/MainActivity.java \
	  src/trigger/app/com/ionstack/trigger/TriggerService.java
	$(JAVA_HOME)/bin/jar cf $(TRIGGER_APP_BUILD)/classes.jar \
	  -C $(TRIGGER_APP_BUILD)/classes .
	$(D8) --min-api 23 --lib $(ANDROID_JAR) --output $(TRIGGER_APP_BUILD)/dex \
	  $(TRIGGER_APP_BUILD)/classes.jar
	cp $(TRIGGER_APP_BUILD)/dex/classes.dex $(TRIGGER_APP_BUILD)/stage/classes.dex
	$(AAPT) package -f -M src/trigger/app/AndroidManifest.xml \
	  -I $(ANDROID_JAR) -F $(TRIGGER_APP_BUILD)/unsigned.apk
	cd $(TRIGGER_APP_BUILD)/stage && \
	  $(AAPT) add ../unsigned.apk classes.dex \
	    lib/armeabi-v7a/libionstack_trigger.so
	$(ZIPALIGN) -f 4 $(TRIGGER_APP_BUILD)/unsigned.apk \
	  $(TRIGGER_APP_BUILD)/aligned.apk
	mkdir -p $(dir $(TRIGGER_APP_KEYSTORE))
	test -f $(TRIGGER_APP_KEYSTORE) || \
	  $(JAVA_HOME)/bin/keytool -genkeypair -noprompt \
	    -keystore $(TRIGGER_APP_KEYSTORE) -storepass android -keypass android \
	    -alias ionstack -keyalg RSA -keysize 2048 -validity 10000 \
	    -dname "CN=Ionstack Debug,O=Ionstack,C=US"
	$(APKSIGNER) sign --ks $(TRIGGER_APP_KEYSTORE) \
	  --ks-pass pass:android --key-pass pass:android --out $@ \
	  $(TRIGGER_APP_BUILD)/aligned.apk

$(XPAD3S_AUDIT_BIN): tools/xpad3s_profile_audit.c \
                     src/exploit/profiles/xpad3s_layout.h \
                     src/exploit/profiles/xpad3s_symbols.h | $(PROFILE_BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(XPAD3S_TRACE_PROBE_BIN): tools/xpad3s_tracepoint_probe.c | $(PROFILE_BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(SU_BIN): tools/su_daemon.c | $(PROFILE_BUILD)
	$(TARGET64_CC) $(TARGET_CFLAGS) $< -o $@

$(PRELOAD_BIN): $(EXPLOIT_SRCS) $(SU_BIN) src/exploit/common.h \
                $(PROFILE_STAMP) \
                src/exploit/offset.h $(EXPLOIT_PROFILE_HEADERS) \
                src/exploit/kernelsnitch/*.h | $(PROFILE_BUILD)
	$(TARGET64_CC) $(EXPLOIT_CFLAGS) $(EXPLOIT_PROFILE_CFLAGS) $(EXPLOIT_SRCS) -shared -pthread -o $@

info:
	@echo PROJECT_ROOT=$(PROJECT_ROOT)
	@echo PROFILE=$(PROFILE)
	@echo PROFILE_BUILD=$(PROFILE_BUILD)
	@echo NDK_ROOT=$(NDK_ROOT)
	@echo HOST_BIN=$(HOST_BIN)
	@echo WINDOWS_HOST_BIN=$(WINDOWS_HOST_BIN)
	@echo DEVICE_BIN=$(DEVICE_BIN)
	@echo TARGET_BIN=$(TARGET_BIN)
	@echo PROBE_BIN=$(PROBE_BIN)
	@echo XPAD3S_AUDIT_BIN=$(XPAD3S_AUDIT_BIN)
	@echo XPAD3S_TRACE_PROBE_BIN=$(XPAD3S_TRACE_PROBE_BIN)
	@echo PRELOAD_BIN=$(PRELOAD_BIN)
	@echo TRIGGER_APK=$(TRIGGER_APK)
	@echo PROFILE_DIAG=$(PROJECT_ROOT)/tools/ionstack_profile_diag.py
	@echo AUTO_POC=$(PROJECT_ROOT)/tools/ionstack_auto_poc.py

clean:
	rm -rf $(BUILD)
