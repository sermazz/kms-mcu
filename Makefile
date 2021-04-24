SHELL = /usr/bin/env bash

# Project set-up
HOST_DIR     := host
DEVICE_DIR   := device
DEVICE_NUM   ?= 2

DEVICE_BIN_PREFIX := $(DEVICE_DIR)/Debug
DEVICE_BIN_NAME   := secube-proj.elf
INSTALL_DIR       := ./install

DEVICE_BINS  := $(addsuffix /$(DEVICE_DIR), $(addprefix $(INSTALL_DIR)/$(DEVICE_DIR)_,$(shell seq -s " " 0 1 $$(( $(DEVICE_NUM) - 1 )) )))

# QEMU set-up
# Use the specified QEMU_PATH only if QEMU_BIN is not found in the PATH variable
QEMU_PATH    ?= /root/opt/xPacks/@xpack-dev-tools/qemu-arm/2.8.0-9.1/.content/bin
QEMU_BIN     := qemu-system-gnuarmeclipse

# Automatically identify whether QEMU binary is in the PATH or not
ifeq ($(shell type $(QEMU_BIN) >/dev/null 2>&1 && echo 1 || echo 0), 1)
QEMU         := $(QEMU_BIN)
else
QEMU         := $(QEMU_PATH)/$(QEMU_BIN)
endif

QEMU_BOARD   := STM32F4-Discovery
QEMU_MCU     := STM32F429ZI
QEMU_FLAGS   := -nographic -semihosting-config enable=on -d unimp,guest_errors

.DEFAULT_GOAL := all

# ---- Installation targets -----

.PHONY: all devices host

# Create device instances and compile host
all: devices host

# Instantiate the directories of all desired devices
#(do this after building device project in Eclipse!)
devices: $(DEVICE_BINS)

# All source files in device project are dependencies of this target
$(DEVICE_BINS): $(shell find ./$(DEVICE_DIR)/Debug -type f) $(shell find ./$(DEVICE_DIR)/include -type f) $(shell find ./$(DEVICE_DIR)/src -type f) $(shell find ./$(DEVICE_DIR)/system -type f)
	@mkdir -p $(INSTALL_DIR)
	@echo "Instantiating device #$(@:$(subst ./,,$(INSTALL_DIR))/$(DEVICE_DIR)_%=%)"
	mkdir -p $(dir $@)
	cp -f $(DEVICE_BIN_PREFIX)/$(DEVICE_BIN_NAME) $@

# Compile host source
host:
	@echo "Building host software"
	TARGET_EXEC=$(HOST_DIR) INSTALL_DIR=.$(INSTALL_DIR) make -C $(HOST_DIR) all

# -------- Run targets ---------

.PHONY: run_device_% run_host

# Launch QEMU running device_% (to exit from QEMU press q, then ENTER)
run_device_%:
	cd $(INSTALL_DIR)/$(DEVICE_DIR)_$* && \
	$(QEMU) $(QEMU_FLAGS) -board $(QEMU_BOARD) -mcu $(QEMU_MCU) --image $(DEVICE_DIR)

# Launch host
run_host:
	cd $(INSTALL_DIR)/$(HOST_DIR) && \
	./$(HOST_DIR)

# ------- Helper targets -------

.PHONY: clean_mem clean

# Clean communication channels and non-volatile memory of every instantiated device
clean_mem:
	@rm -f $(DEVICE_DIR)/channel_* $(DEVICE_DIR)/nv_mem
	@for device_dir in $$(ls $(INSTALL_DIR) | grep $(DEVICE_DIR)); do \
	rm -f $(INSTALL_DIR)/$$device_dir/channel_* $(INSTALL_DIR)/$$device_dir/nv_mem; \
	done
	@echo "Cleaning channel buffers and non-volatile memories"

# Clean the project
clean: clean_mem
	TARGET_EXEC=$(HOST_DIR) INSTALL_DIR=.$(INSTALL_DIR) make -C $(HOST_DIR) clean
	rm -rf $(INSTALL_DIR)
