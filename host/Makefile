# Target binary
TARGET       ?= host

# Directories set-up
INSTALL_DIR  ?= ../install
INSTALL_PATH := $(INSTALL_DIR)/$(TARGET)
BUILD_DIR    ?= ./build
SRC_DIRS     ?= ./src
INC_DIRS     := ./include

MKDIR_P ?= mkdir -p

SRCS := $(shell find $(SRC_DIRS) -name *.cpp -or -name *.c -or -name *.s)
OBJS := $(SRCS:%=$(BUILD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

INC_FLAGS := $(addprefix -I,$(INC_DIRS))

CPPFLAGS ?= $(INC_FLAGS) -MMD -MP

.DEFAULT_GOAL := all

.PHONY: all clean

all: $(INSTALL_PATH)/$(TARGET)

# Compile target binary with all objects
$(INSTALL_PATH)/$(TARGET): $(OBJS)
	@echo $(INSTALL_PATH)/$(TARGET)
	@$(MKDIR_P) $(INSTALL_PATH)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Assembly source
$(BUILD_DIR)/%.s.o: %.s
	@$(MKDIR_P) $(dir $@)
	@echo Compiling $<
	@$(AS) $(ASFLAGS) -c $< -o $@

# C source
$(BUILD_DIR)/%.c.o: %.c
	@$(MKDIR_P) $(dir $@)
	@echo Compiling $<
	@$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

# C++ source
$(BUILD_DIR)/%.cpp.o: %.cpp
	@$(MKDIR_P) $(dir $@)
	@echo Compiling $<
	@$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Inlcude deps makefrags for dependencies of object files on headers
-include $(DEPS)

clean:
	$(RM) -rf $(INSTALL_PATH)
	$(RM) -rf $(BUILD_DIR)
	$(RM) $(SRC_DIRS)/*.d
