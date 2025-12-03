# Makefile for building ca_test

# BoringSSL
BORINGSSL := vendor/boringssl
CJSON := vendor/cJSON

CC        := clang
CFLAGS    := -Ishared -I$(BORINGSSL)/include -I$(CJSON) -std=c11 -Wall -Wextra -DDEBUG
LDFLAGS   := $(BORINGSSL)/build/libcrypto.a -framework Security -framework CoreFoundation

# Main executable, not a daemon yet. WIP is from unittest target
SRC       := ca_server.c main.c shared/utils.c handle_request.c vendor/cJSON/cJSON.c
OBJ       := $(SRC:.c=.o)
TARGET    := crtman

# Unit test executable
TEST_SRC  := ca_server.c unittests.c shared/utils.c handle_request.c vendor/cJSON/cJSON.c
TEST_OBJ  := $(TEST_SRC:.c=.o)
TEST_TARGET := test

CLIENT_SRC := ca_client.c shared/utils.c vendor/cJSON/cJSON.c client_test.c
CLIENT_OBJ := $(CLIENT_SRC:.c=.o)
CLIENT_TARGET := crtman-cli

# Installation constants
DAEMON_BIN := crtman
PLIST := com.nordsec.crtman.plist
LAUNCH_DIR := $(HOME)/Library/LaunchAgents

.PHONY: all clean install-launch clean-launch

all: boringssl crtman crtman-cli

crtman: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# Build rule for any .c → .o
%.o: %.c
	$(CC) $(CFLAGS) -g -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_OBJ) $(TEST_TARGET) $(CLIENT_OBJ) $(CLIENT_TARGET)
	rm -rf db/

boringssl:
	cd vendor/boringssl && \
	mkdir -p build && cd build && \
	cmake -GNinja .. && \
	ninja

test: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

runtest:
	python3 unit_test.py

install-launch:
	@echo "Installing CA daemon to $(LAUNCH_DIR)..."
	mkdir -p "$(LAUNCH_DIR)"
	# Copy the daemon binary
	install -m 755 "$(DAEMON_BIN)" "$(LAUNCH_DIR)/$(DAEMON_BIN)"
	# Copy the plist
	install -m 644 "$(PLIST)"  "$(LAUNCH_DIR)/$(PLIST)"
	# Unload any existing job, then load the new one
	-@launchctl unload "$(LAUNCH_DIR)/$(PLIST)" 2>/dev/null || true
	@launchctl load   "$(LAUNCH_DIR)/$(PLIST)"
	@echo "Done. Use 'launchctl list | grep com.example.myCA.daemon' to verify."

clean-launch:
	@echo "Unloading and removing CA daemon..."
	-@launchctl unload "$(LAUNCH_DIR)/$(PLIST)" 2>/dev/null || true
	rm -f "$(LAUNCH_DIR)/$(PLIST)" "$(LAUNCH_DIR)/$(DAEMON_BIN)"
	@echo "Removed."

crtman-cli: $(CLIENT_TARGET)

$(CLIENT_TARGET): $(CLIENT_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

