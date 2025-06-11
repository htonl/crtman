# Makefile for building ca_test

# BoringSSL
BORINGSSL := vendor/boringssl

CC        := clang
CFLAGS    := -Ishared -I$(BORINGSSL)/include -std=c11 -Wall -Wextra -DDEBUG
LDFLAGS   := $(BORINGSSL)/build/libcrypto.a -framework Security -framework CoreFoundation

# Main executable
SRC       := ca_server.c main.c shared/utils.c
OBJ       := $(SRC:.c=.o)
TARGET    := ca_test

# Unit test executable
TEST_SRC  := ca_server.c unittests.c shared/utils.c
TEST_OBJ  := $(TEST_SRC:.c=.o)
TEST_TARGET := unittests

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

# Build rule for any .c → .o
%.o: %.c
	$(CC) $(CFLAGS) -g -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET) $(TEST_OBJ) $(TEST_TARGET)
	rm -rf db/

boringssl:
	cd vendor/boringssl && \
	mkdir build && cd build && \
	cmake -GNinja .. && \
	ninja

unittest: $(TEST_TARGET)

$(TEST_TARGET): $(TEST_OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

runtests:
	python3 unit_test.py
