# Makefile for building ca_test

# BoringSSL
BORINGSSL := vendor/boringssl

CC        := clang
CFLAGS    := -Ishared -I$(BORINGSSL)/include -std=c11 -Wall -Wextra -DDEBUG
LDFLAGS   := $(BORINGSSL)/build/libcrypto.a -framework Security -framework CoreFoundation

SRC       := ca_server.c test.c
OBJ       := $(SRC:.c=.o)
TARGET    := ca_test

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -g -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)
