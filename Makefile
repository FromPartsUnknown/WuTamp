# Makefile for wutamp.c

CC = gcc
CFLAGS = -std=c99 -O2
TARGET = wutamp
SRC = src/wutamp.c
OS := $(shell uname)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
