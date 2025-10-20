QJSPATH=../../quickjs-2025-09-13

# **
# * Cross
# **
#CROSS_BASE=/media/Kingston/stuff/openwrt-toolchain-23.05.3-kirkwood-generic_gcc-12.3.0_musl_eabi.Linux-x86_64/toolchain-arm_xscale_gcc-12.3.0_musl_eabi/bin/arm-openwrt-linux-

# **
# * Native
# **
CC := $(CROSS_BASE)gcc
LD := $(CROSS_BASE)ld
CFLAGS := -I$(QJSPATH)
LDFLAGS := -lm -ldl

hash.so: quickjs-hash.o
	$(LD) $(LDFLAGS) -shared -soname hash -o hash.so quickjs-hash.o
	ln -s hash.so libhash.so

quickjs-hash.o: quickjs-hash.c
	$(CC) $(CFLAGS) -c -o quickjs-hash.o quickjs-hash.c

test: test.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o test test.c -L. -L$(QJSPATH) -lhash -lquickjs

clean:
	rm hash.so quickjs-hash.o libhash.so

all: hash.so test
