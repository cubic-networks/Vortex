CC=gcc
CFLAG=-O3 -Wall -D_C -g -I../../Vortex/. -I.
TARGET=enc_test
LFLAG=-L. -L/usr/lib/nps/ -L/usr/lib/x86_64-linux-gnu/ -lcubic_crypto -lvortex
SRC=encryption_test.c

all:
	$(CC) $(CFLAG) -D_VER_PRO $(SRC) $(LFLAG) -o $(TARGET)

debug:
	$(CC) $(CFLAG) -DVORTEX_DEBUG $(SRC) $(LFLAG)_dbg -o $(TARGET)_debug

clean:
	rm $(TARGET) $(TARGET)_debug
