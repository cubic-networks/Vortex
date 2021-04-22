CC=gcc
LIB_DIR=/usr/lib/nps
CFLAG=-O3 -Wall -D_C -g -I.
TARGET=enc_test
LFLAG=-L. -L${LIB_DIR} -lcubic_crypto -lvortex
SRC=encryption_test.c

all: debug
	$(CC) $(CFLAG) $(SRC) $(LFLAG) -o $(TARGET)

debug:
	$(CC) $(CFLAG) -DVORTEX_DEBUG $(SRC) $(LFLAG)_dbg -o $(TARGET)_debug

clean:
	rm $(TARGET) $(TARGET)_debugo

install:
	cp *.so $(LIB_DIR)/.
	ldconfig
