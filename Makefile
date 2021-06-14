CC=gcc
LIB_DIR=/usr/lib/nps
CFLAG=-O3 -Wall -D_C -g -I.
ENC_TARGET=enc_test
STOR_TARGET=stor_test
LFLAG=-L. -L${LIB_DIR} -lcubic_crypto -lvortex
ENC_SRC=encryption_test.c
STOR_SRC=storage_test.c

all: encryption storage debug

encryption:
	$(CC) $(CFLAG) $(ENC_SRC) $(LFLAG) -o $(ENC_TARGET)

storage:
	$(CC) $(CFLAG) $(STOR_SRC) $(LFLAG) -o $(STOR_TARGET)

debug:
	$(CC) $(CFLAG) -DVORTEX_DEBUG $(ENC_SRC) $(LFLAG)_dbg -o $(ENC_TARGET)_debug
	$(CC) $(CFLAG) -DVORTEX_DEBUG $(STOR_SRC) $(LFLAG)_dbg -o $(STOR_TARGET)_debug

clean:
	rm $(ENC_TARGET) $(STOR_TARGET) $(ENC_TARGET)_debug $(STOR_TARGET)_debug

install:
	cp *.so $(LIB_DIR)/.
	ldconfig
