CC=gcc
CFLAG=-O3 -Wall -D_C -I.
SHR_FLAG=-fPIC -shared
TARGET=libvortex
LFLAG=-L. -L/usr/lib/x86_64-linux-gnu/ -lssl -lcrypto -lcubic_crypto
LIB_DIR=/usr/lib/nps

SRC=vortex.c

all: 
	$(CC) $(SHR_FLAG) $(CFLAG) $(SRC) $(LFLAG) -o $(TARGET).so

debug:
	$(CC) $(SHR_FLAG) $(CFLAG) -DVORTEX_DEBUG $(SRC) $(LFALG) -o $(TARGET)_debug.so

clean:
	rm $(TARGET)*.so

install:
	cp *.so $(LIB_DIR)/.
