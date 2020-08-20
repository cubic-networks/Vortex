CC=gcc
CFLAG=-O3 -Wall -D_C -g -I../.
TARGET=test
LFLAG=-L/usr/lib/nps/ -lcubic_crypto -lvortex
SRC=test.c

all:
	$(CC) $(CFLAG) $(SRC) $(LFLAG) -o $(TARGET)

clean:
	rm $(TARGET)
