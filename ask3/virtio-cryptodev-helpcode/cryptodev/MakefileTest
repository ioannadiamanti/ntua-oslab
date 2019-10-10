###################################################
#
# Makefile
# Simple example for cryptodev-linux
#
# Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CRYPTODEVDIR=$(HOME)/cryptodev/cryptodev-linux-1.9

CFLAGS = -Wall -I$(CRYPTODEVDIR)
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS = 

BINS = crypto-test

all: $(BINS)

crypto-test: crypto-test.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)
