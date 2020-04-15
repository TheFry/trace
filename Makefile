CC = gcc
CFLAGS = -g -Wall 

all:  trace

trace: trace.c trace.h
	$(CC) $(CFLAGS) -o trace trace.c checksum.c -lpcap
clean:
	rm -f trace
