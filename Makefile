CC = gcc
CFLAGS = -g -Wall 

all:  trace

trace: trace.c trace.h
	$(CC) $(CFLAGS) -o trace trace.c checksum.c -lpcap
clean:
	rm -f trace
	rm -f given/*.user_out
	rm -f given/*.diff_out
