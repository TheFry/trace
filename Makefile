# Example makefile for CPE464 program 1
#
# 

CC = gcc
CFLAGS = -g -Wall 
#CFLAGS = -g

all:  trace

trace: trace.c
	$(CC) $(CFLAGS) -o trace trace.c checksum.c  -lpcap 

test: trace.c trace.h
	$(CC) $(CFLAGS) -o trace trace.c -lpcap
clean:
	rm -f trace
