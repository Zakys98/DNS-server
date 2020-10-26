CFLAGS= -std=c99 -Wextra -pedantic -Wall

all: dns

dns: dns.o
	gcc $(CFLAGS) dns.o -o dns

dns.o: dns.c
	gcc $(CFLAGS) -c dns.c

clean:
	rm *.o dns
