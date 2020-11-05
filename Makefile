CPPFLAGS= -std=c++11 -Wextra -pedantic -Wall

.PHONY: all test clean

all: dns

dns: dns.o
	g++ $(CPPFLAGS) dns.o -o dns

dns.o: dns.cc
	g++ $(CPPFLAGS) -c dns.cc

test:
	./dns -p 3333 -f bad_domain_name_long -s 8.8.8.8 &
	./test.sh
	fuser -k 3333/udp

clean:
	rm *.o dns
