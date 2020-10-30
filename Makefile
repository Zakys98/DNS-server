CPPFLAGS= -std=c++11 -Wextra -pedantic -Wall

all: dns

dns: dns.o
	g++ $(CPPFLAGS) dns.o -o dns

dns.o: dns.cc
	g++ $(CPPFLAGS) -c dns.cc

test:
	./test.sh

clean:
	rm *.o dns
