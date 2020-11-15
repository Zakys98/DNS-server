CPPFLAGS= -std=c++11 -Wextra -pedantic -Wall

.PHONY: all test clean pack

all: dns

dns: dns.o
	g++ $(CPPFLAGS) dns.o -o dns

dns.o: dns.cc
	g++ $(CPPFLAGS) -c dns.cc

test:
	./dns -p 33333 -f bad_domain_name -s 8.8.8.8 &
	./test.sh
	fuser -k 33333/udp

pack:
	tar -cf xzakji02.tar bad_domain_name dns.cc test.sh README.md Makefile manual.pdf 

clean:
	rm *.o dns xzakji02.tar
