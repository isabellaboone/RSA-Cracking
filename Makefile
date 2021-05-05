all: make-test find-key

CFLAGS=-ggdb -O3

rsa.o: rsa.c rsa.h
primefact.o: primefact.c
main.o: main.c

rsa: primefact.o rsa.o main.o
	gcc $(CFLAGS) -o rsa $^  -lgmp -lpthread


make-test: primefact.o rsa.o make-test.o
	gcc $(CFLAGS) -o make-test $^  -lgmp -lpthread

find-key: primefact.o rsa.o find-key.o
	gcc $(CFLAGS) -o find-key $^  -lgmp -lpthread
	
clean:
	rm -f *.o rsa find-key make-test times.txt
