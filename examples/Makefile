CC=gcc
CXX=g++
CFLAGS=-Wall -Wextra -Werror -pedantic -pedantic-errors

all: printer multithread_printer stdout_spoofer unix_sock_dup

printer: printer.c
	${CC} $< -o $@

multithread_printer: multithread_printer.cpp
	${CXX}++ $< -o $@

stdout_spoofer: stdout_spoofer.c ../smock.h
	${CC} $< ${CFLAGS} -o $@

unix_sock_dup: unix_sock_dup.c
	${CC} $< ${CFLAGS} -o $@

