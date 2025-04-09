all: printer multithread_printer stdout_spoofer

printer: printer.c
	gcc $< -o $@

multithread_printer: multithread_printer.cpp
	g++ $< -o $@

stdout_spoofer: stdout_spoofer.c ../smock.h
	gcc $< -O0 -g -no-pie -o $@
