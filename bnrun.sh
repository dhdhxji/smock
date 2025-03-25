#!/bin/sh

set -e

gcc smock.c -O0 -g -o smock

./smock 

