#include <stdio.h>

#define SMOCK_IMPLEMENTATION
#include "../smock.h"

int main(int argc, char *const *argv)
{
    for (int i = 0; i < argc; ++i)
    {
        printf("%s\n", argv[i]);
    }
}
