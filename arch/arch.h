#ifndef SMOCK_ARCH_H
#define SMOCK_ARCH_H

#if defined(__x86_64__) || defined(_M_X64)
#include "x86_64.h"
#else
#error "Architecture is not supported"
#endif 

#endif  // SMOCK_ARCH_H 

