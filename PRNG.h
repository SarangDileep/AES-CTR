//
//  PRNG.h
//  AES
//
//

#ifndef PRNG_h
#define PRNG_h

#include <stdio.h>
#include <stdlib.h>
#include "CSHA512.h"

uint8_t* PRNG(char* seed);
void LFSR(uint8_t *seed);

#endif /* PRNG_h */
