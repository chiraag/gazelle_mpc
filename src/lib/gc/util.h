/*
 This file is part of JustGarble.

    JustGarble is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    JustGarble is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with JustGarble.  If not, see <http://www.gnu.org/licenses/>.

*/

#ifndef UTIL_H_
#define UTIL_H_

#include "common.h"
#include "aes.h"
#include <x86intrin.h>

namespace lbcrypto {

void countToN(ui64 *a, ui64 N);
int dbgBlock(block a);

#define RDTSC ({unsigned long long res;  unsigned hi, lo;   __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi)); res =  ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );res;})
#define fbits( v, p) ((v & (1 << p))>>p)
int getWords(char *line, char *words[], int maxwords);

int median(int A[], int n);
double doubleMean(double A[], int n);

void seedRandom(void);
block randomBlock();
void randAESBlock(block* out);

// Compute AES in place. out is a block and sched is a pointer to an 
// expanded AES key.
#define inPlaceAES(out, sched) {int jx; out = _mm_xor_si128(out, sched[0]);\
                                for (jx = 1; jx < 10; jx++)\
                                  out = _mm_aesenc_si128(out, sched[jx]);\
                                out = _mm_aesenclast_si128(out, sched[jx]);}

extern block __current_rand_index;
extern AES_KEY __rand_aes_key;

// #define getRandContext() ((__m128i *) (__rand_aes_key.rd_key));
// #define randAESBlock(out,sched) {__current_rand_index++; *out = __current_rand_index;inPlaceAES(*out,sched);}
static inline block* getRandContext(void) {return __rand_aes_key.rd_key;};
static inline void randAESBlock(block* out,const block* sched) {__current_rand_index = __current_rand_index+1; *out = __current_rand_index;inPlaceAES(*out,sched);}

void print_block(block x);

void print_gc(GarbledCircuit& gc);

}

#endif /* UTIL_H_ */
