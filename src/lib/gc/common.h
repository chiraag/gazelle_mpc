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


#ifndef common
#define common
#include <stdlib.h>
#include <x86intrin.h>

#include <iostream>
#include <string>
#include <vector>

#include <cryptoTools/Common/BitVector.h>

#include "aes.h"
#include "utils/backend.h"

namespace lbcrypto {

#define xorBlocks(x,y) _mm_xor_si128(x,y)
#define zero_block() _mm_setzero_si128()
#define unequal_blocks(x,y) (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)

#define getLSB(x) (_mm_cvtsi128_si64(x)&1)
#define makeBlock(X,Y) _mm_set_epi64((__m64)(X), (__m64)(Y))
#define getFromBlock(X,i) _mm_extract_epi64(X, i)

#define DOUBLE(B) _mm_slli_epi64(B,1)

#define SUCCESS 0
#define FAILURE -1

// #define STANDARD
#define HALF_GATES

#define FIXED_ZERO_GATE 0x00
#define ANDGATE 0x08
#define ORGATE 0x3e
#define XORGATE 0x06
#define XNORGATE 0x09
#define NOTGATE 0x05
#define FIXED_ONE_GATE 0x0f

#ifdef STANDARD
#define TABLE_SIZE 4
#else
#define TABLE_SIZE 2
#endif

#define TIMES 10
#define RUNNING_TIME_ITER 100
block randomBlock();

typedef struct {
    block label, label0, label1;
} Wire;

typedef struct {
    long input0, input1, output, type;
} GarbledGate;

typedef struct {
    block table[TABLE_SIZE];
} GarbledTable;

typedef struct {
    int n, m, q, r;
    int n_c;
    block table_key;
    std::vector<GarbledGate> garbledGates; // Circuit topology
    std::vector<int> outputs; // Indices of wires that are outputs
    std::vector<GarbledTable> garbledTable; // Tables
    std::vector<Wire> wires; // Labels
} GarbledCircuit;

typedef struct {
    long wireIndex, gateIndex, tableIndex, outputIndex;
} BuildContext;

typedef std::vector<std::array<block, 2>> InputLabels;
typedef std::vector<block> ExtractedLabels;
typedef std::vector<block> OutputLabels;
typedef osuCrypto::BitVector InputMap;
typedef osuCrypto::BitVector OutputMap;

}

#endif
