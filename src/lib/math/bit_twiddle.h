#ifndef LBCRYPTO_MATH_BIT_TWIDDLE_H
#define LBCRYPTO_MATH_BIT_TWIDDLE_H

#include "utils/backend.h"

namespace lbcrypto {
    inline ui64 ones(ui32 n){
        return ((ui64)1 << n)-1;
    }

    // Only works for positive num and den. (num cannot be zero)
    inline ui32 div_ceil(ui32 num, ui32 den){
        return 1 + ((num - 1) / den);
    }

    /**
     * Method to reverse bits of num and return an unsigned int, for all bits up to an including the designated most significant bit.
     *
     * @param input an unsigned int
     * @param msb the most significant bit.  All larger bits are disregarded.
     *
     * @return an unsigned integer that represents the reversed bits.
     */
    ui32 ReverseBits(ui32 input, ui32 msb);

    /**
     * Get MSB of an unsigned 64 bit integer.
     *
     * @param x the input to find MSB of.
     *
     * @return the index of the MSB bit location.
     */
    inline ui32 GetMSB64(uint64_t x) {
        if (x == 0) return 0;

        // hardware instructions for finding MSB are used are used;
#if defined(_MSC_VER)
        // a wrapper for VC++
        unsigned long msb;
        _BitScanReverse64(&msb, x);
        return msb + 1;
#else
        // a wrapper for GCC
        return  64 - (sizeof(unsigned long) == 8 ? __builtin_clzl(x) : __builtin_clzll(x));
#endif
    }

    ui32 log_pow2(ui32 v);

    ui32 nxt_pow2(ui32 x);

    ui32 num_ones(ui32 x);

}


#endif
