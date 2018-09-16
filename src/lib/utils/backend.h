/*
* backend.h
*
*  Created on: Aug 25, 2017
*      Author: chiraag
*
*/

#ifndef LBCRYPTO_MATH_BACKEND_H
#define LBCRYPTO_MATH_BACKEND_H

#include <inttypes.h>
#include <vector>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
    typedef int32_t si32;
    typedef uint32_t ui32;
    typedef int64_t si64;
    typedef uint64_t ui64;
    typedef __uint128_t ui128;

    typedef std::vector<si32> sv32;
    typedef std::vector<ui32> uv32;
    typedef std::vector<si64> sv64;
    typedef std::vector<ui64> uv64;
    typedef std::vector<ui128> uv128;


    /**
    * @brief Lists all modes for RLWE schemes, such as BGV and FV
    */
    enum MODE {
        RLWE = 0,
        OPTIMIZED = 1
    };

} // namespace lbcrypto ends


#endif
