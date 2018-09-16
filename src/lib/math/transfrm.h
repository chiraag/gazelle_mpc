/*
 * transform.h
 *
 *	An initial draft of the transform code is inspired from my experiments with
 *	the PALISADE transform code.
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#ifndef LBCRYPTO_MATH_TRANSFRM_H
#define LBCRYPTO_MATH_TRANSFRM_H


#include "utils/backend.h"
#include "nbtheory.h"
//#include "../utils/utilities.h"
#include <chrono>
#include <complex>
#include <time.h>
#include <map>
#include <fstream>
#include <thread>

/**
* @namespace lbcrypto
* The namespace of lbcrypto
*/
namespace lbcrypto {

    uv64 ftt_fwd(const uv64& element, const ui64 modulus, const ui32 logn);

    uv64 ftt_inv(const uv64& element, const ui64 modulus, const ui32 logn);

    uv64 ftt_fwd_opt(const uv64& element);

    uv64 ftt_inv_opt(const uv64& element);

    uv64 ftt_fwd_opt_p(const uv64& element);

    uv64 ftt_inv_opt_p(const uv64& element);

    void ftt_precompute(const ui64 rootOfUnity, const ui64 modulus, const ui32 logn);

    void ftt_pre_compute(const uv64 &rootOfUnity, const uv64 &moduliiChain, const ui32 logn);

} // namespace lbcrypto ends

#endif
