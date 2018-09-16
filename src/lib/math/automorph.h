/*
 * automorph.h
 *
 *  Created on: Aug 27, 2017
 *      Author: chiraag
 */

#ifndef LBCRYPTO_MATH_AUTOMORPH_H_
#define LBCRYPTO_MATH_AUTOMORPH_H_

#include "utils/backend.h"

namespace lbcrypto{
    std::vector<uv64> base_decompose(const uv64& coeff, const ui32 window_size, const ui32 num_windows);

    void precompute_automorph_index(const ui32 phim);

    ui32 get_automorph_index(const ui32 rot, const ui32 phim);

    uv64 automorph(const uv64& input, const ui32 rot);

    uv64 automorph_pt(const uv64& input, const ui32 rot);
}

#endif /* LBCRYPTO_MATH_AUTOMORPH_H_ */
