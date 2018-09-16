/*
 * conv1d.h
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_PKE_CONV1D_H_
#define SRC_LIB_PKE_CONV1D_H_

#include "utils/backend.h"
#include "pke/layers.h"
#include "pke_types.h"

namespace lbcrypto{

    EncMat preprocess_filter_1d(const uv64& filter, const ui32 window_size,
            const ui32 num_windows, const FVParams& params);

    CTMat conv_1d_rot(const CTVec& ct_vec, const ui32& filter_size, const FVParams& params);

    Ciphertext conv_1d_mul(const CTMat& ct_mat, const EncMat& enc_filter, const FVParams& params);

    Ciphertext conv_1d_online(const CTVec& ct_vec, const EncMat& enc_filter, const FVParams& params);

    uv64 conv_1d_pt(const uv64& vec, const uv64& filter, const ui32 p);
}



#endif /* SRC_LIB_PKE_CONV1D_H_ */
