/*
 * mat_mul.h
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_PKE_MAT_MUL_H_
#define SRC_LIB_PKE_MAT_MUL_H_

#include "utils/backend.h"
#include "pke/layers.h"
#include "pke_types.h"

namespace lbcrypto{
    CTVec preprocess_vec(const SecretKey& sk, const uv64& vec,
            const ui32 window_size, const ui32 num_windows, const FVParams& params);

    EncMat preprocess_matrix(const std::vector<uv64>& mat,
            const ui32 window_size, const ui32 num_windows, const FVParams& params);

    Ciphertext mat_mul_online(const CTVec& vec, const EncMat& enc_mat,
            const ui32 pack_factor, const FVParams& params);

    uv64 postprocess_prod(const SecretKey& sk, const Ciphertext& ct_prod,
            const ui32 vec_size, const ui32 num_rows, const FVParams& params);

    uv64 mat_mul_pt(const uv64& vec, const std::vector<uv64>& mat, const ui64 p);
}




#endif /* SRC_LIB_PKE_MAT_MUL_H_ */
