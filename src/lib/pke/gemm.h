/*
 * mat_mul.h
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_PKE_GEMM_H_
#define SRC_LIB_PKE_GEMM_H_

#include "utils/backend.h"
#include "pke/layers.h"
#include "pke_types.h"

namespace lbcrypto{
    CTMat preprocess_gemm_c(const SecretKey& sk, const std::vector<uv64>& mat,
            const ui32 window_size, const ui32 num_windows, const FVParams& params);

    EncMat preprocess_gemm_s(const std::vector<uv64>& mat, const ui32 num_cols_c,
            const ui32 window_size, const ui32 num_windows, const FVParams& params);

    CTVec gemm_online(const CTMat& ct_mat_c, const EncMat& enc_mat_s,
            const ui32 num_cols_c, const FVParams& params);

    CTVec gemm_phim_online(const CTMat& ct_mat_c, const std::vector<uv64>& mat_s_t,
            const ui32 window_size, const ui32 num_windows, const FVParams& params);

    std::vector<uv64> postprocess_gemm(const SecretKey& sk, const CTVec& ct_prod,
            const ui32 num_rows, const ui32 num_cols, const FVParams& params);

    std::vector<uv64> gemm_pt(const std::vector<uv64>& mat_c,
            const std::vector<uv64>& mat_s_t, const ui64 p);
}




#endif /* SRC_LIB_PKE_MAT_MUL_H_ */
