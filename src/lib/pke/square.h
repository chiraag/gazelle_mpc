/*
 * mat_mul.h
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#ifndef SRC_LIB_PKE_SQUARE_H_
#define SRC_LIB_PKE_SQUARE_H_

#include "utils/backend.h"
#include "pke/layers.h"
#include "pke_types.h"

namespace lbcrypto{
    CTVec preprocess_client_share(const SecretKey& sk, const uv64& vec, const FVParams& params);

    std::tuple<std::vector<uv64>, uv64> preprocess_server_share(const uv64& vec, const FVParams& params);

    Ciphertext square_online(const CTVec& ct_vec_c, const std::vector<uv64>& pt_vec_s, const FVParams& params);

    uv64 postprocess_client_share(const SecretKey& sk, const Ciphertext& ct,
            const ui32 vec_size, const FVParams& params);

    uv64 square_pt(const uv64& vec_c, const uv64& vec_s, const uv64& vec_s_f, const ui64 p);
}




#endif /* SRC_LIB_PKE_MAT_MUL_H_ */
