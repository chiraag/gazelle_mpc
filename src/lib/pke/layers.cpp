/*
 * layers.cpp
 *
 *  Created on: Aug 28, 2017
 *      Author: chiraag
 */

#include "pke/fv.h"

#include "pke/layers.h"

namespace lbcrypto{
/*
CTVec preprocess_vec(const SecretKey& sk, const uv64& pt,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    // Expand the input with multiples of the plaintext base
    std::vector<uv64> pt_scaled(num_windows, uv64(params.phim));
    for (ui32 w=0; w<num_windows; w++){
        for (ui32 i=0; i<params.phim; i++){
            pt_scaled[w][i] = ((pt[i] << (w*window_size)) % params.p);
        }
    }

    CTVec ct_vec(num_windows, Ciphertext(params.phim));
    for (ui32 w=0; w<num_windows; w++){
        ct_vec[w] = Encrypt(sk, pt_scaled[w], params);
    }

    return ct_vec;
}
*/
}

