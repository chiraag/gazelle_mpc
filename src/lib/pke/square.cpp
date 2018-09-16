/*
 * mat_mul.cpp
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#include "math/bit_twiddle.h"
#include "math/automorph.h"
#include "math/params.h"
#include "pke/encoding.h"
#include "pke/fv.h"

#include "pke/square.h"

#include "utils/test.h"
#include <iostream>
#include <algorithm>

namespace lbcrypto{

CTVec preprocess_client_share(const SecretKey& sk, const uv64& vec, const FVParams& params){
    std::vector<uv64> pt(2, uv64(params.phim));
    pt[0] = vec;
    for(ui32 n=0; n<vec.size(); n++){
        if(params.fast_modulli){
            pt[1][n] = opt::modp_full(vec[n]*vec[n]);
        } else {
            pt[1][n] = mod(vec[n]*vec[n], params.p);
        }
    }

    CTVec ct_vec(2, Ciphertext(params.phim));
    for(ui32 i=0; i<2; i++){
        auto pt_enc = packed_encode(pt[i], params.p, params.logn);
        ct_vec[i] = Encrypt(sk, pt_enc, params);
    }

    return ct_vec;
}

std::tuple<std::vector<uv64>, uv64> preprocess_server_share(const uv64& vec, const FVParams& params){
    std::vector<uv64> pt(3, uv64(params.phim));
    for(ui32 n=0; n<vec.size(); n++){
        if(params.fast_modulli){
            pt[0][n] = opt::modp_full(2*vec[n]);
            pt[1][n] = opt::modp_full(vec[n]*vec[n]);
        } else {
            pt[0][n] = mod(2*vec[n], params.p);
            pt[1][n] = mod(vec[n]*vec[n], params.p);
        }
    }
    pt[2] = get_dug_vector(params.phim, params.p);

    std::vector<uv64> ct_vec(3, uv64(params.phim));
    for(ui32 i=0; i<3; i++){
        auto pt_enc = packed_encode(pt[i], params.p, params.logn);
        if(i != 0){
            for(ui32 n=0; n<params.phim; n++){
                pt_enc[n] = pt_enc[n]*params.delta;
            }
        }
        ct_vec[i] = NullEncrypt(pt_enc, params);
    }

    return std::make_tuple(ct_vec, pt[2]);
}

Ciphertext square_online(const CTVec& ct_vec_c, const std::vector<uv64>& pt_vec_s, const FVParams& params){
    auto ct_share = EvalMultPlain(ct_vec_c[0], pt_vec_s[0], params);
    ct_share = EvalAdd(ct_share, ct_vec_c[1], params);
    ct_share = EvalAddPlain(ct_share, pt_vec_s[1], params);
    ct_share = EvalAddPlain(ct_share, pt_vec_s[2], params);
    return ct_share;
}

uv64 postprocess_client_share(const SecretKey& sk, const Ciphertext& ct,
        const ui32 vec_size, const FVParams& params){
    auto pt = packed_decode(Decrypt(sk, ct, params), params.p, params.logn);
    uv64 vec(vec_size);
    for(ui32 n=0; n<vec_size; n++){
        vec[n] = pt[n];
    }

    return vec;
}

uv64 square_pt(const uv64& vec_c, const uv64& vec_s, const uv64& vec_s_f, const ui64 p){
    uv64 vec_c_f(vec_c.size());
    for(ui32 n=0; n<vec_c.size(); n++){
        vec_c_f[n] = mod((vec_c[n]+vec_s[n])*(vec_c[n]+vec_s[n])+vec_s_f[n], p);
    }

    return vec_c_f;
}

}




