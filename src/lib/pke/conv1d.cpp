/*
 * conv1d.cpp
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#include "math/automorph.h"
#include "pke/encoding.h"
#include "pke/fv.h"

#include "pke/conv1d.h"

#include "utils/test.h"
#include <iostream>

namespace lbcrypto {

// TODO: Massive preprocessing savings possible by computing for all ones filter
// scaling for the appropriate filter
EncMat preprocess_filter_1d(const uv64& filter, const ui32 window_size,
        const ui32 num_windows, const FVParams& params){
    // Create the diagonal rotation of the filter matrix
    ui32 filter_size = filter.size();
    ui32 offset = (filter_size-1)/2;
    std::vector<uv64> filter_mat(filter_size, uv64(params.phim, 0));
    for(ui32 row=0; row<filter_size; row++){
        for(ui32 col=0; col<params.phim; col++){
            if((col + row >= offset) && ( col + row < offset + params.phim)) {
                filter_mat[row][col] = filter[row];
            }
        }
    }

    EncMat enc_filter(filter_size, std::vector<uv64>(num_windows, uv64(params.phim)));
    for(ui32 row=0; row<filter_size; row++){
        auto pt_row = packed_encode(filter_mat[row], params.p, params.logn);
        auto decomposed_row = base_decompose(pt_row, window_size, num_windows);
        for(ui32 w=0; w<num_windows; w++){
            enc_filter[row][w] = NullEncrypt(decomposed_row[w], params);
        }
    }
    return enc_filter;
}

CTMat conv_1d_rot(const CTVec& ct_vec, const ui32& filter_size, const FVParams& params){
    ui32 offset = (filter_size-1)/2;
    ui32 mask = (params.phim >> 1)-1;

    CTMat ct_mat(filter_size, std::vector<Ciphertext>(ct_vec.size(), Ciphertext(params.phim)));
    for(ui32 w=0; w<ct_vec.size(); w++){
        auto digits_vec_w = HoistedDecompose(ct_vec[w], params);
        for(ui32 row=0; row<filter_size; row++){
            ui32 rot = (params.phim/2 - offset + row) & mask;
            if(rot == 0){
                ct_mat[row][w] = ct_vec[w];
            } else {
                auto rk = GetAutomorphismKey(rot);
                ct_mat[row][w] = EvalAutomorphismDigits(rot, *rk, ct_vec[w], digits_vec_w, params);
            }
        }
    }

    return ct_mat;
}

Ciphertext conv_1d_mul(const CTMat& ct_mat, const EncMat& enc_filter, const FVParams& params){
    ui32 filter_size = enc_filter.size();

    Ciphertext conv(params.phim);
    for(ui32 w=0; w<ct_mat[0].size(); w++){
        for(ui32 row=0; row<filter_size; row++){
            auto mult = EvalMultPlain(ct_mat[row][w], enc_filter[row][w], params);
            conv = EvalAdd(conv, mult, params);
        }
    }

    return conv;
}

Ciphertext conv_1d_online(const CTVec& ct_vec, const EncMat& enc_filter, const FVParams& params){
    auto filter_size = enc_filter.size();
    auto ct_mat = conv_1d_rot(ct_vec, filter_size, params);
    return conv_1d_mul(ct_mat, enc_filter, params);
}

// FIXME: Need to handle the rotation by 1024 instead of 2048
uv64 conv_1d_pt(const uv64& vec, const uv64& filter, const ui32 p){
    ui32 offset = (filter.size()-1)/2;
    ui32 phim = vec.size();
    ui32 mask = phim-1;

    uv64 conv(phim, 0);
    for (ui32 y = 0; y < phim; y++){
        for (ui32 f = 0; f < filter.size(); f++){
            bool not_edge = (y+f >= offset) && ( y+f < phim + offset);
            ui64 in = ((not_edge) ? vec[(y+f-offset) & mask] : 0);
            conv[y] = (conv[y] + in*filter[f]) % p;
        }
    }

    return conv;
}

}


