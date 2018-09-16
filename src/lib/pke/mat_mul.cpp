/*
 * mat_mul.cpp
 *
 *  Created on: Sep 1, 2017
 *      Author: chiraag
 */

#include "math/bit_twiddle.h"
#include "math/automorph.h"
#include "pke/encoding.h"
#include "pke/fv.h"

#include "pke/mat_mul.h"

#include "utils/test.h"
#include <iostream>
#include <algorithm>

namespace lbcrypto{

CTVec preprocess_vec(const SecretKey& sk, const uv64& vec,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    uv64 pt(params.phim);
    ui32 sz_pow2 = nxt_pow2(vec.size());
    ui32 pack_factor = (params.phim / sz_pow2);
    for(ui32 col=0; col<vec.size(); col++){
        for(ui32 n=0; n<pack_factor; n++){
            pt[col + sz_pow2*n] = vec[col];
        }
    }
    pt = packed_encode(pt, params.p, params.logn);

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

// Assumes mat is vector of phim-sized rows, num_rows can be any integer up to phim
EncMat preprocess_matrix(const std::vector<uv64>& mat,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    // Create the diagonal rotation of the plaintext matrix
    ui32 num_rows = mat.size();
    ui32 num_cols = mat[0].size();
    ui32 num_cols_pow2 = nxt_pow2(num_cols);

    ui32 pack_factor = (params.phim / num_cols_pow2);
    ui32 num_rows_pack = nxt_pow2(num_rows)/pack_factor;
    std::vector<uv64> mat_pack(num_rows_pack, uv64(params.phim));
    for(ui32 row=0; row<num_rows; row++){
        ui32 curr_set = (row / num_rows_pack);
        for(ui32 col=0; col<num_cols; col++){
            mat_pack[row % num_rows_pack][col + num_cols_pow2*curr_set] = mat[row][col];
        }
    }

    ui32 mod_mask = (num_rows_pack-1);
    ui32 wrap_thresh = std::min(params.phim >> 1, nxt_pow2(num_cols));
    ui32 wrap_mask = wrap_thresh - 1;
    std::vector<uv64> mat_diag(num_rows_pack, uv64(params.phim));
    for(ui32 row=0; row<num_rows_pack; row++){
        for(ui32 col=0; col<params.phim; col++){
            ui32 row_diag_l = (col-row) & wrap_mask & mod_mask;
            ui32 row_diag_h = (col^row) & (params.phim/2) & mod_mask;
            ui32 row_diag = (row_diag_h + row_diag_l);

            ui32 col_diag_l = (col - row_diag_l) & wrap_mask;
            ui32 col_diag_h = wrap_thresh*(col/wrap_thresh) ^ row_diag_h;
            ui32 col_diag = col_diag_h + col_diag_l;

            mat_diag[row_diag][col_diag] = mat_pack[row][col];
            // std::cout << row << " " << col << " " << row_diag << " " << col_diag << std::endl;
        }
    }

    EncMat enc_mat(num_rows_pack, std::vector<uv64>(num_windows, uv64(params.phim)));
    for(ui32 row=0; row<num_rows_pack; row++){
        auto pt_row = packed_encode(mat_diag[row], params.p, params.logn);
        auto decomposed_row = base_decompose(pt_row, window_size, num_windows);
        for(ui32 w=0; w<num_windows; w++){
            // std::cout << "Decomposed Row " << row << ": " << std::endl;
            // std::cout << vec_to_str(decomposed_row[w]);
            enc_mat[row][w] = NullEncrypt(decomposed_row[w], params);
        }
    }
    return enc_mat;
}

Ciphertext mat_mul_online(const CTVec& ct_vec, const EncMat& enc_mat,
        const ui32 num_cols, const FVParams& params){
    Ciphertext ret(params.phim);
    ui32 padded_rows = enc_mat.size();
    for(ui32 w=0; w<ct_vec.size(); w++){
        auto digits_vec_w = HoistedDecompose(ct_vec[w], params);
        Ciphertext curr_vec(params.phim);
        for(ui32 row=0; row<padded_rows; row++){
            if(row == 0){
                curr_vec = ct_vec[w];
            } else {
                auto rk = GetAutomorphismKey(row);
                curr_vec = EvalAutomorphismDigits(row, *rk, ct_vec[w], digits_vec_w, params);
            }
            auto mult = EvalMultPlain(curr_vec, enc_mat[row][w], params);
            ret = EvalAdd(ret, mult, params);
        }
    }

    // Rotate and add the partial sums
    ui32 pack_factor = (params.phim / nxt_pow2(num_cols));
    for (ui32 rot = padded_rows; rot < (params.phim/pack_factor); rot *= 2){
        auto rotated_ret = EvalAutomorphism(rot, ret, params);
        ret = EvalAdd(ret, rotated_ret, params);
    }
    return ret;
}

uv64 postprocess_prod(const SecretKey& sk, const Ciphertext& ct_prod,
        const ui32 vec_size, const ui32 num_rows, const FVParams& params){
    auto pt = packed_decode(Decrypt(sk, ct_prod, params), params.p, params.logn);
    auto prod = uv64(num_rows);

    ui32 sz_pow2 = nxt_pow2(vec_size);
    ui32 pack_factor = (params.phim / nxt_pow2(vec_size));
    ui32 set_size = nxt_pow2(num_rows)/pack_factor;
    for(ui32 row=0; row<num_rows; row++){
        ui32 curr_set = (row / set_size);
        prod[row] = pt[(row % set_size) + sz_pow2*curr_set];
    }

    return prod;
}

uv64 mat_mul_pt(const uv64& vec, const std::vector<uv64>& mat, const ui64 p){
    ui32 rows = mat.size();
    ui32 cols = vec.size();

    uv64 product(rows, 0);
    for (ui32 row = 0; row < rows; row++){
        for (ui32 col = 0; col < cols; col++){
            ui64 partial = mod(vec[col]*mat[row][col], p);
            product[row] = mod(product[row] + partial, p);
        }
    }

    return product;
}


}




