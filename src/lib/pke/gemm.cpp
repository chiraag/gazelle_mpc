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
#include "pke/gemm.h"

#include "utils/test.h"
#include <iostream>
#include <algorithm>

namespace lbcrypto{

CTMat preprocess_gemm_c(const SecretKey& sk, const std::vector<uv64>& mat,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    ui32 num_cols = mat[0].size();
    ui32 rows_per_ct = (params.phim / num_cols);
    ui32 num_ct = mat.size()/rows_per_ct;

    uv64 pt(params.phim, 0);
    CTMat ct_mat(num_ct, std::vector<Ciphertext>(num_windows, Ciphertext(params.phim)));

    for(ui32 curr_ct=0; curr_ct<num_ct; curr_ct++){
        for(ui32 curr_row=0; curr_row<rows_per_ct; curr_row++){
            ui32 row = curr_row+curr_ct*rows_per_ct;
            ui32 pt_offset = curr_row*num_cols;
            for(ui32 col=0; col<num_cols; col++){
                pt[pt_offset+col] = mat[row][col];
            }
        }
        pt = packed_encode(pt, params.p, params.logn);

        // Expand the input with multiples of the plaintext base
        for (ui32 w=0; w<num_windows; w++){
            ct_mat[curr_ct][w] = Encrypt(sk, pt, params);
            for (ui32 i=0; i<params.phim; i++){
                pt[i] = ((pt[i] << window_size) % params.p);
            }
        }
    }

    return ct_mat;
}

EncMat preprocess_gemm_s(const std::vector<uv64>& mat, const ui32 num_cols_c,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    ui32 rows_per_ct = params.phim/num_cols_c;
    ui32 num_rows=mat.size(), num_cols=mat[0].size();
    ui32 num_sets = num_rows*num_cols/rows_per_ct;
    ui32 curr_set = 0;

    EncMat enc_mat(num_windows, std::vector<uv64>(num_sets, uv64(params.phim)));
    auto mat_diag = std::vector<uv64>(rows_per_ct, uv64(rows_per_ct));
    uv64 pt(params.phim), pt_scaled(params.phim);
    for(ui32 col=0; col<num_cols; col+=rows_per_ct){
        for(ui32 row=0; row<num_rows; row+=rows_per_ct){
            // auto mat_ref = std::vector<uv64>(rows_per_ct, uv64(rows_per_ct));
            for(ui32 sub_row=0; sub_row<rows_per_ct; sub_row++){
                for(ui32 sub_col=0; sub_col<rows_per_ct; sub_col++){
                    /*ui32 row_diag_l = (sub_col-sub_row) & ((rows_per_ct >> 1)-1);
                    ui32 row_diag_h = (sub_col^sub_row) & (rows_per_ct >> 1);
                    ui32 row_diag = (row_diag_h + row_diag_l);

                    ui32 col_diag_l = (sub_col - row_diag_l) & ((rows_per_ct >> 1)-1);
                    ui32 col_diag_h = (sub_col & (rows_per_ct >> 1)) ^ row_diag_h;
                    ui32 col_diag = col_diag_h + col_diag_l;*/

                    ui32 col_diag = sub_col;
                    ui32 row_diag = ((sub_row-sub_col) & ((rows_per_ct >> 1)-1)) +
                            ((sub_col^sub_row) & (rows_per_ct >> 1));

                    // mat_ref[sub_row][sub_col] = mat[row+sub_row][col+sub_col];
                    mat_diag[row_diag][col_diag] = mat[row+sub_row][col+sub_col];
                }
            }
            // std::cout << mat_to_str(mat_ref) << std::endl;
            // std::cout << mat_to_str(mat_diag) << std::endl;

            for(ui32 row_diag=0; row_diag<rows_per_ct; row_diag++){
                // std::cout << vec_to_str(mat_diag[row_diag]) << std::endl;
                for(ui32 curr_row=0; curr_row<rows_per_ct; curr_row++){
                    ui32 pt_offset = curr_row*num_cols_c;
                    for(ui32 n=0; n<num_cols_c; n++){
                        pt[pt_offset+n] = mat_diag[row_diag][curr_row];
                    }
                }
                // std::cout << vec_to_str(pt) << std::endl;
                pt = packed_encode(pt, params.p, params.logn);

                ui64 mask = (1<<window_size)-1;
                for(ui32 w=0; w<num_windows; w++){
                    ui32 shift = (w*window_size);
                    // std::cout << w << " " << curr_set << std::endl;
                    for(ui32 n=0; n<params.phim; n++){
                        pt_scaled[n] = (pt[n] >> shift) & mask;
                    }
                    enc_mat[w][curr_set] = NullEncrypt(pt_scaled, params);
                }
                curr_set++;
            }
        }
    }

    return enc_mat;
}

CTVec gemm_online(const CTMat& ct_mat_c, const EncMat& enc_mat_s, const ui32 num_cols_c, const FVParams& params){
    ui32 num_in_ct = ct_mat_c.size();
    ui32 num_windows = ct_mat_c[0].size();
    ui32 num_sets=enc_mat_s[0].size();
    ui32 rows_per_ct=params.phim/num_cols_c;
    ui32 num_out_ct = num_sets/(num_in_ct*rows_per_ct);

    // std::cout << num_in_ct << " " << num_sets << " " << num_out_ct << std::endl;

    CTVec psum_ct(num_out_ct*rows_per_ct, Ciphertext(params.phim));
    for(ui32 in_ct=0; in_ct<num_in_ct; in_ct++){
        for(ui32 w=0; w<num_windows; w++){
            ui32 curr_set = in_ct*num_out_ct*rows_per_ct;
            // auto digits_vec_w = HoistedDecompose(ct_mat_c[in_ct][w], params);
            for(ui32 out_ct=0; out_ct<num_out_ct; out_ct++){
                for(ui32 row=0; row<rows_per_ct; row++){
                    ui32 dest = out_ct*rows_per_ct+row;
                    auto mult = EvalMultPlain(ct_mat_c[in_ct][w], enc_mat_s[w][curr_set], params);
                    psum_ct[dest] = EvalAdd(psum_ct[dest], mult, params);
                    curr_set++;
                    // std::cout << in_ct << " " << w << " " << row << " " << rot << " " << curr_set << std::endl;
                    /*for(ui32 n=0; n<params.phim; n++){
                        ret[out_ct].a[n] = opt::modq_part(ret[out_ct].a[n]+
                                opt::mul_modq_part(curr_vec.a[n], enc_mat_s[w][curr_set][n]));
                        ret[out_ct].b[n] = opt::modq_part(ret[out_ct].b[n]+
                                opt::mul_modq_part(curr_vec.b[n], enc_mat_s[w][curr_set][n]));
                        //ret[out_ct].a[n+m] = opt::modq_part((ui128)ret[out_ct].a[n+m]+
                        //      (ui128)curr_vec.a[n+m]*(ui128)enc_mat_s[w][curr_set][m]);
                        //ret[out_ct].b[n+m] = opt::modq_part((ui128)ret[out_ct].b[n+m]+
                        //      (ui128)curr_vec.b[n+m]*(ui128)enc_mat_s[w][curr_set][m]);
                    }*/
                }
            }
        }
    }

    CTVec ret(num_out_ct, Ciphertext(params.phim));
    for(ui32 out_ct=0; out_ct<num_out_ct; out_ct++){
        for(ui32 row=0; row<rows_per_ct; row++){
            ui32 psum_row = out_ct*rows_per_ct + row;
            ui32 rot = ((params.phim/2) & (row*num_cols_c))+
                    ((params.phim/2-row*num_cols_c) & ((params.phim/2)-1));
            if(row == 0){
                ret[out_ct] = psum_ct[psum_row];
            } else {
                auto psum_rot = EvalAutomorphism(rot, psum_ct[psum_row], params);
                ret[out_ct] = EvalAdd(ret[out_ct], psum_rot, params);
            }
        }
    }

    return ret;
}

// Assumes client matrix has phim columns
CTVec gemm_phim_online(const CTMat& ct_mat_c, const std::vector<uv64>& mat_s_t,
        const ui32 window_size, const ui32 num_windows, const FVParams& params){
    ui32 num_ct = mat_s_t[0].size();

    std::vector<uv128> a(num_ct, uv128(params.phim));
    std::vector<uv128> b(num_ct, uv128(params.phim));
    ui64 mask = (1 << window_size)-1;
    for(ui32 in_ct=0; in_ct<ct_mat_c.size(); in_ct++){
        for(ui32 out_ct=0; out_ct<num_ct; out_ct++){
            for(ui32 w=0; w<num_windows; w++){
                ui64 coeff = ((mat_s_t[in_ct][out_ct] >> (window_size*w)) & mask);
                for(ui32 n=0; n<params.phim; n++){
                    a[out_ct][n] += ((ui128)ct_mat_c[in_ct][w].a[n]*(ui128)coeff);
                    b[out_ct][n] += ((ui128)ct_mat_c[in_ct][w].b[n]*(ui128)coeff);
                }
            }
        }
    }

    CTVec ret(num_ct, Ciphertext(params.phim));
    for(ui32 out_ct=0; out_ct<num_ct; out_ct++){
        for(ui32 n=0; n<params.phim; n++){
            ret[out_ct].a[n] = opt::modq_part(a[out_ct][n]);
            ret[out_ct].b[n] = opt::modq_part(b[out_ct][n]);
        }
    }
    return ret;
}

std::vector<uv64> postprocess_gemm(const SecretKey& sk, const CTVec& ct_prod,
        const ui32 num_rows, const ui32 num_cols, const FVParams& params){
    ui32 rows_per_ct = (params.phim / num_cols);
    ui32 num_ct = ct_prod.size();
    // std::cout << rows_per_ct << " " << sz_pow2 << std::endl;

    auto prod = std::vector<uv64>(num_rows, uv64(num_cols));
    for(ui32 curr_ct=0; curr_ct<num_ct; curr_ct++){
        auto pt = packed_decode(Decrypt(sk, ct_prod[curr_ct], params), params.p, params.logn);
        for(ui32 curr_row=0; curr_row<rows_per_ct; curr_row++){
            ui32 row = curr_row+curr_ct*rows_per_ct;
            ui32 pt_offset = curr_row*num_cols;

            for(ui32 col=0; col<num_cols; col++){
                prod[row][col] = pt[pt_offset+col];
            }
        }
    }

    return prod;
}

std::vector<uv64> gemm_pt(const std::vector<uv64>& mat_c, const std::vector<uv64>& mat_s_t, const ui64 p){
    ui32 rows_c = mat_c.size();
    ui32 cols_c = mat_c[0].size();

    // ui32 cols_s = mat_s_t.size();
    ui32 rows_s = mat_s_t[0].size();

    // TODO: assert(cols_c == row_s)

    std::vector<uv64> product(rows_s, uv64(cols_c));
    for (ui32 n=0; n < rows_c; n++){
        for (ui32 row = 0; row < rows_s; row++){
            for (ui32 col = 0; col < cols_c; col++){
                product[row][col] += mat_s_t[n][row]*mat_c[n][col];
            }
        }
    }

    for (ui32 row = 0; row < rows_s; row++){
        for (ui32 col = 0; col < cols_c; col++){
            product[row][col] = mod(product[row][col], p);
        }
    }

    return product;
}


}




