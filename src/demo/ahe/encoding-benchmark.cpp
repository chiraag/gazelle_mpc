/*
Transform-Benchmarking: This code benchmarks the FTT code

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <pke/gazelle.h>
#include <iostream>
#include <cassert>
#include "utils/test.h"

using namespace lbcrypto;


int main() {
    std::cout << "Encoding Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams slow_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        20
    };

    FVParams test_params = slow_params;

    auto kp = KeyGen(test_params);

    ui32 num_cols_c=512;
    ui32 rows_per_ct = test_params.phim/num_cols_c;
    //std::vector<uv64> enc_p_mat(rows_per_ct, uv64(rows_per_ct));
    for(ui32 enc_col=0; enc_col<rows_per_ct; enc_col++){
        ui32 start = enc_col*num_cols_c;
        ui32 end = (enc_col+1)*num_cols_c;
        uv64 v(test_params.phim, 0);
        for(ui32 n=start; n<end; n++){
            v[n] = 1;
        }
        std::cout << "v : " << vec_to_str(v) << std::endl;

        uv64 pt = packed_encode(v, opt::p, opt::logn);
        std::cout << "pt: " << vec_to_str(pt) << std::endl;

        uv64 ct_null = NullEncrypt(pt, test_params);
        /*for(ui32 enc_row=0; enc_row<rows_per_ct; enc_row++){
            enc_p_mat[enc_row][enc_col] = pt[enc_row*test_params.phim/rows_per_ct];
        }*/
        std::cout << "ct: " << vec_to_str(ct_null) << std::endl << std::endl;
    }
    // std::cout << mat_to_str(enc_p_mat) << std::endl;
/*
    std::vector<uv64> enc_q_mat(rows_per_ct, uv64(rows_per_ct));
    for(ui32 enc_col=0; enc_col<rows_per_ct; enc_col++){
        uv64 pt(test_params.phim);
        pt[enc_col*(test_params.phim/rows_per_ct)] = 1;

        auto ct_null = NullEncrypt(pt, test_params);
        for(ui32 enc_row=0; enc_row<rows_per_ct; enc_row++){
            enc_q_mat[enc_row][enc_col] = ct_null[enc_row];
        }
        // std::cout << "ct: " << vec_to_str(ct_null) << std::endl;
    }
    std::cout << mat_to_str(enc_q_mat) << std::endl;
*/
    /*
    ui32 num_rows=2, num_cols=2;
    std::vector<uv64> mat(num_rows, uv64(num_cols));
    for(ui32 row=0; row<num_rows; row++){
        mat[row] = get_dgg_testvector(num_cols, opt::p);
    }

    ui32 num_sets = num_rows*num_cols/rows_per_ct;
    ui32 curr_set = 0;
    std::vector<uv64> enc_mat(num_sets, uv64(rows_per_ct));
    for(ui32 row=0; row<num_rows; row+=rows_per_ct){
        for(ui32 col=0; col<num_cols; col+=rows_per_ct){
            auto mat_ref = std::vector<uv64>(rows_per_ct, uv64(rows_per_ct));
            auto mat_diag = std::vector<uv64>(rows_per_ct, uv64(rows_per_ct));
            for(ui32 sub_row=0; sub_row<rows_per_ct; sub_row++){
                for(ui32 sub_col=0; sub_col<rows_per_ct; sub_col++){
                    ui32 row_diag_l = (sub_col-sub_row) & ((rows_per_ct >> 1)-1);
                    ui32 row_diag_h = (sub_col^sub_row) & (rows_per_ct >> 1);
                    ui32 row_diag = (row_diag_h + row_diag_l);

                    ui32 col_diag_l = (sub_col - row_diag_l) & ((rows_per_ct >> 1)-1);
                    ui32 col_diag_h = (sub_col & (rows_per_ct >> 1)) ^ row_diag_h;
                    ui32 col_diag = col_diag_h + col_diag_l;

                    mat_ref[sub_row][sub_col] = mat[row+sub_row][col+sub_col];
                    mat_diag[row_diag][col_diag] = mat[row+sub_row][col+sub_col];
                }
            }

            if(row==0 && col==0){
                std::cout << mat_to_str(mat_ref) << std::endl;
                std::cout << mat_to_str(mat_diag) << std::endl;
            }

            for(ui32 row_diag=0; row_diag<rows_per_ct; row_diag++){
                auto pt_coeff = uv64(rows_per_ct);
                for(ui32 enc_row=0; enc_row<rows_per_ct; enc_row++){
                    for(ui32 enc_col=0; enc_col<rows_per_ct; enc_col++){
                        pt_coeff[enc_row] += enc_p_mat[enc_row][enc_col]*mat_diag[row_diag][enc_col];
                    }
                    pt_coeff[enc_row] = opt::modp_full(pt_coeff[enc_row]);
                }
                // std::cout << vec_to_str(pt_coeff) << std::endl;

                for(ui32 n=0; n<rows_per_ct; n++){
                    ui128 sum = 0;
                    for(ui32 enc_col=0; enc_col<rows_per_ct; enc_col++){
                        sum += ((ui128)enc_q_mat[n][enc_col] * (ui128)pt_coeff[enc_col]);
                    }
                    sum = opt::modq_full(sum);
                    enc_mat[curr_set][n] = opt::mul_modq_part(sum, test_params.delta);
                }
                curr_set++;
                // std::cout << vec_to_str(ct_coeff) << std::endl;

            }
        }
    }

    for(curr_set=0; curr_set<num_sets; curr_set++){
        auto ct = Ciphertext(test_params.phim);
        for(ui32 n=0; n<test_params.phim; n+=rows_per_ct){
            for(ui32 m=0; m<rows_per_ct; m++){
                ct.b[n+m] = enc_mat[curr_set][m];
            }
        }

        auto vec_decode = packed_decode(Decrypt(kp.sk, ct, test_params), test_params.p, test_params.logn);
        std::cout << vec_to_str(vec_decode) << std::endl;
    }*/
    return 0;
}
