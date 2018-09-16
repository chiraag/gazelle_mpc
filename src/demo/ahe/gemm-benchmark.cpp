/*
NN-Layers-Benchmarking: This code benchmarks FC and Conv layers for a neural network

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <pke/gazelle.h>
#include <iostream>
#include <random>
#include <algorithm>
#include "math/bit_twiddle.h"
using namespace std;
using namespace lbcrypto;

int main() {
    std::cout << "GEMM Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep = 1;
    double start, stop;

    ui64 z = opt::z;
    ui64 z_p = opt::z_p;

    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);
    precompute_automorph_index(opt::phim);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams slow_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        8
    };

    FVParams fast_params = slow_params;
    fast_params.fast_modulli = true;

    FVParams test_params = fast_params;

    //------------------- Synthetic Data -------------------
    ui32 window_size = 20;
    ui32 k = 128;
    ui32 num_rows_s = 128, num_cols_s = k;
    ui32 num_rows_c = k, num_cols_c = 128;
    ui32 mat_window_size = 20;
    ui32 mat_num_windows = 1;
    // std::cin >> num_rows >> num_cols >> window_size;
    test_params.window_size = window_size;

    std::vector<uv64> mat_s(num_rows_s, uv64(num_cols_s));
    std::vector<uv64> mat_s_t(num_cols_s, uv64(num_rows_s));
    for(ui32 row=0; row<num_rows_s; row++){
        mat_s[row] = get_dgg_testvector(num_cols_s, opt::p);
    }
    // std::cout << mat_to_str(mat_s) << std::endl;

    for(ui32 row=0; row<num_rows_s; row++){
        for(ui32 col=0; col<num_cols_s; col++){
            mat_s_t[col][row] = mat_s[row][col];
        }
    }

    std::vector<uv64> mat_c(num_rows_c, uv64(num_cols_c));
    for(ui32 row=0; row<num_rows_c; row++){
        mat_c[row] = get_dgg_testvector(num_cols_c, opt::p);
    }

    //----------------------- KeyGen -----------------------
    nRep = 10;
    auto kp = KeyGen(test_params);

    ui32 rows_per_ct = test_params.phim/num_cols_c;
    uv32 index_list;
    for (ui32 i = 1; i < rows_per_ct; i++){
        index_list.push_back(test_params.phim-i*num_cols_c);
        // index_list.push_back(i+(opt::phim/2));
    }

    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        kp = KeyGen(test_params);
        EvalAutomorphismKeyGen(kp.sk, index_list, test_params);
    }
    stop = currentDateTime();
    std::cout << " KeyGen ("<< index_list.size() <<" keys): " << (stop-start)/nRep << std::endl;

    //-------------- Preprocess Client Matrix --------------
    nRep = 1;
    auto ct_mat_c = preprocess_gemm_c(kp.sk, mat_c, mat_window_size, mat_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_mat_c = preprocess_gemm_c(kp.sk, mat_c, mat_window_size, mat_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Client Matrix ("<< mat_num_windows <<" windows): " << (stop-start)/nRep << std::endl;

    //----------------- Preprocess Matrix ------------------
    EncMat enc_mat_s;
    if(rows_per_ct > 1){
        //enc_mat_s = preprocess_gemm_s(mat_s, num_cols_c, mat_window_size, mat_num_windows, test_params);
        start = currentDateTime();
        for(ui64 i=0; i < nRep; i++){
             enc_mat_s = preprocess_gemm_s(mat_s, num_cols_c, mat_window_size, mat_num_windows, test_params);
        }
        stop = currentDateTime();
        std::cout << " Preprocess Matrix ("<< num_rows_s <<"x"<< num_cols_s << "): " << (stop-start)/nRep << std::endl;
    }

    //--------------------- Multiply -----------------------
    CTVec ct_prod;
    if(rows_per_ct > 1){
        //ct_prod = gemm_online(ct_mat_c, enc_mat_s, num_cols_c, test_params);
        start = currentDateTime();
        for(ui64 i=0; i < nRep; i++){
            ct_prod = gemm_online(ct_mat_c, enc_mat_s, num_cols_c, test_params);
        }
        stop = currentDateTime();

    } else {
        ct_prod = gemm_phim_online(ct_mat_c, mat_s_t, mat_window_size, mat_num_windows, test_params);
        start = currentDateTime();
        for(ui64 i=0; i < nRep; i++){
            ct_prod = gemm_phim_online(ct_mat_c, mat_s_t, mat_window_size, mat_num_windows, test_params);
        }
        stop = currentDateTime();
    }
    std::cout << " Multiply: " << (stop-start)/nRep << std::endl;

    //------------------- Post-Process ---------------------
    auto prod = postprocess_gemm(kp.sk, ct_prod, num_rows_s, num_cols_c, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        prod = postprocess_gemm(kp.sk, ct_prod, num_rows_s, num_cols_c, test_params);
    }
    stop = currentDateTime();
    std::cout << " Post-Process: " << (stop-start)/nRep << std::endl;

    //------------------- Multiply PT ----------------------
    auto prod_ref = gemm_pt(mat_c, mat_s_t, opt::p);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        prod_ref = gemm_pt(mat_c, mat_s_t, opt::p);
    }
    stop = currentDateTime();
    std::cout << " Multiply PT: " << (stop-start)/nRep << std::endl;

    //----------------------- Check ------------------------
    std::cout << std::endl;
    for(ui32 w=0; w<mat_num_windows; w++){
        std::cout << "Margin ct("<<w<<"): " << NoiseMargin(kp.sk, ct_mat_c[0][w], test_params) << std::endl;
    }
    double noise = 100;
    for(ui32 n=0; n<ct_prod.size(); n++){
        double noise_new = NoiseMargin(kp.sk, ct_prod[n], test_params);
        if(noise_new < noise){
            noise = noise_new;
        }
    }
    std::cout << "Margin prod: " << noise << std::endl;
    std::cout << std::endl;

    /*auto pt = packed_decode(Decrypt(kp.sk, ct_prod[0], test_params), test_params.p, test_params.logn);
    std::cout << vec_to_str(pt) << std::endl;
    auto pt_in = packed_decode(Decrypt(kp.sk, ct_mat_c[0][0], test_params), test_params.p, test_params.logn);
    std::cout << vec_to_str(pt_in) << std::endl;
    std::cout << vec_to_str(mat_c[0]) << std::endl;
*/

    /* ui32 err = */ check_mat_eq(prod_ref, prod, "mat_mul mismatch:\n");
    /* if(err != prod_ref.size()){
        std::cout << "Margin err: " << NoiseMargin(kp.sk, ct_prod[err], test_params) << std::endl;
        std::cout << "Coeff err: " << mat_s_t[0][err] << std::endl;

        Ciphertext prod_vec(test_params.phim);
        ui64 coeff = mat_s_t[0][err];
        for(ui32 n=0; n<test_params.phim; n++){
            prod_vec.a[n] = opt::mul_modq_part(ct_mat_c[0][0].a[n], coeff);
            prod_vec.b[n] = opt::mul_modq_part(ct_mat_c[0][0].b[n], coeff);
        }
        std::cout << "Margin: " << NoiseMargin(kp.sk, prod_vec, test_params) << std::endl;

    } */


    return 0;
}

