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
#include "math/bit_twiddle.h"
using namespace std;
using namespace lbcrypto;

int main() {
    std::cout << "NN Layers Benchmark (ms):" << std::endl;

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
    ui32 num_rows = 64, num_cols = 128, window_size = 8;
    std::cin >> num_rows >> num_cols >> window_size;
    test_params.window_size = window_size;

    uv64 vec = get_dgg_testvector(num_cols, opt::p);

    std::vector<uv64> mat(num_rows, uv64(num_cols));
    for(ui32 row=0; row<num_rows; row++){
        mat[row] = get_dgg_testvector(num_cols, opt::p);
    }

    //----------------------- KeyGen -----------------------
    nRep = 10;
    auto kp = KeyGen(test_params);

    ui32 num_rot = nxt_pow2(num_rows)*nxt_pow2(num_cols)/opt::phim;
    uv32 index_list;
    for (ui32 i = 1; i < num_rot; i++){
        index_list.push_back(i);
    }
    for(ui32 i=num_rot; i<num_cols; i*=2){
        index_list.push_back(i);
    }

    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        kp = KeyGen(test_params);
        EvalAutomorphismKeyGen(kp.sk, index_list, test_params);
    }
    stop = currentDateTime();
    std::cout << " KeyGen ("<< index_list.size() <<" keys): " << (stop-start)/nRep << std::endl;

    //----------------- Preprocess Vector ------------------
    nRep = 100;
    ui32 mat_window_size = 10;
    ui32 mat_num_windows = 2;
    auto ct_vec = preprocess_vec(kp.sk, vec, mat_window_size, mat_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_vec = preprocess_vec(kp.sk, vec, mat_window_size, mat_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Vector ("<< mat_num_windows <<" windows): " << (stop-start)/nRep << std::endl;

    //----------------- Preprocess Matrix ------------------
    auto enc_mat = preprocess_matrix(mat, mat_window_size, mat_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
         enc_mat = preprocess_matrix(mat, mat_window_size, mat_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Matrix ("<< num_rows <<" rows): " << (stop-start)/nRep << std::endl;

    //--------------------- Multiply -----------------------
    auto ct_prod = mat_mul_online(ct_vec, enc_mat, num_cols, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_prod = mat_mul_online(ct_vec, enc_mat, num_cols, test_params);
    }
    stop = currentDateTime();
    std::cout << " Multiply: " << (stop-start)/nRep << std::endl;

    //------------------- Post-Process ---------------------
    auto prod = postprocess_prod(kp.sk, ct_prod, num_cols, num_rows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        prod = postprocess_prod(kp.sk, ct_prod, num_cols, num_rows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Post-Process: " << (stop-start)/nRep << std::endl;

    //------------------- Multiply PT ----------------------
    start = currentDateTime();
    auto prod_ref = mat_mul_pt(vec, mat, opt::p);
    for(ui64 i=0; i < nRep; i++){
        prod_ref = mat_mul_pt(vec, mat, opt::p);
    }
    stop = currentDateTime();
    std::cout << " Multiply PT: " << (stop-start)/nRep << std::endl;

    //----------------------- Check ------------------------
    std::cout << std::endl;
    std::cout << "Margin ct: " << NoiseMargin(kp.sk, ct_vec[0], test_params) << std::endl;
    std::cout << "Margin prod: " << NoiseMargin(kp.sk, ct_prod, test_params) << std::endl;
    std::cout << std::endl;

    check_vec_eq(prod_ref, prod, "mat_mul mismatch:\n");

    return 0;
}

