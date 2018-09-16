/*
NN-Layers-Benchmarking: This code benchmarks FC and Conv layers for a neural network

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <iostream>
#include <random>
#include "pke/gazelle.h"

using namespace std;
using namespace lbcrypto;

int main() {
    std::cout << "NN Layers Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep = 1;
    double start, stop;

    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
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
        9
    };

    FVParams fast_params = slow_params;
    fast_params.fast_modulli = true;

    FVParams test_params = fast_params;

    //------------------- Synthetic Data -------------------
    uv64 vec = get_dgg_testvector(opt::phim, opt::p);

    ui32 filter_size = 5;
    auto filter_1d = get_dgg_testvector(filter_size, opt::p);

    //----------------------- KeyGen -----------------------
    nRep = 1;
    auto kp = KeyGen(test_params);
    uv32 index_list;
    for (ui32 i = 1; i <(filter_size/2); i++){
        index_list.push_back(i);
    }

    for(ui32 i=1; i<=(filter_size/2); i++){
        index_list.push_back(opt::phim/2-i);
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
    uv64 pt = packed_encode(vec, opt::p, opt::logn);
    auto ct_vec = preprocess_vec(kp.sk, pt, mat_window_size, mat_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        pt = packed_encode(vec, opt::p, opt::logn);
        ct_vec = preprocess_vec(kp.sk, pt, mat_window_size, mat_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Vector ("<< mat_num_windows <<" windows): " << (stop-start)/nRep << std::endl;

    //----------------- Preprocess Filter ------------------
    auto enc_filter = preprocess_filter_1d(filter_1d, mat_window_size, mat_num_windows, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        enc_filter = preprocess_filter_1d(filter_1d, mat_window_size, mat_num_windows, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Filter: " << (stop-start)/nRep << std::endl;

    //--------------------- Conv1D (Rot) --------------------
    auto ct_conv_rot = conv_1d_rot(ct_vec, enc_filter.size(), test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_conv_rot = conv_1d_rot(ct_vec, enc_filter.size(), test_params);
    }
    stop = currentDateTime();
    std::cout << " Conv1D: " << (stop-start)/nRep << std::endl;

    //--------------------- Conv1D (Mul) --------------------
    auto ct_conv_mul = conv_1d_mul(ct_conv_rot, enc_filter, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_conv_mul = conv_1d_mul(ct_conv_rot, enc_filter, test_params);
    }
    stop = currentDateTime();
    std::cout << " Conv1D: " << (stop-start)/nRep << std::endl;

    //------------------------ Conv1D ----------------------
    auto ct_conv_1d = conv_1d_online(ct_vec, enc_filter, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_conv_1d = conv_1d_online(ct_vec, enc_filter, test_params);
    }
    stop = currentDateTime();
    std::cout << " Conv1D: " << (stop-start)/nRep << std::endl;


    //----------------------- Check ------------------------
    auto conv_1d = packed_decode(Decrypt(kp.sk, ct_conv_1d, test_params), opt::p, opt::logn);

    std::cout << std::endl;
    std::cout << "Margin ct: " << NoiseMargin(kp.sk, ct_vec[0], test_params) << std::endl;
    std::cout << "Margin conv_1d: " << NoiseMargin(kp.sk, ct_conv_1d, test_params) << std::endl;
    std::cout << std::endl;

    auto conv_1d_ref = conv_1d_pt(vec, filter_1d, opt::p);
/*  std::cout << vec_to_str(to_signed(vec, opt::p)) << std::endl;
    std::cout << vec_to_str(to_signed(filter_1d, opt::p)) << std::endl;
    std::cout << vec_to_str(to_signed(conv_1d_ref, opt::p)) << std::endl;
    std::cout << vec_to_str(to_signed(conv_1d, opt::p)) << std::endl;*/
//  check_vec_eq(conv_1d_ref, conv_1d, "conv_1d mismatch:\n");

    return 0;
}

