/*
NN-Layers-Benchmarking: This code benchmarks FC and Conv layers for a neural network

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <pke/gazelle.h>
#include <utils/backend.h>
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
        8
    };

    FVParams fast_params = slow_params;
    fast_params.fast_modulli = true;

    FVParams test_params = fast_params;

    //------------------- Synthetic Data -------------------
    ui32 vec_size = 2048;
    std::cin >> vec_size;
    uv64 vec_c = get_dgg_testvector(vec_size, opt::p);
    uv64 vec_s = get_dgg_testvector(vec_size, opt::p);

    //----------------------- KeyGen -----------------------
    nRep = 10;
    auto kp = KeyGen(test_params);

    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        kp = KeyGen(test_params);
    }
    stop = currentDateTime();
    std::cout << " KeyGen: " << (stop-start)/nRep << std::endl;

    //----------------- Client Preprocess ------------------
    nRep = 100;
    auto ct_vec = preprocess_client_share(kp.sk, vec_c, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_vec = preprocess_client_share(kp.sk, vec_c, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Client: " << (stop-start)/nRep << std::endl;

    //----------------- Server Preprocess -----------------
    std::vector<uv64> pt_vec;
    uv64 vec_s_f;
    std::tie(pt_vec, vec_s_f) = preprocess_server_share(vec_s, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        std::tie(pt_vec, vec_s_f) = preprocess_server_share(vec_s, test_params);
    }
    stop = currentDateTime();
    std::cout << " Preprocess Server: " << (stop-start)/nRep << std::endl;

    //---------------------- Square -----------------------
    auto ct_c_f = square_online(ct_vec, pt_vec, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        ct_c_f = square_online(ct_vec, pt_vec, test_params);
    }
    stop = currentDateTime();
    std::cout << " Multiply: " << (stop-start)/nRep << std::endl;

    //------------------- Post-Process ---------------------
    auto vec_c_f = postprocess_client_share(kp.sk, ct_c_f, vec_size, test_params);
    start = currentDateTime();
    for(ui64 i=0; i < nRep; i++){
        vec_c_f = postprocess_client_share(kp.sk, ct_c_f, vec_size, test_params);
    }
    stop = currentDateTime();
    std::cout << " Post-Process: " << (stop-start)/nRep << std::endl;

    //--------------------- Square PT ----------------------
    start = currentDateTime();
    auto vec_c_f_ref = square_pt(vec_c, vec_s, vec_s_f, opt::p);
    for(ui64 i=0; i < nRep; i++){
        vec_c_f_ref = square_pt(vec_c, vec_s, vec_s_f, opt::p);
    }
    stop = currentDateTime();
    std::cout << " Multiply PT: " << (stop-start)/nRep << std::endl;

    //----------------------- Check ------------------------
    // std::cout << std::endl;
    // std::cout << "Margin ct: " << NoiseMargin(kp.sk, ct_vec[0], test_params) << std::endl;
    // std::cout << "Margin prod: " << NoiseMargin(kp.sk, ct_prod, test_params) << std::endl;
    std::cout << std::endl;

    check_vec_eq(vec_c_f_ref, vec_c_f, "square mismatch:\n");

    return 0;
}

