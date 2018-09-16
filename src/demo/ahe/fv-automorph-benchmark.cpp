/*
FV-Automorphism-Benchmarking: This code benchmarks automorphisms for FV

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <pke/gazelle.h>
#include <iostream>
#include <cassert>
#include <random>

using namespace std;
using namespace lbcrypto;

int main() {
    std::cout << "FV Automorph Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep = 100;
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
        20
    };
    uv32 windows = {20, 10, 5};

    FVParams test_params = slow_params;

    auto kp = KeyGen(test_params);
    uv64 v1 = get_dgg_testvector(opt::phim, opt::p);
    uv64 pt1 = packed_encode(v1, opt::p, opt::logn);
    auto ct1 = Encrypt(kp.sk, pt1, test_params);
    ui32 rot = 2;

    for(ui32 nw=0; nw<windows.size(); nw++){
        test_params.window_size = windows[nw];
        for(ui32 t=0; t<2; t++){
            test_params.fast_modulli = !test_params.fast_modulli;

            //-------------------- Relin KeyGen --------------------
            uv32 index_list(opt::logn);
            ui32 index = 1;
            for(ui32 i=0; i<opt::logn; i++){
                index_list[i] = index;
                index = index*2;
            }
            start = currentDateTime();
            for(ui64 i=0; i < nRep; i++){
                EvalAutomorphismKeyGen(kp.sk, index_list, test_params);
            }
            stop = currentDateTime();
            std::cout << " Relin KeyGen ("<< index_list.size() <<" keys): " << (stop-start)/nRep << std::endl;

            //------------------- EvalAutomorph --------------------
            start = currentDateTime();
            auto ct_rot = EvalAutomorphism(rot, ct1, test_params);
            for(ui64 i=0; i < nRep; i++){
                ct_rot = EvalAutomorphism(rot, ct1, test_params);
            }
            stop = currentDateTime();
            std::cout << " Automorph: " << (stop-start)/nRep << std::endl;

            //------------------ HoistedDecompose ------------------
            start = currentDateTime();
            auto digits_ct1 = HoistedDecompose(ct1, test_params);
            for(ui64 i=0; i < nRep; i++){
                digits_ct1 = HoistedDecompose(ct1, test_params);
            }
            stop = currentDateTime();
            std::cout << " HoistedDecomp: " << (stop-start)/nRep << std::endl;

            //----------------- DecomposedAutomorph ----------------
            start = currentDateTime();
            for(ui64 i=0; i < nRep; i++){
                const auto rk = GetAutomorphismKey(rot);
                auto ct_rotd =  EvalAutomorphismDigits(rot, *rk, ct1, digits_ct1, test_params);
            }
            stop = currentDateTime();
            std::cout << " DecomposedAutomorph: " << (stop-start)/nRep << std::endl;

            //----------------------- Check ------------------------
            auto v1_rot = packed_decode(Decrypt(kp.sk, ct_rot, test_params), opt::p, opt::logn);

            std::cout << std::endl;
            std::cout << "Margin ct: " << NoiseMargin(kp.sk, ct1, test_params) << std::endl;
            std::cout << "Margin rot: " << NoiseMargin(kp.sk, ct_rot, test_params) << std::endl;
            std::cout << std::endl;

            uv64 v1_rot_ref = automorph_pt(v1, rot);

            check_vec_eq(v1_rot_ref, v1_rot, "Rotation mismatch:\n");
        }
    }


    return 0;
}

