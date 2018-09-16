/*
FV-SHE-Benchmarking: This code benchmarks add, sub, neg and mult-plain for FV

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
    std::cout << "FV SHE Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep = 1000;
    double start, stop;

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
    uv64 v1 = get_dgg_testvector(opt::phim, opt::p);
    uv64 v2 = get_dgg_testvector(opt::phim, opt::p);

    uv64 pt1 = packed_encode(v1, opt::p, opt::logn);
    uv64 pt2 = packed_encode(v2, opt::p, opt::logn);

    uv64 v1_f = packed_decode(pt1, opt::p, opt::logn);
    check_vec_eq(v1, v1_f, "Decode mismatch:\n");

    uv64 pt_add(opt::phim);
    for(ui32 i=0; i<opt::phim; i++){
        pt_add[i] = (v1[i] + v2[i]) % opt::p;
    }

    auto ct1 = Encrypt(kp.sk, pt1, test_params);
    auto ct2 = Encrypt(kp.sk, pt2, test_params);
    auto ct2_null = NullEncrypt(pt2, test_params);

    for(ui32 t=0; t<2; t++){
        test_params.fast_modulli = !test_params.fast_modulli;


        //------------------------- Add ------------------------
        start = currentDateTime();
        auto ct_add = EvalAdd(ct1, ct2, test_params);
        for(ui64 i=0; i < nRep; i++){
            ct_add = EvalAdd(ct1, ct2, test_params);
        }
        stop = currentDateTime();
        std::cout << " Add: " << (stop-start)/nRep << std::endl;

        //------------------------- Sub ------------------------
        start = currentDateTime();
        auto ct_sub = EvalSub(ct1, ct2, test_params);
        for(ui64 i=0; i < nRep; i++){
            ct_sub = EvalSub(ct1, ct2, test_params);
        }
        stop = currentDateTime();
        std::cout << " Sub: " << (stop-start)/nRep << std::endl;

        //------------------------- Neg ------------------------
        start = currentDateTime();
        auto ct_neg = EvalNegate(ct1, test_params);
        for(ui64 i=0; i < nRep; i++){
            ct_neg = EvalNegate(ct1, test_params);
        }
        stop = currentDateTime();
        std::cout << " Neg: " << (stop-start)/nRep << std::endl;

        //--------------------- MultPlain ----------------------
        start = currentDateTime();
        auto ct_mul = EvalMultPlain(ct1, ct2_null, test_params);
        for(ui64 i=0; i < nRep; i++){
            ct_mul = EvalMultPlain(ct1, ct2_null, test_params);
        }
        stop = currentDateTime();
        std::cout << " Mult: " << (stop-start)/nRep << std::endl;

        //----------------------- Check ------------------------
        auto v_add = packed_decode(Decrypt(kp.sk, ct_add, test_params), opt::p, opt::logn);
        auto v_sub = packed_decode(Decrypt(kp.sk, ct_sub, test_params), opt::p, opt::logn);
        auto v_neg = packed_decode(Decrypt(kp.sk, ct_neg, test_params), opt::p, opt::logn);
        auto v_mul = packed_decode(Decrypt(kp.sk, ct_mul, test_params), opt::p, opt::logn);

        std::cout << std::endl;
        std::cout << "Margin ct1: " << NoiseMargin(kp.sk, ct1, test_params) << std::endl;
        std::cout << "Margin ct2: " << NoiseMargin(kp.sk, ct2, test_params) << std::endl;

        std::cout << std::endl;
        std::cout << "Margin add: " << NoiseMargin(kp.sk, ct_add, test_params) << std::endl;
        std::cout << "Margin sub: " << NoiseMargin(kp.sk, ct_sub, test_params) << std::endl;
        std::cout << "Margin neg: " << NoiseMargin(kp.sk, ct_neg, test_params) << std::endl;
        std::cout << "Margin mul: " << NoiseMargin(kp.sk, ct_mul, test_params) << std::endl;

        uv64 v_add_ref(opt::phim);
        uv64 v_sub_ref(opt::phim);
        uv64 v_neg_ref(opt::phim);
        uv64 v_mul_ref(opt::phim);

        for(ui32 i=0; i<opt::phim; i++){
            v_add_ref[i] = (v1[i] + v2[i]) % opt::p;
            v_sub_ref[i] = (v1[i] + opt::p - v2[i]) % opt::p;
            v_neg_ref[i] = (opt::p - v1[i]) % opt::p;
            v_mul_ref[i] = (v1[i] * v2[i]) % opt::p;
        }

        check_vec_eq(v_add_ref, v_add, "Add mismatch:\n");
        check_vec_eq(v_sub_ref, v_sub, "Sub mismatch:\n");
        check_vec_eq(v_neg_ref, v_neg, "Neg mismatch:\n");
        check_vec_eq(v_mul_ref, v_mul, "Mul mismatch:\n");
    }

    return 0;
}

