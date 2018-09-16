/*
FV-Benchmarking: This code benchmarks keygen, encrypt and decrypt for FV

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <pke/gazelle.h>
#include <iostream>
#include <cassert>

using namespace std;
using namespace lbcrypto;


int main() {
    std::cout << "FV Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep = 1000;
    double start, stop;

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams slow_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        20
    };
    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);
    //------------------------ Setup -----------------------
    start = currentDateTime();
    for(ui64 i=0; i < 100; i++){
        z = RootOfUnity(opt::phim << 1, opt::q);
        z_p = RootOfUnity(opt::phim << 1, opt::p);
        ftt_precompute(z, opt::q, opt::logn);
        ftt_precompute(z_p, opt::p, opt::logn);
        encoding_precompute(opt::p, opt::logn);
    }
    stop = currentDateTime();
    std::cout << " Setup: " << (stop-start)/100 << std::endl;

    FVParams test_params = slow_params;

    for(ui32 t=0; t<2; t++){
        test_params.fast_modulli = !test_params.fast_modulli;

        uv64 v = get_dgg_testvector(opt::phim, opt::p);
        uv64 pt = packed_encode(v, opt::p, opt::logn);

        //----------------------- KeyGen -----------------------
        auto kp = KeyGen(test_params);
        start = currentDateTime();
        for(ui64 i=0; i < nRep; i++){
            kp = KeyGen(test_params);
        }
        stop = currentDateTime();
        std::cout << " KeyGen: " << (stop-start)/nRep << std::endl;
        //--------------------- PK-Encrypt----------------------
        Ciphertext ct_pk(opt::phim);
        start = currentDateTime();
        for(ui64 i=0; i < nRep; i++){
            ct_pk = Encrypt(kp.pk, pt, test_params);
        }
        stop = currentDateTime();
        std::cout << " PK-Encrypt: " << (stop-start)/nRep << std::endl;

        //--------------------- SK-Encrypt----------------------
        Ciphertext ct_sk(opt::phim);
        start = currentDateTime();
        for(ui64 i=0; i < nRep; i++){
            pt = packed_encode(v, opt::p, opt::logn);
            ct_sk = Encrypt(kp.sk, pt, test_params);
        }
        stop = currentDateTime();
        std::cout << " SK-Encrypt: " << (stop-start)/nRep << std::endl;

        //---------------------- Decrypt -----------------------
        uv64 pt_pk(opt::phim), pt_sk(opt::phim), v_pk(opt::phim), v_sk(opt::phim);
        start = currentDateTime();
        for(ui64 i=0; i < (nRep/2); i++){
            pt_pk = Decrypt(kp.sk, ct_pk, test_params);
            v_pk = packed_decode(pt_pk, opt::p, opt::logn);
            pt_sk = Decrypt(kp.sk, ct_sk, test_params);
            v_sk = packed_decode(pt_sk, opt::p, opt::logn);
        }
        stop = currentDateTime();
        std::cout << " Decrypt: " << (stop-start)/nRep << std::endl;

        check_vec_eq(v, v_pk, "pk enc-dec mismatch:\n");
        check_vec_eq(v, v_sk, "sk enc-dec mismatch:\n");
    }
    return 0;
}

