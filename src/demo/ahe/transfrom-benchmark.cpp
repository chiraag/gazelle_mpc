/*
Transform-Benchmarking: This code benchmarks the FTT code

List of Authors:
Chiraag Juvekar, chiraag@mit.edu

License Information:
MIT License
Copyright (c) 2017, Massachusetts Institute of Technology (MIT)

*/

#include <utils/backend.h>
#include <iostream>
#include <cassert>
#include "utils/debug.h"
#include "utils/test.h"
#include "math/params.h"
#include "math/nbtheory.h"
#include "math/distrgen.h"
#include "math/transfrm.h"

using namespace lbcrypto;


int main() {
    std::cout << "Transform Benchmark (ms):" << std::endl;

    //------------------ Setup Parameters ------------------
    ui64 nRep;
    double start, stop;

    uv64 x = get_dug_vector(opt::phim, opt::q);
    uv64 X, xx;

    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    X = ftt_fwd(x, opt::q, opt::logn);
    xx = ftt_inv(X, opt::q, opt::logn);

    check_vec_eq(x, xx, "ftt mismatch\n");

    //-------------------- Baseline FTT --------------------
    nRep = 1000;
    start = currentDateTime();
    for(uint64_t n=0; n<nRep; n++){
        X = ftt_fwd(x, opt::q, opt::logn);
    }
    stop = currentDateTime();
    std::cout << " ftt_fwd: " << (stop-start)/nRep << std::endl;

    //--------------------- Fast Q FTT ---------------------
    nRep = 10000;
    uv64 Xf, xxf;
    start = currentDateTime();
    for(ui32 n=0; n<nRep; n++){
        Xf = ftt_fwd_opt(x);
        for (ui32 i = 0; i< opt::phim; i++) {
            Xf[i] = opt::modq_full(Xf[i]);
        }
    }
    stop = currentDateTime();
    std::cout << " ftt_fwd_fast: " << (stop-start)/nRep << std::endl;

    check_vec_eq(Xf, X, "fft_fwd_fast mismatch:\n");

    start = currentDateTime();
    for(ui32 n=0; n<nRep; n++){
        xxf = ftt_inv_opt(Xf);
        for (ui32 i = 0; i< opt::phim; i++) {
            xxf[i] = opt::modq_full(xxf[i]);
        }
    }
    stop = currentDateTime();
    std::cout << " ftt_inv_fast: " << (stop-start)/nRep << std::endl;

    check_vec_eq(xxf, x, "fft_inv_fast mismatch:\n");

    //--------------------- Fast P FTT ---------------------
    x = get_dug_vector(opt::phim, opt::p);
    start = currentDateTime();
    for(ui32 n=0; n<nRep; n++){
        Xf = ftt_fwd_opt_p(x);
    }
    stop = currentDateTime();
    std::cout << " ftt_fwd_fast_p: " << (stop-start)/nRep << std::endl;

    start = currentDateTime();
    for(ui32 n=0; n<nRep; n++){
        xxf = ftt_inv_opt_p(Xf);
    }
    stop = currentDateTime();
    std::cout << " ftt_inv_fast_p: " << (stop-start)/nRep << std::endl;

    check_vec_eq(xxf, x, "fft_p mismatch:\n");

    return 0;
}
