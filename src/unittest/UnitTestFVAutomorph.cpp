/*
 * @file 
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /*
    This code tests the transform feature of the PALISADE lattice encryption library.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "../lib/pke/gazelle.h"

using namespace std;
using namespace lbcrypto;


class UnitFVAutomorph : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

TEST(UTFV_Automorph, Ref){
    //------------------ Setup Parameters ------------------
    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);
    precompute_automorph_index(opt::phim);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams test_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        20
    };

    auto kp = KeyGen(test_params);
    uv64 v1 = get_dgg_testvector(opt::phim, opt::p);
    uv64 pt1 = packed_encode(v1, opt::p, opt::logn);
    auto ct1 = Encrypt(kp.sk, pt1, test_params);
    ui32 rot = 4;

    uv32 index_list(opt::logn);
    ui32 index = 1;
    for(ui32 i=0; i<opt::logn; i++){
        index_list[i] = index;
        index = index*2;
    }

    //-------------------- Relin KeyGen --------------------
    EvalAutomorphismKeyGen(kp.sk, index_list, test_params);

    //------------------- EvalAutomorph --------------------
    auto ct_rot = EvalAutomorphism(rot, ct1, test_params);

    //----------------------- Check ------------------------
    auto v1_rot = packed_decode(Decrypt(kp.sk, ct_rot, test_params), opt::p, opt::logn);
    uv64 v1_rot_ref = automorph_pt(v1, rot);

    EXPECT_EQ(v1_rot_ref, v1_rot);

}

TEST(UTFV_Automorph, Fast){
    //------------------ Setup Parameters ------------------
    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);
    precompute_automorph_index(opt::phim);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams test_params {
        true,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg),
        20
    };

    auto kp = KeyGen(test_params);
    uv64 v1 = get_dgg_testvector(opt::phim, opt::p);
    uv64 pt1 = packed_encode(v1, opt::p, opt::logn);
    auto ct1 = Encrypt(kp.sk, pt1, test_params);
    ui32 rot = 4;

    uv32 index_list(opt::logn);
    ui32 index = 1;
    for(ui32 i=0; i<opt::logn; i++){
        index_list[i] = index;
        index = index*2;
    }

    //-------------------- Relin KeyGen --------------------
    EvalAutomorphismKeyGen(kp.sk, index_list, test_params);

    //------------------- EvalAutomorph --------------------
    auto ct_rot = EvalAutomorphism(rot, ct1, test_params);

    //----------------------- Check ------------------------
    auto v1_rot = packed_decode(Decrypt(kp.sk, ct_rot, test_params), opt::p, opt::logn);
    uv64 v1_rot_ref = automorph_pt(v1, rot);

    EXPECT_EQ(v1_rot_ref, v1_rot);

}
