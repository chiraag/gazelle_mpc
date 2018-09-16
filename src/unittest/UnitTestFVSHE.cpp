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


class UnitFVSHE : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

TEST(UTFV_SHE, Ref){
    //------------------ Setup Parameters ------------------
    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams test_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg)
    };

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

    auto ct1 = Encrypt(kp.pk, pt1, test_params);
    auto ct2 = Encrypt(kp.pk, pt2, test_params);
    auto ct2_null = NullEncrypt(pt2, test_params);

    auto ct_add = EvalAdd(ct1, ct2, test_params);
    auto ct_sub = EvalSub(ct1, ct2, test_params);
    auto ct_neg = EvalNegate(ct1, test_params);
    auto ct_mul = EvalMultPlain(ct1, ct2_null, test_params);

    //----------------------- Check ------------------------
    auto v_add = packed_decode(Decrypt(kp.sk, ct_add, test_params), opt::p, opt::logn);
    auto v_sub = packed_decode(Decrypt(kp.sk, ct_sub, test_params), opt::p, opt::logn);
    auto v_neg = packed_decode(Decrypt(kp.sk, ct_neg, test_params), opt::p, opt::logn);
    auto v_mul = packed_decode(Decrypt(kp.sk, ct_mul, test_params), opt::p, opt::logn);

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

    EXPECT_EQ(v_add_ref, v_add);
    EXPECT_EQ(v_sub_ref, v_sub);
    EXPECT_EQ(v_neg_ref, v_neg);
    EXPECT_EQ(v_mul_ref, v_mul);

}

TEST(UTFV_SHE, Fast){
    //------------------ Setup Parameters ------------------
    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ui64 z_p = RootOfUnity(opt::phim << 1, opt::p);
    ftt_precompute(z, opt::q, opt::logn);
    ftt_precompute(z_p, opt::p, opt::logn);
    encoding_precompute(opt::p, opt::logn);

    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams test_params {
        true,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg)
    };

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

    auto ct1 = Encrypt(kp.pk, pt1, test_params);
    auto ct2 = Encrypt(kp.pk, pt2, test_params);
    auto ct2_null = NullEncrypt(pt2, test_params);

    auto ct_add = EvalAdd(ct1, ct2, test_params);
    auto ct_sub = EvalSub(ct1, ct2, test_params);
    auto ct_neg = EvalNegate(ct1, test_params);
    auto ct_mul = EvalMultPlain(ct1, ct2_null, test_params);

    //----------------------- Check ------------------------
    auto v_add = packed_decode(Decrypt(kp.sk, ct_add, test_params), opt::p, opt::logn);
    auto v_sub = packed_decode(Decrypt(kp.sk, ct_sub, test_params), opt::p, opt::logn);
    auto v_neg = packed_decode(Decrypt(kp.sk, ct_neg, test_params), opt::p, opt::logn);
    auto v_mul = packed_decode(Decrypt(kp.sk, ct_mul, test_params), opt::p, opt::logn);

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

    EXPECT_EQ(v_add_ref, v_add);
    EXPECT_EQ(v_sub_ref, v_sub);
    EXPECT_EQ(v_neg_ref, v_neg);
    EXPECT_EQ(v_mul_ref, v_mul);

}
