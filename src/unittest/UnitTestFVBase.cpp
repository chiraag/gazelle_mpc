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


class UnitTestFVBase : public ::testing::Test {
 protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};

/*---------------------------------------   TESTING METHODS OF TRANSFORM      --------------------------------------------*/

// TEST CASE TO TEST POLYNOMIAL MULTIPLICATION USING CHINESE REMAINDER THEOREM

TEST(UTFV, Ref){
    //------------------ Setup Parameters ------------------
    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams test_params {
        false,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg)
    };

    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ftt_precompute(z, opt::q, opt::logn);

    uv64 pt = get_dug_vector(opt::phim, opt::p);

    //----------------------- KeyGen -----------------------
    auto kp = KeyGen(test_params);
    kp = KeyGen(test_params);

    //--------------------- PK-Encrypt----------------------
    Ciphertext ct_pk(opt::phim);
    ct_pk = Encrypt(kp.pk, pt, test_params);

    //--------------------- SK-Encrypt----------------------
    Ciphertext ct_sk(opt::phim);
    ct_sk = Encrypt(kp.sk, pt, test_params);

    //---------------------- Decrypt -----------------------
    uv64 pt_pk(opt::phim), pt_sk(opt::phim);
    pt_pk = Decrypt(kp.sk, ct_pk, test_params);
    pt_sk = Decrypt(kp.sk, ct_sk, test_params);

    EXPECT_EQ(pt, pt_pk);

    EXPECT_EQ(pt, pt_sk);

}

TEST(UTFV, Fast){
    //------------------ Setup Parameters ------------------
    DiscreteGaussianGenerator dgg = DiscreteGaussianGenerator(4.0);

    FVParams test_params {
        true,
        opt::q, opt::p, opt::logn, opt::phim,
        (opt::q/opt::p),
        OPTIMIZED, std::make_shared<DiscreteGaussianGenerator>(dgg)
    };

    ui64 z = RootOfUnity(opt::phim << 1, opt::q);
    ftt_precompute(z, opt::q, opt::logn);

    uv64 pt = get_dug_vector(opt::phim, opt::p);

    //----------------------- KeyGen -----------------------
    auto kp = KeyGen(test_params);
    kp = KeyGen(test_params);

    //--------------------- PK-Encrypt----------------------
    Ciphertext ct_pk(opt::phim);
    ct_pk = Encrypt(kp.pk, pt, test_params);

    //--------------------- SK-Encrypt----------------------
    Ciphertext ct_sk(opt::phim);
    ct_sk = Encrypt(kp.sk, pt, test_params);

    //---------------------- Decrypt -----------------------
    uv64 pt_pk(opt::phim), pt_sk(opt::phim);
    pt_pk = Decrypt(kp.sk, ct_pk, test_params);
    pt_sk = Decrypt(kp.sk, ct_sk, test_params);

    EXPECT_EQ(pt, pt_pk);

    EXPECT_EQ(pt, pt_sk);

}
