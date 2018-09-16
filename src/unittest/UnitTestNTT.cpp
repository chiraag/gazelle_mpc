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

Test cases in this file make the following assumptions:
1. All functionatliy of plaintext (both BytePlainTextEncoding and IntPlainTextEncoding) work.
2. Encrypt/Decrypt work
3. Math layer operations such as functions in nbtheory
*/

#include "include/gtest/gtest.h"
#include <iostream>

//#include "../lib/lattice/dcrtpoly.h"
#include "math/backend.h"
#include "math/transfrm.h"

#include "math/nbtheory.h"
//#include "math/distrgen.h"

using namespace std;
using namespace lbcrypto;

template <class T>
class UTNTT : public ::testing::Test {

public:
    const ui32 m = 16;

protected:
    UTNTT() {}

    virtual void SetUp() {
    }

    virtual void TearDown() {

    }

    virtual ~UTNTT() {  }

};

TEST(UTNTT, switch_format_simple_single_crt) {
    ui32 logn = 3;
    ui32 phim = (1 << logn);
    ui32 m = phim*2;

    ui64 modulus = FirstPrime(22, m);
    ui64 rootOfUnity(RootOfUnity(m, modulus));

    uv64 x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };
    uv64 x1Clone(x1);

    ftt_precompute(rootOfUnity, modulus, logn);

    uv64 X1 = ftt_fwd(x1, modulus, logn);
    x1 = ftt_inv(X1, modulus, logn);

    EXPECT_EQ(x1, x1Clone);
}


/*
TEST(UTNTT, switch_format_simple_single_crt) {
    ui32 m1 = 16;

    BigInteger modulus = FirstPrime<BigInteger>(22, m1);
    BigInteger rootOfUnity(RootOfUnity(m1, modulus));
    ILParams params(m1, modulus, rootOfUnity);
    ILParams params2(m1 / 2, modulus, rootOfUnity);
    shared_ptr<ILParams> x1p( new ILParams(params) );
    shared_ptr<ILParams> x2p( new ILParams(params2) );

    Poly x1( x1p, Format::COEFFICIENT );
    x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

    Poly x2( x2p, Format::COEFFICIENT );
    x2 = { 4127,9647,1987,5410 };

    Poly x1Clone(x1);
    Poly x2Clone(x2);

    x1.SwitchFormat();
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    EXPECT_EQ(x1, x1Clone);
    EXPECT_EQ(x2, x2Clone);
}

TEST(UTNTT, switch_format_simple_double_crt) {
    ui32 init_m = 16;

    float init_stdDev = 4;

    ui32 init_size = 2;

    vector<native_int::BigInteger> init_moduli(init_size);
    vector<native_int::BigInteger> init_rootsOfUnity(init_size);

    native_int::BigInteger q = FirstPrime<native_int::BigInteger>(28, init_m);
    native_int::BigInteger temp;
    BigInteger modulus(1);

    for (size_t i = 0; i < init_size; i++) {
        init_moduli[i] = q;
        init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
        modulus = modulus * BigInteger(init_moduli[i].ConvertToInt());
        q = NextPrime(q, init_m);
    }

    DiscreteGaussianGenerator dgg(init_stdDev);

    shared_ptr<ILDCRTParams<BigInteger>> params( new ILDCRTParams<BigInteger>(init_m, init_moduli, init_rootsOfUnity) );

    DCRTPoly x1(params, Format::COEFFICIENT);
    x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

    DCRTPoly x2(params, Format::COEFFICIENT);
    x2 = { 4127,9647,1987,5410,6541,7014,9741,1256 };

    DCRTPoly x1Clone(x1);
    DCRTPoly x2Clone(x2);

    x1.SwitchFormat();
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    EXPECT_EQ(x1, x1Clone);
    EXPECT_EQ(x2, x2Clone);
}

TEST(UTNTT, switch_format_decompose_single_crt) {
        bool dbg_flag = false;
    ui32 m1 = 16;

    BigInteger modulus = FirstPrime<BigInteger>(22, m1);
    BigInteger rootOfUnity(RootOfUnity(m1, modulus));
    shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
    shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );

    Poly x1(params, Format::COEFFICIENT);
    x1 = { 431,3414,1234,7845,2145,7415,5471,8452 };

    Poly x2(params, Format::COEFFICIENT);
    x2 = { 4127,9647,1987,5410,6541,7014,9741,1256 };

    x1.SwitchFormat(); //EVAL
    x2.SwitchFormat();

    x1.SwitchFormat(); //COEF
    x2.SwitchFormat();

    x1.Decompose();
    x2.Decompose();

    x1.SwitchFormat(); //COEf
    x2.SwitchFormat();

    x1.SwitchFormat(); //EVAL
    x2.SwitchFormat();

    Poly x1Expected(params2, Format::COEFFICIENT);
    x1Expected = { 431,1234,2145,5471};

    Poly x2Expected(params2, Format::COEFFICIENT);
    x2Expected = { 4127,1987,6541,9741 };

    DEBUG("x1: "<<x1);
    DEBUG("x1p: "<<*x1.GetParams());
    DEBUG("x1exp: "<<x1Expected);
    DEBUG("x1exppp: "<<*x1Expected.GetParams());

    DEBUG("x2: "<<x2);
    DEBUG("x2exp: "<<x2Expected);

    EXPECT_EQ(x1, x1Expected);
    EXPECT_EQ(x2, x2Expected);
}

TEST(UTNTT, decomposeMult_double_crt) {
  bool dbg_flag = false;
    ui32 init_m = 16;

    float init_stdDev = 4;

    ui32 init_size = 2;

    vector<native_int::BigInteger> init_moduli(init_size);

    vector<native_int::BigInteger> init_rootsOfUnity(init_size);

    native_int::BigInteger temp;
    
    init_moduli[0] = native_int::BigInteger("17729");
    init_moduli[1] = native_int::BigInteger("17761");


    for (size_t i = 0; i < init_size; i++) {
        init_rootsOfUnity[i] = RootOfUnity(init_m, init_moduli[i]);
    }

    DiscreteGaussianGenerator dgg(init_stdDev);

    shared_ptr<ILDCRTParams<BigInteger>> params( new ILDCRTParams<BigInteger>(init_m, init_moduli, init_rootsOfUnity) );

    DCRTPoly x1(params, Format::COEFFICIENT);
    x1 = { 0,0,0,0,0,0,1,0 };

    DCRTPoly x2(params, Format::COEFFICIENT);
    x2 = { 0,0,0,0,0,0,1,0 };

    DCRTPoly resultsEval(x2.CloneParametersOnly());
    resultsEval = { 0,0,0,0,0,0,0,0 };
    resultsEval.SwitchFormat();

    x1.SwitchFormat();
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    x1.Decompose();
    x2.Decompose();

    x1.SwitchFormat();
    x2.SwitchFormat();

    resultsEval = x1*x2;

    resultsEval.SwitchFormat(); // COEF


    DEBUG("resultsEval ix 0: "<<resultsEval.GetElementAtIndex(0).GetValues());
    DEBUG("resultsEval ix 1: "<<resultsEval.GetElementAtIndex(1).GetValues());

    EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(0), 0);
    EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(1), 0);
    EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(2), native_int::BigInteger("17728"));
    EXPECT_EQ(resultsEval.GetElementAtIndex(0).GetValAtIndex(3), 0);

    EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(0), 0);
    EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(1), 0);
    EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(2), native_int::BigInteger("17760"));
    EXPECT_EQ(resultsEval.GetElementAtIndex(1).GetValAtIndex(3), 0);
}

TEST(UTNTT, decomposeMult_single_crt) {
  bool dbg_flag = false;
    ui32 m1 = 16;

    BigInteger modulus("17729");
    BigInteger rootOfUnity(RootOfUnity(m1, modulus));
    shared_ptr<ILParams> params( new ILParams(m1, modulus, rootOfUnity) );
    shared_ptr<ILParams> params2( new ILParams(m1 / 2, modulus, rootOfUnity) );

    Poly x1(params, Format::COEFFICIENT);

    x1 = { 0,0,0,0,0,0,1,0 };

    Poly x2(params, Format::COEFFICIENT);
    x2 = { 0,0,0,0,0,0,1,0 };

    x1.SwitchFormat(); //dbc remember to remove thtese. 
    x2.SwitchFormat();
    x1.SwitchFormat();
    x2.SwitchFormat();

    x1.Decompose();
    x2.Decompose();

    DEBUG("x1.Decompose() "<<x1.GetValues());
    DEBUG("x2.Decompose() "<<x2.GetValues());

    Poly resultsEval(params2, Format::EVALUATION);
    DEBUG("resultsEval.modulus"<< resultsEval.GetModulus());

    x1.SwitchFormat();
    x2.SwitchFormat();

    DEBUG("x1.SwitchFormat() "<<x1.GetValues());
    DEBUG("x2.SwitchFormat() "<<x2.GetValues());

    resultsEval = x1*x2;
    DEBUG("resultsEval.eval "<<resultsEval.GetValues());

    resultsEval.SwitchFormat(); // COEF 
    DEBUG("resultsEval.coef "<<resultsEval.GetValues());
    DEBUG("resultsEval.modulus"<< resultsEval.GetModulus());

    EXPECT_EQ(resultsEval.GetValAtIndex(0), 0);
    EXPECT_EQ(resultsEval.GetValAtIndex(1), 0);
    EXPECT_EQ(resultsEval.GetValAtIndex(2), BigInteger("17728"));
    EXPECT_EQ(resultsEval.GetValAtIndex(3), 0);

}
*/
