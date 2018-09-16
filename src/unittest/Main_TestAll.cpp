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
 
#include <iostream>

//#include "../lib/lattice/dcrtpoly.h"
#include "include/gtest/gtest.h"


#include "math/backend.h"
//#include "math/nbtheory.h"
//#include "lattice/elemparams.h"
//#include "lattice/ilparams.h"
//#include "lattice/ildcrtparams.h"
//#include "lattice/ilelement.h"
#include "math/distrgen.h"
//#include "lattice/poly.h"
//#include "utils/utilities.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char **argv) {

  ::testing::InitGoogleTest(&argc, argv);
  
  // if there are no filters used, default to omitting VERY_LONG tests
  // otherwise we lose control over which tests we can run
  //::testing::GTEST_FLAG(filter) = "*CRT_polynomial_multiplication_small";

  if (::testing::GTEST_FLAG(filter) == "*") {
    ::testing::GTEST_FLAG(filter) = "-*_VERY_LONG";
  }
  int rv = RUN_ALL_TESTS();

  std::cout << rv << ", press return to continue..." << std::endl;
  std::cin.get();

  return 0;
}

