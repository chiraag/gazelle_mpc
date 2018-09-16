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
  This code exercises the random number distribution generator libraries
  of the PALISADE lattice encryption library.

  4/22/2016 DBC: modified to new UT format. Adding validity checks for parallelization code.
*/

#include "include/gtest/gtest.h"
#include <iostream>

#include "utils/debug.h"
#include "math/backend.h"
#include "math/distrgen.h"

#include <omp.h>

using namespace std;
using namespace lbcrypto;

class UnitTestDistrGen : public ::testing::Test {
protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
    // Code here will be called immediately after each test
    // (right before the destructor).
  }
};
//////////////////////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteUniformGenerator
//////////////////////////////////////////////////////////////////

TEST(UTPRNG, PRNG ) {
    auto prng = get_prng();
    std::uniform_int_distribution<ui32> dist(0, 1);

    ui32 max_output = 0;
    for(ui32 t=0; t<1000; t++){
        ui32 output = dist(prng);
        if (output < max_output){
            max_output = output;
        }
    }

    EXPECT_LT(max_output, 2) << "Failure in testing PRNG";
}


// helper functions defined later
void testDiscreteUniformGenerator(ui64 &modulus, std::string test_name);
void testParallelDiscreteUniformGenerator(ui64 &modulus, std::string test_name);


TEST(UTDistrGen, DiscreteUniformGenerator_LONG ) {
  //TEST CASE TO GENERATE A UNIFORM BIG BINARY VECTOR WITH LARGE MODULUS
  
  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS SMALL MODULUS
    ui64 small_modulus(7919);
    testDiscreteUniformGenerator(small_modulus, "small_modulus");
  }
  {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS LARGE MODULUS
    ui64 large_modulus(100019);
    testDiscreteUniformGenerator(large_modulus, "large_modulus");
  }
  if( MATH_DEFBITS > 64 ) {
    // TEST CASE ON FIRST AND SECOND CENTRAL MOMENTS HUGE MODULUS
    ui64 huge_modulus(10/*"10402635286389262637365363"*/);
    testDiscreteUniformGenerator(huge_modulus, "huge_modulus");
  }

} //end TEST(UTDistrGen, DiscreteUniformGenerator)

//
// helper function to test first and second central moment of discrete uniform generator
// single thread case
void testDiscreteUniformGenerator(ui64 &modulus, std::string test_name){
  // TEST CASE ON FIRST CENTRAL MOMENT
    ui32 size = 50000;

    uv64 rand_vec = get_dug_vector(size, modulus);

    ui64 min_output = *std::min_element(rand_vec.begin(), rand_vec.end());
    EXPECT_GE(min_output, 0) << "Failure testing min_value";

    ui64 max_output = *std::max_element(rand_vec.begin(), rand_vec.end());
    EXPECT_LT(max_output, modulus) << "Failure testing max_value";

    double expectedMean = (double)modulus / 2.0;

    double sum=0;
    for(ui32 index=0; index<size; index++) {
      sum += (double)(rand_vec[index]);
    }

    double computedMean = sum/size;
    double diffInMeans = abs(computedMean - expectedMean);

    //within 1% of expected mean
    EXPECT_LT(diffInMeans, 0.01*modulus) <<
      "Failure testing first_moment_test_convertToDouble " << test_name;


    // TEST CASE ON SECOND CENTRAL MOMENT
    double expectedVariance = ((modulus - 1.0)*(modulus - 1.0))/12.0;
    double expectedStdDev = sqrt(expectedVariance);

    sum=0;
    double temp;
    for(ui32 index=0; index<size; index++) {
      temp = rand_vec[index] - expectedMean;
      temp *= temp;
      sum += temp;
    }

    double computedVariance = (sum/size);
    double computedStdDev = sqrt(computedVariance);
    double diffInStdDev = abs(computedStdDev - expectedStdDev);

    EXPECT_LT(diffInStdDev, 0.01*expectedStdDev) <<
      "Failure testing second_moment_test_convertToDouble "<< test_name;
}


TEST(UTDistrGen, ParallelDiscreteUniformGenerator_LONG ) {

  //BUILD SEVERAL VECTORS OF BBI IN PARALLEL, CONCATENATE THEM TO ONE LARGE VECTOR AND TEST
  //THE RESULT OF THE FIRST AND SECOND CENTRAL MOMENTS

  ui64 small_modulus(7919); // test small modulus
  testParallelDiscreteUniformGenerator(small_modulus, "small_modulus");

  ui64 large_modulus(100019);// test large modulus
  testParallelDiscreteUniformGenerator(large_modulus, "large_modulus");

  if( MATH_DEFBITS > 64 ) {
      ui64 huge_modulus(10/*10402635286389262637365363*/);
      testParallelDiscreteUniformGenerator(huge_modulus, "huge_modulus");
  }

}

//
// helper function to test first and second central moment of discrete uniform generator
// multi thread case
void testParallelDiscreteUniformGenerator(ui64 &modulus, std::string test_name){
  // we expect the mean to be modulus/2 (the mid range of the min-max data);
  double expectedMean = (double)modulus / 2.0;
  ui32 size = 50000;
  //ui32 size = omp_get_max_threads() * 4;

  bool dbg_flag = false;
  uv64 rand_vec;
#pragma omp parallel // this is executed in parallel
  {
    //private copies of our vector
    uv64 rand_vec_pvt;

    // build the vectors in parallel
    rand_vec_pvt = get_dug_vector(size, modulus);

#pragma omp for schedule(static) ordered
    // now stitch them back together sequentially to preserve order of i
    for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
        {
          DEBUG("thread #" << omp_get_thread_num() << " moving "
                  << (int)rand_vec_pvt.size()  << " to starting point "
                  << (int)rand_vec.size() );
          rand_vec.insert(rand_vec.end(), rand_vec_pvt.begin(), rand_vec_pvt.end());
          DEBUG("thread #" << omp_get_thread_num() << " moved");
        }
    }

  }

  // now compute the sum over the entire vector
  double sum = 0;
  size = rand_vec.size();
  
  for(ui32 index=0; index<size; index++) {
    sum += (double)rand_vec[index];
  }
  // divide by the size (i.e. take mean)
  double computedMean = sum/size;
  // compute the difference between the expected and actual
  double diffInMeans = abs(computedMean - expectedMean);
  
  //within 1% of expected mean
  EXPECT_LT(diffInMeans, 0.01*modulus) << "Failure testing parallel_first_central_moment_test " << test_name;
  
  // TEST CASE ON SECOND CENTRAL MOMENT SMALL MODULUS
  double expectedVariance = ((modulus - 1.0)*(modulus - 1.0))/12.0; // var = ((b-a)^2) /12
  double expectedStdDev = sqrt(expectedVariance);
  
  sum=0;
  double temp;
  for(ui32 index=0; index<size; index++) {
    temp = (double)rand_vec[index] - expectedMean;
    temp *= temp;
    sum += temp;
  }
  
  double computedVariance = (sum/size);
  double computedStdDev = sqrt(computedVariance);
  
  double diffInStdDev = abs(computedStdDev - expectedStdDev);

  //within 1% of expected std dev
  EXPECT_LT(diffInStdDev, 0.01*expectedStdDev) << "Failure testing second_central_moment_test " << test_name;
}

////////////////////////////////////////////////
// Testing Methods of BigInteger BinaryUniformGenerator
////////////////////////////////////////////////


 TEST(UTDistrGen, BinaryUniformGenerator ) {


  // min, max and mean test
  {

    ui32 size = 100000;
    uv64 randBigVector = get_bug_vector(size);

    ui32 sum = 0, min_out = 1, max_out = 0;

    for(ui32 index=0; index<randBigVector.size(); index++) {
      sum += randBigVector[index];
      min_out = (min_out > randBigVector[index])? randBigVector[index]: min_out;
      max_out = (max_out < randBigVector[index])? randBigVector[index]: max_out;
    }
    //std::cout << "Observed sum is " << sum << std::endl;
    //std::cout << "Length is " << length << std::endl;
    float computedMean = (float)sum/(float)size;
    //std::cout << "The computedMean is " << computedMean << std::endl;
    float expectedMean = 0.5;
    float dif = abs(computedMean-expectedMean);
    //std::cout << "The difference is " << dif << std::endl;

    //std::cout << "Running Test." << std::endl;
    EXPECT_LT(dif,0.01)
      << "Failure Mean is incorrect";
    // a large sample. Max of them should be less than q
    EXPECT_GE(min_out, 0ULL)
      << "Failure less than 0";
    EXPECT_LE(max_out, 1ULL)
      << "Failure greater than 1";

  }
} // end TEST(


 // mean test
 TEST(UTDistrGen, TernaryUniformGenerator) {
     
     ui32 length = 100000;
     ui64 modulus = ui64(1041);
     uv64 randBigVector = get_tug_vector(length, modulus);

     int32_t sum = 0;

     for (ui32 index = 0; index<randBigVector.size(); index++) {
         if (randBigVector[index] == modulus - 1)
             sum -= 1;
         else
             sum += randBigVector[index];
     }

     float computedMean = (double)sum / (double)length;

     float expectedMean = 0;
     float dif = abs(computedMean - expectedMean);

     //std::cout << "Running Test." << std::endl;
     EXPECT_LT(dif, 0.01)
         << "Ternary Uniform Distribution Failure Mean is incorrect";
     // a large sample. Max of them should be less than q

 }

////////////////////////////////////////////////
// Testing Methods of BigInteger DiscreteGaussianGenerator
////////////////////////////////////////////////


TEST(UTDistrGen, DiscreteGaussianGenerator) {
  //mean test

  {
    std::cout<<"note this sometimes fails. are limits set correctly?"<<std::endl;
    double stdev = 5;
    ui32 size = 10000;
    ui64 modulus(10403);
    const DiscreteGaussianGenerator& dgg = lbcrypto::DiscreteGaussianGenerator(stdev);
    uv64 dggCharVector = dgg.GenerateVector(size, modulus);

    double mean = 0;
    for(ui32 i=0; i<size; i++) {
        if(dggCharVector[i] <= (modulus-1)/2){
            mean += (double) dggCharVector[i];
        } else {
            mean -= (double) (modulus-dggCharVector[i]);
        }
        // std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
    }
    mean /= size;
    // std::cout << "The mean of the values is " << mean << std::endl;

    EXPECT_LE(mean, 0.1) << "Failure generate_char_vector_mean_test mean > 0.1";
    EXPECT_GE(mean, -0.1) << "Failure generate_char_vector_mean_test mean < -0.1";;
  }

  // generate_vector_mean_test
  {
    si32 stdev = 5;
    ui32 size = 100000;
    ui64 modulus(10403);
    ui64 modulusByTwo(modulus/2);
    DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);
    uv64 dggBigVector = dgg.GenerateVector(size,modulus);

    ui32 countOfZero = 0;
    double mean = 0, current = 0;

    for(ui32 i=0; i<size; i++) {
      current = (double)dggBigVector[i];
      if(current == 0)
        countOfZero++;
      mean += current;
    }

    mean /= (size - countOfZero);
    // std::cout << "The mean of the values is " << mean << std::endl;

    double diff = abs((double)modulusByTwo - mean);
    EXPECT_LT(diff, 104) << "Failure generate_vector_mean_test";
  }

}


TEST(UTDistrGen, ParallelDiscreteGaussianGenerator_LONG) {
    bool dbg_flag = false;
    {
        //mean test
        si32 stdev = 5;
        ui32 size = 10000;
        ui64 modulus(10403);


        uv64 dggBigVector;
#pragma omp parallel // this is executed in parallel
        {
            //private copies of our vector
            vector <ui64> dggBigVectorPvt;
            DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);

            // build the vectors in parallel
            dggBigVectorPvt = dgg.GenerateVector(size, modulus);

#pragma omp for schedule(static) ordered
            // now stitch them back together sequentially to preserve order of i
            for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
                {
                    DEBUG("thread #" << omp_get_thread_num() << " " << "moving "
                        << (int)dggBigVectorPvt.size()  << " to starting point"
                        << (int)dggBigVector.size() );
                    dggBigVector.insert(dggBigVector.end(), dggBigVectorPvt.begin(), dggBigVectorPvt.end());
                }
            }
        }

        double mean = 0;
        for(ui32 i=0; i<size; i++) {
            if(dggBigVector[i] <= (modulus-1)/2){
                mean += (double) dggBigVector[i];
            } else {
                mean -= (double) (modulus-dggBigVector[i]);
            }
            // std::cout << i << "th value is " << std::to_string(dggCharVector[i]) << std::endl;
        }
        mean /= size;
        // std::cout << "The mean of the values is " << mean << std::endl;

        EXPECT_LE(mean, 0.1) << "Failure parallel generate_char_vector_mean_test mean > 0.1";
        EXPECT_GE(mean, -0.1) << "Failure parallel generate_char_vector_mean_test mean < -0.1";;

    }

    {
        // generate_vector_mean_test
        si32 stdev = 5;
        ui32 size = 100000;
        ui64 modulus(10403);
        ui64 modulusByTwo(modulus/2);

        uv64 dggBigVector;
#pragma omp parallel // this is executed in parallel
        {
            //private copies of our vector
            vector <ui64> dggBigVectorPvt;
            DiscreteGaussianGenerator dgg = lbcrypto::DiscreteGaussianGenerator(stdev);

            // build the vectors in parallel
            dggBigVectorPvt = dgg.GenerateVector(size, modulus);

#pragma omp for schedule(static) ordered
            // now stitch them back together sequentially to preserve order of i
            for (int i=0; i<omp_get_num_threads(); i++) {
#pragma omp ordered
                {
                    DEBUG("thread #" << omp_get_thread_num() << " " << "moving "
                        << (int)dggBigVectorPvt.size()  << " to starting point"
                        << (int)dggBigVector.size() );
                    dggBigVector.insert(dggBigVector.end(), dggBigVectorPvt.begin(), dggBigVectorPvt.end());
                }
            }
        }

        ui32 countOfZero = 0;
        double mean = 0, current = 0;

        for(ui32 i=0; i<size; i++) {
            current = (double)(dggBigVector[i]);
            if(current == 0)
                countOfZero++;
            mean += current;
        }

        mean /= (size - countOfZero);
        // std::cout << "The mean of the values is " << mean << std::endl;

        double diff = abs((double)modulusByTwo - mean);
        EXPECT_LT(diff, 104) << "Failure generate_vector_mean_test";

    }
}
