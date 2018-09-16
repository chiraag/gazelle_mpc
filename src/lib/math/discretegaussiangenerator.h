/**
 * @file discretegaussiangenerator.h This code provides generation of gaussian distibutions of discrete values. 
 * Discrete uniform generator relies on the built-in C++ generator for 32-bit unsigned integers defined in <random>.
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

#ifndef LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
#define LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_

#define _USE_MATH_DEFINES // added for Visual Studio support

#include <math.h>
#include <random>
#include <memory>

#include "utils/backend.h"
#include "distributiongenerator.h"

namespace lbcrypto {
    /**
    * @brief The class for Discrete Gaussion Distribution generator.
    */
    class DiscreteGaussianGenerator : public DistributionGenerator {

    public:
        /**
        * @brief         Basic constructor for specifying distribution parameter and modulus.
        * @param modulus The modulus to use to generate discrete values.
        * @param std     The standard deviation for this Gaussian Distribution.
        */
        DiscreteGaussianGenerator (double std = 4.0);

        /**
        * @brief           Generates a vector of random values within this Discrete Gaussian Distribution. Uses Peikert's inversion method.
        *
        * @param  size     The number of values to return.
        * @param  modulus  modulus of the polynomial ring.
        * @return          The vector of values within this Discrete Gaussian Distribution.
        */
        uv64 GenerateVector (ui32 size, const ui64 &modulus) const;

    private:
        ui32 FindInVector (const std::vector<double> &S, double search) const;

        // Gyana to add precomputation methods and data members
        // all parameters are set as int because it is assumed that they are used for generating "small" polynomials only
        double m_a;

        std::vector<double> m_vals;
    
        /**
        * The standard deviation of the distribution.
        */
        double m_std;

    };
    
}  // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISCRETEGAUSSIANGENERATOR_H_
