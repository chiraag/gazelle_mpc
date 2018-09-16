/*
 * @file discretegaussiangenerator.cpp This code provides generation of gaussian distibutions of discrete values. 
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
 
#include <utils/backend.h>
#include "discretegaussiangenerator.h"

// #include <iostream>

namespace lbcrypto {

    DiscreteGaussianGenerator::DiscreteGaussianGenerator(double std) : DistributionGenerator() {
        m_std = std;

        m_vals.clear();

        //weightDiscreteGaussian
        double acc = 1e-15;
        double variance = m_std * m_std;

        int fin = (int)ceil(m_std * sqrt(-2 * log(acc)));
        //this value of fin (M) corresponds to the limit for double precision
        // usually the bound of m_std * M is used, where M = 20 .. 40 - see DG14 for details
        // M = 20 corresponds to 1e-87
        //double mr = 20; // see DG14 for details
        //int fin = (int)ceil(m_std * mr);

        double cusum = 1.0;

        for (si32 x = 1; x <= fin; x++) {
            cusum = cusum + 2 * exp(-x * x / (variance * 2));
        }

        m_a = 1 / cusum;

        //fin = (int)ceil(sqrt(-2 * variance * log(acc))); //not needed - same as above
        double temp;

        for (si32 i = 1; i <= fin; i++) {
            temp = m_a * exp(-((double)(i * i) / (2 * variance)));
            m_vals.push_back(temp);
        }

        // take cumulative summation
        for (ui32 i = 1; i < m_vals.size(); i++) {
            m_vals[i] += m_vals[i - 1];
        }

        // for (ui32 i = 0; i<m_vals.size(); i++) {
        //  std::cout << m_vals[i] << std::endl;
        // }

        //std::cout<<m_a<<std::endl;
    }

    ui32 DiscreteGaussianGenerator::FindInVector(const std::vector<double> &S, double search) const {
        //STL binary search implementation
        auto lower = std::lower_bound(S.begin(), S.end(), search);
        if (lower != S.end())
            return lower - S.begin();
        else
            throw std::runtime_error("DGG Inversion Sampling. FindInVector value not found: " + std::to_string(search));
    }

    uv64 DiscreteGaussianGenerator::GenerateVector(const ui32 size, const ui64 &modulus) const {
        //we need to use the binary uniform generator rathen than regular continuous distribution; see DG14 for details
        std::uniform_real_distribution<double> distribution(0.0, 1.0);

        uv64 ans(size);
        auto& prng = get_prng();
        for (ui32 i = 0; i < size; i++) {
            double seed = distribution(prng) - 0.5;
            if (std::abs(seed) <= m_a / 2) {
                ans[i] = ui64(0);
            } else{
                ui32 val = FindInVector(m_vals, (std::abs(seed) - m_a / 2));
                if (seed > 0) {
                    ans[i] = ui64(val+1);
                } else {
                    ans[i] = ui64(modulus-val-1);
                }
            }
        }
        return ans;
    }

} // namespace lbcrypto
