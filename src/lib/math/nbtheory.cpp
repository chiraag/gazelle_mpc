/**
 * @file nbtheory.cpp This code provides number theory utilities.
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

#include "nbtheory.h"
#include "distributiongenerator.h"

#include "time.h"
#include <chrono>
#include <stdexcept>

#include "../utils/debug.h"

#define _USE_MATH_DEFINES
//#include <cmath>
//#include <time.h>
//#include <sstream>

namespace lbcrypto {
    /*
        Generates a random number between 0 and n.
        Input: BigInteger n.
        Output: Randomly generated BigInteger between 0 and n.
    */
    static ui64 RNG(const ui64 modulus)
    {
        // static parameters for the 32-bit unsigned integers used for multiprecision random number generation
        auto distribution = std::uniform_int_distribution<ui64>(0, modulus-1);
        return distribution(get_prng());

    }

    /*
        A witness function used for the Miller-Rabin Primality test.
        Inputs: a is a randomly generated witness between 2 and p-1,
                p is the number to be tested for primality,
                s and d satisfy p-1 = ((2^s) * d), d is odd.
        Output: true if p is composite,
                false if p is likely prime
    */
    static bool WitnessFunction(const ui64 a, const ui64 d, ui32 s, const ui64 p)
    {
        bool dbg_flag = false;
        DEBUG("calling modexp a " << a << " d " << d << " p " << p);
        ui64 mod = mod_exp(a, d, p);
        DEBUG("mod " << mod);
        bool prevMod = false;
        for (ui32 i = 1; i < s + 1; i++) {
            DEBUG("wf " << i);
            if (mod != 1 && mod != p - 1)
                prevMod = true;
            else
                prevMod = false;
            mod = (mod*mod) % p;
            if (mod == 1 && prevMod) return true;
        }
        return (mod != 1);
    }

    /*
        A helper function to RootOfUnity function. This finds a generator for a given prime q.
        Input: BigInteger q which is a prime.
        Output: A generator of prime q
    */
    static ui64 FindGenerator(const ui64 q)
    {
        bool dbg_flag = false;
        std::set<ui64> primeFactors;
        DEBUG("calling PrimeFactorize");

        ui64 qm1 = q - 1;
        ui64 qm2 = q - 2;
        PrimeFactorize(qm1, primeFactors);
        DEBUG("done");
        bool generatorFound = false;
        ui64 gen;
        while (!generatorFound) {
            ui32 count = 0;
            gen = (RNG(qm2) + 1) % q;
            DEBUG("Trying gen " << gen);

            for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
                auto test = mod_exp(gen, qm1 / (*it), q);
                DEBUG("mod_exp(" << gen << ", " << (qm1 / (*it)) << ", " << q << ") = " << test);
                if (test == 1)
                    break;
                else
                    count++;
            }
            if (count == primeFactors.size()) generatorFound = true;
        }
        return gen;
    }

    /*
    A helper function for arbitrary cyclotomics. This finds a generator for any composite q (cyclic group).
    Input: BigInteger q (cyclic group).
    Output: A generator of prime q
    */
    ui64 FindGeneratorCyclic(const ui64 q)
    {
        bool dbg_flag = false;
        std::set<ui64> primeFactors;
        DEBUG("calling PrimeFactorize");

        ui64 phi_q = ui64(GetTotient(q));
        ui64 phi_q_m1 = ui64(GetTotient(q));

        PrimeFactorize(phi_q, primeFactors);
        DEBUG("done");
        bool generatorFound = false;
        ui64 gen;
        while (!generatorFound) {
            ui32 count = 0;
            DEBUG("count " << count);

            gen = RNG(phi_q_m1) + 1; // gen is random in [1, phi(q)]
            if (GreatestCommonDivisor(gen, q) != 1) {
                // Generator must lie in the group!
                continue;
            }

            // Order of a generator cannot divide any co-factor
            for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
                DEBUG("in set");
                DEBUG("divide " << phi_q << " by " << *it);

                if (mod_exp(gen, phi_q / (*it), q) == 1){
                    break;
                } else {
                    count++;
                }
            }

            if (count == primeFactors.size()) generatorFound = true;
        }
        return gen;
    }

    /*
    A helper function for arbitrary cyclotomics. Checks if g is a generator of q (supports any cyclic group, not just prime-modulus groups)
    Input: Candidate generator g and modulus q
    Output: returns true if g is a generator for q
    */
    bool IsGenerator(const ui64 g, const ui64 q)
    {
        bool dbg_flag = false;
        std::set<ui64> primeFactors;
        DEBUG("calling PrimeFactorize");

        ui64 qm1 = ui64(GetTotient(q));

        PrimeFactorize(qm1, primeFactors);
        DEBUG("done");

        ui32 count = 0;

        for (auto it = primeFactors.begin(); it != primeFactors.end(); ++it) {
            DEBUG("in set");
            DEBUG("divide " << qm1 << " by " << *it);

            if (mod_exp(g, qm1 / (*it), q) == 1) break;
            else count++;
        }

        if (count == primeFactors.size())
            return true;
        else
            return false;

    }

    /*
        finds roots of unity for given input.  Assumes the the input is a power of two.  Mostly likely does not give correct results otherwise.
        input:  m as number which is cyclotomic(in format of int),
                modulo which is used to find generator (in format of BigInteger)

        output: root of unity (in format of BigInteger)
    */
    ui64 RootOfUnity(ui32 m, const ui64 modulo)
    {
        bool dbg_flag = false;
        DEBUG("in Root of unity m :" << m << " modulo " << modulo);
        ui64 M(m);
        if (((modulo - 1) % M) != 0) {
            std::string errMsg = "Please provide a primeModulus(q) and a cyclotomic number(m) satisfying the condition: (q-1)/m is an integer. The values of primeModulus = " + std::to_string(modulo) + " and m = " + std::to_string(m) + " do not satisfy this condition";
            throw std::runtime_error(errMsg);
        }
        ui64 result;
        DEBUG("calling FindGenerator");
        ui64 gen = FindGenerator(modulo);
        DEBUG("gen = " << gen);

        DEBUG("calling gen.ModExp( " << ((modulo - 1)/M) << ", modulus " << modulo << ")");
        result = mod_exp(gen, (modulo - 1)/M, modulo);
        DEBUG("result = " << result);
        if (result == 1) {
            DEBUG("LOOP?");
            return RootOfUnity(m, modulo);
        }
        return result;
    }

    uv64 RootsOfUnity(ui32 m, const uv64 moduli) {
        uv64 rootsOfUnity(moduli.size());
        for (ui32 i = 0; i < moduli.size(); i++) {
            rootsOfUnity[i] = RootOfUnity(m, moduli[i]);
        }
        return rootsOfUnity;
    }

    ui64 GreatestCommonDivisor(const ui64 a, const ui64 b)
    {
        bool dbg_flag = false;
        ui64 m_a, m_b, m_t;
        m_a = a;
        m_b = b;
        DEBUG("GCD a " << a << " b " << b);
        while (m_b != 0) {
            m_t = m_b;
            DEBUG("GCD m_a.Mod(b) " << m_a << "( " << m_b << ")");
            m_b = m_a % m_b;

            m_a = m_t;
            DEBUG("GCD m_a " << m_b << " m_b " << m_b);
        }
        DEBUG("GCD ret " << m_a);
        return m_a;
    }

    /*
      The Miller-Rabin Primality Test
      Input: p the number to be tested for primality.
      Output: true if p is prime,
      false if p is not prime
    */
    bool MillerRabinPrimalityTest(const ui64 p, const ui32 niter)
    {
        bool dbg_flag = false;
        if (p < 2 || ((p != 2) && ((p%2) == 0)))
            return false;
        if (p == 2 || p == 3 || p == 5)
            return true;

        ui64 d = p - 1;
        ui32 s = 0;
        DEBUG("start while d " << d);
        while ((d%2) == 0) {
            d = d/2;
            s++;
        }
        DEBUG("end while s " << s);
        bool composite = true;
        for (ui32 i = 0; i < niter; i++) {
            DEBUG(".1");
            ui64 a = (RNG(p - 3)+2)%p;
            DEBUG(".2");
            composite = (WitnessFunction(a, d, s, p));
            if (composite)
                break;
        }
        DEBUG("done composite " << composite);
        return (!composite);
    }

    /*
        The Pollard Rho factorization of a number n.
        Input: n the number to be factorized.
        Output: a factor of n.
    */
    const ui64 PollardRhoFactorization(const ui64 n)
    {
        bool dbg_flag = false;
        ui64 divisor(1);

        ui64 c(RNG(n));
        ui64 x(RNG(n));
        ui64 xx(x);

        //check divisibility by 2
        if (n%2 == 0)
            return ui64(2);

        do {
            x = (x*x + c) % n;
            xx = (xx*xx + c) % n;
            xx = (xx*xx + c) % n;
            divisor = GreatestCommonDivisor(((x - xx) > 0) ? x - xx : xx - x, n);
            DEBUG("PRF divisor " << divisor);

        } while (divisor == 1);

        return divisor;
    }

    /*
        Recursively factorizes and find the distinct primefactors of a number
        Input: n is the number to be prime factorized,
               primeFactors is a set of prime factors of n.
    */
    void PrimeFactorize(ui64 n, std::set<ui64>& primeFactors)
    {
        bool dbg_flag = false;
        DEBUG("PrimeFactorize " << n);

        // primeFactors.clear();
        DEBUG("In PrimeFactorize n " << n);
        DEBUG("set size " << primeFactors.size());

        if (n == 0 || n == 1) return;
        DEBUG("calling MillerRabinPrimalityTest(" << n << ")");
        if (MillerRabinPrimalityTest(n)) {
            DEBUG("Miller true");
            primeFactors.insert(n);
            return;
        }

        DEBUG("calling PrFact n " << n);
        ui64 divisor(PollardRhoFactorization(n));

        DEBUG("calling PF " << divisor);
        PrimeFactorize(divisor, primeFactors);

        DEBUG("calling div " << divisor);
        //ui64 reducedN = n.DividedBy(divisor);
        n /= divisor;

        DEBUG("calling PF reduced n " << n);
        PrimeFactorize(n, primeFactors);
    }

    ui64 FirstPrime(ui32 nBits, ui32 m) {
        ui64 r = mod_exp(ui64(2), ui64(nBits), ui64(m));
        ui64 qNew = (ui64(1) << nBits) + (ui64(m) - r) + ui64(1);

        size_t i = 1;

        while (!MillerRabinPrimalityTest(qNew)) {
            qNew += ui64(i*m);
            i++;
        }

        return qNew;

    }

    ui64 NextPrime(const ui64 &q, ui32 m) {
        ui64 qNew = q + m - (q % m) + 1;
        while (!MillerRabinPrimalityTest(qNew)) {
            qNew += m;
        }

        return qNew;

    }

    ui32 GreatestCommonDivisor(const ui32& a, const ui32& b)
    {
        bool dbg_flag = false;
        ui32 m_a, m_b, m_t;
        m_a = a;
        m_b = b;
        DEBUG("GCD a " << a << " b " << b);
        while (m_b != 0) {
            m_t = m_b;
            DEBUG("GCD m_a.Mod(b) " << m_a << "( " << m_b << ")");
            m_b = m_a % (m_b);

            m_a = m_t;
            DEBUG("GCD m_a " << m_b << " m_b " << m_b);
        }
        DEBUG("GCD ret " << m_a);
        return m_a;
    }

    ui64 NextPowerOfTwo(const ui64 &n) {
        ui32 result = ceil(log2(n));
        return result;
    }

    ui64 GetTotient(const ui64 n) {

        std::set<ui64> factors;
        ui64 enn(n);
        PrimeFactorize(enn, factors);

        ui64 primeProd(1);
        ui64 numerator(1);
        for (auto &r : factors) {
            numerator = numerator * (r - 1);
            primeProd = primeProd * r;
        }

        primeProd = (enn / primeProd) * numerator;
        return primeProd;
    }

    /*Naive Loop to find coprimes to n*/
    uv64 GetTotientList(const ui64 &n) {

        uv64 result;
        ui64 one(1);
        for (ui64 i = ui64(1); i < n; i = i + ui64(1)) {
            if (GreatestCommonDivisor(i, n) == one)
                result.push_back(i);
        }

        return result; //std::move(result); 
    }

    sv32 GetCyclotomicPolynomialRecursive(ui32 m) {
        sv32 poly;
        if (m == 1) {
            poly = { -1,1 };
            return poly;
        }
        if (m == 2) {
            poly = { 1,1 };
            return poly;
        }
        auto IsPrime = [](ui32 mm) {
            bool flag = true;
            for (ui32 i = 2; i < mm; i++) {
                if (mm%i == 0) {
                    flag = false;
                    return flag;
                }
            }
            return flag;
        };
        if (IsPrime(m)) {
            poly = sv32(m, 1);
            return poly;
        }

        auto GetDivisibleNumbers = [](ui32 mm) {
            std::vector<ui32> div;
            for (ui32 i = 1; i < mm; i++) {
                if (mm%i == 0) {
                    div.push_back(i);
                }
            }
            return div;
        };

        auto PolyMult = [](const sv32 &a, const sv32 &b) {
            ui32 degreeA = a.size() - 1;
            ui32 degreeB = b.size() - 1;

            ui32 degreeResultant = degreeA + degreeB;

            sv32 result(degreeResultant + 1, 0);

            for (ui32 i = 0; i < a.size(); i++) {

                for (ui32 j = 0; j < b.size(); j++) {
                    const auto &valResult = result.at(i + j);
                    const auto &valMult = a.at(i)*b.at(j);
                    result.at(i + j) = valMult + valResult;
                }
            }

            return result;
        };

        auto PolyQuotient = [](const sv32 &dividend, const sv32 &divisor) {
            ui32 divisorLength = divisor.size();
            ui32 dividendLength = dividend.size();

            ui32 runs = dividendLength - divisorLength + 1; //no. of iterations
            sv32 result(runs + 1);

            auto mat = [](const int x, const int y, const int z) {
                int result = z - (x*y);
                return result;
            };

            sv32 runningDividend(dividend);

            ui32  divisorPtr;
            for (ui32 i = 0; i < runs; i++) {
                int divConst = (runningDividend.at(dividendLength - 1));//get the highest degree coeff
                divisorPtr = divisorLength - 1;
                for (ui32 j = 0; j < dividendLength - i - 1; j++) {
                    if (divisorPtr > j) {
                        runningDividend.at(dividendLength - 1 - j) = mat(divisor.at(divisorPtr - 1 - j), divConst, runningDividend.at(dividendLength - 2 - j));
                    }
                    else
                        runningDividend.at(dividendLength - 1 - j) = runningDividend.at(dividendLength - 2 - j);

                }
                result.at(i + 1) = runningDividend.at(dividendLength - 1);
            }
            result.at(0) = 1;//under the assumption that both dividend and divisor are monic
            result.pop_back();

            return result;
        };
        auto divisibleNumbers = GetDivisibleNumbers(m);

        sv32 product(1, 1);

        for (ui32 i = 0; i < divisibleNumbers.size(); i++) {
            auto P = GetCyclotomicPolynomialRecursive(divisibleNumbers[i]);
            product = PolyMult(product, P);
        }

        //make big poly = x^m - 1
        sv32 bigPoly(m + 1, 0);
        bigPoly.at(0) = -1;
        bigPoly.at(m) = 1;

        poly = PolyQuotient(bigPoly, product);

        return poly;
    }

    uv64 GetCyclotomicPolynomial(ui32 m, const ui64 modulus) {
        auto intCP = GetCyclotomicPolynomialRecursive(m);
        uv64 result(intCP.size(), modulus);
        for (ui32 i = 0; i < intCP.size(); i++) {
            auto val = intCP[i];
            if (intCP.at(i) > -1)
                result[i] = ui64(val);
            else {
                val *= -1;
                result[i] = ui64(modulus - ui64(val));
            }

        }

        return result;

    }
}
