/**
 * @file nbtheory.h This code provides number theory utilities.
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
 *  NBTHEORY is set set of functions that will be used to calculate following:
 *      - If two numbers are coprime.
 *      - GCD of two numbers 
 *      - If number i Prime
 *      - witnesss function to test if number is prime
 *      - Roots of unit for provided cyclotomic integer
 *      - Eulers Totient function phin(n)
 *      - Generator algorithm
 */

#ifndef LBCRYPTO_MATH_NBTHEORY_H
#define LBCRYPTO_MATH_NBTHEORY_H

#include "utils/backend.h"
#include <vector>
#include <set>
#include <string>
#include <random>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {
    ui64 inline mod(ui128 a, ui64 q){
        ui128 r = a % (ui128)q;
        return (ui64)(r);
    };

    ui64 inline mod(ui64 a, ui64 q){
        return (a % q);
    };

    ui64 inline mod_mul(ui64 a, ui64 b, ui64 q){
        return (ui64)(((ui128)a*(ui128)b) % (ui128)q);
    };

    ui64 inline mod_exp(ui64 a, ui64 b, ui64 q){
        ui64 r = 1, an = a;
        while(b != 0){
            if((b & 1) == 1){
                r = mod_mul(r, an, q);
            }
            an = mod_mul(an, an, q);
            b = (b >> 1);
        }
        return r;
    };

    ui64 inline mod_inv(ui64 a, ui64 q) {
        return mod_exp(a, q-2, q);
    }

    /**
     * Finds roots of unity for given input.  Assumes the the input is a power of two.
     *
     * @param m as number which is cyclotomic(in format of int).
     * @param &modulo which is used to find generator.
     *
     * @return a root of unity.
     */
    ui64 RootOfUnity(ui32 m, const ui64 modulo);

    /**
     * Finds roots of unity for given input.  Assumes the the input cyclotomicorder is a power of two.
     *
     * @param m as number which is cyclotomic(in format of int).
     * @param moduli vector of modulus
     *
     * @returns a vector of roots of unity corresponding to each modulus.
     */
    uv64 RootsOfUnity(ui32 m, const uv64 moduli);

    /**
     * Return greatest common divisor of two big binary integers.
     *
     * @param a one integer to find greatest common divisor of.
     * @param b another integer to find greatest common divisor of.
     *
     * @return the greatest common divisor.
     */
    ui64 GreatestCommonDivisor(const ui64 a, const ui64 b);

    /**
     * Perform the MillerRabin primality test on an ui64.
     * This approach to primality testing is iterative and randomized.
     * It returns false if evidence of non-primality is found, and true if no evidence is found after multiple rounds of testing.
     * The const parameter PRIMALITY_NO_OF_ITERATIONS determines how many rounds are used ( set in nbtheory.h).
     *
     * @param p the candidate prime to test.
     * @param niter Number of iterations used for primality
     *              testing (default = 100.
     *
     * @return false if evidence of non-primality is found.  True is no evidence of non-primality is found.
     */
    bool MillerRabinPrimalityTest(const ui64 p, const ui32 niter = 100);

    /**
     * Perform the PollardRho factorization of a ui64.
     * Returns ui64::ONE if no factorization is found.
     *
     * @param n the value to perform a factorization on.
     * @return a factor of n, and ui64::ONE if no other factor is found.
     */
    const ui64 PollardRhoFactorization(const ui64 n);

    /**
     * Recursively factorizes to find the distinct primefactors of a number.
     * @param &n the value to factorize. [note the value of n is destroyed]
     * @param &primeFactors set of factors found [must begin cleared]
     Side effects: n is destroyed.
     */
    void PrimeFactorize( ui64 n, std::set<ui64>& primeFactors);

    /**
    * Finds the first prime that satisfies q = 1 mod m
    *
    * @param nBits the number of bits needed to be in q.
    * @param m the the ring parameter.
    *
    * @return the next prime modulus.
    */
    ui64 FirstPrime(ui32 nBits, ui32 m);

    /**
    * Finds the next prime that satisfies q = 1 mod m
    *
    * @param &q is the prime number to start from (the number itself is not included)
    *
    * @return the next prime modulus.
    */
    ui64 NextPrime(const ui64 q, ui32 cyclotomicOrder);

    /**
    * Returns the next power of 2 that is greater than the input number.
    *
    * @param &n is the input value for which next power of 2 needs to be computed.
    * @return Next power of 2 that is greater or equal to n.
    */
    ui64 NextPowerOfTwo(const ui64 n);

    /**
    * Returns the totient value φ(n) of a number n.
    *
    * @param &n the input number.
    * @return φ(n) which is the number of integers m coprime to n such that 1 ≤ m ≤ n.
    */
    ui64 GetTotient(const ui64 n);


    /**
    * Returns the list of coprimes to number n in ascending order.
    *
    * @param &n the input number.
    * @return vector of mi's such that 1 ≤ mi ≤ n and gcd(mi,n)==1.
    */
    uv64 GetTotientList(const ui64 n);

    /**
    * Returns the m-th cyclotomic polynomial.
    * Added as a wrapper to GetCyclotomicPolynomialRecursive
    * @param &m the input cyclotomic order.
    * @param &modulus is the working modulus.
    * @return resultant m-th cyclotomic polynomial with coefficients in modulus.
    */
    uv64 GetCyclotomicPolynomial(ui32 m, const ui64 modulus);

    /**
    * Returns the m-th cyclotomic polynomial.
    *
    * @param &m the input cyclotomic order.
    * @return resultant m-th cyclotomic polynomial.
    */
    sv32 GetCyclotomicPolynomialRecursive(ui32 m);

    /**
    * Checkes if g is a generator for any cyclic group with modulus q (non-prime moduli are supported); currently q up to 64 bits only are supported
    * @param &g is candidate generator
    * @param &q is the modulus ( 2, 4, p^k, or 2*p^k where p^k is a power of an odd prime number )
    * @return true if g is a generator
    */
    bool IsGenerator(const ui64 g, const ui64 q);

    /**
    * Finds a generator for any cyclic group with modulus q (non-prime moduli are supported); currently q up to 64 bits only are supported
    * @param &q is the modulus ( 2, 4, p^k, or 2*p^k where p^k is a power of an odd prime number )
    * @return true if g is a generator
    */
    ui64 FindGeneratorCyclic(const ui64 q);

} // namespace lbcrypto ends

#endif
