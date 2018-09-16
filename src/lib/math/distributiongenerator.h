/*
 * distributiongenerator.h
 *
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#ifndef LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
#define LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_

//used to define a thread-safe generator
#if defined (_MSC_VER)  // Visual studio
    //#define thread_local __declspec( thread )
#elif defined (__GCC__) // GCC
    #define thread_local __thread
#endif

#include "utils/backend.h"
#include <random>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>

namespace lbcrypto {

    // AES Engine
    struct aes128_engine {
    private:
        static osuCrypto::PRNG m_prng;

    public:
        aes128_engine(){};
        ~aes128_engine() {};
        using result_type = uint64_t;
        constexpr static result_type min() { return 0; }
        constexpr static result_type max() { return -1; }

        result_type operator()();
    };

    // Return a static generator object
    aes128_engine &get_prng();
    // std::mt19937_64 &get_prng();

    uv64 get_bug_vector(const ui32 size);

    uv64 get_tug_vector(const ui32 size, const ui64 modulus);

    uv64 get_dug_vector(const ui32 size, const ui64 modulus);

    uv64 get_dug_vector_opt(const ui32 size);

    uv64 get_dgg_testvector(ui32 size, ui64 p, float std_dev = 40.0);

    uv64 get_uniform_testvector(ui32 size, ui64 max);

    /**
    * @brief Abstract class describing generator requirements.
    *
    * The Distribution Generator defines the methods that must be implemented by a real generator.
    * It also holds the single PRNG, which should be called by all child class when generating a random number is required.
    *
    */

    // Base class for Distribution Generator by type
    class DistributionGenerator {
        public:
            DistributionGenerator () {}
            virtual ~DistributionGenerator() {}
    };

} // namespace lbcrypto

#endif // LBCRYPTO_MATH_DISTRIBUTIONGENERATOR_H_
