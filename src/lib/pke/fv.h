/*
 * fv.h
 *
 *	This implementation is broadly similar to the PALISADE FV implementation
 *  Created on: Aug 25, 2017
 *      Author: chiraag
 *
 */

#ifndef LBCRYPTO_CRYPTO_FV_H
#define LBCRYPTO_CRYPTO_FV_H

#include <memory>
using std::shared_ptr;

#include "utils/backend.h"
#include "math/transfrm.h"
#include "pke_types.h"

namespace lbcrypto {

    /**
    * @brief This is the parameters class for the FV encryption scheme.
    *
    * The FV scheme parameter guidelines are introduced here:
    *   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
    *
    * We used the optimized parameter selection from the designs here:
    *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
    *
    * @tparam Element a ring element type.
    */
    struct FVParams {
        bool fast_modulli;

        ui64 q, p;
        ui32 logn, phim;

        // delta = floor(modq/modp) __NOT__ the delta from params
        ui64 delta;

        // specifies whether the keys are generated from discrete
        // Gaussian distribution or ternary distribution with the norm of unity
        MODE mode;
        shared_ptr<DiscreteGaussianGenerator> dgg;

        ui32 window_size;
    };

    extern std::map<ui32, shared_ptr<RelinKey>> g_rk_map;

    uv64 inline ToCoeff(const uv64& eval, const FVParams& params){
        if(params.fast_modulli){
            return ftt_inv_opt(eval);
        } else {
            return ftt_inv(eval, params.q, params.logn);
        }
    }

    uv64 inline ToEval(const uv64& coeff, const FVParams& params){
        if(params.fast_modulli){
            return ftt_fwd_opt(coeff);
        } else {
            return ftt_fwd(coeff, params.q, params.logn);
        }
    }

    uv64 NullEncrypt(uv64& pt, const FVParams& params);

    Ciphertext Encrypt(const PublicKey& pk, uv64& pt, const FVParams& params);

    Ciphertext Encrypt(const SecretKey& sk, uv64& pt, const FVParams& params);

    uv64 Decrypt(const SecretKey& sk, const Ciphertext& ct, const FVParams& params);

    sv64 Noise(const SecretKey& sk, const Ciphertext& ct, const FVParams& params);

    double NoiseMargin(const SecretKey& sk, const Ciphertext& ct, const FVParams& params);

    KeyPair KeyGen(const FVParams& params);

    Ciphertext EvalAdd(const Ciphertext& ct1, const Ciphertext& ct2, const FVParams& params);

    Ciphertext EvalAddPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params);

    Ciphertext EvalSub(const Ciphertext& ct1, const Ciphertext& ct2, const FVParams& params);

    Ciphertext EvalSubPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params);

    Ciphertext EvalMultPlain(const Ciphertext& ct, const uv64& pt, const FVParams& params);

    Ciphertext EvalNegate(const Ciphertext& ct, const FVParams& params);

    std::vector<uv64> HoistedDecompose(const Ciphertext& ct, const FVParams& params);

    Ciphertext KeySwitchDigits(const RelinKey& rk, const Ciphertext& ct,
            const std::vector<uv64> digits_ct, const FVParams& params);

    RelinKey KeySwitchGen(const SecretKey& orig_sk, const SecretKey& new_sk, const FVParams& params);

    Ciphertext KeySwitch(const RelinKey& relin_key, const Ciphertext& ct, const FVParams& params);

    Ciphertext EvalAutomorphismDigits(const ui32 rot, const RelinKey& rk, const Ciphertext& ct,
            const std::vector<uv64>& digits_ct, const FVParams& params);

    Ciphertext EvalAutomorphism(const ui32 rot, const Ciphertext& ct, const FVParams& params);

    shared_ptr<RelinKey> GetAutomorphismKey(ui32 rot);

    void EvalAutomorphismKeyGen(const SecretKey& sk, const uv32& index_list, const FVParams& params);

    Ciphertext AddRandomNoise(const Ciphertext& ct, const FVParams& params);

} // namespace lbcrypto ends
#endif
